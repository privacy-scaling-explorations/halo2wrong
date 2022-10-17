use super::{IntegerChip, IntegerInstructions, Range};
use crate::rns::{Common, Integer, MaybeReduced};
use crate::{AssignedInteger, FieldExt};
use halo2::{arithmetic::Field, plonk::Error};
use maingate::{
    halo2, AssignedValue, CombinationOptionCommon, MainGateInstructions, RangeInstructions,
    RegionCtx, Term,
};

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn constrain_binary_crt(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        t: &[AssignedValue<N>; NUMBER_OF_LIMBS],
        residues: Vec<AssignedValue<N>>,
        result: Option<&AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        // Constrain residues
        let lsh_one = self.rns.left_shifter(1);
        let lsh_two = self.rns.left_shifter(2);
        let mut carry = Term::Zero;

        let result: Vec<Option<AssignedValue<N>>> = match result {
            Some(result) => result
                .limbs()
                .iter()
                .map(|limb| Some(limb.value.clone()))
                .collect(),
            None => {
                vec![None; NUMBER_OF_LIMBS]
            }
        };

        for ((t_chunk, r_chunk), v) in t.chunks(2).zip(result.chunks(2)).zip(residues.iter()) {
            let r_lo = match r_chunk[0].as_ref() {
                Some(r_lo) => Term::Assigned(r_lo, -one),
                None => Term::Zero,
            };
            if t_chunk.len() == 2 {
                let (t_lo, t_hi) = (&t_chunk[0], &t_chunk[1]);
                let r_hi = match r_chunk[1].as_ref() {
                    Some(r_hi) => Term::Assigned(r_hi, -lsh_one),
                    None => Term::Zero,
                };
                main_gate.assert_zero_sum(
                    ctx,
                    &[
                        // v * R^2 = t_lo + R * t_hi  + r_lo + R * r_hi + carry
                        Term::Assigned(t_lo, one),
                        Term::Assigned(t_hi, lsh_one),
                        Term::Assigned(v, -lsh_two),
                        r_lo,
                        r_hi,
                        carry.clone(),
                    ],
                    zero,
                )?;
                carry = Term::Assigned(v, one);
            } else {
                main_gate.assert_zero_sum(
                    ctx,
                    &[
                        // v * R = r_lo + t + carry
                        Term::Assigned(&t_chunk[0], one),
                        r_lo,
                        Term::Assigned(v, -lsh_one),
                        carry.clone(),
                    ],
                    zero,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::needless_range_loop)]
    pub(super) fn mul_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed;

        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = a
            .integer()
            .zip(b.integer())
            .map(|(a_int, b_int)| a_int.mul(&b_int))
            .into();
        let result = witness.result();
        let quotient = witness.long();

        // Apply ranges
        let range_chip = self.range_chip();
        let result = self.assign_integer(ctx, result.into(), Range::Remainder)?;

        let quotient = &self.assign_integer(ctx, quotient.into(), Range::MulQuotient)?;
        let residues = witness
            .residues()
            .iter()
            .map(|v| range_chip.assign(ctx, *v, Self::sublimb_bit_len(), self.rns.mul_v_bit_len))
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        let mut t: Vec<AssignedValue<N>> = vec![];

        // Assign intermediate values
        for (i, intermediate_value) in witness.intermediates().into_iter().enumerate() {
            let mut intermediate_value = intermediate_value;

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOptionCommon::OneLinerMul
                } else {
                    CombinationOptionCommon::CombineToNextMul(one)
                }
                .into();

                let t_i = main_gate
                    .apply(
                        ctx,
                        [
                            Term::Assigned(a.limb(j), zero),
                            Term::Assigned(b.limb(k), zero),
                            Term::Assigned(quotient.limb(k), negative_wrong_modulus[j]),
                            Term::Zero,
                            Term::Unassigned(intermediate_value, -one),
                        ],
                        zero,
                        combination_option,
                    )?
                    .swap_remove(4);

                if j == 0 {
                    // first time we see t_j assignment
                    t.push(t_i);
                }

                // update running temp value
                intermediate_value = intermediate_value
                    .zip(a.limb(j).value())
                    .zip(b.limb(k).value())
                    .zip(quotient.limb(k).value())
                    .map(|(((t, a), b), q)| {
                        let p = negative_wrong_modulus[j];
                        t - (*a * *b + *q * p)
                    });

                // Sanity check for the last running subtraction value
                {
                    if j == i {
                        intermediate_value.assert_if_known(Field::is_zero_vartime);
                    }
                }
            }
        }

        // Constrain binary part of crt
        self.constrain_binary_crt(
            ctx,
            &t.try_into()
                .expect("Unexpected failure in AssignedCell -> AssignedValue conversion"),
            residues,
            Some(&result),
        )?;

        // Constrain native part of crt
        main_gate.apply(
            ctx,
            [
                Term::Assigned(a.native(), zero),
                Term::Assigned(b.native(), zero),
                Term::Assigned(quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Zero,
                Term::Assigned(result.native(), -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(result)
    }

    pub(crate) fn mul_constant_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed;

        let a_int = a.integer();
        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
            a_int.map(|a_int| a_int.mul(b)).into();
        let result = witness.result();
        let quotient = witness.long();

        // Apply ranges
        let range_chip = self.range_chip();
        let quotient = &self.assign_integer(ctx, quotient.into(), Range::MulQuotient)?;
        let result = self.assign_integer(ctx, result.into(), Range::Remainder)?;
        let residues = witness
            .residues()
            .iter()
            .map(|v| range_chip.assign(ctx, *v, Self::sublimb_bit_len(), self.rns.mul_v_bit_len))
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Assign intermediate values
        let t: Vec<AssignedValue<N>> = witness
            .intermediates()
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let terms: Vec<Term<N>> = (0..=i)
                    .map(|j| {
                        let k = i - j;
                        Term::Assigned(a.limb(j), b.limb(k).fe())
                    })
                    .chain((0..=i).map(|j| {
                        let k = i - j;
                        Term::Assigned(quotient.limb(j), negative_wrong_modulus[k])
                    }))
                    .collect();
                main_gate.compose(ctx, &terms[..], zero)
            })
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Constrain binary part of crt
        self.constrain_binary_crt(
            ctx,
            &t.try_into()
                .expect("Unexpected failure in AssignedCell -> AssignedValue conversion"),
            residues,
            Some(&result),
        )?;

        // Update native value
        main_gate.apply(
            ctx,
            [
                Term::Assigned(a.native(), b.native()),
                Term::Zero,
                Term::Assigned(quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Assigned(result.native(), -one),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(result)
    }

    #[allow(clippy::needless_range_loop)]
    pub(crate) fn mul_into_one_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed;

        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = a
            .integer()
            .zip(b.integer())
            .map(|(a_int, b_int)| a_int.mul(&b_int))
            .into();
        let _ = witness.result(); // Must be equal to 1
        let quotient = witness.long();

        // Apply ranges
        let range_chip = self.range_chip();
        let quotient = &self.assign_integer(ctx, quotient.into(), Range::MulQuotient)?;
        let residues = witness
            .residues()
            .iter()
            .map(|v| range_chip.assign(ctx, *v, Self::sublimb_bit_len(), self.rns.mul_v_bit_len))
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        let mut t: Vec<AssignedValue<N>> = vec![];

        // Assign intermediate values
        for (i, intermediate_value) in witness.intermediates().into_iter().enumerate() {
            let mut intermediate_value = intermediate_value;

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOptionCommon::OneLinerMul
                } else {
                    CombinationOptionCommon::CombineToNextMul(one)
                }
                .into();

                let t_i = main_gate
                    .apply(
                        ctx,
                        [
                            Term::Assigned(a.limb(j), zero),
                            Term::Assigned(b.limb(k), zero),
                            Term::Assigned(quotient.limb(k), negative_wrong_modulus[j]),
                            Term::Zero,
                            Term::Unassigned(intermediate_value, -one),
                        ],
                        zero,
                        combination_option,
                    )?
                    .swap_remove(4);

                if j == 0 {
                    // first time we see t_j assignment
                    t.push(t_i);
                }

                // update running temp value
                intermediate_value = intermediate_value
                    .zip(a.limb(j).value())
                    .zip(b.limb(k).value())
                    .zip(quotient.limb(k).value())
                    .map(|(((t, a), b), q)| {
                        let p = negative_wrong_modulus[j];
                        t - (*a * *b + *q * p)
                    });

                // Sanity check for the last running subtraction value
                {
                    if j == i {
                        intermediate_value.assert_if_known(Field::is_zero_vartime);
                    }
                }
            }
        }

        // Constrain binary part of crt
        let lsh_one = self.rns.left_shifter(1);
        let lsh_two = self.rns.left_shifter(2);
        let mut carry = Term::Zero;

        for (i, (t_chunk, v)) in t.chunks(2).zip(residues.iter()).enumerate() {
            if t_chunk.len() == 2 {
                let (t_lo, t_hi) = (&t_chunk[0], &t_chunk[1]);
                main_gate.assert_zero_sum(
                    ctx,
                    &[
                        // R^2 * v = t_lo - 1 + R * t_hi
                        Term::Assigned(t_lo, one),
                        Term::Assigned(t_hi, lsh_one),
                        Term::Assigned(v, -lsh_two),
                        carry.clone(),
                    ],
                    if i == 0 { -one } else { zero },
                )?;
                carry = Term::Assigned(v, one);
            } else {
                main_gate.assert_zero_sum(
                    ctx,
                    &[
                        Term::Assigned(&t_chunk[0], one),
                        Term::Assigned(v, -lsh_one),
                        carry.clone(),
                    ],
                    zero,
                )?;
            }
        }

        // Constrain native part of crt
        main_gate.apply(
            ctx,
            [
                Term::Assigned(a.native(), zero),
                Term::Assigned(b.native(), zero),
                Term::Assigned(quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Zero,
                Term::Zero,
            ],
            -one,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(())
    }
}
