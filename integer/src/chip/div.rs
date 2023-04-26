use super::{IntegerChip, IntegerInstructions, Range};
use crate::rns::MaybeReduced;
use crate::{AssignedInteger, PrimeField};
use halo2::{arithmetic::Field, plonk::Error};
use maingate::{
    halo2, AssignedCondition, AssignedValue, CombinationOptionCommon, MainGateInstructions,
    RangeInstructions, RegionCtx, Term,
};

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn div_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<
        (
            AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedCondition<N>,
        ),
        Error,
    > {
        let (b_inv, cond) = self.invert_generic(ctx, b)?;
        let a_mul_b_inv = self.mul_generic(ctx, a, &b_inv)?;

        Ok((a_mul_b_inv, cond))
    }

    #[allow(clippy::needless_range_loop)]
    pub(crate) fn div_incomplete_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        // a / b = result
        // a = b * result
        // self + w * quotient = b * result

        let main_gate = self.main_gate();
        let (zero, one) = (N::ZERO, N::ONE);

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed;

        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = a
            .integer()
            .zip(b.integer())
            .map(|(a_int, b_int)| a_int.div(&b_int))
            .into();

        let result = witness.result();
        let quotient = witness.long();

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
                            Term::Assigned(result.limb(j), zero),
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
                    .zip(result.limb(j).value())
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
        self.constrain_binary_crt(ctx, &t.try_into().unwrap(), a, residues)?;

        // Constrain native part of crt
        main_gate.apply(
            ctx,
            [
                Term::Assigned(result.native(), zero),
                Term::Assigned(b.native(), zero),
                Term::Assigned(quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Zero,
                Term::Assigned(a.native(), -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(result)
    }
}
