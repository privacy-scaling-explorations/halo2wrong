use super::{IntegerChip, IntegerInstructions, Range};
use crate::rns::MaybeReduced;
use crate::{AssignedInteger, PrimeField};
use halo2::plonk::Error;
use maingate::{halo2, AssignedValue, MainGateInstructions, RangeInstructions, RegionCtx, Term};

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Reduces an [`AssignedInteger`] if any of its limbs values is greater
    /// than the [`Rns`] `max_unreduced_limb`.
    ///
    /// Panics if the value of the integer is greater than [`Rns`]
    /// `max_reducible_value`.
    pub(super) fn reduce_if_limb_values_exceeds_unreduced(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let exceeds_max_limb_value = a
            .limbs
            .iter()
            .any(|limb| limb.max_val() > self.rns.max_unreduced_limb);
        {
            // Sanity check for completeness

            // Reduction quotient is limited upto a dense single limb. It is quite possible
            // to make it more than a single limb. However even single limb will
            // support quite amount of lazy additions and make reduction process
            // much easier.
            let max_reduction_quotient = self.rns.max_reduced_limb.clone();
            let max_reducible_value =
                max_reduction_quotient * &self.rns.wrong_modulus + &self.rns.max_remainder;
            assert!(a.max_val() < max_reducible_value);
        }
        if exceeds_max_limb_value {
            self.reduce(ctx, a)
        } else {
            Ok(self.new_assigned_integer(a.limbs(), a.native().clone()))
        }
    }

    /// Reduces an [`AssignedInteger`] if any of its limbs values is greater
    /// than the [`Rns`] `max_reduced_limb`
    pub(super) fn reduce_if_limb_values_exceeds_reduced(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let exceeds_max_limb_value = a
            .limbs
            .iter()
            .any(|limb| limb.max_val() > self.rns.max_reduced_limb);
        if exceeds_max_limb_value {
            self.reduce(ctx, a)
        } else {
            Ok(self.new_assigned_integer(a.limbs(), a.native().clone()))
        }
    }

    /// Reduces an [`AssignedInteger`] if any of its max value is greater
    /// than the [`Rns`] `max_operand`.
    pub(super) fn reduce_if_max_operand_value_exceeds(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let exceeds_max_value = a.max_val() > self.rns.max_operand;
        if exceeds_max_value {
            self.reduce(ctx, a)
        } else {
            Ok(self.new_assigned_integer(a.limbs(), a.native().clone()))
        }
    }

    pub(super) fn reduce_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::ZERO, N::ONE);

        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
            a.integer().as_ref().map(|a_int| a_int.reduce()).into();
        let quotient = witness.short();
        let result = witness.result();

        // Apply ranges
        let range_chip = self.range_chip();
        let result = self.assign_integer(ctx, result.into(), Range::Remainder)?;
        let quotient = range_chip.assign(ctx, quotient, Self::sublimb_bit_len(), BIT_LEN_LIMB)?;
        let residues = witness
            .residues()
            .iter()
            .map(|v| range_chip.assign(ctx, *v, Self::sublimb_bit_len(), self.rns.red_v_bit_len))
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Assign intermediate values
        let t: Vec<AssignedValue<N>> = a
            .limbs()
            .iter()
            .zip(self.rns.negative_wrong_modulus_decomposed.into_iter())
            .map(|(a_i, w_i)| {
                main_gate.compose(
                    ctx,
                    &[
                        Term::Assigned(a_i.as_ref(), one),
                        Term::Assigned(&quotient, w_i),
                    ],
                    zero,
                )
            })
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Constrain binary part of crt
        self.constrain_binary_crt(
            ctx,
            &t.try_into()
                .expect("Unexpected failure in AssignedCell -> AssignedValue conversion"),
            &result,
            residues,
        )?;

        // Constrain native part of crt
        main_gate.assert_zero_sum(
            ctx,
            &[
                Term::Assigned(a.native(), -one),
                Term::Assigned(&quotient, self.rns.wrong_modulus_in_native_modulus),
                Term::Assigned(result.native(), one),
            ],
            zero,
        )?;

        Ok(result)
    }
}
