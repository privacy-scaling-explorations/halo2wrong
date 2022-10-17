use super::IntegerChip;
use crate::rns::MaybeReduced;
use crate::{AssignedInteger, FieldExt};
use halo2::plonk::Error;

use maingate::{halo2, AssignedValue, MainGateInstructions, RangeInstructions, RegionCtx, Term};

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn assert_zero_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
            a.integer().as_ref().map(|a_int| a_int.reduce()).into();
        let quotient = witness.short();

        // Apply ranges
        let range_chip = self.range_chip();
        let quotient = range_chip.assign(ctx, quotient, Self::sublimb_bit_len(), BIT_LEN_LIMB)?;
        let residues = witness
            .residues()
            .iter()
            .map(|v| {
                let residue =
                    range_chip.assign(ctx, *v, Self::sublimb_bit_len(), self.rns.red_v_bit_len)?;
                Ok(residue)
            })
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Assign intermediate values
        let t: Vec<AssignedValue<N>> = a
            .limbs()
            .iter()
            .zip(self.rns.negative_wrong_modulus_decomposed.into_iter())
            .map(|(a_i, w_i)| {
                let t = main_gate.compose(
                    ctx,
                    &[
                        Term::Assigned(a_i.as_ref(), one),
                        Term::Assigned(&quotient, w_i),
                    ],
                    zero,
                )?;
                Ok(t)
            })
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Constrain binary part of crt
        self.constrain_binary_crt(
            ctx,
            &t.try_into()
                .expect("Unexpected failure in AssignedCell -> AssignedValue conversion"),
            residues,
            None,
        )
    }
}
