use super::{IntegerChip, IntegerInstructions, Range};
use crate::rns::MaybeReduced;
use crate::{AssignedInteger, WrongExt};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::{
    halo2, CombinationOptionCommon, MainGateInstructions, RangeInstructions, RegionCtx, Term,
};

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Reduces an [`AssignedInteger`] if any of its limbs values is greater
    /// than the [`Rns`] `max_unreduced_limb`.
    ///
    /// Panics if the value of the integer is greater than [`Rns`]
    /// `max_reducible_value`.
    pub(super) fn reduce_if_limb_values_exceeds_unreduced(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let exceeds_max_limb_value = a.limbs.iter().fold(false, |must_reduce, limb| {
            must_reduce | (limb.max_val() > self.rns.max_unreduced_limb)
        });
        assert!(a.max_val() < self.rns.max_reducible_value);
        if exceeds_max_limb_value {
            self.reduce(ctx, a)
        } else {
            Ok(self.new_assigned_integer(a.limbs.clone(), a.native_value))
        }
    }

    /// Reduces an [`AssignedInteger`] if any of its limbs values is greater
    /// than the [`Rns`] `max_reduced_limb`.
    pub(super) fn reduce_if_limb_values_exceeds_reduced(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let exceeds_max_limb_value = a.limbs.iter().fold(false, |must_reduce, limb| {
            must_reduce | (limb.max_val() > self.rns.max_reduced_limb)
        });
        if exceeds_max_limb_value {
            self.reduce(ctx, a)
        } else {
            Ok(self.new_assigned_integer(a.limbs.clone(), a.native_value))
        }
    }

    /// Reduces an [`AssignedInteger`] if any of its max value is greater
    /// than the [`Rns`] `max_operand`.
    pub(super) fn reduce_if_max_operand_value_exceeds(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let exceeds_max_value = a.max_val() > self.rns.max_operand;
        if exceeds_max_value {
            self.reduce(ctx, a)
        } else {
            Ok(self.new_assigned_integer(a.limbs.clone(), a.native_value))
        }
    }

    /// Reduction circuit for an [`AssignedInteger`].
    pub(super) fn _reduce(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed;

        let a_int = a.integer();
        let reduction_witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
            a_int.as_ref().map(|a_int| a_int.reduce()).into();
        let quotient = reduction_witness.short();
        let result = reduction_witness.result();
        let (t_0, t_1, t_2, t_3) = reduction_witness.intermediate_values();
        let (u_0, u_1, v_0, v_1) = reduction_witness.residues();

        // Apply ranges
        let range_chip = self.range_chip();
        let result = &self.range_assign_integer(ctx, result.into(), Range::Remainder)?;
        let quotient = range_chip.range_value(ctx, &quotient.into(), BIT_LEN_LIMB)?;
        let v_0 = range_chip.range_value(ctx, &v_0.into(), self.rns.red_v0_bit_len)?;
        let v_1 = range_chip.range_value(ctx, &v_1.into(), self.rns.red_v1_bit_len)?;

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        let t_0 = main_gate.combine(
            ctx,
            &[
                Term::Assigned(a.limb(0), one),
                Term::Assigned(quotient, negative_wrong_modulus[0]),
                Term::Unassigned(t_0, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2];

        let t_1 = main_gate.combine(
            ctx,
            &[
                Term::Assigned(a.limb(1), one),
                Term::Assigned(quotient, negative_wrong_modulus[1]),
                Term::Unassigned(t_1, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2];

        let t_2 = main_gate.combine(
            ctx,
            &[
                Term::Assigned(a.limb(2), one),
                Term::Assigned(quotient, negative_wrong_modulus[2]),
                Term::Unassigned(t_2, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2];

        let t_3 = main_gate.combine(
            ctx,
            &[
                Term::Assigned(a.limb(3), one),
                Term::Assigned(quotient, negative_wrong_modulus[3]),
                Term::Unassigned(t_3, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2];

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        main_gate.combine(
            ctx,
            &[
                Term::Assigned(t_0, one),
                Term::Assigned(t_1, left_shifter_r),
                Term::Assigned(result.limb(0), -one),
                Term::Assigned(result.limb(1), -left_shifter_r),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            ctx,
            &[
                Term::Zero,
                Term::Zero,
                Term::Assigned(v_0, left_shifter_2r),
                Term::Zero,
                Term::Unassigned(u_0, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            ctx,
            &[
                Term::Assigned(t_2, one),
                Term::Assigned(t_3, left_shifter_r),
                Term::Assigned(result.limb(2), -one),
                Term::Zero,
                Term::Assigned(result.limb(3), -left_shifter_r),
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            ctx,
            &[
                Term::Zero,
                Term::Assigned(v_1, left_shifter_2r),
                Term::Assigned(v_0, -one),
                Term::Zero,
                Term::Unassigned(u_1, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // update native value

        main_gate.combine(
            ctx,
            &[
                Term::Assigned(a.native(), -one),
                Term::Assigned(quotient, self.rns.wrong_modulus_in_native_modulus),
                Term::Assigned(result.native(), one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(result.clone())
    }
}
