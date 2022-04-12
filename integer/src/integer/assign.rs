use std::rc::Rc;

use super::{IntegerChip, Range};
use crate::rns::{Common, Integer};
use crate::{AssignedInteger, AssignedLimb, UnassignedInteger, WrongExt, NUMBER_OF_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::{
    fe_to_big, halo2, CombinationOptionCommon, MainGateInstructions, RangeInstructions, RegionCtx,
    Term,
};
use num_bigint::BigUint as big_uint;
use num_traits::One;

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _range_assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N>,
        range: Range,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let range_chip = self.range_chip();
        let max_val = (big_uint::one() << self.rns.bit_len_limb) - 1usize;

        let most_significant_limb_bit_len = match range {
            Range::Operand => self.rns.max_most_significant_operand_limb.bits() as usize,
            Range::Remainder => self.rns.max_most_significant_reduced_limb.bits() as usize,
            Range::MulQuotient => self.rns.max_most_significant_mul_quotient_limb.bits() as usize,
        };

        let assigned = range_chip.range_value(ctx, &integer.limb(0), BIT_LEN_LIMB)?;
        let limb_0 = AssignedLimb::from(assigned, max_val.clone());

        let assigned = range_chip.range_value(ctx, &integer.limb(1), BIT_LEN_LIMB)?;
        let limb_1 = AssignedLimb::from(assigned, max_val.clone());

        let assigned = range_chip.range_value(ctx, &integer.limb(2), BIT_LEN_LIMB)?;
        let limb_2 = AssignedLimb::from(assigned, max_val);

        let max_val = (big_uint::one() << most_significant_limb_bit_len) - 1usize;
        let assigned =
            range_chip.range_value(ctx, &integer.limb(3), most_significant_limb_bit_len)?;
        let limb_3 = AssignedLimb::from(assigned, max_val);

        // find the native value
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let r = self.rns.left_shifter_r;
        let rr = self.rns.left_shifter_2r;
        let rrr = self.rns.left_shifter_3r;

        let native_value = main_gate.combine(
            ctx,
            &[
                Term::Assigned(limb_0.clone().into(), one),
                Term::Assigned(limb_1.clone().into(), r),
                Term::Assigned(limb_2.clone().into(), rr),
                Term::Assigned(limb_3.clone().into(), rrr),
                Term::Unassigned(integer.native().into(), -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[4];

        // let native_value = main_gate.assign_to_acc(ctx, &integer.native())?;
        Ok(self.new_assigned_integer(vec![limb_0, limb_1, limb_2, limb_3], native_value))
    }

    pub(super) fn _assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: W,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let integer = Integer::from_fe(integer, Rc::clone(&self.rns));

        let main_gate = self.main_gate();

        let limbs = integer.limbs();
        let mut assigned_limbs = vec![];
        for limb in limbs.iter() {
            let assigned = main_gate.assign_constant(ctx, *limb)?;
            assigned_limbs.push(AssignedLimb::from(assigned, fe_to_big(*limb)));
        }
        let native = main_gate.assign_constant(ctx, integer.native())?;

        Ok(self.new_assigned_integer(assigned_limbs, native))
    }

    pub(super) fn _assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N>,
        should_be_in_remainder_range: bool,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        if let Some(value) = integer.value() {
            if should_be_in_remainder_range {
                assert!(value <= self.rns.max_remainder)
            } else {
                assert!(value <= self.rns.max_with_max_unreduced_limbs);
            }
        }

        let (zero, one) = (N::zero(), N::one());
        let r = self.rns.left_shifter_r;
        let rr = self.rns.left_shifter_2r;
        let rrr = self.rns.left_shifter_3r;

        let assigned_values = main_gate.combine(
            ctx,
            &[
                Term::Unassigned(integer.limb(0).into(), one),
                Term::Unassigned(integer.limb(1).into(), r),
                Term::Unassigned(integer.limb(2).into(), rr),
                Term::Unassigned(integer.limb(3).into(), rrr),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;
        let assigned_values = vec![
            assigned_values[0],
            assigned_values[1],
            assigned_values[2],
            assigned_values[3],
        ];

        let native_value = main_gate.assign_to_acc(ctx, &integer.native())?;

        let limbs = assigned_values
            .into_iter()
            .enumerate()
            .map(|(i, assigned_value)| {
                let max_val = if should_be_in_remainder_range {
                    if i == NUMBER_OF_LIMBS - 1 {
                        self.rns.max_most_significant_reduced_limb.clone()
                    } else {
                        self.rns.max_reduced_limb.clone()
                    }
                } else {
                    self.rns.max_unreduced_limb.clone()
                };

                AssignedLimb::from(assigned_value, max_val)
            })
            .collect();

        Ok(self.new_assigned_integer(limbs, native_value))
    }
}
