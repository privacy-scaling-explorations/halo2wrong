use super::{IntegerChip, Range};
use crate::circuit::main_gate::{CombinationOption, MainGateInstructions, Term};
use crate::circuit::range::RangeInstructions;
use crate::circuit::{AssignedInteger, AssignedLimb, AssignedValue, UnassignedInteger};
use crate::rns::Common;
use crate::rns::Integer;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use num_bigint::BigUint as big_uint;
use num_traits::One;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _range_assign_integer(
        &self,
        region: &mut Region<'_, N>,
        integer: UnassignedInteger<N>,
        range: Range,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let range_chip = self.range_chip();
        let max_val = (big_uint::one() << self.rns.bit_len_limb) - 1usize;

        let most_significant_limb_bit_len = match range {
            Range::Operand => self.rns.max_most_significant_operand_limb.bits() as usize,
            Range::Remainder => self.rns.max_most_significant_reduced_limb.bits() as usize,
            Range::MulQuotient => self.rns.max_most_significant_mul_quotient_limb.bits() as usize,
        };

        let assigned = range_chip.range_value(region, &integer.limb(0), self.rns.bit_len_limb, offset)?;
        let limb_0 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val.clone());

        let assigned = range_chip.range_value(region, &integer.limb(1), self.rns.bit_len_limb, offset)?;
        let limb_1 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val.clone());

        let assigned = range_chip.range_value(region, &integer.limb(2), self.rns.bit_len_limb, offset)?;
        let limb_2 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val.clone());

        let max_val = (big_uint::one() << most_significant_limb_bit_len) - 1usize;
        let assigned = range_chip.range_value(region, &integer.limb(3), most_significant_limb_bit_len, offset)?;
        let limb_3 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val);

        // find the native value
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let r = self.rns.left_shifter_r;
        let rr = self.rns.left_shifter_2r;
        let rrr = self.rns.left_shifter_3r;

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(limb_0, one),
            Term::Assigned(limb_1, r),
            Term::Assigned(limb_2, rr),
            Term::Assigned(limb_3, rrr),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        let native_value = integer.native();
        let (_, _, _, native_value_cell) = main_gate.combine(
            region,
            Term::Zero,
            Term::Zero,
            Term::Zero,
            Term::Unassigned(native_value.value, zero),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        let native_value = native_value.assign(native_value_cell);

        Ok(self.new_assigned_integer(vec![limb_0.clone(), limb_1.clone(), limb_2.clone(), limb_3.clone()], native_value))
    }

    pub(super) fn _assign_integer(&self, region: &mut Region<'_, N>, integer: Option<Integer<N>>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let (zero, one) = (N::zero(), N::one());
        let r = self.rns.left_shifter_r;
        let rr = self.rns.left_shifter_2r;
        let rrr = self.rns.left_shifter_3r;

        let (cell_0, cell_1, cell_2, cell_3) = main_gate.combine(
            region,
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(0)), one),
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(1)), r),
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(2)), rr),
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(3)), rrr),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        let native_value = integer.as_ref().map(|integer| integer.native());

        let (_, _, _, native_value_cell) = main_gate.combine(
            region,
            Term::Zero,
            Term::Zero,
            Term::Zero,
            Term::Unassigned(native_value, zero),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        let cells = vec![cell_0, cell_1, cell_2, cell_3];

        let limbs = cells
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let max_val = if i == NUMBER_OF_LIMBS - 1 {
                    self.rns.max_most_significant_reduced_limb.clone()
                } else {
                    self.rns.max_reduced_limb.clone()
                };
                AssignedLimb {
                    value: integer.as_ref().map(|integer| integer.limb(i)),
                    cell: *cell,
                    max_val,
                }
            })
            .collect();

        let native_value = AssignedValue {
            value: native_value,
            cell: native_value_cell,
        };

        Ok(self.new_assigned_integer(limbs, native_value))
    }
}
