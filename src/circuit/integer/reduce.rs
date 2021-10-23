use super::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{CombinationOption, CombinationTerm, MainGateInstructions};
use crate::circuit::range::{RangeInstructions, RangeTune};
use crate::circuit::{AssignedInteger, AssignedValue};
use crate::rns::Quotient;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    fn red_v0_range_tune(&self) -> RangeTune {
        RangeTune::Fits
    }

    fn red_v1_range_tune(&self) -> RangeTune {
        RangeTune::Fits
    }

    fn red_result_range_tune(&self) -> RangeTune {
        RangeTune::Fits
    }

    fn red_quotient_range_tune(&self) -> RangeTune {
        RangeTune::Fits
    }

    pub(crate) fn _reduce(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let mut offset = 0;
        let negative_wrong_modulus: Vec<N> = self.rns.negative_wrong_modulus.limbs();

        let reduction_result = a.integer().map(|integer_a| self.rns.reduce(&integer_a));

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Short(quotient) => quotient.fe(),
                _ => panic!("short quotient expected"),
            };
            quotient
        });

        let result = reduction_result.as_ref().map(|u| u.result.clone());
        let result = &mut self.assign_integer(region, result, &mut offset)?;
        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.iter().map(|t| t.fe()).collect());

        let u_0 = reduction_result.as_ref().map(|u| u.u_0);
        let v_0 = reduction_result.as_ref().map(|u| u.v_0);
        let u_1 = reduction_result.as_ref().map(|u| u.u_1);
        let v_1 = reduction_result.as_ref().map(|u| u.v_1);

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        let t_0 = intermediate_values.as_ref().map(|t| t[0]);
        let t_1 = intermediate_values.as_ref().map(|t| t[1]);
        let t_2 = intermediate_values.as_ref().map(|t| t[2]);
        let t_3 = intermediate_values.as_ref().map(|t| t[3]);

        let (a_0_new_cell, q_cell, t_0_cell, _) = main_gate.combine(
            region,
            CombinationTerm::Assigned(&mut a.limb(0), one),
            CombinationTerm::Unassigned(quotient, negative_wrong_modulus[0]),
            CombinationTerm::Unassigned(t_0, -one),
            CombinationTerm::Zero,
            zero,
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;

        a.update_limb_cell(0, a_0_new_cell);
        let quotient = &mut AssignedValue::<N>::new(q_cell, quotient);
        let t_0 = &mut AssignedValue::<N>::new(t_0_cell, t_0);

        let (a_1_new_cell, _, t_1_cell, _) = main_gate.combine(
            region,
            CombinationTerm::Assigned(&mut a.limb(1), one),
            CombinationTerm::Assigned(quotient, negative_wrong_modulus[1]),
            CombinationTerm::Unassigned(t_1, -one),
            CombinationTerm::Zero,
            zero,
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;
        a.update_limb_cell(1, a_1_new_cell);
        let t_1 = &mut AssignedValue::<N>::new(t_1_cell, t_1);

        let (a_2_new_cell, _, t_2_cell, _) = main_gate.combine(
            region,
            CombinationTerm::Assigned(&mut a.limb(2), one),
            CombinationTerm::Assigned(quotient, negative_wrong_modulus[2]),
            CombinationTerm::Unassigned(t_2, -one),
            CombinationTerm::Zero,
            zero,
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;
        a.update_limb_cell(2, a_2_new_cell);
        let t_2 = &mut AssignedValue::<N>::new(t_2_cell, t_2);

        let (a_3_new_cell, _, t_3_cell, _) = main_gate.combine(
            region,
            CombinationTerm::Assigned(&mut a.limb(3), one),
            CombinationTerm::Assigned(quotient, negative_wrong_modulus[3]),
            CombinationTerm::Unassigned(t_3, -one),
            CombinationTerm::Zero,
            zero,
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;
        a.update_limb_cell(3, a_3_new_cell);
        let t_3 = &mut AssignedValue::<N>::new(t_3_cell, t_3);

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        // result.cycle_cell(region, 1, r_1_new_cell)?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let (_, _, result_0_cell, result_1_cell) = main_gate.combine(
            region,
            CombinationTerm::Assigned(t_0, one),
            CombinationTerm::Assigned(t_1, left_shifter_r),
            CombinationTerm::Assigned(&mut result.limb(0), -one),
            CombinationTerm::Assigned(&mut result.limb(1), -left_shifter_r),
            zero,
            &mut offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        result.update_limb_cell(0, result_0_cell);
        result.update_limb_cell(1, result_1_cell);

        let (_, _, v_0_cell, _) = main_gate.combine(
            region,
            CombinationTerm::Zero,
            CombinationTerm::Zero,
            CombinationTerm::Unassigned(v_0, left_shifter_2r),
            CombinationTerm::Unassigned(u_0, -one),
            zero,
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let v_0 = &mut AssignedValue::<N>::new(v_0_cell, v_0);

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        let (_, _, result_2_cell, result_3_cell) = main_gate.combine(
            region,
            CombinationTerm::Assigned(t_2, one),
            CombinationTerm::Assigned(t_3, left_shifter_r),
            CombinationTerm::Assigned(&mut result.limb(2), -one),
            CombinationTerm::Assigned(&mut result.limb(3), -left_shifter_r),
            zero,
            &mut offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        result.update_limb_cell(2, result_2_cell);
        result.update_limb_cell(3, result_3_cell);

        let (_, v_1_cell, _, _) = main_gate.combine(
            region,
            CombinationTerm::Zero,
            CombinationTerm::Unassigned(v_1, left_shifter_2r),
            CombinationTerm::Assigned(v_0, -one),
            CombinationTerm::Unassigned(u_1, -one),
            zero,
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let v_1 = &mut AssignedValue::<N>::new(v_1_cell, v_1);

        // ranges

        let range_chip = self.range_chip();

        range_chip.range_value(region, quotient, self.red_quotient_range_tune(), &mut offset)?;
        range_chip.range_integer(region, result, self.red_result_range_tune(), &mut offset)?;
        let _ = range_chip.range_value(region, v_0, self.red_v0_range_tune(), &mut offset)?;
        let _ = range_chip.range_value(region, v_1, self.red_v1_range_tune(), &mut offset)?;

        // native red

        let (a_native_new_cell, _, _, result_native_new_cell) = main_gate.combine(
            region,
            CombinationTerm::Assigned(&mut a.native(), -one),
            CombinationTerm::Zero,
            CombinationTerm::Assigned(quotient, self.rns.wrong_modulus_in_native_modulus),
            CombinationTerm::Assigned(&mut result.native(), one),
            zero,
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;

        a.update_native_cell(a_native_new_cell);
        result.update_native_cell(result_native_new_cell);

        Ok(result.clone())
    }
}
