use super::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{CombinationOption, CombinationTerm, MainGateInstructions};
use crate::circuit::range::{RangeInstructions, RangeTune};
use crate::circuit::{AssignedInteger, AssignedValue};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    fn range_tune_assert_in_field_result(&self) -> RangeTune {
        // TODO:
        RangeTune::Fits
    }

    pub(crate) fn _assert_in_field(&self, region: &mut Region<'_, N>, input: &mut AssignedInteger<N>) -> Result<(), Error> {
        // Constraints:

        // 0 = -c_0 + p_0 - a_0 + b_0 * R
        // 0 = -c_1 + p_1 - a_1 + b_1 * R - b_0
        // 0 = -c_2 + p_2 - a_2 + b_2 * R - b_1
        // 0 = -c_3 + p_3 - a_3           - b_2

        // Witness Layout:
        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_0 | a_0 | b_0 | -     |
        // | c_1 | a_1 | b_1 | b_0   |
        // | c_2 | a_2 | b_2 | b_1   |
        // | c_3 | a_3 | -   | b_2   |

        let main_gate = self.main_gate();
        let mut offset = 0;

        // to make a=p case is not passing compare with p-1
        let modulus_minus_one = &self.rns.wrong_modulus_minus_one.clone();

        // result comtains borrows must be bits and subtraaction result must be in range
        let comparision_result = input.integer().map(|input| {
            let comparision_result = self.rns.compare_to_modulus(&input);
            comparision_result
        });

        let result = comparision_result.as_ref().map(|r| r.result.clone());
        let result = &mut self.assign_integer(region, result, &mut offset)?;

        // assert borrow values are bits
        let borrow = comparision_result.as_ref().map(|r| r.borrow.clone());
        let b_0 = borrow.map(|borrow| if borrow[0] { N::one() } else { N::zero() });
        let b_1 = borrow.map(|borrow| if borrow[1] { N::one() } else { N::zero() });
        let b_2 = borrow.map(|borrow| if borrow[2] { N::one() } else { N::zero() });
        let b_0: &mut AssignedValue<N> = &mut main_gate.assign_bit(region, b_0, &mut offset)?.into();
        let b_1: &mut AssignedValue<N> = &mut main_gate.assign_bit(region, b_1, &mut offset)?.into();
        let b_2: &mut AssignedValue<N> = &mut main_gate.assign_bit(region, b_2, &mut offset)?.into();

        let left_shifter = self.rns.left_shifter_r;
        let one = N::one();
        let minus_one = -one;

        let result_0 = &mut result.limb(0);
        let result_1 = &mut result.limb(1);
        let result_2 = &mut result.limb(2);
        let result_3 = &mut result.limb(3);

        let input_0 = &mut input.limb(0);
        let input_1 = &mut input.limb(1);
        let input_2 = &mut input.limb(2);
        let input_3 = &mut input.limb(3);

        // | A   | B   | C   | D     |
        // | c_0 | a_0 | b_0 | -     |

        // 0 = -c_0 + p_0 - a_0 + b_0 * R
        main_gate.combine(
            region,
            CombinationTerm::Assigned(result_0, minus_one),
            CombinationTerm::Assigned(input_0, minus_one),
            CombinationTerm::Assigned(b_0, left_shifter),
            CombinationTerm::Zero,
            modulus_minus_one.limb_value(0),
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_1 | a_1 | b_1 | b_0   |

        // 0 = -c_1 + p_1 - a_1 + b_1 * R - b_0
        main_gate.combine(
            region,
            CombinationTerm::Assigned(result_1, minus_one),
            CombinationTerm::Assigned(input_1, minus_one),
            CombinationTerm::Assigned(b_1, left_shifter),
            CombinationTerm::Assigned(b_0, minus_one),
            modulus_minus_one.limb_value(1),
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_2 | a_2 | b_2 | b_1   |

        // 0 = -c_2 + p_2 - a_2 + b_2 * R - b_1
        main_gate.combine(
            region,
            CombinationTerm::Assigned(result_2, minus_one),
            CombinationTerm::Assigned(input_2, minus_one),
            CombinationTerm::Assigned(b_2, left_shifter),
            CombinationTerm::Assigned(b_1, minus_one),
            modulus_minus_one.limb_value(2),
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_3 | a_3 | -   | b_2   |

        // 0 = -c_3 + p_3 - a_3 - b_2

        main_gate.combine(
            region,
            CombinationTerm::Assigned(result_3, minus_one),
            CombinationTerm::Assigned(input_3, minus_one),
            CombinationTerm::Zero,
            CombinationTerm::Assigned(b_2, minus_one),
            modulus_minus_one.limb_value(3),
            &mut offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // update cells
        result.update_limb_cell(0, result_0.cell);
        result.update_limb_cell(1, result_1.cell);
        result.update_limb_cell(2, result_2.cell);
        result.update_limb_cell(3, result_3.cell);

        input.update_limb_cell(0, input_0.cell);
        input.update_limb_cell(1, input_1.cell);
        input.update_limb_cell(2, input_2.cell);
        input.update_limb_cell(3, input_3.cell);

        // ranges

        let range_chip = self.range_chip();
        range_chip.range_integer(region, result, self.range_tune_assert_in_field_result(), &mut offset)?;

        Ok(())
    }
}
