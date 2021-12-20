use super::{IntegerChip, IntegerInstructions, Range};
use crate::circuit::main_gate::{CombinationOption, MainGateInstructions, Term};
use crate::circuit::{AssignedInteger, AssignedValue};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _assert_in_field(&self, region: &mut Region<'_, N>, input: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        // Constraints:
        // 0 = -c_0 + p_0 - a_0 + b_0 * R
        // 0 = -c_1 + p_1 - a_1 + b_1 * R - b_0
        // 0 = -c_2 + p_2 - a_2 + b_2 * R - b_1
        // 0 = -c_3 + p_3 - a_3           - b_2

        // Witness layout:
        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_0 | a_0 | b_0 | -     |
        // | c_1 | a_1 | b_1 | b_0   |
        // | c_2 | a_2 | b_2 | b_1   |
        // | c_3 | a_3 | -   | b_2   |

        let main_gate = self.main_gate();

        // to make a=p case not passing compare with p-1
        let modulus_minus_one = &self.rns.wrong_modulus_minus_one.clone();

        // result containts borrows must be bits and subtraaction result must be in range
        let comparision_result = input.integer(self.rns.bit_len_limb).map(|input| {
            let comparision_result = self.rns.compare_to_modulus(&input);
            comparision_result
        });

        let result = comparision_result.as_ref().map(|r| r.result.clone());
        let result = &self.range_assign_integer(region, result.into(), Range::Remainder, offset)?;

        // assert borrow values are bits
        let borrow = comparision_result.as_ref().map(|r| r.borrow.clone());
        let b_0 = borrow.map(|borrow| if borrow[0] { N::one() } else { N::zero() });
        let b_1 = borrow.map(|borrow| if borrow[1] { N::one() } else { N::zero() });
        let b_2 = borrow.map(|borrow| if borrow[2] { N::one() } else { N::zero() });
        let b_0: &AssignedValue<N> = &main_gate.assign_bit(region, b_0, offset)?.into();
        let b_1: &AssignedValue<N> = &main_gate.assign_bit(region, b_1, offset)?.into();
        let b_2: &AssignedValue<N> = &main_gate.assign_bit(region, b_2, offset)?.into();

        let left_shifter = self.rns.left_shifter_r;
        let one = N::one();

        // | A   | B   | C   | D     |
        // | c_0 | a_0 | b_0 | -     |

        // 0 = -c_0 + p_0 - a_0 + b_0 * R
        main_gate.combine(
            region,
            Term::Assigned(&result.limb(0), -one),
            Term::Assigned(&input.limb(0), -one),
            Term::Assigned(b_0, left_shifter),
            Term::Zero,
            modulus_minus_one.limb_value(0),
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_1 | a_1 | b_1 | b_0   |

        // 0 = -c_1 + p_1 - a_1 + b_1 * R - b_0
        main_gate.combine(
            region,
            Term::Assigned(&result.limb(1), -one),
            Term::Assigned(&input.limb(1), -one),
            Term::Assigned(b_1, left_shifter),
            Term::Assigned(b_0, -one),
            modulus_minus_one.limb_value(1),
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_2 | a_2 | b_2 | b_1   |

        // 0 = -c_2 + p_2 - a_2 + b_2 * R - b_1
        main_gate.combine(
            region,
            Term::Assigned(&result.limb(2), -one),
            Term::Assigned(&input.limb(2), -one),
            Term::Assigned(b_2, left_shifter),
            Term::Assigned(b_1, -one),
            modulus_minus_one.limb_value(2),
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | c_3 | a_3 | -   | b_2   |

        // 0 = -c_3 + p_3 - a_3 - b_2

        main_gate.combine(
            region,
            Term::Assigned(&result.limb(3), -one),
            Term::Assigned(&input.limb(3), -one),
            Term::Zero,
            Term::Assigned(b_2, -one),
            modulus_minus_one.limb_value(3),
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        Ok(())
    }
}
