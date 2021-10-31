use super::IntegerChip;
use crate::circuit::main_gate::{CombinationOption, MainGateInstructions, Term};
use crate::circuit::range::{RangeInstructions, RangeTune};
use crate::circuit::{AssignedInteger, AssignedValue};
use crate::rns::{Common, Quotient};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use num_bigint::BigUint as big_uint;
use num_traits::Zero;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    fn assert_zero_v0_range_tune(&self) -> RangeTune {
        // RangeTune::Overflow(2)
        RangeTune::Fits
    }

    fn assert_zero_v1_range_tune(&self) -> RangeTune {
        // RangeTune::Overflow(3)
        RangeTune::Fits
    }

    fn assert_zero_quotient_range_tune(&self) -> RangeTune {
        RangeTune::Fits
    }

    pub(crate) fn _assert_zero(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let negative_wrong_modulus: Vec<N> = self.rns.negative_wrong_modulus.clone();

        let reduction_result = a.integer().map(|integer_a| {
            let reduction_result = self.rns.reduce(&integer_a);

            assert_eq!(reduction_result.result.value(), big_uint::zero());
            reduction_result
        });

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Short(quotient) => quotient,
                _ => panic!("short quotient expected"),
            };
            quotient
        });

        let v_0 = reduction_result.as_ref().map(|u| u.v_0);
        let v_1 = reduction_result.as_ref().map(|u| u.v_1);

        // apply ranges

        let range_chip = self.range_chip();
        // main_gate.assign_value(region, value, M, offset);
        let quotient = &mut range_chip.range_value(region, &quotient.into(), self.assert_zero_quotient_range_tune(), offset)?;
        let v_0 = &mut range_chip.range_value(region, &v_0.into(), self.assert_zero_v0_range_tune(), offset)?;
        let v_1 = &mut range_chip.range_value(region, &v_1.into(), self.assert_zero_v1_range_tune(), offset)?;

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        let intermediate_values = reduction_result.as_ref().map(|u| u.t.clone());
        let t_0 = intermediate_values.as_ref().map(|t| t[0]);
        let t_1 = intermediate_values.as_ref().map(|t| t[1]);
        let t_2 = intermediate_values.as_ref().map(|t| t[2]);
        let t_3 = intermediate_values.as_ref().map(|t| t[3]);

        let (_, _, t_0_cell, _) = main_gate.combine(
            region,
            Term::Assigned(a.limb(0), one),
            Term::Assigned(quotient, negative_wrong_modulus[0]),
            Term::Unassigned(t_0, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_0 = &mut AssignedValue::<N>::new(t_0_cell, t_0);

        let (_, _, t_1_cell, _) = main_gate.combine(
            region,
            Term::Assigned(a.limb(1), one),
            Term::Assigned(quotient, negative_wrong_modulus[1]),
            Term::Unassigned(t_1, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_1 = &mut AssignedValue::<N>::new(t_1_cell, t_1);

        let (_, _, t_2_cell, _) = main_gate.combine(
            region,
            Term::Assigned(a.limb(2), one),
            Term::Assigned(quotient, negative_wrong_modulus[2]),
            Term::Unassigned(t_2, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_2 = &mut AssignedValue::<N>::new(t_2_cell, t_2);

        let (_, _, t_3_cell, _) = main_gate.combine(
            region,
            Term::Assigned(a.limb(3), one),
            Term::Assigned(quotient, negative_wrong_modulus[3]),
            Term::Unassigned(t_3, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_3 = &mut AssignedValue::<N>::new(t_3_cell, t_3);

        // u_0 = t_0 + t_1 * R
        // u_0 = v_0 * R^2
        // 0 = t_0 + t_1 * R - v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | v_0 | -     |

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(t_0, one),
            Term::Assigned(t_1, left_shifter_r),
            Term::Assigned(v_0, -left_shifter_2r),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // u_1 = t_2 + t_3 * R
        // v_1 * 2R = u_1 + v_0
        // 0 = t_2 + t_3 * R + v_0 - v_1 * 2R

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | v_0 | v_1   |

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(t_2, one),
            Term::Assigned(t_3, left_shifter_r),
            Term::Assigned(v_0, one),
            Term::Assigned(v_1, -left_shifter_2r),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // native red

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(a.native(), -one),
            Term::Zero,
            Term::Assigned(quotient, self.rns.wrong_modulus_in_native_modulus),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        Ok(())
    }
}
