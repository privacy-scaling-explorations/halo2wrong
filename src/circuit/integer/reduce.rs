use super::{IntegerChip, IntegerInstructions, Range};
use crate::circuit::main_gate::{CombinationOption, MainGateInstructions, Term};
use crate::circuit::range::RangeInstructions;
use crate::circuit::{AssignedInteger, AssignedValue};
use crate::rns::Quotient;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn reduce_if_limb_values_exceeds_unreduced(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let exceeds_max_limb_value = a
            .limbs
            .iter()
            .fold(false, |must_reduce, limb| must_reduce | (limb.max_val() > self.rns.max_unreduced_limb));
        assert!(a.max_val() < self.rns.max_reducible_value);
        if exceeds_max_limb_value {
            self.reduce(region, a, offset)
        } else {
            Ok(a.clone())
        }
    }

    pub(super) fn reduce_if_limb_values_exceeds_reduced(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let exceeds_max_limb_value = a
            .limbs
            .iter()
            .fold(false, |must_reduce, limb| must_reduce | (limb.max_val() > self.rns.max_reduced_limb));

        if exceeds_max_limb_value {
            self.reduce(region, a, offset)
        } else {
            Ok(a.clone())
        }
    }

    pub(super) fn reduce_if_max_operand_value_exceeds(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let exceeds_max_value = a.max_val() > self.rns.max_operand;

        if exceeds_max_value {
            self.reduce(region, a, offset)
        } else {
            Ok(a.clone())
        }
    }

    fn red_v0_range_tune(&self) -> usize {
        self.rns.bit_len_limb + self.rns.red_v0_overflow
    }

    fn red_v1_range_tune(&self) -> usize {
        self.rns.bit_len_limb + self.rns.red_v1_overflow
    }

    pub(super) fn _reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let reduction_result = a.integer().map(|integer_a| self.rns.reduce(&integer_a));

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Short(quotient) => quotient,
                _ => panic!("short quotient expected"),
            };
            quotient
        });

        let result = reduction_result.as_ref().map(|u| u.result.clone());
        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.clone());
        let u_0 = reduction_result.as_ref().map(|u| u.u_0);
        let v_0 = reduction_result.as_ref().map(|u| u.v_0);
        let u_1 = reduction_result.as_ref().map(|u| u.u_1);
        let v_1 = reduction_result.as_ref().map(|u| u.v_1);

        // Apply ranges

        let range_chip = self.range_chip();
        let result = &self.range_assign_integer(region, result.into(), Range::Remainder, offset)?;
        let quotient = &range_chip.range_value(region, &quotient.into(), self.rns.bit_len_limb, offset)?;
        let v_0 = &range_chip.range_value(region, &v_0.into(), self.red_v0_range_tune(), offset)?;
        let v_1 = &range_chip.range_value(region, &v_1.into(), self.red_v1_range_tune(), offset)?;

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

        let (_, _, t_0_cell, _) = main_gate.combine(
            region,
            Term::Assigned(&a.limb(0), one),
            Term::Assigned(quotient, negative_wrong_modulus[0]),
            Term::Unassigned(t_0, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_0 = &AssignedValue::<N>::new(t_0_cell, t_0);

        let (_, _, t_1_cell, _) = main_gate.combine(
            region,
            Term::Assigned(&a.limb(1), one),
            Term::Assigned(quotient, negative_wrong_modulus[1]),
            Term::Unassigned(t_1, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_1 = &AssignedValue::<N>::new(t_1_cell, t_1);

        let (_, _, t_2_cell, _) = main_gate.combine(
            region,
            Term::Assigned(&a.limb(2), one),
            Term::Assigned(quotient, negative_wrong_modulus[2]),
            Term::Unassigned(t_2, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_2 = &AssignedValue::<N>::new(t_2_cell, t_2);

        let (_, _, t_3_cell, _) = main_gate.combine(
            region,
            Term::Assigned(&a.limb(3), one),
            Term::Assigned(quotient, negative_wrong_modulus[3]),
            Term::Unassigned(t_3, -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;
        let t_3 = &AssignedValue::<N>::new(t_3_cell, t_3);

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        main_gate.combine(
            region,
            Term::Assigned(t_0, one),
            Term::Assigned(t_1, left_shifter_r),
            Term::Assigned(&result.limbs[0].clone(), -one),
            Term::Assigned(&result.limbs[1].clone(), -left_shifter_r),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        main_gate.combine(
            region,
            Term::Zero,
            Term::Zero,
            Term::Assigned(v_0, left_shifter_2r),
            Term::Unassigned(u_0, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            region,
            Term::Assigned(t_2, one),
            Term::Assigned(t_3, left_shifter_r),
            Term::Assigned(&result.limbs[2].clone(), -one),
            Term::Assigned(&result.limbs[3].clone(), -left_shifter_r),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        main_gate.combine(
            region,
            Term::Zero,
            Term::Assigned(v_1, left_shifter_2r),
            Term::Assigned(v_0, -one),
            Term::Unassigned(u_1, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // update native value

        main_gate.combine(
            region,
            Term::Assigned(&a.native(), -one),
            Term::Zero,
            Term::Assigned(quotient, self.rns.wrong_modulus_in_native_modulus),
            Term::Assigned(&result.native(), one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        Ok(result.clone())
    }
}
