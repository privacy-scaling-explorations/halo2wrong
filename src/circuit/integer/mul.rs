use super::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{CombinationOption, CombinationTerm, MainGateInstructions};
use crate::circuit::range::{RangeInstructions, RangeTune};
use crate::circuit::{AssignedInteger, AssignedValue};
use crate::rns::Quotient;
use crate::NUMBER_OF_LIMBS;

use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    fn mul_v0_range_tune(&self) -> RangeTune {
        RangeTune::Overflow(2)
    }

    fn mul_v1_range_tune(&self) -> RangeTune {
        RangeTune::Overflow(3)
    }

    fn mul_quotient_range_tune(&self) -> RangeTune {
        // TODO:
        RangeTune::Fits
    }

    fn mul_result_range_tune(&self) -> RangeTune {
        // TODO:
        RangeTune::Fits
    }

    pub(crate) fn _mul(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let mut offset = 0;
        let negative_wrong_modulus: Vec<N> = self.rns.negative_wrong_modulus.limbs();

        let reduction_result = a.integer().map(|integer_a| {
            let b_integer = b.integer().unwrap();
            self.rns.mul(&integer_a, &b_integer)
        });

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Long(quotient) => quotient,
                _ => panic!("long quotient expected"),
            };
            quotient
        });

        let result = reduction_result.as_ref().map(|u| u.result.clone());
        let result = &mut self.assign_integer(region, result, &mut offset)?;
        let quotient = &mut self.assign_integer(region, quotient, &mut offset)?;
        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.iter().map(|t| t.fe()).collect());

        let u_0 = reduction_result.as_ref().map(|u| u.u_0);
        let v_0 = reduction_result.as_ref().map(|u| u.v_0);
        let u_1 = reduction_result.as_ref().map(|u| u.u_1);
        let v_1 = reduction_result.as_ref().map(|u| u.v_1);

        // t_0 = a_0 * b_0 + q_0 * p_0

        // t_1 =    a_0 * b_1 + a_1 * b_0 + q_0 * p_1 + q_1 * p_0
        // t_1 =    a_0 * b_1 + q_0 * p_1 + tmp
        // tmp =    a_1 * b_0 + q_1 * p_0

        // t_2   =    a_0 * b_2 + a_1 * b_1e + a_2 * b_0 + q_0 * p_2 + q_1 * p_1 + q_2 * p_0
        // t_2   =    a_0 * b_2 + q_0 * p_2 + tmp_a
        // tmp_a =    a_1 * b_1 + q_1 * p_1 + tmp_b
        // tmp_b =    a_2 * b_0 + q_2 * p_0

        // t_3   =    a_0 * b_3 + a_1 * b_2 + a_1 * b_2 + a_3 * b_0 + q_0 * p_3 + q_1 * p_2 + q_2 * p_1 + q_3 * p_0
        // t_3   =    a_0 * b_3 + q_0 * p_3 + tmp_a
        // tmp_a =    a_1 * b_2 + q_1 * p_2 + tmp_b
        // tmp_b =    a_2 * b_1 + q_2 * p_1 + tmp_c
        // tmp_c =    a_3 * b_0 + q_3 * p_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | b_0 | q_0 | t_0   |

        // | a_0 | b_1 | q_1 | t_1   |
        // | a_1 | b_0 | q_0 | tmp   |

        // | a_0 | b_2 | q_2 | t_2   |
        // | a_1 | b_1 | q_1 | tmp_a |
        // | a_2 | b_0 | q_0 | tmp_b |

        // | a_0 | b_3 | q_3 | t_3   |
        // | a_1 | b_1 | q_2 | tmp_b |
        // | a_2 | b_2 | q_1 | tmp_a |
        // | a_3 | b_0 | q_0 | tmp_c |

        let mut intermediate_values_cycling: Vec<AssignedValue<N>> = vec![];

        for i in 0..NUMBER_OF_LIMBS {
            let mut t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[i]);

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOption::SingleLinerMul
                } else {
                    CombinationOption::CombineToNextMul(one)
                };

                let (a_j_new_cell, b_k_new_cell, q_k_new_cell, t_i_cell) = main_gate.combine(
                    region,
                    CombinationTerm::Assigned(&mut a.limb(j), zero),
                    CombinationTerm::Assigned(&mut b.limb(k), zero),
                    CombinationTerm::Assigned(&mut quotient.limb(k), negative_wrong_modulus[j]),
                    CombinationTerm::Unassigned(t, -one),
                    zero,
                    &mut offset,
                    combination_option,
                )?;

                // update operand limb assignments
                a.update_limb_cell(j, a_j_new_cell);
                b.update_limb_cell(k, b_k_new_cell);
                quotient.update_limb_cell(k, q_k_new_cell);

                if j == 0 {
                    // first time we see t_j assignment
                    intermediate_values_cycling.push(AssignedValue::<N>::new(t_i_cell, t));
                }

                // update running temp value
                t = t.map(|t| {
                    let a = a.limb_value(j).unwrap();
                    let b = b.limb_value(k).unwrap();
                    let q = quotient.limb_value(k).unwrap();
                    let p = negative_wrong_modulus[j];
                    t - (a * b + q * p)
                });
            }
        }

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        let (_, _, result_0_cell, result_1_cell) = main_gate.combine(
            region,
            CombinationTerm::Assigned(&mut intermediate_values_cycling[0].clone(), one),
            CombinationTerm::Assigned(&mut intermediate_values_cycling[1].clone(), left_shifter_r),
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
            CombinationTerm::Assigned(&mut intermediate_values_cycling[2].clone(), one),
            CombinationTerm::Assigned(&mut intermediate_values_cycling[3].clone(), left_shifter_r),
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

        range_chip.range_integer(region, quotient, self.mul_quotient_range_tune(), &mut offset)?;
        range_chip.range_integer(region, result, self.mul_result_range_tune(), &mut offset)?;
        let _ = range_chip.range_value(region, v_0, self.mul_v0_range_tune(), &mut offset)?;
        let _ = range_chip.range_value(region, v_1, self.mul_v1_range_tune(), &mut offset)?;

        let (a_native_new_cell, b_native_new_cell, _, result_native_new_cell) = main_gate.combine(
            region,
            CombinationTerm::Assigned(&mut a.native(), zero),
            CombinationTerm::Assigned(&mut b.native(), zero),
            CombinationTerm::Assigned(&mut quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
            CombinationTerm::Assigned(&mut result.native(), -one),
            zero,
            &mut offset,
            CombinationOption::SingleLinerMul,
        )?;

        a.update_native_cell(a_native_new_cell);
        b.update_native_cell(b_native_new_cell);
        result.update_native_cell(result_native_new_cell);

        Ok(result.clone())
    }
}
