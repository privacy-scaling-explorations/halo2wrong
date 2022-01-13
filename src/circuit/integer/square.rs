use super::{IntegerChip, IntegerInstructions, Range};
use crate::{NUMBER_OF_LIMBS, WrongExt};
use crate::{circuit::AssignedInteger, rns::MaybeReduced};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::{halo2, main_gate::five::range::RangeInstructions, AssignedValue, CombinationOptionCommon, MainGateInstructions, Term};

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _square(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let a_int = self.rns.to_integer(a);

        let reduction_witness: MaybeReduced<W, N> = a_int.map(|a_int| a_int.square()).into();
        let quotient = reduction_witness.long();
        let result = reduction_witness.result();
        let (t_0, t_1, t_2, t_3) = reduction_witness.intermediate_values();
        let intermediate_values = vec![t_0, t_1, t_2, t_3];
        let (u_0, u_1, v_0, v_1) = reduction_witness.residues();

        // Apply ranges

        let range_chip = self.range_chip();
        let quotient = &self.range_assign_integer(region, quotient.into(), Range::MulQuotient, offset)?;
        let result = &self.range_assign_integer(region, result.into(), Range::Remainder, offset)?;
        let v_0 = &range_chip.range_value(region, &v_0.into(), self.mul_v0_range_tune(), offset)?;
        let v_1 = &range_chip.range_value(region, &v_1.into(), self.mul_v1_range_tune(), offset)?;

        // Constaints:
        // t_0 =  a_0 * b_0
        //     +  q_0 * p_0
        // t_1 =  2 * a_0 * a_1
        //     +  q_0 * p_1 + q_1 * p_0
        // t_2 =  2 * a_0 * a_2 + a_1 * a_1
        //     +  q_0 * p_2 + q_1 * p_1 + q_2 * p_0
        // t_3 =  2 * a_0 * a_3 + 2 * a_1 * a_2
        //        + q_0 * p_3 + q_1 * p_2 + q_2 * p_1 + q_3 * p_0

        // Follow same witness layout with mul:
        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | a_0 | q_0 | t_0   |

        // | a_0 | a_1 | q_1 | t_1   |
        // | a_1 | a_0 | q_0 | tmp   |

        // | a_0 | a_2 | q_2 | t_2   |
        // | a_1 | a_1 | q_1 | tmp_a |
        // | a_2 | a_0 | q_0 | tmp_b |

        // | a_0 | a_3 | q_3 | t_3   |
        // | a_1 | a_2 | q_2 | tmp_b |
        // | a_2 | a_1 | q_1 | tmp_a |
        // | a_3 | a_0 | q_0 | tmp_c |

        // A bit more optimized witness layout that we didn't apply yet is below:

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | a_0 | q_0 | t_0   | t_0 = a_0 * a_0 + q_0 * p_0
        // | a_0 | a_1 | q_0 | q_1   | t_1 = 2 * a_0 * a_1 + q_0 * p_1 + q_1 * p_0
        // | a_0 | a_2 | q_0 | t_1   | tmp_a = 2 * a_0 * a_2 + q_0 * p_2
        // | a_1 | a_1 | q_0 | tmp_a | tmp_b = a_1 * a_1 + q_1 * p_1 + tmp_a
        // | t_2 | -   | q_2 | tmp_b | t_2 = tmp_b + q_2 * p_0
        // | a_0 | a_3 | q_0 | q_1   | tmp_a = 2 * a_0 * a_3 + q_0 * p_3 + q_1 * p_2
        // | a_1 | a_2 | q_2 | tmp_a | tmp_b = 2 * a_0 * a_2 + q_2 * p_1 + q_3 * p_0
        // | t_3 | -   | q_3 | tmp_b | t_3 = tmp_b + q_3 * p_0

        let mut intermediate_values_cycling: Vec<AssignedValue<N>> = vec![];

        for i in 0..NUMBER_OF_LIMBS {
            let mut intermediate_value = intermediate_values[i].clone();

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOptionCommon::OneLinerMul
                } else {
                    CombinationOptionCommon::CombineToNextMul(one)
                }
                .into();

                let (_, _, _, _, t) = main_gate.combine(
                    region,
                    [
                        Term::Assigned(&a.limb(j), zero),
                        Term::Assigned(&a.limb(k), zero),
                        Term::Assigned(&quotient.limb(k), negative_wrong_modulus[j]),
                        Term::Zero,
                        Term::Unassigned(intermediate_value, -one),
                    ],
                    zero,
                    offset,
                    combination_option,
                )?;

                if j == 0 {
                    // first time we see t_j assignment
                    intermediate_values_cycling.push(t);
                }

                // update running temp value
                intermediate_value = intermediate_value.map(|t| {
                    let a_j = a.limb_value(j).unwrap();
                    let a_k = a.limb_value(k).unwrap();
                    let q = quotient.limb_value(k).unwrap();
                    let p = negative_wrong_modulus[j];
                    t - (a_j * a_k + q * p)
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

        main_gate.combine(
            region,
            [
                Term::Assigned(&intermediate_values_cycling[0].clone(), one),
                Term::Assigned(&intermediate_values_cycling[1].clone(), left_shifter_r),
                Term::Assigned(&result.limbs[0].clone(), -one),
                Term::Assigned(&result.limbs[1].clone(), -left_shifter_r),
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            region,
            [
                Term::Zero,
                Term::Zero,
                Term::Assigned(v_0, left_shifter_2r),
                Term::Zero,
                Term::Unassigned(u_0, -one),
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            region,
            [
                Term::Assigned(&intermediate_values_cycling[2].clone(), one),
                Term::Assigned(&intermediate_values_cycling[3].clone(), left_shifter_r),
                Term::Assigned(&result.limbs[2].clone(), -one),
                Term::Assigned(&result.limbs[3].clone(), -left_shifter_r),
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            region,
            [
                Term::Zero,
                Term::Assigned(v_1, left_shifter_2r),
                Term::Assigned(v_0, -one),
                Term::Zero,
                Term::Unassigned(u_1, -one),
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // update native value
        let a_native = a.native();
        main_gate.combine(
            region,
            [
                Term::Assigned(&a_native, zero),
                Term::Assigned(&a_native, zero),
                Term::Assigned(&quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Assigned(&result.native(), -one),
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(result.clone())
    }
}
