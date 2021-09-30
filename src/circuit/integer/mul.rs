use super::IntegerChip;
use crate::circuit::integer::{AssignedInteger, AssignedLimb};
use crate::circuit::range::{Overflow, RangeInstructions};
use crate::rns::{Limb, Quotient};
use crate::NUMBER_OF_LIMBS;

use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    fn mul_v0_overflow(&self) -> Overflow {
        Overflow::Size(2)
    }

    fn mul_v1_overflow(&self) -> Overflow {
        Overflow::Size(3)
    }

    pub(crate) fn _mul(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        let main_gate = self.main_gate();

        let reduction_result = a.value().map(|integer_a| {
            let b_integer = b.value().unwrap();
            self.rns.mul(&integer_a, &b_integer)
        });

        let negative_wrong_modulus: Vec<N> = self.rns.negative_wrong_modulus.limbs.iter().map(|limb| limb.fe()).collect();

        let a_integer: Option<Vec<N>> = a.value.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());
        let b_integer: Option<Vec<N>> = b.value.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());
        let result: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.result.limbs().iter().map(|limb| limb.fe()).collect());
        let quotient: Option<Vec<N>> = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Long(quotient) => quotient.limbs,
                _ => panic!("long quotient expected"),
            };
            quotient.iter().map(|limb| limb.fe()).collect()
        });
        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.iter().map(|t| t.fe()).collect());

        let u_0 = reduction_result.as_ref().map(|u| u.u_0.fe());
        let v_0 = reduction_result.as_ref().map(|u| u.v_0.fe());
        let u_1 = reduction_result.as_ref().map(|u| u.u_1.fe());
        let v_1 = reduction_result.as_ref().map(|u| u.v_1.fe());

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

        let mut offset = 0;
        let a_running = &mut a.clone();
        let b_running = &mut b.clone();

        let mut quotient_cycling: Vec<Cell> = vec![];
        let mut intermediate_values_cycling: Vec<Cell> = vec![];

        for i in 0..NUMBER_OF_LIMBS {
            let mut t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[i]);

            for j in 0..=i {
                let k = i - j;

                let a_j_new_cell = region.assign_advice(|| "a_", main_gate.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[j]))?;
                let b_k_new_cell = region.assign_advice(|| "b_", main_gate.b, offset, || Ok(b_integer.as_ref().ok_or(Error::SynthesisError)?[k]))?;
                let q_k_new_cell = region.assign_advice(|| "q_", main_gate.c, offset, || Ok(quotient.as_ref().ok_or(Error::SynthesisError)?[k]))?;
                let t_i_cell = region.assign_advice(|| "t_", main_gate.d, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;

                region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::one()))?;
                region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(negative_wrong_modulus[j]))?;
                region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(-N::one()))?;

                if k == 0 {
                    region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
                } else {
                    region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::one()))?;
                }

                // zero selectors
                region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::zero()))?;
                region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(N::zero()))?;
                region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

                // cycle and update operand limb assignments
                region.constrain_equal(a_running.cells[j], a_j_new_cell)?;
                region.constrain_equal(b_running.cells[k], b_k_new_cell)?;
                a_running.cells[j] = a_j_new_cell;
                b_running.cells[k] = b_k_new_cell;

                if j == 0 {
                    // first time we see jth quotient limb
                    quotient_cycling.push(q_k_new_cell);
                } else {
                    // cycle and update quotient limb assignment
                    region.constrain_equal(quotient_cycling[k], q_k_new_cell)?;
                    quotient_cycling[k] = q_k_new_cell;
                }

                if j == 0 {
                    // first time we see t_j assignment
                    intermediate_values_cycling.push(t_i_cell);
                }

                // update running temp value
                t = t.map(|t| {
                    let a = a_integer.as_ref().unwrap()[j];
                    let b = b_integer.as_ref().unwrap()[k];
                    let q = quotient.as_ref().unwrap()[k];
                    let p = negative_wrong_modulus[j];
                    t - (a * b + q * p)
                });

                offset += 1;
            }
        }

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let mut result_cells: Vec<Cell> = vec![];
        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        let t_0_new_cell = region.assign_advice(
            || "t_0",
            main_gate.a,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[0]),
        )?;
        let t_1_new_cell = region.assign_advice(
            || "t_1",
            main_gate.b,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[1]),
        )?;

        let r_0_cell = region.assign_advice(|| "r_0", main_gate.c, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[0]))?;
        let r_1_cell = region.assign_advice(|| "r_1", main_gate.d, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[1]))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-N::one()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(-left_shifter_r))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(intermediate_values_cycling[0], t_0_new_cell)?;
        region.constrain_equal(intermediate_values_cycling[1], t_1_new_cell)?;

        result_cells.push(r_0_cell);
        result_cells.push(r_1_cell);

        offset += 1;

        let u_0_cell = region.assign_advice(|| "u_0", main_gate.d, offset, || u_0.ok_or(Error::SynthesisError))?;
        let v_0_cell = region.assign_advice(|| "v_0", main_gate.c, offset, || v_0.ok_or(Error::SynthesisError))?;

        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(left_shifter_2r))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        offset += 1;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        let t_2_new_cell = region.assign_advice(
            || "t_2",
            main_gate.a,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[2]),
        )?;
        let t_3_new_cell = region.assign_advice(
            || "t_3",
            main_gate.b,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[3]),
        )?;

        let r_2_cell = region.assign_advice(|| "r_2", main_gate.c, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[2]))?;
        let r_3_cell = region.assign_advice(|| "r_3", main_gate.d, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[3]))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-N::one()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(-left_shifter_r))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(intermediate_values_cycling[2], t_2_new_cell)?;
        region.constrain_equal(intermediate_values_cycling[3], t_3_new_cell)?;

        result_cells.push(r_2_cell);
        result_cells.push(r_3_cell);

        offset += 1;

        let v_1_cell = region.assign_advice(|| "v_1", main_gate.b, offset, || v_1.ok_or(Error::SynthesisError))?;
        let v_0_new_cell = region.assign_advice(|| "v_0", main_gate.c, offset, || v_0.ok_or(Error::SynthesisError))?;
        let _ = region.assign_advice(|| "u_1", main_gate.d, offset, || u_1.ok_or(Error::SynthesisError))?;

        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(left_shifter_2r))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-N::one()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(v_0_cell, v_0_new_cell)?;

        let v_0 = &mut AssignedLimb::<N>::new(v_0_new_cell, v_0.map(|v_0| Limb::<N>::from_fe(v_0)));
        let v_1 = &mut AssignedLimb::<N>::new(v_1_cell, v_1.map(|e| Limb::<N>::from_fe(e)));

        offset += 1;

        // ranges
        let range_chip = self.range_chip();

        // range quotient
        for (i, cell) in quotient_cycling.iter().enumerate() {
            let value = quotient.as_ref().map(|quotient| Limb::<N>::from_fe(quotient[i]));
            let limb = AssignedLimb::new(cell.clone(), value);
            let (_, updated_offset) = range_chip.range_limb(region, &limb, Overflow::NoOverflow, offset)?;
            offset = updated_offset;
        }

        // range result
        for (i, cell) in result_cells.clone().iter().enumerate() {
            let value = result.as_ref().map(|result| Limb::<N>::from_fe(result[i]));
            let limb = AssignedLimb::new(cell.clone(), value);
            let (new_limb, updated_offset) = range_chip.range_limb(region, &limb, Overflow::NoOverflow, offset)?;
            offset = updated_offset;

            // cycle and update cell
            region.constrain_equal(result_cells[i], new_limb.cell)?;
            result_cells[i] = new_limb.cell;
        }

        // range v0 and v1

        let (_, offset) = range_chip.range_limb(region, &v_0, self.mul_v0_overflow(), offset)?;
        let (_, _) = range_chip.range_limb(region, &v_1, self.mul_v1_overflow(), offset)?;

        let a: AssignedInteger<N> = a_running.clone();
        let b: AssignedInteger<N> = b_running.clone();

        let result_integer = result.map(|limbs| self.rns.new_from_limbs(limbs.iter().map(|limb| Limb::<N>::from_fe(*limb)).collect()));
        let result = AssignedInteger::<N>::new(result_cells, result_integer);

        Ok((a, b, result))
    }
}
