use super::IntegerChip;
use crate::circuit::range::RangeInstructions;
use crate::rns::{Integer, Quotient, NUMBER_OF_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _mul(&self, region: &mut Region<'_, N>, a: Option<&mut Integer<N>>, b: Option<&mut Integer<N>>) -> Result<Integer<N>, Error> {
        let range_chip = self.range_chip();

        let mut offset = 0;

        let a = a.ok_or(Error::SynthesisError)?;
        let b = b.ok_or(Error::SynthesisError)?;
        let reduction_context = self.rns.mul(a, b);

        let a = &mut a.limbs();
        let b = &mut b.limbs();

        let quotient = &mut match reduction_context.quotient {
            Quotient::Long(quotient) => Ok(quotient.limbs),
            _ => Err(Error::SynthesisError),
        }?;

        let intermediate_values = &mut reduction_context.t.clone();
        let negative_modulus = reduction_context.negative_modulus;

        // range quotient
        for limb in quotient.iter_mut() {
            range_chip.range_limb(region, Some(limb)).unwrap();
        }

        // range residues
        // FIX: constaint overflow bits

        let v_0 = &mut reduction_context.v_0.clone();
        let v_1 = &mut reduction_context.v_1.clone();

        range_chip.range_limb(region, Some(v_0))?;
        range_chip.range_limb(region, Some(v_1))?;

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
        // | a_0 | b_0 | t_0 | q_0   |
        // | a_0 | b_1 | q_0 | t_1   |
        // | a_1 | b_0 | q_1 | tmp   |
        // | a_0 | b_2 | q_0 | t_2   |
        // | a_1 | b_1 | q_1 | tmp_a |
        // | a_2 | b_0 | q_2 | tmp_b |
        // | a_0 | b_3 | q_0 | t_3   |
        // | a_1 | b_1 | q_2 | tmp_b |
        // | a_2 | b_2 | q_1 | tmp_a |
        // | a_3 | b_0 | q_3 | tmp_c |

        for i in 0..NUMBER_OF_LIMBS {
            let mut t = intermediate_values[i].fe();
            for k in 0..=i {
                let j = i - k;

                let a_i_cell = a[i].cell.ok_or(Error::SynthesisError)?;
                let b_j_cell = b[j].cell.ok_or(Error::SynthesisError)?;
                let q_i_cell = quotient[i].cell.ok_or(Error::SynthesisError)?;

                let a_i_new_cell = region.assign_advice(|| "a_", self.config.a, offset, || Ok(a[i].fe()))?;
                let b_j_new_cell = region.assign_advice(|| "b_", self.config.b, offset, || Ok(b[j].fe()))?;
                let q_i_new_cell = region.assign_advice(|| "q_", self.config.c, offset, || Ok(quotient[i].fe()))?;
                let t_i_cell = region.assign_advice(|| "t_", self.config.d, offset, || Ok(t))?;

                region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::one()))?;
                region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[i].fe()))?;
                region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
                region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

                // zeroize unused selectors
                region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
                region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
                region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

                // cycle equal limbs
                region.constrain_equal(a_i_cell, a_i_new_cell)?;
                region.constrain_equal(b_j_cell, b_j_new_cell)?;
                region.constrain_equal(q_i_cell, q_i_new_cell)?;

                // update cells
                a[i].cell = Some(a_i_new_cell);
                b[j].cell = Some(b_j_new_cell);
                quotient[i].cell = Some(q_i_new_cell);

                if k == 0 {
                    // assign new cell
                    intermediate_values[i].cell = Some(t_i_cell);
                }

                // update running sum
                t = t - a[i].fe() * b[j].fe() - quotient[i].fe() * negative_modulus[i].fe();

                // bump offset by a row
                offset += 1;
            }
        }

        let result = &mut reduction_context.result.clone();
        let result_limbs = &mut result.limbs();
        let u_0 = &mut reduction_context.u_0.clone();
        let u_1 = &mut reduction_context.u_1.clone();
        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        // u_0 = t_0 + (t_1 << s) - r_0 - (r_1 << s)
        // u_0 = v_0 << 2s

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let t_0_cell = intermediate_values[0].cell.ok_or(Error::SynthesisError)?;
        let t_1_cell = intermediate_values[1].cell.ok_or(Error::SynthesisError)?;

        let t_0_new_cell = region.assign_advice(|| "t_0", self.config.a, offset, || Ok(intermediate_values[0].fe()))?;
        let t_1_new_cell = region.assign_advice(|| "t_1", self.config.b, offset, || Ok(intermediate_values[1].fe()))?;
        let r_0_cell = region.assign_advice(|| "r_0", self.config.c, offset, || Ok(result_limbs[0].fe()))?;
        let r_1_cell = region.assign_advice(|| "r_1", self.config.d, offset, || Ok(result_limbs[1].fe()))?;

        let _ = region.assign_advice(|| "u_0", self.config.d, offset + 1, || Ok(u_0.fe()))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(-N::one()))?;

        // zeroize unused selectors
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle equal limbs
        region.constrain_equal(t_0_cell, t_0_new_cell)?;
        region.constrain_equal(t_1_cell, t_1_new_cell)?;

        // update cells
        intermediate_values[0].cell = Some(t_0_new_cell);
        intermediate_values[1].cell = Some(t_1_new_cell);

        // assign new cells
        result_limbs[0].cell = Some(r_0_cell);
        result_limbs[1].cell = Some(r_1_cell);

        offset += 1;

        let v_0_cell = v_0.cell.ok_or(Error::SynthesisError)?;

        let v_0_new_cell = region.assign_advice(|| "v_0", self.config.c, offset, || Ok(left_shifter_2r))?;

        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(left_shifter_2r))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;

        // zeroize unused selectors
        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle equal limbs
        region.constrain_equal(v_0_cell, v_0_new_cell)?;

        // update_cells
        v_0.cell = Some(v_0_new_cell);

        offset += 1;

        // u_1 = t_2 + (t_3 << s) - r_2 - (r_3 << s)
        // u_1 = v_1 << 2s

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | -   | v_1 | u_1   |

        let t_2_cell = intermediate_values[2].cell.ok_or(Error::SynthesisError)?;
        let t_3_cell = intermediate_values[3].cell.ok_or(Error::SynthesisError)?;

        let t_2_new_cell = region.assign_advice(|| "t_2", self.config.a, offset, || Ok(intermediate_values[2].fe()))?;
        let t_3_new_cell = region.assign_advice(|| "t_3", self.config.b, offset, || Ok(intermediate_values[3].fe()))?;
        let r_2_cell = region.assign_advice(|| "r_0", self.config.c, offset, || Ok(result_limbs[2].fe()))?;
        let r_3_cell = region.assign_advice(|| "r_1", self.config.d, offset, || Ok(result_limbs[3].fe()))?;

        let _ = region.assign_advice(|| "u_1", self.config.d, offset + 1, || Ok(u_1.fe()))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(-N::one()))?;

        // zeroize unused selectors
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle equal limbs
        region.constrain_equal(t_2_cell, t_2_new_cell)?;
        region.constrain_equal(t_3_cell, t_3_new_cell)?;

        // update cells
        intermediate_values[2].cell = Some(t_2_new_cell);
        intermediate_values[3].cell = Some(t_3_new_cell);

        // assign new cells
        result_limbs[2].cell = Some(r_2_cell);
        result_limbs[3].cell = Some(r_3_cell);

        offset += 1;

        let v_1_cell = v_1.cell.ok_or(Error::SynthesisError)?;

        let v_1_new_cell = region.assign_advice(|| "v_1", self.config.c, offset, || Ok(left_shifter_2r))?;

        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(left_shifter_2r))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;

        // zeroize unused selectors
        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle equal limbs
        region.constrain_equal(v_1_cell, v_1_new_cell)?;

        // update_cells
        v_1.cell = Some(v_1_new_cell);

        Ok(result.clone())
    }
}
