use super::IntegerChip;
use crate::circuit::range::RangeInstructions;
use crate::rns::{Integer, Quotient};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _reduce(&self, region: &mut Region<'_, N>, a: Option<&Integer<N>>) -> Result<Integer<N>, Error> {
        let range_chip = self.range_chip();

        let a = a.ok_or(Error::SynthesisError)?;
        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;
        let reduced = self.rns.reduce(a);
        let negative_modulus = reduced.negative_modulus;
        let intermediate_values = &mut reduced.t.clone();
        let a = &mut a.limbs();

        let quotient = &mut match reduced.quotient {
            Quotient::Short(quotient) => Ok(quotient),
            _ => Err(Error::SynthesisError),
        }?
        .clone();

        let v_0 = &mut reduced.v_0.clone();
        let v_1 = &mut reduced.v_1.clone();

        // constaint quotient is in 64 bit range
        range_chip.range_limb(region, Some(quotient))?;

        // constaint residues are in 64 bit range
        range_chip.range_limb(region, Some(v_0))?;
        range_chip.range_limb(region, Some(v_1))?;

        // set intermediate values
        // t_i = a_i + p_i * q

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        let mut offset = 0;

        for ((ai, pi), ti) in a.iter_mut().zip(negative_modulus.iter()).zip(intermediate_values.iter_mut()) {
            let a_cell = ai.cell.ok_or(Error::SynthesisError)?;
            // should be set above in range constaint
            let q_cell = quotient.cell.ok_or(Error::SynthesisError)?;

            let a_new_cell = region.assign_advice(|| "a", self.config.a, offset, || Ok(ai.fe()))?;
            let q_new_cell = region.assign_advice(|| "b", self.config.b, offset, || Ok(quotient.fe()))?;
            let t_cell = region.assign_advice(|| "c", self.config.c, offset, || Ok(ti.fe()))?;
            region.assign_fixed(|| "a", self.config.sa, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "b", self.config.sb, offset, || Ok(pi.fe()))?;
            region.assign_fixed(|| "c", self.config.sc, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "d", self.config.sd, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", self.config.s_mul, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_cell, a_new_cell)?;
            region.constrain_equal(q_cell, q_new_cell)?;

            // assign new cells
            ti.cell = Some(t_cell);

            offset += 1;
        }

        // constaint result limbs is in 64 bit range
        let result = &mut reduced.result.clone();
        for limb in result.decomposed.limbs.iter_mut() {
            range_chip.range_limb(region, Some(limb)).unwrap();
        }

        // u_0 = t_0 + 2^b * t_1 - r_0 - 2^b * r_1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_0 | t_1 | r_0 | r_1 |
        // | -   | -   | -   | u_0 |

        let u_0 = &mut reduced.u_0.clone();
        let offset = 0; // TODO:fix
        {
            let t_0_cell = intermediate_values[0].cell.ok_or(Error::SynthesisError)?;
            let t_1_cell = intermediate_values[1].cell.ok_or(Error::SynthesisError)?;
            let r_0_cell = result.decomposed.limbs[0].cell.ok_or(Error::SynthesisError)?;
            let r_1_cell = result.decomposed.limbs[1].cell.ok_or(Error::SynthesisError)?;

            // assign equation
            let t_0_new_cell = region.assign_advice(|| "t_0", self.config.a, offset, || Ok(intermediate_values[0].fe()))?;
            region.assign_fixed(|| "a", self.config.sa, offset, || Ok(N::one()))?;

            let t_1_new_cell = region.assign_advice(|| "t_1", self.config.b, offset, || Ok(intermediate_values[1].fe()))?;
            region.assign_fixed(|| "b", self.config.sb, offset, || Ok(left_shifter_r))?;

            let r_0_new_cell = region.assign_advice(|| "r_0", self.config.c, offset, || Ok(result.decomposed.limbs[0].fe()))?;
            region.assign_fixed(|| "c", self.config.sc, offset, || Ok(N::one()))?;

            let r_1_new_cell = region.assign_advice(|| "r_1", self.config.d, offset, || Ok(result.decomposed.limbs[1].fe()))?;
            region.assign_fixed(|| "d", self.config.sd, offset, || Ok(-left_shifter_r))?;

            let u_0_cell = region.assign_advice(|| "u_0", self.config.d, offset + 1, || Ok(u_0.fe()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(N::one()))?;

            // cycle cells
            region.constrain_equal(t_0_cell, t_0_new_cell)?;
            region.constrain_equal(t_1_cell, t_1_new_cell)?;
            region.constrain_equal(r_0_cell, r_0_new_cell)?;
            region.constrain_equal(r_1_cell, r_1_new_cell)?;

            // update cells
            intermediate_values[0].cell = Some(t_0_new_cell);
            intermediate_values[1].cell = Some(t_1_new_cell);
            result.decomposed.limbs[0].cell = Some(r_0_new_cell);
            result.decomposed.limbs[1].cell = Some(r_1_new_cell);

            // assing new cells
            u_0.cell = Some(u_0_cell);

            // zeroize unused selectors
            region.assign_fixed(|| "a * b", self.config.s_mul, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(N::zero()))?;
        }

        // v_0 * 2B = u_0

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_0 | t_1 | r_0 | r_1 |
        // | -   | -   | v_0 | u_0 |

        {
            let v_0_cell = v_0.cell.ok_or(Error::SynthesisError)?;

            let v_0_new_cell = region.assign_advice(|| "v_0", self.config.d, offset + 1, || Ok(v_0.fe()))?;
            region.assign_fixed(|| "c", self.config.sc, offset + 1, || Ok(left_shifter_2r))?;
            // u_0 is set to `d` above at this offset
            region.assign_fixed(|| "d", self.config.sd, offset + 1, || Ok(N::one()))?;

            // cycle cells
            region.constrain_equal(v_0_cell, v_0_new_cell)?;

            // update_cells
            v_0.cell = Some(v_0_new_cell);

            // zeroize unused selectors
            region.assign_fixed(|| "a", self.config.sa, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "b", self.config.sb, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", self.config.s_mul, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(N::zero()))?;
        }

        // u_0 = t_0 + 2^b * t_1 - r_0 - 2^b * r_1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_2 | t_3 | r_2 | r_3 |
        // | -   | -   | -   | u_1 |

        let u_1 = &mut reduced.u_1.clone();
        let offset = offset + 2; // TODO:fix
        {
            let t_2_cell = intermediate_values[2].cell.ok_or(Error::SynthesisError)?;
            let t_3_cell = intermediate_values[3].cell.ok_or(Error::SynthesisError)?;
            let r_2_cell = result.decomposed.limbs[2].cell.ok_or(Error::SynthesisError)?;
            let r_3_cell = result.decomposed.limbs[3].cell.ok_or(Error::SynthesisError)?;

            // assign equation
            let t_2_new_cell = region.assign_advice(|| "t_2", self.config.a, offset, || Ok(intermediate_values[2].fe()))?;
            region.assign_fixed(|| "a", self.config.sa, offset, || Ok(N::one()))?;

            let t_3_new_cell = region.assign_advice(|| "t_3", self.config.b, offset, || Ok(intermediate_values[3].fe()))?;
            region.assign_fixed(|| "b", self.config.sb, offset, || Ok(left_shifter_r))?;

            let r_2_new_cell = region.assign_advice(|| "r_2", self.config.c, offset, || Ok(result.decomposed.limbs[2].fe()))?;
            region.assign_fixed(|| "c", self.config.sc, offset, || Ok(N::one()))?;

            let r_3_new_cell = region.assign_advice(|| "r_1", self.config.d, offset, || Ok(result.decomposed.limbs[3].fe()))?;
            region.assign_fixed(|| "d", self.config.sd, offset, || Ok(-left_shifter_r))?;

            let u_1_cell = region.assign_advice(|| "u_0", self.config.d, offset + 1, || Ok(u_1.fe()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(N::one()))?;

            // cycle cells
            region.constrain_equal(t_2_cell, t_2_new_cell)?;
            region.constrain_equal(t_3_cell, t_3_new_cell)?;
            region.constrain_equal(r_2_cell, r_2_new_cell)?;
            region.constrain_equal(r_3_cell, r_3_new_cell)?;

            // update cells
            intermediate_values[2].cell = Some(t_2_new_cell);
            intermediate_values[3].cell = Some(t_3_new_cell);
            result.decomposed.limbs[2].cell = Some(r_2_new_cell);
            result.decomposed.limbs[3].cell = Some(r_3_new_cell);

            // assing new cells
            u_1.cell = Some(u_1_cell);

            // zeroize unused selectors
            region.assign_fixed(|| "a * b", self.config.s_mul, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, offset, || Ok(N::zero()))?;
        }

        // v_1 * 2B = u_1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_2 | t_3 | r_2 | r_3 |
        // | -   | -   | v_1 | u_1 |

        {
            let v_1_cell = v_1.cell.ok_or(Error::SynthesisError)?;

            let v_1_new_cell = region.assign_advice(|| "v_1", self.config.d, offset + 1, || Ok(v_1.fe()))?;

            region.assign_fixed(|| "c", self.config.sc, offset + 1, || Ok(left_shifter_2r))?;
            // u_0 is set to `d` above at this offset
            region.assign_fixed(|| "d", self.config.sd, offset + 1, || Ok(N::one()))?;

            // cycle cells
            region.constrain_equal(v_1_cell, v_1_new_cell)?;

            // update_cells
            v_1.cell = Some(v_1_new_cell);

            // zeroize unused selectors
            region.assign_fixed(|| "a", self.config.sa, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "b", self.config.sb, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", self.config.s_mul, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, offset + 1, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(N::zero()))?;
        }

        Ok(result.clone())
    }
}
