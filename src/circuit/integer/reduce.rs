use super::IntegerChip;
use crate::circuit::integer::{AssignedInteger, AssignedLimb};
use crate::circuit::range::RangeInstructions;
use crate::rns::{Limb, Quotient};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    // pub(crate) fn _reduce(&self, region: &mut Region<'_, N>, a: Option<&Integer<N>>) -> Result<Integer<N>, Error> {
    pub(crate) fn _reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>) -> Result<(AssignedInteger<N>, AssignedInteger<N>), Error> {
        let reduction_result = a.value().map(|integer_a| self.rns.reduce(&integer_a));
        let negative_wrong_modulus: Vec<N> = self.rns.negative_wrong_modulus.limbs.iter().map(|limb| limb.fe()).collect();

        let a_integer: Option<Vec<N>> = a.value.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());

        let result: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.result.limbs().iter().map(|limb| limb.fe()).collect());
        let quotient: Option<N> = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Short(quotient) => quotient,
                _ => panic!("short quotient expected"),
            };
            quotient.fe()
        });
        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.iter().map(|t| t.fe()).collect());

        let u_0 = reduction_result.as_ref().map(|u| u.u_0.fe());
        let v_0 = reduction_result.as_ref().map(|u| u.v_0.fe());
        let u_1 = reduction_result.as_ref().map(|u| u.u_1.fe());
        let v_1 = reduction_result.as_ref().map(|u| u.v_1.fe());

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        let mut offset = 0;
        let a_running = &mut a.clone();

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[0]);

        let a_0_new_cell = region.assign_advice(|| "a_", self.config.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[0]))?;
        let mut q_cell = region.assign_advice(|| "q", self.config.b, offset, || Ok(quotient.ok_or(Error::SynthesisError)?))?;
        let t_0_cell = region.assign_advice(|| "t_", self.config.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(negative_wrong_modulus[0]))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        region.constrain_equal(a_running.cells[0], a_0_new_cell)?;
        a_running.cells[0] = a_0_new_cell;

        offset += 1;

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[1]);

        let a_1_new_cell = region.assign_advice(|| "a_", self.config.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[1]))?;
        let q_new_cell = region.assign_advice(|| "q", self.config.b, offset, || Ok(quotient.ok_or(Error::SynthesisError)?))?;
        let t_1_cell = region.assign_advice(|| "t_", self.config.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(negative_wrong_modulus[1]))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        region.constrain_equal(a_running.cells[1], a_1_new_cell)?;
        a_running.cells[1] = a_1_new_cell;
        region.constrain_equal(q_cell, q_new_cell)?;
        q_cell = q_new_cell;

        offset += 1;

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[2]);

        let a_2_new_cell = region.assign_advice(|| "a_", self.config.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[2]))?;
        let q_new_cell = region.assign_advice(|| "q", self.config.b, offset, || Ok(quotient.ok_or(Error::SynthesisError)?))?;
        let t_2_cell = region.assign_advice(|| "t_", self.config.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(negative_wrong_modulus[2]))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        region.constrain_equal(a_running.cells[2], a_2_new_cell)?;
        a_running.cells[2] = a_2_new_cell;
        region.constrain_equal(q_cell, q_new_cell)?;
        q_cell = q_new_cell;

        offset += 1;

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[3]);

        let a_3_new_cell = region.assign_advice(|| "a_", self.config.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[3]))?;
        let q_new_cell = region.assign_advice(|| "q", self.config.b, offset, || Ok(quotient.ok_or(Error::SynthesisError)?))?;
        let t_3_cell = region.assign_advice(|| "t_", self.config.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(negative_wrong_modulus[3]))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        region.constrain_equal(a_running.cells[3], a_3_new_cell)?;
        a_running.cells[3] = a_3_new_cell;
        region.constrain_equal(q_cell, q_new_cell)?;
        q_cell = q_new_cell;

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let mut result_cells: Vec<Cell> = vec![];
        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;
        let left_shifter_4r = self.rns.left_shifter_4r;

        let t_0_new_cell = region.assign_advice(
            || "t_0",
            self.config.a,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[0]),
        )?;
        let t_1_new_cell = region.assign_advice(
            || "t_1",
            self.config.b,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[1]),
        )?;

        let r_0_cell = region.assign_advice(|| "r_0", self.config.c, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[0]))?;
        let r_1_cell = region.assign_advice(|| "r_1", self.config.d, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[1]))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(t_0_cell, t_0_new_cell)?;
        region.constrain_equal(t_1_cell, t_1_new_cell)?;

        result_cells.push(r_0_cell);
        result_cells.push(r_1_cell);

        offset += 1;

        let u_0_cell = region.assign_advice(|| "u_0", self.config.d, offset, || u_0.ok_or(Error::SynthesisError))?;
        let v_0_cell = region.assign_advice(|| "v_0", self.config.c, offset, || v_0.ok_or(Error::SynthesisError))?;

        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(left_shifter_2r))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        let v_0 = &mut AssignedLimb::<N>::new(v_0_cell, v_0.map(|v_0| Limb::<N>::from_fe(v_0)));

        offset += 1;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 4R = u_1 * 2R + u_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | u_0 | u_1   |

        let t_2_new_cell = region.assign_advice(
            || "t_2",
            self.config.a,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[2]),
        )?;
        let t_3_new_cell = region.assign_advice(
            || "t_3",
            self.config.b,
            offset,
            || Ok(intermediate_values.as_ref().ok_or(Error::SynthesisError)?[3]),
        )?;

        let r_2_cell = region.assign_advice(|| "r_2", self.config.c, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[2]))?;
        let r_3_cell = region.assign_advice(|| "r_3", self.config.d, offset, || Ok(result.as_ref().ok_or(Error::SynthesisError)?[3]))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(t_2_cell, t_2_new_cell)?;
        region.constrain_equal(t_3_cell, t_3_new_cell)?;

        result_cells.push(r_2_cell);
        result_cells.push(r_3_cell);

        offset += 1;

        let v_1_cell = region.assign_advice(|| "v_1", self.config.b, offset, || v_1.ok_or(Error::SynthesisError))?;
        let u_0_new_cell = region.assign_advice(|| "u_0", self.config.c, offset, || u_0.ok_or(Error::SynthesisError))?;
        let _ = region.assign_advice(|| "u_1", self.config.d, offset, || u_1.ok_or(Error::SynthesisError))?;

        region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(-left_shifter_4r))?;
        region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(left_shifter_2r))?;

        region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_m", self.config.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

        let v_1 = &mut AssignedLimb::<N>::new(v_1_cell, v_1.map(|e| Limb::<N>::from_fe(e)));

        region.constrain_equal(u_0_cell, u_0_new_cell)?;

        // ranges
        let range_chip = self.range_chip();

        // quotient
        let quotient = &mut AssignedLimb::<N>::new(q_cell, quotient.map(|e| Limb::<N>::from_fe(e)));
        range_chip.range_limb(region, &quotient)?;

        // range result
        for (i, cell) in result_cells.clone().iter().enumerate() {
            let value = result.as_ref().map(|result| Limb::<N>::from_fe(result[i]));
            let limb = AssignedLimb::new(cell.clone(), value);
            let new_limb = range_chip.range_limb(region, &limb)?;

            // cycle and update cell
            region.constrain_equal(result_cells[i], new_limb.cell)?;
            result_cells[i] = new_limb.cell;
        }

        // TODO: overflow flag
        range_chip.range_limb(region, &v_0)?;
        range_chip.range_limb(region, &v_1)?;

        let a: AssignedInteger<N> = a_running.clone();

        let result_integer = result.map(|limbs| self.rns.new_from_limbs(limbs.iter().map(|limb| Limb::<N>::from_fe(*limb)).collect()));
        let result = AssignedInteger::<N>::new(result_cells, result_integer);

        Ok((a, result))
    }
}
