use super::IntegerChip;
use crate::circuit::range::{RangeInstructions, RangeTune};
use crate::circuit::{AssignedInteger, AssignedValue};
use crate::rns::Quotient;

use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    fn assert_zero_v0_range_tune(&self) -> RangeTune {
        RangeTune::Overflow(2)
    }

    fn assert_zero_v1_range_tune(&self) -> RangeTune {
        RangeTune::Overflow(3)
    }

    fn assert_zero_quotient_range_tune(&self) -> RangeTune {
        RangeTune::Fits
    }

    pub(crate) fn _assert_zero(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>) -> Result<(), Error> {
        let main_gate = self.main_gate_config();
        let mut offset = 0;
        let negative_wrong_modulus: Vec<N> = self.rns.negative_wrong_modulus.limbs();

        let reduction_result = a.integer().map(|integer_a| self.rns.reduce(&integer_a));

        // assert_eq!(reduction_result.result, N::zero());

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Short(quotient) => quotient.fe(),
                _ => panic!("short quotient expected"),
            };
            quotient
        });

        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.iter().map(|t| t.fe()).collect());

        let v_0 = reduction_result.as_ref().map(|u| u.v_0.fe());
        let v_1 = reduction_result.as_ref().map(|u| u.v_1.fe());

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[0]);

        let a_0_new_cell = region.assign_advice(|| "a_", main_gate.a, offset, || a.limb_value(0))?;
        let q_cell = region.assign_advice(|| "q", main_gate.b, offset, || Ok(quotient.ok_or(Error::SynthesisError)?))?;
        let t_0_cell = region.assign_advice(|| "t_", main_gate.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;
        let _ = region.assign_advice(|| "zero", main_gate.d, offset, || Ok(N::zero()))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(negative_wrong_modulus[0]))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        region.constrain_equal(a.cells[0], a_0_new_cell)?;
        a.cells[0] = a_0_new_cell;

        offset += 1;

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[1]);
        let quotient = &mut AssignedValue::<N>::new(q_cell, quotient);

        let a_1_new_cell = region.assign_advice(|| "a_", main_gate.a, offset, || a.limb_value(1))?;
        let q_new_cell = region.assign_advice(|| "q", main_gate.b, offset, || quotient.value())?;
        let t_1_cell = region.assign_advice(|| "t_", main_gate.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;
        let _ = region.assign_advice(|| "zero", main_gate.d, offset, || Ok(N::zero()))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(negative_wrong_modulus[1]))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        a.cycle_cell(region, 1, a_1_new_cell)?;
        quotient.cycle_cell(region, q_new_cell)?;

        offset += 1;

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[2]);

        let a_2_new_cell = region.assign_advice(|| "a_", main_gate.a, offset, || a.limb_value(2))?;
        let q_new_cell = region.assign_advice(|| "q", main_gate.b, offset, || quotient.value())?;
        let t_2_cell = region.assign_advice(|| "t_", main_gate.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;
        let _ = region.assign_advice(|| "zero", main_gate.d, offset, || Ok(N::zero()))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(negative_wrong_modulus[2]))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        a.cycle_cell(region, 2, a_2_new_cell)?;
        quotient.cycle_cell(region, q_new_cell)?;

        offset += 1;

        let t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[3]);

        let a_3_new_cell = region.assign_advice(|| "a_", main_gate.a, offset, || a.limb_value(3))?;
        let q_new_cell = region.assign_advice(|| "q", main_gate.b, offset, || quotient.value())?;
        let t_3_cell = region.assign_advice(|| "t_", main_gate.c, offset, || Ok(t.ok_or(Error::SynthesisError)?.clone()))?;
        let _ = region.assign_advice(|| "zero", main_gate.d, offset, || Ok(N::zero()))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(negative_wrong_modulus[3]))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-N::one()))?;

        // zero selectors
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        // cycle and update operand limb assignments
        a.cycle_cell(region, 3, a_3_new_cell)?;
        quotient.cycle_cell(region, q_new_cell)?;

        offset += 1;

        // u_0 = t_0 + t_1 * R
        // u_0 = v_0 * R^2
        // 0 = t_0 + t_1 * R - v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | v_0 | -     |

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
        let v_0_cell = region.assign_advice(|| "v_0", main_gate.c, offset, || v_0.ok_or(Error::SynthesisError))?;
        let _ = region.assign_advice(|| "zero", main_gate.d, offset, || Ok(N::zero()))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(-left_shifter_2r))?;

        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(-N::zero()))?;
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(t_0_cell, t_0_new_cell)?;
        region.constrain_equal(t_1_cell, t_1_new_cell)?;

        offset += 1;

        // u_1 = t_2 + t_3 * R
        // v_1 * 2R = u_1 + v_0
        // 0 = t_2 + t_3 * R + v_0 - v_1 * 2R

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | v_0 | v_1   |

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

        let v_0_new_cell = region.assign_advice(|| "v_0", main_gate.c, offset, || v_0.ok_or(Error::SynthesisError))?;
        let v_1_cell = region.assign_advice(|| "v_1", main_gate.d, offset, || v_1.ok_or(Error::SynthesisError))?;

        region.assign_fixed(|| "s_a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_b", main_gate.sb, offset, || Ok(left_shifter_r))?;
        region.assign_fixed(|| "s_c", main_gate.sc, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "s_d", main_gate.sd, offset, || Ok(-left_shifter_2r))?;

        region.assign_fixed(|| "s_d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_m", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(t_2_cell, t_2_new_cell)?;
        region.constrain_equal(t_3_cell, t_3_new_cell)?;
        region.constrain_equal(v_0_cell, v_0_new_cell)?;

        offset += 1;

        let v_0 = &mut AssignedValue::<N>::new(v_0_new_cell, v_0);
        let v_1 = &mut AssignedValue::<N>::new(v_1_cell, v_1);

        // ranges

        let range_chip = self.range_chip();

        range_chip.range_value(region, quotient, self.assert_zero_quotient_range_tune(), &mut offset)?;
        let _ = range_chip.range_value(region, v_0, self.assert_zero_v0_range_tune(), &mut offset)?;
        let _ = range_chip.range_value(region, v_1, self.assert_zero_v1_range_tune(), &mut offset)?;

        // native red

        let a_native_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || a.native_value())?;
        let _ = region.assign_advice(|| "b", main_gate.b, offset, || Ok(N::zero()))?;
        let q_new_cell = region.assign_advice(|| "d", main_gate.c, offset, || quotient.value())?;
        let _ = region.assign_advice(|| "d", main_gate.d, offset, || Ok(N::zero()))?;

        region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(-N::one()))?;
        region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(self.rns.wrong_modulus_in_native_modulus))?;

        region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        a.cycle_native_cell(region, a_native_new_cell)?;
        quotient.cycle_cell(region, q_new_cell)?;

        Ok(())
    }
}