use super::{IntegerChip, IntegerInstructions};
use crate::circuit::AssignedInteger;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _add(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate_config();
        let mut offset = 0;

        let c = a.integer().map(|integer_a| {
            let b_integer = b.integer().unwrap();
            self.rns.add(&integer_a, &b_integer)
        });

        let c = &mut self.assign_integer(region, c, &mut offset)?;

        for idx in 0..NUMBER_OF_LIMBS {
            let a_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || a.limb_value(idx))?;
            let b_new_cell = region.assign_advice(|| "b", main_gate.b, offset, || b.limb_value(idx))?;
            let c_new_cell = region.assign_advice(|| "c", main_gate.c, offset, || c.limb_value(idx))?;

            region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(-N::one()))?;

            region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

            a.cycle_cell(region, idx, a_new_cell)?;
            b.cycle_cell(region, idx, b_new_cell)?;
            c.cycle_cell(region, idx, c_new_cell)?;

            offset += 1;
        }

        let a_native_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || a.native_value())?;
        let b_native_new_cell = region.assign_advice(|| "b", main_gate.b, offset, || b.native_value())?;
        let c_native_new_cell = region.assign_advice(|| "c", main_gate.c, offset, || c.native_value())?;

        region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        a.cycle_native_cell(region, a_native_new_cell)?;
        b.cycle_native_cell(region, b_native_new_cell)?;
        c.cycle_native_cell(region, c_native_new_cell)?;

        Ok(c.clone())
    }
}
