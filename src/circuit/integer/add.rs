use super::{IntegerChip, IntegerInstructions};
use crate::circuit::AssignedInteger;
use crate::rns::Common;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _add(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate_config();
        let mut offset = 0;

        let c = a.value().map(|integer_a| {
            let b_integer = b.value().unwrap();
            self.rns.add(&integer_a, &b_integer)
        });
        let c = &mut self.assign(region, c, &mut offset)?;

        let mut a_updated_cells = a.cells.clone();
        let mut b_updated_cells = b.cells.clone();
        let mut c_updated_cells = c.cells.clone();

        let a_integer = a.value.as_ref().map(|e| e.limbs());
        let b_integer = b.value.as_ref().map(|e| e.limbs());
        let c_integer = c.value.as_ref().map(|e| e.limbs());

        for idx in 0..NUMBER_OF_LIMBS {
            let a_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let b_new_cell = region.assign_advice(|| "b", main_gate.b, offset, || Ok(b_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let c_new_cell = region.assign_advice(|| "c", main_gate.c, offset, || Ok(c_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;

            region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(-N::one()))?;

            region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

            region.constrain_equal(a.cells[idx], a_new_cell)?;
            region.constrain_equal(b.cells[idx], b_new_cell)?;
            region.constrain_equal(c.cells[idx], c_new_cell)?;

            a_updated_cells[idx] = a_new_cell;
            b_updated_cells[idx] = b_new_cell;
            c_updated_cells[idx] = c_new_cell;
            offset += 1;
        }

        let a_native: Option<N> = a.value.as_ref().map(|integer| integer.native());
        let b_native: Option<N> = b.value.as_ref().map(|integer| integer.native());
        let c_native: Option<N> = c.value.as_ref().map(|integer| integer.native());

        let a_native_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || Ok(a_native.ok_or(Error::SynthesisError)?))?;
        let b_native_new_cell = region.assign_advice(|| "b", main_gate.b, offset, || Ok(b_native.ok_or(Error::SynthesisError)?))?;
        let c_native_new_cell = region.assign_advice(|| "c", main_gate.c, offset, || Ok(c_native.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(a.native_value_cell, a_native_new_cell)?;
        region.constrain_equal(b.native_value_cell, b_native_new_cell)?;
        region.constrain_equal(c.native_value_cell, c_native_new_cell)?;

        a.update_cells(Some(a_updated_cells), Some(a_native_new_cell));
        b.update_cells(Some(b_updated_cells), Some(b_native_new_cell));
        c.update_cells(Some(c_updated_cells), Some(c_native_new_cell));

        Ok(c.clone())
    }
}
