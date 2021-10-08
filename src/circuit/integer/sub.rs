use super::{IntegerChip, IntegerInstructions};
use crate::circuit::AssignedInteger;
use crate::rns::Common;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        let main_gate = self.main_gate_config();
        let mut offset = 0;

        let c = a.value().map(|integer_a| {
            let b_integer = b.value().unwrap();
            self.rns.sub(&integer_a, &b_integer)
        });
        let c = self.assign(region, c, &mut offset)?;
        let aux: Vec<N> = self.rns.aux.limbs();

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
            let _ = region.assign_advice(|| "d", main_gate.d, offset, || Ok(N::zero()))?;

            region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(aux[idx]))?;

            region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;

            region.constrain_equal(a.cells[idx], a_new_cell)?;
            region.constrain_equal(b.cells[idx], b_new_cell)?;
            region.constrain_equal(c.cells[idx], c_new_cell)?;

            a_updated_cells[idx] = a_new_cell;
            b_updated_cells[idx] = b_new_cell;
            c_updated_cells[idx] = c_new_cell;

            offset += 1;
        }

        let a_native: Option<N> = a.value.as_ref().map(|e| e.native());
        let b_native: Option<N> = b.value.as_ref().map(|e| e.native());
        let c_native: Option<N> = c.value.as_ref().map(|e| e.native());

        let a_native_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || Ok(a_native.ok_or(Error::SynthesisError)?))?;
        let b_native_new_cell = region.assign_advice(|| "b", main_gate.b, offset, || Ok(b_native.ok_or(Error::SynthesisError)?))?;
        let c_native_new_cell = region.assign_advice(|| "c", main_gate.c, offset, || Ok(c_native.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
        region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(-N::one()))?;
        region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

        region.constrain_equal(a.native_value_cell, a_native_new_cell)?;
        region.constrain_equal(b.native_value_cell, b_native_new_cell)?;
        region.constrain_equal(c.native_value_cell, c_native_new_cell)?;

        let a = a.clone_with_cells(a_updated_cells, a_native_new_cell);
        let b = b.clone_with_cells(b_updated_cells, b_native_new_cell);
        let c = c.clone_with_cells(c_updated_cells, c_native_new_cell);

        Ok((a, b, c))
    }
}
