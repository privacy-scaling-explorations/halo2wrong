use super::IntegerChip;
use crate::circuit::AssignedInteger;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        let main_gate = self.main_gate_config();

        let c = a.value().map(|integer_a| {
            let b_integer = b.value().unwrap();
            self.rns.sub(&integer_a, &b_integer)
        });
        let aux: Vec<N> = self.rns.aux.clone().limbs.iter().map(|limb| limb.fe()).collect();

        let mut c_cells: Vec<Cell> = Vec::new();
        let mut a_updated_cells: Vec<Cell> = a.cells.clone();
        let mut b_updated_cells: Vec<Cell> = b.cells.clone();

        let a_integer: Option<Vec<N>> = a.value.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());
        let b_integer: Option<Vec<N>> = b.value.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());
        let c_integer: Option<Vec<N>> = c.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());

        let mut offset = 0;

        for idx in 0..NUMBER_OF_LIMBS {
            let a_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let b_new_cell = region.assign_advice(|| "b", main_gate.b, offset, || Ok(b_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let c_cell = region.assign_advice(|| "c", main_gate.c, offset, || Ok(c_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let _ = region.assign_advice(|| "d", main_gate.d, offset, || Ok(N::zero()))?;

            c_cells.push(c_cell);

            region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(aux[idx]))?;

            region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;

            region.constrain_equal(a.cells[idx], a_new_cell)?;
            region.constrain_equal(b.cells[idx], b_new_cell)?;

            a_updated_cells[idx] = a_new_cell;
            b_updated_cells[idx] = b_new_cell;
            offset += 1;
        }

        let a = a.clone_with_cells(a_updated_cells);
        let b = b.clone_with_cells(b_updated_cells);
        let c = AssignedInteger::<N>::new(c_cells, c);
        Ok((a, b, c))
    }
}
