use super::{AssignedInteger, IntegerChip};
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

        for idx in 0..NUMBER_OF_LIMBS {
            let a_new_cell = region.assign_advice(|| "b", self.config.b, 0, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let b_new_cell = region.assign_advice(|| "b", self.config.b, 0, || Ok(b_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let c_cell = region.assign_advice(|| "b", self.config.b, 0, || Ok(c_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            c_cells.push(c_cell);

            region.assign_fixed(|| "a", self.config.sa, 0, || Ok(N::one()))?;
            region.assign_fixed(|| "b", self.config.sb, 0, || Ok(-N::one()))?;
            region.assign_fixed(|| "c", self.config.sc, 0, || Ok(N::one()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(aux[idx]))?;

            region.assign_fixed(|| "d", self.config.sd, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", self.config.s_mul, 0, || Ok(N::zero()))?;

            region.constrain_equal(a.cells[idx], a_new_cell)?;
            region.constrain_equal(b.cells[idx], b_new_cell)?;

            a_updated_cells[idx] = a_new_cell;
            b_updated_cells[idx] = b_new_cell;
        }

        let a = a.clone_with_cells(a_updated_cells);
        let b = b.clone_with_cells(b_updated_cells);
        let c = AssignedInteger::<N>::new(c_cells, c);
        Ok((a, b, c))
    }
}
