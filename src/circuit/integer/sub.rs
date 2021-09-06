use super::{IntegerChip, IntegerInstructions};

use crate::circuit::main_gate::{MainGate, MainGateConfig, MainGateInstructions};
use crate::circuit::range::{RangeChip, RangeConfig, RangeInstructions};
use crate::rns::{Integer, Quotient};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _sub(&self, region: &mut Region<'_, N>, a: Option<&mut Integer<N>>, b: Option<&mut Integer<N>>) -> Result<Integer<N>, Error> {
        let a = a.ok_or(Error::SynthesisError)?;
        let b = b.ok_or(Error::SynthesisError)?;
        let mut c: Integer<_> = self.rns.sub(a, b);
        let aux = self.rns.aux.clone();

        for (((a, b), c), aux) in a
            .decomposed
            .limbs
            .iter_mut()
            .zip(b.decomposed.limbs.iter_mut())
            .zip(c.decomposed.limbs.iter_mut())
            .zip(aux.limbs.iter())
        {
            // expect operands are assigned
            let a_cell = a.cell.ok_or(Error::SynthesisError)?;
            let b_cell = b.cell.ok_or(Error::SynthesisError)?;

            // let (a_new_cell, b_new_cell, c_cell) = main_gate.sub_add_constant(region, Some((a.fe(), b.fe(), c.fe(), aux.fe())))?;

            let a_new_cell = region.assign_advice(|| "a", self.config.a, 0, || Ok(a.fe()))?;
            let b_new_cell = region.assign_advice(|| "b", self.config.b, 0, || Ok(b.fe()))?;
            let c_cell = region.assign_advice(|| "c", self.config.c, 0, || Ok(c.fe()))?;
            region.assign_fixed(|| "sa", self.config.sa, 0, || Ok(N::one()))?;
            region.assign_fixed(|| "sb", self.config.sb, 0, || Ok(-N::one()))?;
            region.assign_fixed(|| "sc", self.config.sc, 0, || Ok(N::one()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(aux.fe()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "d", self.config.sd, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", self.config.sm, 0, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_cell, a_new_cell)?;
            region.constrain_equal(b_cell, b_new_cell)?;

            // update cells of operands
            a.cell = Some(a_new_cell);
            b.cell = Some(b_new_cell);

            // assing cell to the result
            c.cell = Some(c_cell)
        }

        self._reduce(region, Some(&c))?;

        Ok(c)
    }
}
