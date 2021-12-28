use super::IntegerChip;
use crate::circuit::main_gate::MainGateInstructions;
use crate::circuit::{AssignedInteger, AssignedLimb, Common};
use crate::rns::Integer;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _add(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let b_limb = b.limb(idx);
            let c_max = a_limb.add(&b_limb);
            let c_limb = main_gate.add(region, a_limb, b_limb, offset)?;

            c_limbs.push(AssignedLimb::<N>::new(c_limb.cell, c_limb.value, c_max))
        }
        let c_native = main_gate.add(region, a.native(), b.native(), offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(crate) fn _mul2(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let c_max = a_limb.mul2();
            let c_limb = main_gate.mul2(region, a_limb, offset)?;

            c_limbs.push(AssignedLimb::<N>::new(c_limb.cell, c_limb.value, c_max))
        }
        let c_native = main_gate.mul2(region, a.native(), offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(crate) fn _mul3(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let c_max = a_limb.mul3();
            let c_limb = main_gate.mul3(region, a_limb, offset)?;

            c_limbs.push(AssignedLimb::<N>::new(c_limb.cell, c_limb.value, c_max))
        }
        let c_native = main_gate.mul3(region, a.native(), offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(crate) fn _add_constant(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &Integer<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let b_limb = b.limb(idx);
            let c_max = a_limb.add_big(b_limb.value());
            let c_limb = main_gate.add_constant(region, a_limb, b_limb.fe(), offset)?;

            c_limbs.push(AssignedLimb::<N>::new(c_limb.cell, c_limb.value, c_max))
        }
        let c_native = main_gate.add_constant(region, a.native(), b.native(), offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }
}
