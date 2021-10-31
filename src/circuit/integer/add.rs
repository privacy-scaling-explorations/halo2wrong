use super::IntegerChip;
use crate::circuit::main_gate::MainGateInstructions;
use crate::circuit::{AssignedInteger, AssignedLimb};
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _add(
        &self,
        region: &mut Region<'_, N>,
        a: &mut AssignedInteger<N>,
        b: &mut AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let b_limb = b.limb(idx);
            let c_limb = main_gate.add(region, a_limb, b_limb, offset)?;
            let c_max = a_limb.add(b_limb);

            c_limbs.push(AssignedLimb::<N>::new(c_limb.cell, c_limb.value, c_max))
        }
        let c_native = main_gate.add(region, a.native(), b.native(), offset)?;

        Ok(AssignedInteger::new(c_limbs, c_native))
    }
}
