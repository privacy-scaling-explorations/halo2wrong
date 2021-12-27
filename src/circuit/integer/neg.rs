use super::IntegerChip;
use crate::circuit::main_gate::MainGateInstructions;
use crate::circuit::{AssignedInteger, AssignedLimb};
use crate::rns::{fe_to_big, Common};
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _neg(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let aux = self.rns.make_aux(a.max_vals());
        let aux_limbs = aux.limbs();
        let aux_native = aux.native();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let aux = aux_limbs[idx];
            let c_limb = main_gate.neg_with_constant(region, a_limb, aux, offset)?;

            c_limbs.push(AssignedLimb::<N>::new(c_limb.cell, c_limb.value, fe_to_big(aux)))
        }

        let c_native = main_gate.neg_with_constant(region, a.native(), aux_native, offset)?;

        Ok(AssignedInteger::new(c_limbs, c_native, self.rns.bit_len_limb))
    }
}
