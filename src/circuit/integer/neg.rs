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

        let aux: Vec<N> = self.rns.aux.limbs();
        let aux_native = self.rns.aux.native();
        let mut b_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let aux = aux[idx];
            let b_limb = main_gate.neg_with_constant(region, a_limb, aux, offset)?;

            b_limbs.push(AssignedLimb::<N>::new(b_limb.cell, b_limb.value, fe_to_big(aux)))
        }

        let b_native = main_gate.neg_with_constant(region, a.native(), aux_native, offset)?;

        Ok(AssignedInteger::new(b_limbs, b_native, self.rns.bit_len_limb))
    }
}
