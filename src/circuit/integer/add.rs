use super::IntegerChip;
use crate::circuit::{AssignedInteger, AssignedLimb, Common};
use crate::rns::Integer;
use crate::{NUMBER_OF_LIMBS, WrongExt};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::{halo2, utils::fe_to_big, MainGateInstructions};

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
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

            c_limbs.push(AssignedLimb::from(c_limb, c_max))
        }
        let c_native = main_gate.add(region, a.native(), b.native(), offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(super) fn _sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let aux = self.rns.make_aux(b.max_vals());
        let aux_limbs = aux.limbs();
        let aux_native = aux.native();
        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let b_limb = b.limb(idx);

            let aux = aux_limbs[idx];
            let c_max = a_limb.add_fe(aux);
            let c_limb = main_gate.sub_with_constant(region, a_limb, b_limb, aux, offset)?;

            c_limbs.push(AssignedLimb::from(c_limb, c_max));
        }

        let c_native = main_gate.sub_with_constant(region, a.native(), b.native(), aux_native, offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(super) fn _sub_sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b_0: &AssignedInteger<N>,
        b_1: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        // c = a - b_0 - b_1

        let max_vals = b_0.max_vals().iter().zip(b_1.max_vals().iter()).map(|(b_0, b_1)| b_0 + b_1).collect();
        let aux = self.rns.make_aux(max_vals);
        let aux_limbs = aux.limbs();
        let aux_native = aux.native();
        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let b_0_limb = b_0.limb(idx);
            let b_1_limb = b_1.limb(idx);

            let aux = aux_limbs[idx];
            let c_max = a_limb.add_fe(aux);
            let c_limb = main_gate.sub_sub_with_constant(region, a_limb, b_0_limb, b_1_limb, aux, offset)?;

            c_limbs.push(AssignedLimb::from(c_limb, c_max));
        }

        let c_native = main_gate.sub_sub_with_constant(region, a.native(), b_0.native(), b_1.native(), aux_native, offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

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

            c_limbs.push(AssignedLimb::from(c_limb, fe_to_big(aux)));
        }

        let c_native = main_gate.neg_with_constant(region, a.native(), aux_native, offset)?;

        Ok(AssignedInteger::new(c_limbs, c_native, self.rns.bit_len_limb))
    }

    pub(crate) fn _mul2(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let c_max = a_limb.mul2();
            let c_limb = main_gate.mul2(region, a_limb, offset)?;

            c_limbs.push(AssignedLimb::from(c_limb, c_max));
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

            c_limbs.push(AssignedLimb::from(c_limb, c_max));
        }
        let c_native = main_gate.mul3(region, a.native(), offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(crate) fn _add_constant(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &Integer<W, N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut c_limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = a.limb(idx);
            let b_limb = b.limb(idx);
            let c_max = a_limb.add_big(b_limb.value());
            let c_limb = main_gate.add_constant(region, a_limb, b_limb.fe(), offset)?;

            c_limbs.push(AssignedLimb::from(c_limb, c_max));
        }
        let c_native = main_gate.add_constant(region, a.native(), b.native(), offset)?;

        Ok(self.new_assigned_integer(c_limbs, c_native))
    }
}
