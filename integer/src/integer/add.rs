use super::IntegerChip;
use crate::rns::Integer;
use crate::{AssignedInteger, AssignedLimb, Common, WrongExt};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::{halo2, utils::fe_to_big, MainGateInstructions, RegionCtx};
use std::rc::Rc;

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        let c_limbs = a
            .limbs()
            .iter()
            .zip(b.limbs().iter())
            .map(|(a_limb, b_limb)| {
                let c_max = a_limb.add(b_limb);
                let c_limb = main_gate.add(ctx, &a_limb.into(), &b_limb.into())?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;
        let c_native = main_gate.add(ctx, &a.native(), &b.native())?;
        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(super) fn _sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();
        let aux = Integer::subtracion_aux(b.max_vals(), Rc::clone(&self.rns));

        let c_limbs: Vec<AssignedLimb<N>> = a
            .limbs()
            .iter()
            .zip(b.limbs().iter())
            .zip(aux.limbs().iter())
            .map(|((a_limb, b_limb), aux)| {
                let c_max = a_limb.add_fe(*aux);
                let c_limb =
                    main_gate.sub_with_constant(ctx, &a_limb.into(), &b_limb.into(), *aux)?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;
        let c_native = main_gate.sub_with_constant(ctx, &a.native(), &b.native(), aux.native())?;
        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(super) fn _sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b_0: &AssignedInteger<W, N>,
        b_1: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        let max_vals = b_0
            .max_vals()
            .iter()
            .zip(b_1.max_vals().iter())
            .map(|(b_0, b_1)| b_0 + b_1)
            .collect();
        let aux = Integer::subtracion_aux(max_vals, Rc::clone(&self.rns));

        let c_limbs: Vec<AssignedLimb<N>> = a
            .limbs()
            .iter()
            .zip(b_0.limbs().iter())
            .zip(b_1.limbs().iter())
            .zip(aux.limbs().iter())
            .map(|(((a_limb, b_0_limb), b_1_limb), aux)| {
                let c_max = a_limb.add_fe(*aux);
                let c_limb = main_gate.sub_sub_with_constant(
                    ctx,
                    &a_limb.into(),
                    &b_0_limb.into(),
                    &b_1_limb.into(),
                    *aux,
                )?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;
        let c_native = main_gate.sub_sub_with_constant(
            ctx,
            &a.native(),
            &b_0.native(),
            &b_1.native(),
            aux.native(),
        )?;
        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(super) fn _neg(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();
        let aux = a.make_aux();

        let c_limbs = a
            .limbs()
            .iter()
            .zip(aux.limbs().iter())
            .map(|(a_limb, aux)| {
                let c_limb = main_gate.neg_with_constant(ctx, &a_limb.into(), *aux)?;
                Ok(AssignedLimb::from(c_limb, fe_to_big(*aux)))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;
        let c_native = main_gate.neg_with_constant(ctx, &a.native(), aux.native())?;
        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(crate) fn _mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        let c_limbs = a
            .limbs()
            .iter()
            .map(|a_limb| {
                let c_max = a_limb.mul2();
                let c_limb = main_gate.mul2(ctx, &a_limb.into())?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;
        let c_native = main_gate.mul2(ctx, &a.native())?;
        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(crate) fn _mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        let c_limbs = a
            .limbs()
            .iter()
            .map(|a_limb| {
                let c_max = a_limb.mul3();
                let c_limb = main_gate.mul3(ctx, &a_limb.into())?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;
        let c_native = main_gate.mul3(ctx, &a.native())?;
        Ok(self.new_assigned_integer(c_limbs, c_native))
    }

    pub(crate) fn _add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &Integer<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        let c_limbs = a
            .limbs()
            .iter()
            .zip(b.limbs().iter())
            .map(|(a_limb, b_limb)| {
                let c_max = a_limb.add_big(fe_to_big(*b_limb));
                let c_limb = main_gate.add_constant(ctx, &a_limb.into(), *b_limb)?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;
        let c_native = main_gate.add_constant(ctx, &a.native(), b.native())?;
        Ok(self.new_assigned_integer(c_limbs, c_native))
    }
}
