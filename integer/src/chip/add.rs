use crate::chip::IntegerChip;
use crate::rns::Integer;
use crate::{AssignedInteger, AssignedLimb, Common, PrimeField};
use halo2::plonk::Error;
use maingate::{fe_to_big, halo2, MainGateInstructions, RegionCtx, Term};
use num_bigint::BigUint as big_uint;
use std::rc::Rc;

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn add_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
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
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.add(ctx, a.native(), b.native())?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }

    pub(super) fn add_add_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_0: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_1: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();

        let c_limbs = a
            .limbs()
            .iter()
            .zip(b_0.limbs().iter())
            .zip(b_1.limbs().iter())
            .map(|((a_limb, b_limb_0), b_limb_1)| {
                let c_max = a_limb.add_add(b_limb_0, b_limb_1);
                let c_limb = main_gate.compose(
                    ctx,
                    &[
                        Term::assigned_to_add(&a_limb.into()),
                        Term::assigned_to_add(&b_limb_0.into()),
                        Term::assigned_to_add(&b_limb_1.into()),
                    ],
                    N::ZERO,
                )?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.compose(
            ctx,
            &[
                Term::assigned_to_add(a.native()),
                Term::assigned_to_add(b_0.native()),
                Term::assigned_to_add(b_1.native()),
            ],
            N::ZERO,
        )?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }

    pub(super) fn sub_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();
        let aux = Integer::subtracion_aux(&b.max_vals(), Rc::clone(&self.rns));

        let c_limbs = a
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
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.sub_with_constant(ctx, a.native(), b.native(), aux.native())?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }

    pub(super) fn sub_sub_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_0: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_1: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();

        let max_vals = b_0
            .max_vals()
            .iter()
            .zip(b_1.max_vals().iter())
            .map(|(b_0, b_1)| b_0 + b_1)
            .collect::<Vec<big_uint>>()
            .try_into()
            .unwrap();
        let aux = Integer::subtracion_aux(&max_vals, Rc::clone(&self.rns));

        let c_limbs = a
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
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.sub_sub_with_constant(
            ctx,
            a.native(),
            b_0.native(),
            b_1.native(),
            aux.native(),
        )?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }

    pub(super) fn neg_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
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
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.neg_with_constant(ctx, a.native(), aux.native())?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }

    pub(crate) fn mul2_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();

        let c_limbs = a
            .limbs()
            .iter()
            .map(|a_limb| {
                let c_max = a_limb.mul2();
                let c_limb = main_gate.mul2(ctx, &a_limb.into())?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.mul2(ctx, a.native())?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }

    pub(crate) fn mul3_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();

        let c_limbs = a
            .limbs()
            .iter()
            .map(|a_limb| {
                let c_max = a_limb.mul3();
                let c_limb = main_gate.mul3(ctx, &a_limb.into())?;
                Ok(AssignedLimb::from(c_limb, c_max))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.mul3(ctx, a.native())?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }

    pub(crate) fn add_constant_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
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
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?
            .try_into()
            .unwrap();
        let c_native = main_gate.add_constant(ctx, a.native(), b.native())?;
        Ok(self.new_assigned_integer(&c_limbs, c_native))
    }
}
