use super::{IntegerChip, IntegerInstructions, Range};
use crate::{rns::Integer, AssignedInteger, PrimeField};
use halo2::plonk::Error;
use maingate::{
    halo2, AssignedCondition, CombinationOptionCommon, MainGateInstructions, RegionCtx, Term,
};
use std::rc::Rc;

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn invert_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<
        (
            AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedCondition<N>,
        ),
        Error,
    > {
        let main_gate = self.main_gate();

        let inv_or_one = a.integer().map(|a| {
            a.invert()
                .unwrap_or_else(|| Integer::from_big(1u32.into(), Rc::clone(&self.rns)))
        });

        // TODO: For range constraints, we have these options:
        // 1. extend mul to support prenormalized value.
        // 2. call normalize here.
        // 3. add wrong field range check on inv.
        let inv_or_one = self.assign_integer(ctx, inv_or_one.into(), Range::Remainder)?;
        let a_mul_inv = &self.mul(ctx, a, &inv_or_one)?;

        // We believe the mul result is strictly less than wrong modulus, so we add
        // strict constraints here. The limbs[1..NUMBER_OF_LIMBS] of a_mul_inv
        // should be 0.
        self.assert_strict_bit(ctx, a_mul_inv)?;

        // If a_mul_inv is 0 (i.e. not 1), then inv_or_one must be 1.
        // inv_or_one = 1 <-> inv_or_one[0] = 1 /\ inv_or_one.natvie = 1.
        // Here we short x.limbs[i] as x[i].
        // 1. (a_mul_inv[0] - 1) * (inv_or_one.native - 1) = 0
        // 2. (a_mul_inv[0] - 1) * (inv_or_one[0] - 1) = 0
        main_gate.one_or_one(ctx, a_mul_inv.limb(0), inv_or_one.native())?;
        main_gate.one_or_one(ctx, a_mul_inv.limb(0), inv_or_one.limb(0))?;

        // Align with main_gain.invert(), cond = 1 - a_mul_inv
        let cond = a_mul_inv
            .limb(0)
            .value()
            .map(|a_mul_inv| N::ONE - a_mul_inv);

        let cond = main_gate
            .apply(
                ctx,
                [
                    Term::Assigned(a_mul_inv.limb(0), N::ONE),
                    Term::Unassigned(cond, N::ONE),
                    Term::Zero,
                    Term::Zero,
                    Term::Zero,
                ],
                -N::ONE,
                CombinationOptionCommon::OneLinerMul.into(),
            )?
            .swap_remove(1);

        Ok((inv_or_one, cond))
    }

    pub(crate) fn invert_incomplete_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let a_int = a.integer();
        let inv = a_int.map(|a| {
            a.invert().unwrap_or_else(|| {
                // any number will fail it if a is zero
                // no assertion here for now since we might want to fail in tests
                Integer::from_big(1u32.into(), Rc::clone(&self.rns))
            })
        });
        let inv = self.assign_integer(ctx, inv.into(), Range::Remainder)?;
        self.mul_into_one(ctx, a, &inv)?;
        Ok(inv)
    }
}
