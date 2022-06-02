use super::{AssignedCondition, IntegerChip};
use crate::{AssignedInteger, WrongExt};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::{halo2, RegionCtx};

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn div_generic(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<
        (
            AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedCondition<N>,
        ),
        Error,
    > {
        let (b_inv, cond) = self.invert_generic(ctx, b)?;
        let a_mul_b_inv = self.mul_generic(ctx, a, &b_inv)?;

        Ok((a_mul_b_inv, cond))
    }

    pub(crate) fn div_incomplete_generic(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let b_inv = self.invert_incomplete_generic(ctx, b)?;
        self.mul_generic(ctx, a, &b_inv)
    }
}
