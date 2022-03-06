use super::{AssignedCondition, IntegerChip, IntegerInstructions};
use crate::{AssignedInteger, WrongExt};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::{halo2, RegionCtx};

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _div(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        let (b_inv, cond) = self._invert(ctx, b)?;
        let a_mul_b_inv = self._mul(ctx, a, &b_inv)?;

        Ok((a_mul_b_inv, cond))
    }

    pub(crate) fn _div_incomplete(&self, ctx: &mut RegionCtx<'_, '_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        let b_inv = self._invert_incomplete(ctx, b)?;
        self.mul(ctx, a, &b_inv)
    }
}
