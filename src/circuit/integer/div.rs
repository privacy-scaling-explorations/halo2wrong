use super::AssignedCondition;
use super::IntegerChip;
use super::IntegerInstructions;
use crate::circuit::AssignedInteger;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _div(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        let (b_inv, cond) = self.invert(region, b, offset)?;
        let a_mul_b_inv = self.mul(region, a, &b_inv, offset)?;

        Ok((a_mul_b_inv, cond))
    }
}
