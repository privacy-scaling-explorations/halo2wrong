use super::AssignedCondition;
use super::IntegerChip;
use super::IntegerInstructions;
use crate::WrongExt;
use crate::circuit::AssignedInteger;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::halo2;

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _div(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        let (b_inv, cond) = self._invert(region, b, offset)?;
        let a_mul_b_inv = self._mul(region, a, &b_inv, offset)?;

        Ok((a_mul_b_inv, cond))
    }

    pub(crate) fn _div_incomplete(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let b_inv = self._invert_incomplete(region, b, offset)?;
        self.mul(region, a, &b_inv, offset)
    }
}
