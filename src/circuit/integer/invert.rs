use super::IntegerChip;
use super::IntegerInstructions;
use crate::{NUMBER_OF_LIMBS};
use crate::circuit::{AssignedInteger};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _invert(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let integer_inv = a.integer().and_then(|integer_a| {
            self.rns.invert(&integer_a)
        });
        let integer_one = self.rns.new_from_big(1u32.into());

        // TODO: For range constraints, we have these options:
        // 1. extend mul to support prenormalized value.
        // 2. call normalize here.
        // 3. add wrong field range check on inv.
        let most_significant_limb_bit_len = self.rns.bit_len_prenormalized - (self.rns.bit_len_limb * (NUMBER_OF_LIMBS - 1)) + 1;
        let inv = self.range_assign_integer(region, integer_inv.into(), most_significant_limb_bit_len, offset)?;
        let one = self.assign_integer(region, Some(integer_one), offset)?;
        let a_mul_inv = self._mul(region, &a, &inv, offset)?;

        self.assert_equal(region, &a_mul_inv, &one, offset)?;

        Ok(inv)
    }
}
