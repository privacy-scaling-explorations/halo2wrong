use super::{AssignedInteger, UnassignedInteger};
use crate::maingate::{halo2, AssignedCondition, RegionCtx};
use crate::rns::Integer;
use crate::WrongExt;
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;

// Signals the range mode that should be applied when assigning a new `Integer`Ï
pub enum Range {
    Remainder,
    Operand,
    MulQuotient,
    Unreduced,
}

pub trait IntegerInstructions<
    W: WrongExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>
{
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        range: Range,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: W,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedCondition<N>>, Error>;

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_0: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_1: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn mul_into_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn square(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn div(
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
    >;

    fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<
        (
            AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedCondition<N>,
        ),
        Error,
    >;

    fn invert_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn reduce(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_strict_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_strict_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_strict_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_strict_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        input: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error>;

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn reduce_external<T: WrongExt>(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<T, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error>;

    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedCondition<N>, Error>;
}
