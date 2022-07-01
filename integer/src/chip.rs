use std::rc::Rc;

use super::{AssignedInteger, AssignedLimb, UnassignedInteger};
use crate::instructions::{IntegerInstructions, Range};
use crate::rns::{Common, Integer, Rns};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::{halo2, AssignedCondition, AssignedValue, MainGateInstructions, RegionCtx};
use maingate::{MainGate, MainGateConfig};
use maingate::{RangeChip, RangeConfig};

mod add;
mod assert_in_field;
mod assert_not_zero;
mod assert_zero;
mod assign;
mod div;
mod invert;
mod mul;
mod reduce;
mod square;

/// Configuration for [`IntegerChip`]
#[derive(Clone, Debug)]
pub struct IntegerConfig {
    /// Configuration for [`RangeChip`]
    range_config: RangeConfig,
    /// Configuration for [`MainGate`]
    main_gate_config: MainGateConfig,
}

impl IntegerConfig {
    // Creates a new [`IntegerConfig`] from a [`RangeConfig`] and a
    /// [`MainGateConfig`]
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        Self {
            range_config,
            main_gate_config,
        }
    }
}

/// Chip for integer instructions
#[derive(Debug)]
pub struct IntegerChip<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    /// Chip configuration
    config: IntegerConfig,
    /// Residue number system used to represent the integers
    rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
}

impl<'a, W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn sublimb_bit_len() -> usize {
        let number_of_lookup_limbs = 4;
        assert!(BIT_LEN_LIMB % number_of_lookup_limbs == 0);
        BIT_LEN_LIMB / number_of_lookup_limbs
    }

    /// Creates a new [`AssignedInteger`] from its limb representation and its
    /// native value
    pub(crate) fn new_assigned_integer(
        &self,
        limbs: &[AssignedLimb<N>; NUMBER_OF_LIMBS],
        native_value: AssignedValue<N>,
    ) -> AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        AssignedInteger::new(Rc::clone(&self.rns), limbs, native_value)
    }
}

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerInstructions<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    for IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn reduce_external<T: FieldExt>(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        // TODO: external integer might have different parameter settings
        a: &AssignedInteger<T, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let to_be_reduced = self.new_assigned_integer(&a.limbs(), a.native());
        self.reduce(ctx, &to_be_reduced)
    }

    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        range: Range,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.assign_integer_generic(ctx, integer, range)
    }

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: W,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.assign_constant_generic(ctx, integer)
    }

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedCondition<N>>, Error> {
        self.assert_in_field(ctx, integer)?;

        let main_gate = self.main_gate();

        let mut decomposed = Vec::new();
        for idx in 0..NUMBER_OF_LIMBS {
            let number_of_bits = if idx == NUMBER_OF_LIMBS - 1 {
                self.rns.wrong_modulus.bits() as usize % BIT_LEN_LIMB
            } else {
                BIT_LEN_LIMB
            };
            let decomposed_limb = main_gate.to_bits(ctx, &integer.limb(idx), number_of_bits)?;
            decomposed.extend(decomposed_limb);
        }

        assert_eq!(decomposed.len(), self.rns.wrong_modulus.bits() as usize);

        Ok(decomposed)
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b)?,
        );
        self.add_generic(ctx, a, b)
    }

    fn add_add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_0: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_1: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let (a, b_0, b_1) = (
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b_0)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b_1)?,
        );
        self.add_add_generic(ctx, a, b_0, b_1)
    }

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?;
        self.add_constant_generic(ctx, a, b)
    }

    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.mul2_generic(ctx, a)
    }

    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.mul3_generic(ctx, a)
    }

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b)?,
        );
        self.sub_generic(ctx, a, b)
    }

    fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_0: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b_1: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let (a, b_0, b_1) = (
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b_0)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b_1)?,
        );
        self.sub_sub_generic(ctx, a, b_0, b_1)
    }

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?;
        self.neg_generic(ctx, a)
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self.mul_generic(ctx, a, b)
    }

    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self.mul_constant_generic(ctx, a, b)
    }

    fn mul_into_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self.mul_into_one_generic(ctx, a, b)
    }

    fn square(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self.square_generic(ctx, a)
    }

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
    > {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self.div_generic(ctx, a, b)
    }

    fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self.div_incomplete_generic(ctx, a, b)
    }

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
    > {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self.invert_generic(ctx, a)
    }

    fn invert_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self.invert_incomplete_generic(ctx, a)
    }

    fn reduce(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self.reduce_generic(ctx, a)
    }

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let c = &self.sub(ctx, a, b)?;
        self.assert_zero_generic(ctx, c)?;
        Ok(())
    }

    fn assert_strict_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for idx in 0..NUMBER_OF_LIMBS {
            main_gate.assert_equal(ctx, &a.limb(idx), &b.limb(idx))?;
        }
        Ok(())
    }

    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let c = &self.sub(ctx, a, b)?;
        self.assert_not_zero_generic(ctx, c)?;
        Ok(())
    }

    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self.assert_not_zero_generic(ctx, a)?;
        Ok(())
    }

    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        let main_gate = self.main_gate();
        for limb in a.limbs() {
            main_gate.assert_zero(ctx, &limb.into())?;
        }
        Ok(())
    }

    fn assert_strict_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for limb in a.limbs() {
            main_gate.assert_zero(ctx, &limb.into())?;
        }
        Ok(())
    }

    fn assert_strict_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.assert_zero(ctx, &a.limb(i))?;
        }
        main_gate.assert_one(ctx, &a.limb(0))
    }

    fn assert_strict_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.assert_zero(ctx, &a.limb(i))?;
        }
        main_gate.assert_bit(ctx, &a.limb(0))
    }

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let res = main_gate.select(ctx, &a.limb(i), &b.limb(i), cond)?;

            let max_val = if a.limbs[i].max_val > b.limbs[i].max_val {
                a.limbs[i].max_val.clone()
            } else {
                b.limbs[i].max_val.clone()
            };

            limbs.push(AssignedLimb::from(res, max_val));
        }

        let native_value = main_gate.select(ctx, &a.native(), &b.native(), cond)?;

        Ok(self.new_assigned_integer(&limbs.try_into().unwrap(), native_value))
    }

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let b_limb = b.limb(i);

            let res = main_gate.select_or_assign(ctx, &a.limb(i), b_limb.fe(), cond)?;

            // here we assume given constant is always in field
            let max_val = a.limbs[i].max_val();
            limbs.push(AssignedLimb::from(res, max_val));
        }

        let native_value = main_gate.select_or_assign(ctx, &a.native(), b.native(), cond)?;

        Ok(self.new_assigned_integer(&limbs.try_into().unwrap(), native_value))
    }

    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self.assert_in_field_generic(ctx, a)
    }

    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedCondition<N>, Error> {
        self.assert_in_field(ctx, a)?;
        self.main_gate().sign(ctx, &a.limb(0))
    }
}

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Create new ['IntegerChip'] with the configuration and a shared [`Rns`]
    pub fn new(config: IntegerConfig, rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        IntegerChip { config, rns }
    }

    /// Getter for [`RangeChip`]
    pub fn range_chip(&self) -> RangeChip<N> {
        RangeChip::<N>::new(self.config.range_config.clone())
    }

    /// Getter for [`MainGate`]
    pub fn main_gate(&self) -> MainGate<N> {
        let main_gate_config = self.config.main_gate_config.clone();
        MainGate::<N>::new(main_gate_config)
    }
}

#[cfg(test)]
mod tests {
    use super::{IntegerChip, IntegerConfig, IntegerInstructions, Range};
    use crate::rns::{Common, Integer, Rns};
    use crate::{FieldExt, UnassignedInteger};
    use core::panic;
    use halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use maingate::{
        big_to_fe, decompose_big, fe_to_big, halo2, AssignedCondition, MainGate, MainGateConfig,
        MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };
    use num_bigint::{BigUint as big_uint, RandBigInt};
    use num_traits::Zero;
    use rand_core::OsRng;
    use std::rc::Rc;

    const NUMBER_OF_LIMBS: usize = 4;

    fn rns<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize>(
    ) -> Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        Rns::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct()
    }

    fn setup<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize>(
    ) -> (Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, u32) {
        let rns = rns();
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        (rns, k)
    }

    impl<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize>
        From<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>
        for UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        fn from(integer: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) -> Self {
            UnassignedInteger(Value::known(integer))
        }
    }

    pub(crate) struct TestRNS<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize> {
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    }

    impl<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize> TestRNS<W, N, BIT_LEN_LIMB> {
        pub(crate) fn rand_in_field(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            Integer::from_fe(W::random(OsRng), Rc::clone(&self.rns))
        }

        pub(crate) fn rand_in_remainder_range(
            &self,
        ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            let el = OsRng.gen_biguint(self.rns.max_remainder.bits() as u64);
            Integer::from_big(el, Rc::clone(&self.rns))
        }

        pub(crate) fn rand_in_operand_range(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            let el = OsRng.gen_biguint(self.rns.max_operand.bits() as u64);
            Integer::from_big(el, Rc::clone(&self.rns))
        }

        pub(crate) fn rand_in_unreduced_range(
            &self,
        ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            self.rand_with_limb_bit_size(self.rns.max_unreduced_limb.bits() as usize)
        }

        pub(crate) fn rand_with_limb_bit_size(
            &self,
            bit_len: usize,
        ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            let limbs = (0..NUMBER_OF_LIMBS)
                .map(|_| {
                    let el = OsRng.gen_biguint(bit_len as u64);
                    big_to_fe(el)
                })
                .collect::<Vec<N>>()
                .try_into()
                .unwrap();

            Integer::from_limbs(&limbs, Rc::clone(&self.rns))
        }

        pub(crate) fn new_from_big(
            &self,
            e: big_uint,
        ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            Integer::from_big(e, Rc::clone(&self.rns))
        }

        pub(crate) fn new_from_limbs(
            &self,
            e: &[N; NUMBER_OF_LIMBS],
        ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            Integer::from_limbs(e, Rc::clone(&self.rns))
        }

        pub(crate) fn max_in_remainder_range(
            &self,
        ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            self.new_from_big(self.rns.max_remainder.clone())
        }

        pub(crate) fn max_in_operand_range(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            self.new_from_big(self.rns.max_operand.clone())
        }

        // pub(crate) fn max_in_unreduced_range(
        //     &self,
        // ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        //     let limbs = [big_to_fe(self.rns.max_unreduced_limb.clone());
        // NUMBER_OF_LIMBS];     Integer::from_limbs(&limbs,
        // Rc::clone(&self.rns)) }

        pub fn zero(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
            Integer::from_big(big_uint::zero(), Rc::clone(&self.rns))
        }
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        range_config: RangeConfig,
        main_gate_config: MainGateConfig,
    }

    impl TestCircuitConfig {
        fn new<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize>(
            meta: &mut ConstraintSystem<N>,
        ) -> Self {
            let main_gate_config = MainGate::<N>::configure(meta);

            let overflow_bit_lens = rns::<W, N, BIT_LEN_LIMB>().overflow_lengths();
            let composition_bit_len =
                IntegerChip::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::sublimb_bit_len();
            let range_config = RangeChip::<N>::configure(
                meta,
                &main_gate_config,
                vec![composition_bit_len],
                overflow_bit_lens,
            );

            TestCircuitConfig {
                range_config,
                main_gate_config,
            }
        }

        fn integer_chip_config(&self) -> IntegerConfig {
            IntegerConfig {
                range_config: self.range_config.clone(),
                main_gate_config: self.main_gate_config.clone(),
            }
        }

        fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_composition_tables(layouter)?;
            range_chip.load_overflow_tables(layouter)?;

            Ok(())
        }
    }

    macro_rules! impl_circuit {
        ($circuit_name:ident, $( $synth:tt )*) => {


            #[derive(Clone, Debug)]
            struct $circuit_name<W: FieldExt, N: FieldExt, const BIT_LEN_LIMB: usize> {
                rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
            }

            impl<W: FieldExt, N: FieldExt,  const BIT_LEN_LIMB: usize> $circuit_name<W, N, BIT_LEN_LIMB> {
                fn integer_chip(&self, config:TestCircuitConfig) -> IntegerChip<W, N, NUMBER_OF_LIMBS,BIT_LEN_LIMB>{
                    IntegerChip::<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(config.integer_chip_config(), Rc::clone(&self.rns))
                }

                fn tester(&self) -> TestRNS<W, N, BIT_LEN_LIMB> {
                    TestRNS {rns:Rc::clone(&self.rns)}
                }

            }

            impl<W: FieldExt, N: FieldExt,  const BIT_LEN_LIMB: usize> Circuit<N> for $circuit_name<W, N, BIT_LEN_LIMB> {
                type Config = TestCircuitConfig;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
                    TestCircuitConfig::new::<W, N, BIT_LEN_LIMB>(meta)
                }

                $( $synth )*
            }
        };
    }

    impl_circuit!(
        TestCircuitRange,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a = t.max_in_remainder_range();
                    integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;
                    // should fail
                    // let a = t.new_from_big(rns.max_remainder.clone() + 1usize);
                    // integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;
                    let a = t.max_in_operand_range();
                    integer_chip.assign_integer(ctx, a.into(), Range::Operand)?;
                    // should fail
                    // let a = t.new_from_big(rns.max_operand.clone() + 1usize);
                    // integer_chip.assign_integer(ctx, a.into(), Range::Operand)?
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitReduction,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let overflows = t.rand_with_limb_bit_size(BIT_LEN_LIMB + 5);
                    let unreduced = overflows.clone();
                    let reduced = overflows.reduce();
                    let reduced = reduced.result;
                    let overflows = &integer_chip.assign_integer(
                        ctx,
                        Value::known(unreduced).into(),
                        Range::Unreduced,
                    )?;
                    let reduced_0 = &integer_chip.assign_integer(
                        ctx,
                        Value::known(reduced).into(),
                        Range::Remainder,
                    )?;
                    let reduced_1 = &integer_chip.reduce(ctx, overflows)?;
                    assert_eq!(reduced_1.max_val(), self.rns.max_remainder);
                    integer_chip.assert_equal(ctx, reduced_0, reduced_1)?;
                    integer_chip.assert_strict_equal(ctx, reduced_0, reduced_1)?;
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitEquality,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a = t.rand_in_operand_range();
                    let b = t.rand_in_operand_range();
                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Operand)?;
                    let b = &integer_chip.assign_integer(ctx, b.into(), Range::Operand)?;
                    integer_chip.assert_not_equal(ctx, a, b)?;
                    integer_chip.assert_equal(ctx, a, a)?;
                    integer_chip.assert_not_zero(ctx, a)?;
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitMultiplication,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let a = t.rand_in_operand_range();
                    let b = t.rand_in_operand_range();
                    let c = (a.value() * b.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Operand)?;
                    let b = &integer_chip.assign_integer(ctx, b.into(), Range::Operand)?;
                    let c_0 = &integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.mul(ctx, a, b)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    let a = t.rand_in_unreduced_range();
                    let b = t.rand_in_unreduced_range();
                    let c = (a.value() * b.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;
                    let b = &integer_chip.assign_integer(ctx, b.into(), Range::Unreduced)?;
                    let c_0 = &integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.mul(ctx, a, b)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    let a = t.rand_in_unreduced_range();
                    let b = t.rand_in_field();
                    let c = (a.value() * b.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;
                    let c_0 = &integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.mul_constant(ctx, a, &b)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    let a = W::random(OsRng);
                    let inv = a.invert().unwrap();

                    let a = t.new_from_big(fe_to_big(a));
                    let inv = t.new_from_big(fe_to_big(inv));

                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;
                    let inv = &integer_chip.assign_integer(ctx, inv.into(), Range::Remainder)?;
                    integer_chip.mul_into_one(ctx, a, inv)?;

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitSquaring,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let a = t.rand_in_operand_range();
                    let c = (a.value() * a.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Operand)?;
                    let c_0 = &integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.square(ctx, a)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    let a = t.rand_in_unreduced_range();
                    let c = (a.value() * a.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;
                    let c_0 = &integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.square(ctx, a)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitInField,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let a = t.rand_in_field();
                    let a = &integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;
                    integer_chip.assert_in_field(ctx, a)?;
                    // must fail
                    // let a = t.new_from_big(rns.wrong_modulus.clone());
                    // let a = &integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;
                    // integer_chip.assert_in_field(ctx, a)?;
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitNonDeterministic,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let a = t.rand_in_remainder_range();
                    let inv = a.invert().unwrap();

                    // 1 / a
                    let a = &integer_chip.assign_integer(
                        ctx,
                        Value::known(a).into(),
                        Range::Remainder,
                    )?;
                    let inv_0 = &integer_chip.assign_integer(
                        ctx,
                        Value::known(inv).into(),
                        Range::Remainder,
                    )?;
                    let (inv_1, cond) = integer_chip.invert(ctx, a)?;
                    integer_chip.assert_equal(ctx, inv_0, &inv_1)?;
                    main_gate.assert_zero(ctx, &cond)?;

                    // 1 / 0
                    let zero =
                        integer_chip.assign_integer(ctx, t.zero().into(), Range::Remainder)?;
                    let (must_be_one, cond) = integer_chip.invert(ctx, &zero)?;
                    integer_chip.assert_strict_one(ctx, &must_be_one)?;
                    main_gate.assert_one(ctx, &cond)?;

                    // 1 / p
                    let wrong_modulus = t.new_from_limbs(&self.rns.wrong_modulus_decomposed);
                    let modulus =
                        integer_chip.assign_integer(ctx, wrong_modulus.into(), Range::Remainder)?;
                    let (must_be_one, cond) = integer_chip.invert(ctx, &modulus)?;
                    integer_chip.assert_strict_one(ctx, &must_be_one)?;
                    main_gate.assert_one(ctx, &cond)?;

                    // 1 / a
                    let inv_1 = integer_chip.invert_incomplete(ctx, a)?;
                    integer_chip.assert_equal(ctx, inv_0, &inv_1)?;

                    // must fail
                    // integer_chip.invert_incomplete(ctx, &zero)?;

                    // a / b
                    let a = t.rand_in_remainder_range();
                    let b = t.rand_in_remainder_range();

                    let c = a.mul(&b.invert().unwrap()).result;
                    let a = &integer_chip.assign_integer(
                        ctx,
                        Value::known(a).into(),
                        Range::Remainder,
                    )?;
                    let b = &integer_chip.assign_integer(
                        ctx,
                        Value::known(b).into(),
                        Range::Remainder,
                    )?;
                    let c_0 = &integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                    let (c_1, cond) = integer_chip.div(ctx, a, b)?;
                    integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    main_gate.assert_zero(ctx, &cond)?;

                    // 0 / b
                    let (c_1, cond) = integer_chip.div(ctx, &zero, b)?;
                    integer_chip.assert_zero(ctx, &c_1)?;
                    main_gate.assert_zero(ctx, &cond)?;

                    // p / b
                    let (c_1, cond) = integer_chip.div(ctx, &modulus, b)?;
                    integer_chip.assert_zero(ctx, &c_1)?;
                    main_gate.assert_zero(ctx, &cond)?;

                    // a / 0
                    let (must_be_self, cond) = integer_chip.div(ctx, a, &zero)?;
                    integer_chip.assert_equal(ctx, &must_be_self, a)?;
                    main_gate.assert_one(ctx, &cond)?;

                    // a / p
                    let (must_be_self, cond) = integer_chip.div(ctx, a, &modulus)?;
                    integer_chip.assert_equal(ctx, &must_be_self, a)?;
                    main_gate.assert_one(ctx, &cond)?;

                    // a / b
                    let c_1 = integer_chip.div_incomplete(ctx, a, b)?;
                    integer_chip.assert_equal(ctx, c_0, &c_1)?;

                    // must fail
                    // integer_chip.div_incomplete(ctx, a, &zero)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    );

    impl_circuit!(
        TestCircuitAddition,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    {
                        let a = t.rand_in_remainder_range();
                        let b = t.rand_in_remainder_range();
                        let c = a.value() + b.value();
                        let c = t.new_from_big(c);

                        let c_in_field = (a.value() + b.value()) % &self.rns.wrong_modulus;
                        let c_in_field = t.new_from_big(c_in_field);
                        let a = integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;
                        let b = integer_chip.assign_integer(ctx, b.into(), Range::Remainder)?;

                        let c_0 = &integer_chip.add(ctx, &a, &b)?;
                        let c_1 = integer_chip.assign_integer(ctx, c.into(), Range::Unreduced)?;

                        assert_eq!(a.max_val() + b.max_val(), c_0.max_val());

                        integer_chip.assert_equal(ctx, c_0, &c_1)?;

                        // reduce and enfoce strict equality
                        let c_0 = integer_chip.reduce(ctx, c_0)?;
                        let c_1 = integer_chip.assign_integer(
                            ctx,
                            c_in_field.into(),
                            Range::Remainder,
                        )?;
                        integer_chip.assert_equal(ctx, &c_0, &c_1)?;
                        integer_chip.assert_strict_equal(ctx, &c_0, &c_1)?;
                    }

                    {
                        // constant addition in remainder range
                        let a = t.rand_in_remainder_range();
                        let b = t.rand_in_field();

                        let c = a.value() + b.value();
                        let c = t.new_from_big(c);
                        let c_in_field = (a.value() + b.value()) % &self.rns.wrong_modulus;
                        let c_in_field = t.new_from_big(c_in_field);

                        let a = integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;

                        let c_0 = &integer_chip.add_constant(ctx, &a, &b)?;
                        let c_1 = integer_chip.assign_integer(ctx, c.into(), Range::Unreduced)?;
                        assert_eq!(a.max_val() + b.value(), c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;

                        // reduce and enfoce strict equality
                        let c_0 = integer_chip.reduce(ctx, c_0)?;
                        let c_1 = integer_chip.assign_integer(
                            ctx,
                            c_in_field.into(),
                            Range::Remainder,
                        )?;
                        integer_chip.assert_equal(ctx, &c_0, &c_1)?;
                        integer_chip.assert_strict_equal(ctx, &c_0, &c_1)?;
                    }

                    {
                        // go beyond unreduced range
                        let a = t.rand_in_remainder_range();
                        let mut a = integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;

                        for _ in 0..10 {
                            let c = a
                                .integer()
                                .map(|a| (a.value() * 2usize) % &self.rns.wrong_modulus)
                                .map(|c| t.new_from_big(c));
                            a = integer_chip.add(ctx, &a, &a)?;
                            let c_1 =
                                integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                            let c_0 = integer_chip.reduce(ctx, &a)?;
                            integer_chip.assert_equal(ctx, &a, &c_1)?;
                            integer_chip.assert_equal(ctx, &c_0, &c_1)?;
                            integer_chip.assert_strict_equal(ctx, &c_0, &c_1)?;
                        }
                    }

                    {
                        // addition in unreduced range
                        for _ in 0..10 {
                            let a = t.rand_in_unreduced_range();
                            let b = t.rand_in_unreduced_range();
                            let c = (a.value() + b.value()) % self.rns.wrong_modulus.clone();
                            let c = t.new_from_big(c);

                            let a = integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;
                            let b = integer_chip.assign_integer(ctx, b.into(), Range::Unreduced)?;
                            let c_0 = &integer_chip.add(ctx, &a, &b)?;
                            let c_1 =
                                integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                            assert_eq!(a.max_val() + b.max_val(), c_0.max_val());
                            integer_chip.assert_equal(ctx, c_0, &c_1)?;

                            // reduce and enfoce strict equality
                            let c_0 = integer_chip.reduce(ctx, c_0)?;
                            integer_chip.assert_equal(ctx, &c_0, &c_1)?;
                            integer_chip.assert_strict_equal(ctx, &c_0, &c_1)?;
                        }
                    }

                    {
                        // subtraction in remainder range
                        let a = t.rand_in_remainder_range();
                        let b = t.rand_in_remainder_range();

                        let a_norm = (a.value() % self.rns.wrong_modulus.clone())
                            + self.rns.wrong_modulus.clone();
                        let b_norm = b.value() % self.rns.wrong_modulus.clone();
                        let c = (a_norm - b_norm) % self.rns.wrong_modulus.clone();
                        let c = t.new_from_big(c);

                        let a = integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;
                        let b = integer_chip.assign_integer(ctx, b.into(), Range::Remainder)?;
                        let aux = b.make_aux();

                        let c_0 = &integer_chip.sub(ctx, &a, &b)?;
                        let c_1 = integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(a.max_val() + aux.value(), c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    {
                        // subtraction in unreduced range
                        let a = t.rand_in_unreduced_range();
                        let b = t.rand_in_unreduced_range();

                        let a_norm = (a.value() % self.rns.wrong_modulus.clone())
                            + self.rns.wrong_modulus.clone();
                        let b_norm = b.value() % self.rns.wrong_modulus.clone();
                        let c = (a_norm - b_norm) % self.rns.wrong_modulus.clone();
                        let c = t.new_from_big(c);

                        let a = integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;
                        let b = integer_chip.assign_integer(ctx, b.into(), Range::Unreduced)?;
                        let aux = b.make_aux();

                        let c_0 = &integer_chip.sub(ctx, &a, &b)?;
                        let c_1 = integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(a.max_val() + aux.value(), c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    {
                        // go beyond unreduced range
                        let a = t.rand_in_remainder_range();
                        let mut a = integer_chip.assign_integer(ctx, a.into(), Range::Remainder)?;

                        for _ in 0..10 {
                            let b = t.rand_in_unreduced_range();

                            let a_norm = a.integer().map(|a| {
                                a.value() % self.rns.wrong_modulus.clone()
                                    + self.rns.wrong_modulus.clone()
                            });
                            let b_norm = b.value() % self.rns.wrong_modulus.clone();
                            let c = a_norm
                                .map(|a_norm| (a_norm - b_norm) % self.rns.wrong_modulus.clone())
                                .map(|c| t.new_from_big(c));

                            let b = integer_chip.assign_integer(ctx, b.into(), Range::Unreduced)?;

                            let c_0 = &integer_chip.sub(ctx, &a, &b)?;
                            let c_1 =
                                integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                            integer_chip.assert_equal(ctx, c_0, &c_1)?;
                            a = c_0.clone();
                        }
                    }

                    {
                        // negation in unreduced range
                        let a = t.rand_in_unreduced_range();
                        let a_norm = a.value() % self.rns.wrong_modulus.clone();
                        let c = self.rns.wrong_modulus.clone() - a_norm;
                        let c = t.new_from_big(c);

                        let a = integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;
                        let aux = a.make_aux();

                        let c_0 = &integer_chip.neg(ctx, &a)?;
                        let c_1 = integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(aux.value(), c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    {
                        // mul2 in unreduced range
                        let a = t.rand_in_unreduced_range();
                        let c = (a.value() * 2usize) % self.rns.wrong_modulus.clone();
                        let c = t.new_from_big(c);

                        let a = integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;

                        let c_0 = &integer_chip.mul2(ctx, &a)?;
                        let c_1 = integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(a.max_val() * 2usize, c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    {
                        // mul3 in unreduced range
                        let a = t.rand_in_unreduced_range();
                        let c = (a.value() * 3usize) % self.rns.wrong_modulus.clone();
                        let c = t.new_from_big(c);

                        let a = integer_chip.assign_integer(ctx, a.into(), Range::Unreduced)?;
                        let c_0 = &integer_chip.mul3(ctx, &a)?;
                        let c_1 = integer_chip.assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(a.max_val() * 3usize, c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitConditionals,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    // select second operand when condision is zero

                    let a = t.rand_in_remainder_range().into();
                    let b = t.rand_in_remainder_range().into();
                    let cond = N::zero();
                    let cond = Value::known(cond);

                    let a = integer_chip.assign_integer(ctx, a, Range::Remainder)?;
                    let b = integer_chip.assign_integer(ctx, b, Range::Remainder)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, cond)?;
                    let selected = integer_chip.select(ctx, &a, &b, &cond)?;
                    integer_chip.assert_equal(ctx, &b, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &b, &selected)?;
                    assert_eq!(b.max_val(), selected.max_val());

                    // select first operand when condision is one

                    let a = t.rand_in_remainder_range().into();
                    let b = t.rand_in_remainder_range().into();
                    let cond = N::one();
                    let cond = Value::known(cond);

                    let a = integer_chip.assign_integer(ctx, a, Range::Remainder)?;
                    let b = integer_chip.assign_integer(ctx, b, Range::Remainder)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, cond)?;
                    let selected = integer_chip.select(ctx, &a, &b, &cond)?;
                    integer_chip.assert_equal(ctx, &a, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &a, &selected)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select constant operand when condision is zero

                    let a = t.rand_in_remainder_range().into();
                    let b = t.rand_in_remainder_range();
                    let cond = N::zero();
                    let cond = Value::known(cond);

                    let a = integer_chip.assign_integer(ctx, a, Range::Remainder)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, cond)?;
                    let selected = integer_chip.select_or_assign(ctx, &a, &b, &cond)?;
                    let b_assigned =
                        integer_chip.assign_integer(ctx, b.into(), Range::Remainder)?;
                    integer_chip.assert_equal(ctx, &b_assigned, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &b_assigned, &selected)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select non constant operand when condision is zero

                    let a = t.rand_in_remainder_range().into();
                    let b = t.rand_in_remainder_range();
                    let cond = N::one();
                    let cond = Value::known(cond);

                    let a = integer_chip.assign_integer(ctx, a, Range::Remainder)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, cond)?;
                    let selected = integer_chip.select_or_assign(ctx, &a, &b, &cond)?;
                    integer_chip.assert_equal(ctx, &a, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &a, &selected)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitDecomposition,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    for _ in 0..2 {
                        let integer = t.rand_in_field();
                        let integer_big = integer.value();
                        let assigned =
                            integer_chip.assign_integer(ctx, integer.into(), Range::Remainder)?;
                        let decomposed = integer_chip.decompose(ctx, &assigned)?;
                        let expected = decompose_big::<W>(
                            integer_big,
                            self.rns.wrong_modulus.bits() as usize,
                            1,
                        );
                        assert_eq!(expected.len(), decomposed.len());
                        for (c, expected) in decomposed.iter().zip(expected.into_iter()) {
                            if expected != W::zero() {
                                main_gate.assert_one(ctx, c)?;
                            } else {
                                main_gate.assert_zero(ctx, c)?;
                            }
                        }
                    }
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    impl_circuit!(
        TestCircuitSign,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let integer_chip = self.integer_chip(config.clone());
            let t = self.tester();
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let integer = t.new_from_big(big_uint::from(20u64));
                    let assigned =
                        integer_chip.assign_integer(ctx, integer.into(), Range::Remainder)?;
                    let assigned_sign = integer_chip.sign(ctx, &assigned)?;
                    main_gate.assert_zero(ctx, &assigned_sign)?;

                    let integer = t.new_from_big(big_uint::from(21u64));
                    let assigned =
                        integer_chip.assign_integer(ctx, integer.into(), Range::Remainder)?;
                    let assigned_sign = integer_chip.sign(ctx, &assigned)?;
                    main_gate.assert_one(ctx, &assigned_sign)?;

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter)
        }
    );

    macro_rules! test_circuit_runner {
        (
            $circuit:ident, $([$wrong_field:ident, $native_field:ident, $bit_len_limb:expr]),*
        ) => {
            $(
                let (rns, k):(Rns<$wrong_field, $native_field, NUMBER_OF_LIMBS, $bit_len_limb>, u32) = setup();

                let circuit = $circuit::<$wrong_field, $native_field, $bit_len_limb> { rns: Rc::new(rns) };
                let public_inputs = vec![vec![]];
                let prover = match MockProver::run(k, &circuit, public_inputs) {
                    Ok(prover) => prover,
                    Err(e) => panic!("{:#?}", e),
                };
                assert_eq!(prover.verify(), Ok(()));
            )*
        };
    }

    macro_rules! test_circuit {
        (
            $circuit:ident
        ) => {
            use crate::curves::bn256::{Fq as BnBase, Fr as BnScalar};
            use crate::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
            use crate::curves::secp256k1::{Fp as Secp256k1Base, Fq as Secp256k1Scalar};
            test_circuit_runner!(
                $circuit,
                [PastaFp, PastaFq, 68],
                [PastaFq, PastaFp, 68],
                [BnBase, BnScalar, 68],
                [BnScalar, BnScalar, 68],
                [Secp256k1Base, BnScalar, 68],
                [Secp256k1Base, PastaFp, 68],
                [Secp256k1Base, PastaFq, 68],
                [Secp256k1Scalar, BnScalar, 68],
                [Secp256k1Scalar, PastaFp, 68],
                [Secp256k1Scalar, PastaFq, 68]
            );
        };
    }

    #[test]
    fn test_integer_circuit_range() {
        test_circuit!(TestCircuitRange);
    }
    #[test]
    fn test_integer_circuit_reduction() {
        test_circuit!(TestCircuitReduction);
    }
    #[test]
    fn test_integer_circuit_multiplication() {
        test_circuit!(TestCircuitMultiplication);
    }
    #[test]
    fn test_integer_circuit_squaring() {
        test_circuit!(TestCircuitSquaring);
    }
    #[test]
    fn test_integer_circuit_infield() {
        test_circuit!(TestCircuitInField);
    }
    #[test]
    fn test_integer_circuit_nondeterministic() {
        test_circuit!(TestCircuitNonDeterministic);
    }
    #[test]
    fn test_integer_circuit_equality() {
        test_circuit!(TestCircuitEquality);
    }
    #[test]
    fn test_integer_circuit_addition() {
        test_circuit!(TestCircuitAddition);
    }
    #[test]
    fn test_integer_circuit_conditionals() {
        test_circuit!(TestCircuitConditionals);
    }
    #[test]
    fn test_integer_circuit_decomposition() {
        test_circuit!(TestCircuitDecomposition);
    }
    #[test]
    fn test_integer_circuit_sign() {
        test_circuit!(TestCircuitSign);
    }
}
