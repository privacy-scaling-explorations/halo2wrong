use std::rc::Rc;

use super::{AssignedInteger, AssignedLimb, UnassignedInteger};
use crate::rns::{Common, Integer, Rns};
use crate::{WrongExt, NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};
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

pub enum Range {
    Remainder,
    Operand,
    MulQuotient,
}

#[derive(Clone, Debug)]
pub struct IntegerConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

impl IntegerConfig {
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        Self {
            range_config,
            main_gate_config,
        }
    }
}

pub struct IntegerChip<W: WrongExt, N: FieldExt> {
    config: IntegerConfig,
    rns: Rc<Rns<W, N>>,
}

impl<'a, W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn new_assigned_integer(
        &self,
        limbs: Vec<AssignedLimb<N>>,
        native_value: AssignedValue<N>,
    ) -> AssignedInteger<W, N> {
        AssignedInteger::new(Rc::clone(&self.rns), limbs, native_value)
    }
}

pub trait IntegerInstructions<W: WrongExt, N: FieldExt> {
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: W,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn range_assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N>,
        range: Range,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: &AssignedInteger<W, N>,
    ) -> Result<Vec<AssignedCondition<N>>, Error>;

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &Integer<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b_0: &AssignedInteger<W, N>,
        b_1: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &Integer<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn mul_into_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn square(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn div(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(AssignedInteger<W, N>, AssignedCondition<N>), Error>;
    fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(AssignedInteger<W, N>, AssignedCondition<N>), Error>;
    fn invert_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn reduce(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn assert_strict_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn assert_strict_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn assert_strict_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        input: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &Integer<W, N>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn reduce_external<T: WrongExt>(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<T, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
}

impl<W: WrongExt, N: FieldExt> IntegerInstructions<W, N> for IntegerChip<W, N> {
    fn reduce_external<T: WrongExt>(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<T, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let to_be_reduced = self.new_assigned_integer(a.limbs(), a.native());
        self.reduce(ctx, &to_be_reduced)
    }

    fn range_assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N>,
        range: Range,
    ) -> Result<AssignedInteger<W, N>, Error> {
        self._range_assign_integer(ctx, integer, range)
    }

    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: UnassignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        self._assign_integer(ctx, integer, true)
    }

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: W,
    ) -> Result<AssignedInteger<W, N>, Error> {
        self._assign_constant(ctx, integer)
    }

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        integer: &AssignedInteger<W, N>,
    ) -> Result<Vec<AssignedCondition<N>>, Error> {
        self.assert_in_field(ctx, integer)?;

        let main_gate = self.main_gate();

        let mut decomposed = Vec::new();
        for idx in 0..NUMBER_OF_LIMBS {
            let number_of_bits = if idx == NUMBER_OF_LIMBS - 1 {
                self.rns.bit_len_last_limb
            } else {
                self.rns.bit_len_limb
            };
            let decomposed_limb = main_gate.decompose(ctx, integer.limb(idx), number_of_bits)?;
            decomposed.extend(decomposed_limb);
        }

        assert_eq!(decomposed.len(), self.rns.bit_len_wrong_modulus);

        Ok(decomposed)
    }

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b)?,
        );
        self._add(ctx, a, b)
    }

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &Integer<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?;
        self._add_constant(ctx, a, b)
    }

    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        self._mul2(ctx, a)
    }

    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        self._mul3(ctx, a)
    }

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b)?,
        );
        self._sub(ctx, a, b)
    }

    fn sub_sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b_0: &AssignedInteger<W, N>,
        b_1: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let (a, b_0, b_1) = (
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b_0)?,
            &self.reduce_if_limb_values_exceeds_unreduced(ctx, b_1)?,
        );
        self._sub_sub(ctx, a, b_0, b_1)
    }

    fn neg(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_unreduced(ctx, a)?;
        self._neg(ctx, a)
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self._mul(ctx, a, b)
    }

    fn mul_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &Integer<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self._mul_constant(ctx, a, b)
    }

    fn mul_into_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self._mul_into_one(ctx, a, b)
    }

    fn square(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self._square(ctx, a)
    }

    fn div(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(AssignedInteger<W, N>, AssignedCondition<N>), Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self._div(ctx, a, b)
    }

    fn div_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?,
            &self.reduce_if_limb_values_exceeds_reduced(ctx, b)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(ctx, a)?,
            &self.reduce_if_max_operand_value_exceeds(ctx, b)?,
        );
        self._div_incomplete(ctx, a, b)
    }

    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(AssignedInteger<W, N>, AssignedCondition<N>), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self._invert(ctx, a)
    }

    fn invert_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self._invert_incomplete(ctx, a)
    }

    fn reduce(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        self._reduce(ctx, a)
    }

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let c = &self.sub(ctx, a, b)?;
        self.assert_zero(ctx, c)?;
        Ok(())
    }

    fn assert_strict_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for idx in 0..NUMBER_OF_LIMBS {
            main_gate.assert_equal(ctx, a.limb(idx), b.limb(idx))?;
        }
        Ok(())
    }

    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let c = &self.sub(ctx, a, b)?;
        self.assert_not_zero(ctx, c)?;
        Ok(())
    }

    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self._assert_not_zero(ctx, a)?;
        Ok(())
    }

    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self._assert_zero(ctx, a)
    }

    fn assert_strict_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.assert_zero(ctx, a.limb(i))?;
        }
        main_gate.assert_one(ctx, a.limb(0))
    }

    fn assert_strict_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.assert_zero(ctx, a.limb(i))?;
        }
        main_gate.assert_bit(ctx, a.limb(0))
    }

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let res = main_gate.select(ctx, a.limb(i), b.limb(i), cond)?;

            let max_val = if a.limbs[i].max_val > b.limbs[i].max_val {
                a.limbs[i].max_val.clone()
            } else {
                b.limbs[i].max_val.clone()
            };

            limbs.push(AssignedLimb::from(res, max_val));
        }

        let native_value = main_gate.select(ctx, a.native(), b.native(), cond)?;

        Ok(self.new_assigned_integer(limbs, native_value))
    }

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
        b: &Integer<W, N>,
        cond: &AssignedCondition<N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let b_limb = b.limb(i);

            let res = main_gate.select_or_assign(ctx, a.limb(i), b_limb.fe(), cond)?;

            // here we assume given constant is always in field
            let max_val = a.limb(i).max_val();
            limbs.push(AssignedLimb::from(res, max_val));
        }

        let native_value = main_gate.select_or_assign(ctx, a.native(), b.native(), cond)?;

        Ok(self.new_assigned_integer(limbs, native_value))
    }

    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<(), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(ctx, a)?;
        let a = &self.reduce_if_max_operand_value_exceeds(ctx, a)?;
        self._assert_in_field(ctx, a)
    }
}

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub fn new(config: IntegerConfig, rns: Rc<Rns<W, N>>) -> Self {
        IntegerChip { config, rns }
    }

    pub fn range_chip(&self) -> RangeChip<N> {
        let bit_len_lookup = self.rns.bit_len_limb / NUMBER_OF_LOOKUP_LIMBS;
        RangeChip::<N>::new(self.config.range_config.clone(), bit_len_lookup)
    }

    pub fn main_gate(&self) -> MainGate<N> {
        let main_gate_config = self.config.main_gate_config.clone();
        MainGate::<N>::new(main_gate_config)
    }
}

#[cfg(test)]
mod tests {
    use super::{IntegerChip, IntegerConfig, IntegerInstructions, Range};
    use crate::rns::{Common, Integer, Rns};
    use crate::{
        AssignedInteger, UnassignedInteger, WrongExt, NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS,
    };
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use maingate::{
        big_to_fe, decompose_big, fe_to_big, halo2, AssignedCondition, MainGate, MainGateConfig,
        MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };
    use num_bigint::{BigUint as big_uint, RandBigInt};
    use num_traits::Zero;
    use rand::thread_rng;
    use secp256k1::Fp as Secp256k1_Fp;
    use secp256k1::Fq as Secp256k1_Fq;
    use std::rc::Rc;

    fn rns<W: WrongExt, N: FieldExt, const BIT_LEN_LIMB: usize>() -> Rns<W, N> {
        Rns::<W, N>::construct(BIT_LEN_LIMB)
    }

    fn setup<W: WrongExt, N: FieldExt, const BIT_LEN_LIMB: usize>() -> (Rns<W, N>, u32) {
        let rns = rns::<_, _, BIT_LEN_LIMB>();
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        (rns, k)
    }

    impl<W: WrongExt, N: FieldExt> From<Integer<W, N>> for UnassignedInteger<W, N> {
        fn from(integer: Integer<W, N>) -> Self {
            UnassignedInteger(Some(integer))
        }
    }

    impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
        fn assign_integer_no_check(
            &self,
            ctx: &mut RegionCtx<'_, '_, N>,
            integer: UnassignedInteger<W, N>,
        ) -> Result<AssignedInteger<W, N>, Error> {
            self._assign_integer(ctx, integer, false)
        }
    }

    pub(crate) struct TestRNS<W: WrongExt, N: FieldExt> {
        rns: Rc<Rns<W, N>>,
    }

    impl<W: WrongExt, N: FieldExt> TestRNS<W, N> {
        pub(crate) fn rand_in_field(&self) -> Integer<W, N> {
            let mut rng = thread_rng();
            Integer::from_fe(W::random(&mut rng), Rc::clone(&self.rns))
        }

        pub(crate) fn rand_in_remainder_range(&self) -> Integer<W, N> {
            let mut rng = thread_rng();
            let el = rng.gen_biguint(self.rns.max_remainder.bits() as u64);
            Integer::from_big(el, Rc::clone(&self.rns))
        }

        pub(crate) fn rand_in_operand_range(&self) -> Integer<W, N> {
            let mut rng = thread_rng();
            let el = rng.gen_biguint(self.rns.max_operand.bits() as u64);
            Integer::from_big(el, Rc::clone(&self.rns))
        }

        pub(crate) fn rand_in_unreduced_range(&self) -> Integer<W, N> {
            self.rand_with_limb_bit_size(self.rns.max_unreduced_limb.bits() as usize)
        }

        pub(crate) fn rand_with_limb_bit_size(&self, bit_len: usize) -> Integer<W, N> {
            let limbs: Vec<N> = (0..NUMBER_OF_LIMBS)
                .map(|_| {
                    let mut rng = thread_rng();
                    let el = rng.gen_biguint(bit_len as u64);
                    big_to_fe(el)
                })
                .collect();

            Integer::from_limbs(limbs, Rc::clone(&self.rns))
        }

        pub(crate) fn new_from_big(&self, e: big_uint) -> Integer<W, N> {
            Integer::from_big(e, Rc::clone(&self.rns))
        }

        pub(crate) fn new_from_limbs(&self, e: Vec<N>) -> Integer<W, N> {
            Integer::from_limbs(e, Rc::clone(&self.rns))
        }

        pub(crate) fn max_in_remainder_range(&self) -> Integer<W, N> {
            self.new_from_big(self.rns.max_remainder.clone())
        }

        pub(crate) fn max_in_operand_range(&self) -> Integer<W, N> {
            self.new_from_big(self.rns.max_operand.clone())
        }

        pub(crate) fn max_in_unreduced_range(&self) -> Integer<W, N> {
            let limbs = vec![big_to_fe(self.rns.max_unreduced_limb.clone()); 4];
            Integer::from_limbs(limbs, Rc::clone(&self.rns))
        }

        pub fn zero(&self) -> Integer<W, N> {
            Integer::from_big(big_uint::zero(), Rc::clone(&self.rns))
        }
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        range_config: RangeConfig,
        main_gate_config: MainGateConfig,
    }

    impl TestCircuitConfig {
        fn new<W: WrongExt, N: FieldExt, const BIT_LEN_LIMB: usize>(
            meta: &mut ConstraintSystem<N>,
        ) -> Self {
            let main_gate_config = MainGate::<N>::configure(meta);

            let overflow_bit_lengths = rns::<W, N, BIT_LEN_LIMB>().overflow_lengths();
            let range_config =
                RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);

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

        fn config_range<N: FieldExt>(
            &self,
            layouter: &mut impl Layouter<N>,
            bit_len_limb: usize,
        ) -> Result<(), Error> {
            let bit_len_lookup = bit_len_limb / NUMBER_OF_LOOKUP_LIMBS;
            let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
            range_chip.load_limb_range_table(layouter)?;
            range_chip.load_overflow_range_tables(layouter)?;

            Ok(())
        }
    }

    macro_rules! impl_circuit {
        ($circuit_name:ident, $( $synth:tt )*) => {


            #[derive(Default, Clone, Debug)]
            struct $circuit_name<W: WrongExt, N: FieldExt, const BIT_LEN_LIMB: usize> {
                rns: Rc<Rns<W, N>>,
            }

            impl<W: WrongExt, N: FieldExt, const BIT_LEN_LIMB: usize> $circuit_name<W, N, BIT_LEN_LIMB> {
                fn integer_chip(&self, config:TestCircuitConfig) -> IntegerChip<W,N>{
                    IntegerChip::<W, N>::new(config.integer_chip_config(), Rc::clone(&self.rns))
                }

                fn tester(&self) -> TestRNS<W,N> {
                    TestRNS {rns:Rc::clone(&self.rns)}
                }

            }

            impl<W: WrongExt, N: FieldExt, const BIT_LEN_LIMB: usize> Circuit<N> for $circuit_name<W, N, BIT_LEN_LIMB> {
                type Config = TestCircuitConfig;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    Self::default()
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
                    integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;
                    // should fail
                    // let a = t.new_from_big(rns.max_remainder.clone() + 1usize);
                    // integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;
                    let a = t.max_in_operand_range();
                    integer_chip.range_assign_integer(ctx, a.into(), Range::Operand)?;
                    // should fail
                    // let a = t.new_from_big(rns.max_operand.clone() + 1usize);
                    // integer_chip.range_assign_integer(ctx, a.into(), Range::Operand)?
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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
                    let overflows = t.rand_with_limb_bit_size(self.rns.bit_len_limb + 5);
                    let unreduced = overflows.clone();
                    let reduced = overflows.reduce();
                    let reduced = reduced.result;
                    let overflows =
                        &integer_chip.assign_integer_no_check(ctx, Some(unreduced).into())?;
                    let reduced_0 = &integer_chip.range_assign_integer(
                        ctx,
                        Some(reduced).into(),
                        Range::Remainder,
                    )?;
                    let reduced_1 = &integer_chip.reduce(ctx, overflows)?;
                    assert_eq!(reduced_1.max_val(), self.rns.max_remainder);
                    integer_chip.assert_equal(ctx, reduced_0, reduced_1)?;
                    integer_chip.assert_strict_equal(ctx, reduced_0, reduced_1)?;
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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
                    let a = &integer_chip.range_assign_integer(ctx, a.into(), Range::Operand)?;
                    let b = &integer_chip.range_assign_integer(ctx, b.into(), Range::Operand)?;
                    integer_chip.assert_not_equal(ctx, a, b)?;
                    integer_chip.assert_equal(ctx, a, a)?;
                    integer_chip.assert_not_zero(ctx, a)?;
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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

                    let a = &integer_chip.range_assign_integer(ctx, a.into(), Range::Operand)?;
                    let b = &integer_chip.range_assign_integer(ctx, b.into(), Range::Operand)?;
                    let c_0 =
                        &integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.mul(ctx, a, b)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    let a = t.rand_in_unreduced_range();
                    let b = t.rand_in_unreduced_range();
                    let c = (a.value() * b.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer_no_check(ctx, a.into())?;
                    let b = &integer_chip.assign_integer_no_check(ctx, b.into())?;
                    let c_0 =
                        &integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.mul(ctx, a, b)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    let a = t.rand_in_unreduced_range();
                    let b = t.rand_in_field();
                    let c = (a.value() * b.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer_no_check(ctx, a.into())?;
                    let c_0 =
                        &integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.mul_constant(ctx, a, &b)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    use rand::thread_rng;
                    let mut rng = thread_rng();
                    let a = W::random(&mut rng);
                    let inv = a.invert().unwrap();

                    let a = t.new_from_big(fe_to_big(a));
                    let inv = t.new_from_big(fe_to_big(inv));

                    let a = &integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;
                    let inv =
                        &integer_chip.range_assign_integer(ctx, inv.into(), Range::Remainder)?;
                    integer_chip.mul_into_one(ctx, a, inv)?;

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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

                    let a = &integer_chip.range_assign_integer(ctx, a.into(), Range::Operand)?;
                    let c_0 =
                        &integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.square(ctx, a)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    let a = t.rand_in_unreduced_range();
                    let c = (a.value() * a.value()) % &self.rns.wrong_modulus;
                    let c = t.new_from_big(c);

                    let a = &integer_chip.assign_integer_no_check(ctx, a.into())?;
                    let c_0 =
                        &integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                    let c_1 = &integer_chip.square(ctx, a)?;
                    assert_eq!(c_1.max_val(), self.rns.max_remainder);

                    integer_chip.assert_equal(ctx, c_0, c_1)?;
                    integer_chip.assert_strict_equal(ctx, c_0, c_1)?;

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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
                    let a = &integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;
                    integer_chip.assert_in_field(ctx, a)?;
                    // must fail
                    // let a = t.new_from_big(rns.wrong_modulus.clone());
                    // let a = &integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;
                    // integer_chip.assert_in_field(ctx, a)?;
                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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
                    let a = &integer_chip.range_assign_integer(
                        ctx,
                        Some(a.clone()).into(),
                        Range::Remainder,
                    )?;
                    let inv_0 = &integer_chip.range_assign_integer(
                        ctx,
                        Some(inv.clone()).into(),
                        Range::Remainder,
                    )?;
                    let (inv_1, cond) = integer_chip.invert(ctx, a)?;
                    integer_chip.assert_equal(ctx, inv_0, &inv_1)?;
                    main_gate.assert_zero(ctx, cond)?;

                    // 1 / 0
                    let zero = integer_chip.assign_integer(ctx, t.zero().into())?;
                    let (must_be_one, cond) = integer_chip.invert(ctx, &zero)?;
                    integer_chip.assert_strict_one(ctx, &must_be_one)?;
                    main_gate.assert_one(ctx, cond)?;

                    // 1 / p
                    let wrong_modulus = t.new_from_limbs(self.rns.wrong_modulus_decomposed.clone());
                    let modulus = integer_chip.assign_integer(ctx, wrong_modulus.into())?;
                    let (must_be_one, cond) = integer_chip.invert(ctx, &modulus)?;
                    integer_chip.assert_strict_one(ctx, &must_be_one)?;
                    main_gate.assert_one(ctx, cond)?;

                    // 1 / a
                    let inv_1 = integer_chip.invert_incomplete(ctx, a)?;
                    integer_chip.assert_equal(ctx, inv_0, &inv_1)?;

                    // must be failing
                    // integer_chip.invert_incomplete(ctx, &zero)?;

                    // a / b
                    let a = t.rand_in_remainder_range();
                    let b = t.rand_in_remainder_range();
                    let c = a.div(&b).unwrap();
                    let a = &integer_chip.range_assign_integer(
                        ctx,
                        Some(a.clone()).into(),
                        Range::Remainder,
                    )?;
                    let b = &integer_chip.range_assign_integer(
                        ctx,
                        Some(b.clone()).into(),
                        Range::Remainder,
                    )?;
                    let c_0 =
                        &integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                    let (c_1, cond) = integer_chip.div(ctx, a, b)?;
                    integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    main_gate.assert_zero(ctx, cond)?;

                    // 0 / b
                    let (c_1, cond) = integer_chip.div(ctx, &zero, b)?;
                    integer_chip.assert_zero(ctx, &c_1)?;
                    main_gate.assert_zero(ctx, cond)?;

                    // p / b
                    let (c_1, cond) = integer_chip.div(ctx, &modulus, b)?;
                    integer_chip.assert_zero(ctx, &c_1)?;
                    main_gate.assert_zero(ctx, cond)?;

                    // a / 0
                    let (must_be_self, cond) = integer_chip.div(ctx, a, &zero)?;
                    integer_chip.assert_equal(ctx, &must_be_self, a)?;
                    main_gate.assert_one(ctx, cond)?;

                    // a / p
                    let (must_be_self, cond) = integer_chip.div(ctx, a, &modulus)?;
                    integer_chip.assert_equal(ctx, &must_be_self, a)?;
                    main_gate.assert_one(ctx, cond)?;

                    // a / b
                    let c_1 = integer_chip.div_incomplete(ctx, a, b)?;
                    integer_chip.assert_equal(ctx, c_0, &c_1)?;

                    // must be failing
                    // integer_chip.div_incomplete(ctx, a, &zero)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, BIT_LEN_LIMB)?;

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
                        // addition in remainder range
                        let a = t.rand_in_remainder_range();
                        let b = t.rand_in_remainder_range();

                        let c = a.value() + b.value();
                        let c = t.new_from_big(c);
                        let c_in_field = (a.value() + b.value()) % &self.rns.wrong_modulus;
                        let c_in_field = t.new_from_big(c_in_field);

                        let a =
                            integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;
                        let b =
                            integer_chip.range_assign_integer(ctx, b.into(), Range::Remainder)?;

                        let c_0 = &integer_chip.add(ctx, &a, &b)?;
                        let c_1 = integer_chip.assign_integer_no_check(ctx, c.into())?;

                        assert_eq!(a.max_val() + b.max_val(), c_0.max_val());

                        integer_chip.assert_equal(ctx, c_0, &c_1)?;

                        // reduce and enfoce strict equality
                        let c_0 = integer_chip.reduce(ctx, c_0)?;
                        let c_1 = integer_chip.range_assign_integer(
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

                        let a =
                            integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;

                        let c_0 = &integer_chip.add_constant(ctx, &a, &b)?;
                        let c_1 = integer_chip.assign_integer_no_check(ctx, c.into())?;
                        assert_eq!(a.max_val() + b.value(), c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;

                        // reduce and enfoce strict equality
                        let c_0 = integer_chip.reduce(ctx, c_0)?;
                        let c_1 = integer_chip.range_assign_integer(
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
                        let mut a = integer_chip.assign_integer(ctx, a.into())?;

                        for _ in 0..10 {
                            let c =
                                (a.integer().unwrap().value() * 2usize) % &self.rns.wrong_modulus;
                            let c = t.new_from_big(c);
                            a = integer_chip.add(ctx, &a, &a)?;
                            let c_1 = integer_chip.range_assign_integer(
                                ctx,
                                c.into(),
                                Range::Remainder,
                            )?;
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

                            let a = integer_chip.assign_integer_no_check(ctx, a.into())?;
                            let b = integer_chip.assign_integer_no_check(ctx, b.into())?;
                            let c_0 = &integer_chip.add(ctx, &a, &b)?;
                            let c_1 = integer_chip.range_assign_integer(
                                ctx,
                                c.into(),
                                Range::Remainder,
                            )?;
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

                        let a =
                            integer_chip.range_assign_integer(ctx, a.into(), Range::Remainder)?;
                        let b =
                            integer_chip.range_assign_integer(ctx, b.into(), Range::Remainder)?;
                        let aux = b.make_aux();

                        let c_0 = &integer_chip.sub(ctx, &a, &b)?;
                        let c_1 =
                            integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
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

                        let a = integer_chip.assign_integer_no_check(ctx, a.into())?;
                        let b = integer_chip.assign_integer_no_check(ctx, b.into())?;
                        let aux = b.make_aux();

                        let c_0 = &integer_chip.sub(ctx, &a, &b)?;
                        let c_1 =
                            integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(a.max_val() + aux.value(), c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    {
                        // go beyond unreduced range
                        let a = t.rand_in_remainder_range();
                        let mut a = integer_chip.assign_integer(ctx, a.into())?;

                        for _ in 0..10 {
                            let b = t.rand_in_unreduced_range();

                            let a_norm = (a.integer().unwrap().value()
                                % self.rns.wrong_modulus.clone())
                                + self.rns.wrong_modulus.clone();
                            let b_norm = b.value() % self.rns.wrong_modulus.clone();
                            let c = (a_norm - b_norm) % self.rns.wrong_modulus.clone();
                            let c = t.new_from_big(c);

                            let b = integer_chip.assign_integer_no_check(ctx, b.into())?;

                            let c_0 = &integer_chip.sub(ctx, &a, &b)?;
                            let c_1 = integer_chip.range_assign_integer(
                                ctx,
                                c.into(),
                                Range::Remainder,
                            )?;
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

                        let a = integer_chip.assign_integer_no_check(ctx, a.into())?;
                        let aux = a.make_aux();

                        let c_0 = &integer_chip.neg(ctx, &a)?;
                        let c_1 =
                            integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(aux.value(), c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    {
                        // mul2 in unreduced range
                        let a = t.rand_in_unreduced_range();
                        let c = (a.value() * 2usize) % self.rns.wrong_modulus.clone();
                        let c = t.new_from_big(c);

                        let a = integer_chip.assign_integer_no_check(ctx, a.into())?;

                        let c_0 = &integer_chip.mul2(ctx, &a)?;
                        let c_1 =
                            integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(a.max_val() * 2usize, c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    {
                        // mul3 in unreduced range
                        let a = t.rand_in_unreduced_range();
                        let c = (a.value() * 3usize) % self.rns.wrong_modulus.clone();
                        let c = t.new_from_big(c);

                        let a = integer_chip.assign_integer_no_check(ctx, a.into())?;
                        let c_0 = &integer_chip.mul3(ctx, &a)?;
                        let c_1 =
                            integer_chip.range_assign_integer(ctx, c.into(), Range::Remainder)?;
                        assert_eq!(a.max_val() * 3usize, c_0.max_val());
                        integer_chip.assert_equal(ctx, c_0, &c_1)?;
                    }

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(ctx, a, Range::Remainder)?;
                    let b = integer_chip.range_assign_integer(ctx, b, Range::Remainder)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, &cond)?.into();
                    let selected = integer_chip.select(ctx, &a, &b, &cond)?;
                    integer_chip.assert_equal(ctx, &b, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &b, &selected)?;
                    assert_eq!(b.max_val(), selected.max_val());

                    // select first operand when condision is one

                    let a = t.rand_in_remainder_range().into();
                    let b = t.rand_in_remainder_range().into();
                    let cond = N::one();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(ctx, a, Range::Remainder)?;
                    let b = integer_chip.range_assign_integer(ctx, b, Range::Remainder)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, &cond)?.into();
                    let selected = integer_chip.select(ctx, &a, &b, &cond)?;
                    integer_chip.assert_equal(ctx, &a, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &a, &selected)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select constant operand when condision is zero

                    let a = t.rand_in_remainder_range().into();
                    let b = t.rand_in_remainder_range();
                    let cond = N::zero();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(ctx, a, Range::Remainder)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, &cond)?.into();
                    let selected = integer_chip.select_or_assign(ctx, &a, &b, &cond)?;
                    let b_assigned = integer_chip.assign_integer(ctx, b.into())?;
                    integer_chip.assert_equal(ctx, &b_assigned, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &b_assigned, &selected)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select non constant operand when condision is zero

                    let a = t.rand_in_remainder_range().into();
                    let b = t.rand_in_remainder_range();
                    let cond = N::one();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(ctx, a, Range::Remainder)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(ctx, &cond)?.into();
                    let selected = integer_chip.select_or_assign(ctx, &a, &b, &cond)?;
                    integer_chip.assert_equal(ctx, &a, &selected)?;
                    integer_chip.assert_strict_equal(ctx, &a, &selected)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    Ok(())
                },
            )?;
            config.config_range(&mut layouter, BIT_LEN_LIMB)
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
                        let assigned = integer_chip.range_assign_integer(
                            ctx,
                            integer.into(),
                            Range::Remainder,
                        )?;
                        let decomposed = integer_chip.decompose(ctx, &assigned)?;
                        let expected =
                            decompose_big::<W>(integer_big, self.rns.bit_len_wrong_modulus, 1);
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
            config.config_range(&mut layouter, BIT_LEN_LIMB)
        }
    );

    macro_rules! test_circuit_runner {
        (
            $circuit:ident, $([$wrong_field:ident, $native_field:ident, $bit_len_limb:expr]),*
        ) => {
            $(
                let (rns, k) = setup::<_, _, $bit_len_limb>();
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
            #[cfg(not(feature = "kzg"))]
            {
                use halo2::pasta::{Fp as Pasta_Fp, Fq as Pasta_Fq};
                test_circuit_runner!(
                    $circuit,
                    [Pasta_Fp, Pasta_Fq, 68],
                    [Pasta_Fq, Pasta_Fp, 68],
                    [Secp256k1_Fp, Pasta_Fq, 68],
                    [Secp256k1_Fp, Pasta_Fp, 68],
                    [Secp256k1_Fq, Pasta_Fq, 68],
                    [Secp256k1_Fq, Pasta_Fp, 68]
                );
            }
            #[cfg(feature = "kzg")]
            {
                use halo2::pairing::bn256::{Fq, Fr};
                test_circuit_runner!(
                    $circuit,
                    [Fq, Fr, 68],
                    [Fr, Fr, 68],
                    [Secp256k1_Fp, Fr, 68],
                    [Secp256k1_Fq, Fr, 68]
                );
            }
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
}
