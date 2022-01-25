use super::{AssignedInteger, AssignedLimb, UnassignedInteger};
use crate::rns::{Common, Integer, Rns};
use crate::{WrongExt, NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::main_gate::five::main_gate::{MainGate, MainGateConfig};
use halo2arith::main_gate::five::range::{RangeChip, RangeConfig};
use halo2arith::{halo2, AssignedCondition, AssignedValue, MainGateInstructions};

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
    rns: Rns<W, N>,
}

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn new_assigned_integer(&self, limbs: Vec<AssignedLimb<N>>, native_value: AssignedValue<N>) -> AssignedInteger<N> {
        AssignedInteger::new(limbs, native_value, self.rns.bit_len_limb)
    }
}

pub trait IntegerInstructions<W: WrongExt, N: FieldExt> {
    fn assign_integer(&self, region: &mut Region<'_, N>, integer: UnassignedInteger<W, N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn assign_constant(&self, region: &mut Region<'_, N>, integer: W, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn range_assign_integer(
        &self,
        region: &mut Region<'_, N>,
        integer: UnassignedInteger<W, N>,
        range: Range,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;
    fn decompose(&self, region: &mut Region<'_, N>, integer: &AssignedInteger<N>, offset: &mut usize) -> Result<Vec<AssignedCondition<N>>, Error>;

    fn add(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn add_constant(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &Integer<W, N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn mul2(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn mul3(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn sub(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn sub_sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b_0: &AssignedInteger<N>,
        b_1: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;
    fn neg(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn mul(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn mul_constant(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &Integer<W, N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn mul_into_one(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn square(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn div(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error>;
    fn div_incomplete(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;
    fn invert(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error>;
    fn invert_incomplete(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn assert_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_strict_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_not_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_not_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_strict_one(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_strict_bit(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_in_field(&self, region: &mut Region<'_, N>, input: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn select(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;
    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &Integer<W, N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;
}

impl<W: WrongExt, N: FieldExt> IntegerInstructions<W, N> for IntegerChip<W, N> {
    fn range_assign_integer(
        &self,
        region: &mut Region<'_, N>,
        integer: UnassignedInteger<W, N>,
        range: Range,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        self._range_assign_integer(region, integer, range, offset)
    }

    fn assign_integer(&self, region: &mut Region<'_, N>, integer: UnassignedInteger<W, N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._assign_integer(region, integer, offset, true)
    }

    fn assign_constant(&self, region: &mut Region<'_, N>, integer: W, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._assign_constant(region, integer, offset)
    }

    fn decompose(&self, region: &mut Region<'_, N>, integer: &AssignedInteger<N>, offset: &mut usize) -> Result<Vec<AssignedCondition<N>>, Error> {
        self.assert_in_field(region, integer, offset)?;

        let main_gate = self.main_gate();

        let mut decomposed = Vec::new();
        for idx in 0..NUMBER_OF_LIMBS {
            let number_of_bits = if idx == NUMBER_OF_LIMBS - 1 {
                self.rns.bit_len_last_limb
            } else {
                self.rns.bit_len_limb
            };
            let decomposed_limb = main_gate.decompose(region, integer.limb(idx), number_of_bits, offset)?;
            decomposed.extend(decomposed_limb);
        }

        assert_eq!(decomposed.len(), self.rns.bit_len_wrong_modulus);

        Ok(decomposed)
    }

    fn add(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_unreduced(region, a, offset)?,
            &self.reduce_if_limb_values_exceeds_unreduced(region, b, offset)?,
        );
        self._add(region, a, b, offset)
    }

    fn add_constant(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &Integer<W, N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_unreduced(region, a, offset)?;
        self._add_constant(region, a, b, offset)
    }

    fn mul2(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._mul2(region, a, offset)
    }

    fn mul3(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._mul3(region, a, offset)
    }

    fn sub(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_unreduced(region, a, offset)?,
            &self.reduce_if_limb_values_exceeds_unreduced(region, b, offset)?,
        );
        self._sub(region, a, b, offset)
    }

    fn sub_sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b_0: &AssignedInteger<N>,
        b_1: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let (a, b_0, b_1) = (
            &self.reduce_if_limb_values_exceeds_unreduced(region, a, offset)?,
            &self.reduce_if_limb_values_exceeds_unreduced(region, b_0, offset)?,
            &self.reduce_if_limb_values_exceeds_unreduced(region, b_1, offset)?,
        );
        self._sub_sub(region, a, b_0, b_1, offset)
    }

    fn neg(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_unreduced(region, a, offset)?;
        self._neg(region, a, offset)
    }

    fn mul(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?,
            &self.reduce_if_limb_values_exceeds_reduced(region, b, offset)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(region, a, offset)?,
            &self.reduce_if_max_operand_value_exceeds(region, b, offset)?,
        );
        self._mul(region, a, b, offset)
    }

    fn mul_constant(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &Integer<W, N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?;
        let a = &self.reduce_if_max_operand_value_exceeds(region, a, offset)?;
        self._mul_constant(region, a, b, offset)
    }

    fn mul_into_one(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?,
            &self.reduce_if_limb_values_exceeds_reduced(region, b, offset)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(region, a, offset)?,
            &self.reduce_if_max_operand_value_exceeds(region, b, offset)?,
        );
        self._mul_into_one(region, a, b, offset)
    }

    fn square(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?;
        let a = &self.reduce_if_max_operand_value_exceeds(region, a, offset)?;
        self._square(region, a, offset)
    }

    fn div(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?,
            &self.reduce_if_limb_values_exceeds_reduced(region, b, offset)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(region, a, offset)?,
            &self.reduce_if_max_operand_value_exceeds(region, b, offset)?,
        );
        self._div(region, a, b, offset)
    }

    fn div_incomplete(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let (a, b) = (
            &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?,
            &self.reduce_if_limb_values_exceeds_reduced(region, b, offset)?,
        );
        let (a, b) = (
            &self.reduce_if_max_operand_value_exceeds(region, a, offset)?,
            &self.reduce_if_max_operand_value_exceeds(region, b, offset)?,
        );
        self._div_incomplete(region, a, b, offset)
    }

    fn invert(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?;
        let a = &self.reduce_if_max_operand_value_exceeds(region, a, offset)?;
        self._invert(region, a, offset)
    }

    fn invert_incomplete(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?;
        let a = &self.reduce_if_max_operand_value_exceeds(region, a, offset)?;
        self._invert_incomplete(region, a, offset)
    }

    fn reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._reduce(region, a, offset)
    }

    fn assert_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let c = &self.sub(region, a, b, offset)?;
        self.assert_zero(region, c, offset)?;
        Ok(())
    }

    fn assert_strict_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for idx in 0..NUMBER_OF_LIMBS {
            main_gate.assert_equal(region, a.limb(idx), b.limb(idx), offset)?;
        }
        Ok(())
    }

    fn assert_not_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let c = &self.sub(region, a, b, offset)?;
        self.assert_not_zero(region, c, offset)?;
        Ok(())
    }

    fn assert_not_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?;
        let a = &self.reduce_if_max_operand_value_exceeds(region, a, offset)?;
        self._assert_not_zero(region, a, offset)?;
        Ok(())
    }

    fn assert_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let a = &self.reduce_if_max_operand_value_exceeds(region, a, offset)?;
        self._assert_zero(region, a, offset)
    }

    fn assert_strict_one(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.assert_zero(region, a.limb(i), offset)?;
        }
        main_gate.assert_one(region, a.limb(0), offset)
    }

    fn assert_strict_bit(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.assert_zero(region, a.limb(i), offset)?;
        }
        main_gate.assert_bit(region, a.limb(0), offset)
    }

    fn select(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let res = main_gate.select(region, a.limb(i), b.limb(i), cond, offset)?;

            let max_val = if a.limbs[i].max_val > b.limbs[i].max_val {
                a.limbs[i].max_val.clone()
            } else {
                b.limbs[i].max_val.clone()
            };

            limbs.push(AssignedLimb::from(res, max_val));
        }

        let native_value = main_gate.select(region, a.native(), b.native(), cond, offset)?;

        Ok(self.new_assigned_integer(limbs, native_value))
    }

    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &Integer<W, N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let b_limb = b.limb(i);

            let res = main_gate.select_or_assign(region, a.limb(i), b_limb.fe(), cond, offset)?;

            // here we assume given constant is always in field
            let max_val = a.limb(i).max_val();
            limbs.push(AssignedLimb::from(res, max_val));
        }

        let native_value = main_gate.select_or_assign(region, a.native(), b.native(), cond, offset)?;

        Ok(self.new_assigned_integer(limbs, native_value))
    }

    fn assert_in_field(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let a = &self.reduce_if_limb_values_exceeds_reduced(region, a, offset)?;
        let a = &self.reduce_if_max_operand_value_exceeds(region, a, offset)?;
        self._assert_in_field(region, a, offset)
    }
}

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub fn new(config: IntegerConfig, rns: Rns<W, N>) -> Self {
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
    use crate::circuit::{AssignedInteger, UnassignedInteger};
    use crate::rns::{Common, Integer, Rns};
    use crate::{WrongExt, NUMBER_OF_LOOKUP_LIMBS};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, Region, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use halo2arith::main_gate::five::main_gate::{MainGate, MainGateConfig};
    use halo2arith::main_gate::five::range::{RangeChip, RangeConfig, RangeInstructions};
    use halo2arith::main_gate::MainGateInstructions;
    use halo2arith::utils::fe_to_big;
    use halo2arith::{decompose_big, halo2, AssignedCondition};

    cfg_if::cfg_if! {
      if #[cfg(feature = "kzg")] {
        use halo2::pairing::bn256::Fq as Wrong;
        use halo2::pairing::bn256::Fr as Native;
      } else {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;
      }
    }

    impl<'a, W: WrongExt, N: FieldExt> From<Integer<'a, W, N>> for UnassignedInteger<'a, W, N> {
        fn from(integer: Integer<'a, W, N>) -> Self {
            UnassignedInteger(Some(integer))
        }
    }

    impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
        fn assign_integer_no_check(
            &self,
            region: &mut Region<'_, N>,
            integer: UnassignedInteger<W, N>,
            offset: &mut usize,
        ) -> Result<AssignedInteger<N>, Error> {
            self._assign_integer(region, integer, offset, false)
        }
    }
    const BIT_LEN_LIMB: usize = 68;

    fn rns<W: WrongExt, N: FieldExt>() -> Rns<W, N> {
        Rns::<W, N>::construct(BIT_LEN_LIMB)
    }

    fn setup<W: WrongExt, N: FieldExt>() -> (Rns<W, N>, u32) {
        let rns = rns();
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        (rns, k)
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        range_config: RangeConfig,
        main_gate_config: MainGateConfig,
    }

    impl TestCircuitConfig {
        fn new<W: WrongExt, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
            let main_gate_config = MainGate::<N>::configure(meta);

            let overflow_bit_lengths = rns::<W, N>().overflow_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);

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
            let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
            let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
            range_chip.load_limb_range_table(layouter)?;
            range_chip.load_overflow_range_tables(layouter)?;

            Ok(())
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitRange<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitRange<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = rns.new_from_big(rns.max_remainder.clone());
                    integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;

                    // should fail
                    // let a = rns.new_from_big(rns.max_remainder.clone() + 1usize);
                    // integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;

                    let a = rns.new_from_big(rns.max_operand.clone());
                    integer_chip.range_assign_integer(&mut region, a.into(), Range::Operand, offset)?;

                    // should fail
                    // let a = rns.new_from_big(rns.max_operand.clone() + 1usize);
                    // integer_chip.range_assign_integer(&mut region, a.into(), Range::Operand, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_circuit_range() {
        let (rns, k) = setup();
        let circuit = TestCircuitRange::<Wrong, Native> { rns };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitReduction<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitReduction<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let overflows = rns.rand_with_limb_bit_size(rns.bit_len_limb + 5);
                    let unreduced = overflows.clone();
                    let reduced = overflows.reduce();
                    let reduced = reduced.result;

                    let overflows = &integer_chip.assign_integer_no_check(&mut region, Some(unreduced).into(), offset)?;
                    let reduced_0 = &integer_chip.range_assign_integer(&mut region, Some(reduced).into(), Range::Remainder, offset)?;
                    let reduced_1 = &integer_chip.reduce(&mut region, overflows, offset)?;
                    assert_eq!(reduced_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, reduced_0, reduced_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, reduced_0, reduced_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_reduction_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitReduction::<Wrong, Native> { rns };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitEquality<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitEquality<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = rns.rand_in_operand_range();
                    let b = rns.rand_in_operand_range();
                    let a = &integer_chip.range_assign_integer(&mut region, a.into(), Range::Operand, offset)?;
                    let b = &integer_chip.range_assign_integer(&mut region, b.into(), Range::Operand, offset)?;
                    integer_chip.assert_not_equal(&mut region, a, b, offset)?;
                    integer_chip.assert_equal(&mut region, a, a, offset)?;
                    integer_chip.assert_not_zero(&mut region, a, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_equality_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitReduction::<Wrong, Native> { rns };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitMultiplication<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitMultiplication<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = rns.rand_in_operand_range();
                    let b = rns.rand_in_operand_range();
                    let c = (a.value() * b.value()) % &rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a = &integer_chip.range_assign_integer(&mut region, a.into(), Range::Operand, offset)?;
                    let b = &integer_chip.range_assign_integer(&mut region, b.into(), Range::Operand, offset)?;
                    let c_0 = &integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                    let c_1 = &integer_chip.mul(&mut region, a, b, offset)?;
                    assert_eq!(c_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, c_0, c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, c_0, c_1, offset)?;

                    let a = rns.rand_in_unreduced_range();
                    let b = rns.rand_in_unreduced_range();
                    let c = (a.value() * b.value()) % &rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a = &integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;
                    let b = &integer_chip.assign_integer_no_check(&mut region, b.into(), offset)?;
                    let c_0 = &integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                    let c_1 = &integer_chip.mul(&mut region, a, b, offset)?;
                    assert_eq!(c_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, c_0, c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, c_0, c_1, offset)?;

                    let a = rns.rand_in_unreduced_range();
                    let b = rns.rand_in_field();
                    let c = (a.value() * b.value()) % &rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a = &integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;
                    let c_0 = &integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                    let c_1 = &integer_chip.mul_constant(&mut region, a, &b, offset)?;
                    assert_eq!(c_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, c_0, c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, c_0, c_1, offset)?;

                    use rand::thread_rng;
                    let mut rng = thread_rng();
                    let a = W::random(&mut rng);
                    let inv = a.invert().unwrap();

                    // will fail
                    // let inv = W::rand();

                    let a = fe_to_big(a);
                    let inv = fe_to_big(inv);
                    let a = rns.new_from_big(a);
                    let inv = rns.new_from_big(inv);

                    let a = &integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;
                    let inv = &integer_chip.range_assign_integer(&mut region, inv.into(), Range::Remainder, offset)?;
                    integer_chip.mul_into_one(&mut region, a, inv, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_multiplication_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitMultiplication::<Wrong, Native> { rns };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitSquaring<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitSquaring<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = rns.rand_in_operand_range();
                    let c = (a.value() * a.value()) % &rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a = &integer_chip.range_assign_integer(&mut region, a.into(), Range::Operand, offset)?;
                    let c_0 = &integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                    let c_1 = &integer_chip.square(&mut region, a, offset)?;
                    assert_eq!(c_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, c_0, c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, c_0, c_1, offset)?;

                    let a = rns.rand_in_unreduced_range();
                    let c = (a.value() * a.value()) % &rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a = &integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;
                    let c_0 = &integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                    let c_1 = &integer_chip.square(&mut region, a, offset)?;
                    assert_eq!(c_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, c_0, c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, c_0, c_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_squaring_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitSquaring::<Wrong, Native> { rns };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitInField<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitInField<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let a = rns.rand_in_field();
                    let a = &integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;
                    integer_chip.assert_in_field(&mut region, a, offset)?;

                    // must fail
                    // let a = rns.new_from_big(rns.wrong_modulus.clone());
                    // let a = &integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;
                    // integer_chip.assert_in_field(&mut region, a, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_assert_in_field_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitInField::<Wrong, Native> { rns };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitNonDeterministic<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitNonDeterministic<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let a = rns.rand_in_remainder_range();
                    let inv = a.invert().unwrap();

                    // 1 / a
                    let a = &integer_chip.range_assign_integer(&mut region, Some(a.clone()).into(), Range::Remainder, offset)?;
                    let inv_0 = &integer_chip.range_assign_integer(&mut region, Some(inv.clone()).into(), Range::Remainder, offset)?;
                    let (inv_1, cond) = integer_chip.invert(&mut region, a, offset)?;
                    integer_chip.assert_equal(&mut region, inv_0, &inv_1, offset)?;
                    main_gate.assert_zero(&mut region, cond, offset)?;

                    // 1 / 0
                    let zero = integer_chip.assign_integer(&mut region, rns.zero().into(), offset)?;
                    let (must_be_one, cond) = integer_chip.invert(&mut region, &zero, offset)?;
                    integer_chip.assert_strict_one(&mut region, &must_be_one, offset)?;
                    main_gate.assert_one(&mut region, cond, offset)?;

                    // 1 / p
                    let wrong_modulus = rns.new_from_limbs(rns.wrong_modulus_decomposed.clone());
                    let modulus = integer_chip.assign_integer(&mut region, wrong_modulus.into(), offset)?;
                    let (must_be_one, cond) = integer_chip.invert(&mut region, &modulus, offset)?;
                    integer_chip.assert_strict_one(&mut region, &must_be_one, offset)?;
                    main_gate.assert_one(&mut region, cond, offset)?;

                    // 1 / a
                    let inv_1 = integer_chip.invert_incomplete(&mut region, a, offset)?;
                    integer_chip.assert_equal(&mut region, inv_0, &inv_1, offset)?;

                    // must be failing
                    // integer_chip.invert_incomplete(&mut region, &zero, offset)?;

                    // a / b
                    let a = rns.rand_in_remainder_range();
                    let b = rns.rand_in_remainder_range();
                    let c = a.div(&b).unwrap();
                    let a = &integer_chip.range_assign_integer(&mut region, Some(a.clone()).into(), Range::Remainder, offset)?;
                    let b = &integer_chip.range_assign_integer(&mut region, Some(b.clone()).into(), Range::Remainder, offset)?;
                    let c_0 = &integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                    let (c_1, cond) = integer_chip.div(&mut region, a, b, offset)?;
                    integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;
                    main_gate.assert_zero(&mut region, cond, offset)?;

                    // 0 / b
                    let (c_1, cond) = integer_chip.div(&mut region, &zero, b, offset)?;
                    integer_chip.assert_zero(&mut region, &c_1, offset)?;
                    main_gate.assert_zero(&mut region, cond, offset)?;

                    // p / b
                    let (c_1, cond) = integer_chip.div(&mut region, &modulus, b, offset)?;
                    integer_chip.assert_zero(&mut region, &c_1, offset)?;
                    main_gate.assert_zero(&mut region, cond, offset)?;

                    // a / 0
                    let (must_be_self, cond) = integer_chip.div(&mut region, a, &zero, offset)?;
                    integer_chip.assert_equal(&mut region, &must_be_self, a, offset)?;
                    main_gate.assert_one(&mut region, cond, offset)?;

                    // a / p
                    let (must_be_self, cond) = integer_chip.div(&mut region, a, &modulus, offset)?;
                    integer_chip.assert_equal(&mut region, &must_be_self, a, offset)?;
                    main_gate.assert_one(&mut region, cond, offset)?;

                    // a / b
                    let c_1 = integer_chip.div_incomplete(&mut region, a, b, offset)?;
                    integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;

                    // must be failing
                    // integer_chip.div_incomplete(&mut region, a, &zero, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_non_deterministic_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitNonDeterministic::<Wrong, Native> { rns };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitAddition<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitAddition<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    {
                        // addition in remainder range
                        let a = rns.rand_in_remainder_range();
                        let b = rns.rand_in_remainder_range();

                        let c = a.value() + b.value();
                        let c = rns.new_from_big(c);
                        let c_in_field = (a.value() + b.value()) % &self.rns.wrong_modulus;
                        let c_in_field = rns.new_from_big(c_in_field);

                        let a = integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;
                        let b = integer_chip.range_assign_integer(&mut region, b.into(), Range::Remainder, offset)?;

                        let c_0 = &integer_chip.add(&mut region, &a, &b, offset)?;
                        let c_1 = integer_chip.assign_integer_no_check(&mut region, c.into(), offset)?;

                        assert_eq!(a.max_val() + b.max_val(), c_0.max_val());
                        integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;

                        // reduce and enfoce strict equality
                        let c_0 = integer_chip.reduce(&mut region, c_0, offset)?;
                        let c_1 = integer_chip.range_assign_integer(&mut region, c_in_field.into(), Range::Remainder, offset)?;
                        integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;
                        integer_chip.assert_strict_equal(&mut region, &c_0, &c_1, offset)?;
                    }

                    {
                        // constant addition in remainder range
                        let a = rns.rand_in_remainder_range();
                        let b = rns.rand_in_field();

                        let c = a.value() + b.value();
                        let c = rns.new_from_big(c);
                        let c_in_field = (a.value() + b.value()) % &self.rns.wrong_modulus;
                        let c_in_field = rns.new_from_big(c_in_field);

                        let a = integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;

                        let c_0 = &integer_chip.add_constant(&mut region, &a, &b, offset)?;
                        let c_1 = integer_chip.assign_integer_no_check(&mut region, c.into(), offset)?;
                        assert_eq!(a.max_val() + b.value(), c_0.max_val());
                        integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;

                        // reduce and enfoce strict equality
                        let c_0 = integer_chip.reduce(&mut region, c_0, offset)?;
                        let c_1 = integer_chip.range_assign_integer(&mut region, c_in_field.into(), Range::Remainder, offset)?;
                        integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;
                        integer_chip.assert_strict_equal(&mut region, &c_0, &c_1, offset)?;
                    }

                    {
                        // go beyond unreduced range
                        let a = rns.rand_in_remainder_range();
                        let mut a = integer_chip.assign_integer(&mut region, a.into(), offset)?;

                        for _ in 0..10 {
                            let c = (rns.to_integer(&a).unwrap().value() * 2usize) % &self.rns.wrong_modulus;
                            let c = rns.new_from_big(c);
                            a = integer_chip.add(&mut region, &a, &a, offset)?;
                            let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                            let c_0 = integer_chip.reduce(&mut region, &a, offset)?;
                            integer_chip.assert_equal(&mut region, &a, &c_1, offset)?;
                            integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;
                            integer_chip.assert_strict_equal(&mut region, &c_0, &c_1, offset)?;
                        }
                    }

                    {
                        // addition in unreduced range
                        for _ in 0..10 {
                            let a = rns.rand_in_unreduced_range();
                            let b = rns.rand_in_unreduced_range();
                            let c = (a.value() + b.value()) % rns.wrong_modulus.clone();
                            let c = rns.new_from_big(c);

                            let a = integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;
                            let b = integer_chip.assign_integer_no_check(&mut region, b.into(), offset)?;
                            let c_0 = &integer_chip.add(&mut region, &a, &b, offset)?;
                            let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                            assert_eq!(a.max_val() + b.max_val(), c_0.max_val());
                            integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;

                            // reduce and enfoce strict equality
                            let c_0 = integer_chip.reduce(&mut region, c_0, offset)?;
                            integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;
                            integer_chip.assert_strict_equal(&mut region, &c_0, &c_1, offset)?;
                        }
                    }

                    {
                        // subtraction in remainder range
                        let a = rns.rand_in_remainder_range();
                        let b = rns.rand_in_remainder_range();

                        let a_norm = (a.value() % rns.wrong_modulus.clone()) + rns.wrong_modulus.clone();
                        let b_norm = b.value() % rns.wrong_modulus.clone();
                        let c = (a_norm - b_norm) % rns.wrong_modulus.clone();
                        let c = rns.new_from_big(c);

                        let a = integer_chip.range_assign_integer(&mut region, a.into(), Range::Remainder, offset)?;
                        let b = integer_chip.range_assign_integer(&mut region, b.into(), Range::Remainder, offset)?;

                        let c_0 = &integer_chip.sub(&mut region, &a, &b, offset)?;
                        let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                        assert_eq!(a.max_val() + rns.make_aux(b.max_vals()).value(), c_0.max_val());
                        integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;
                    }

                    {
                        // subtraction in unreduced range
                        let a = rns.rand_in_unreduced_range();
                        let b = rns.rand_in_unreduced_range();

                        let a_norm = (a.value() % rns.wrong_modulus.clone()) + rns.wrong_modulus.clone();
                        let b_norm = b.value() % rns.wrong_modulus.clone();
                        let c = (a_norm - b_norm) % rns.wrong_modulus.clone();
                        let c = rns.new_from_big(c);

                        let a = integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;
                        let b = integer_chip.assign_integer_no_check(&mut region, b.into(), offset)?;

                        let c_0 = &integer_chip.sub(&mut region, &a, &b, offset)?;
                        let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                        assert_eq!(a.max_val() + rns.make_aux(b.max_vals()).value(), c_0.max_val());
                        integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;
                    }

                    {
                        // go beyond unreduced range
                        let a = rns.rand_in_remainder_range();
                        let mut a = integer_chip.assign_integer(&mut region, a.into(), offset)?;

                        for _ in 0..10 {
                            let b = rns.rand_in_unreduced_range();

                            let a_norm = (rns.to_integer(&a).unwrap().value() % rns.wrong_modulus.clone()) + rns.wrong_modulus.clone();
                            let b_norm = b.value() % rns.wrong_modulus.clone();
                            let c = (a_norm - b_norm) % rns.wrong_modulus.clone();
                            let c = rns.new_from_big(c);

                            let b = integer_chip.assign_integer_no_check(&mut region, b.into(), offset)?;

                            let c_0 = &integer_chip.sub(&mut region, &a, &b, offset)?;
                            let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                            integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;
                            a = c_0.clone();
                        }
                    }

                    {
                        // negation in unreduced range
                        let a = rns.rand_in_unreduced_range();
                        let a_norm = a.value() % rns.wrong_modulus.clone();
                        let c = rns.wrong_modulus.clone() - a_norm;
                        let c = rns.new_from_big(c);

                        let a = integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;

                        let c_0 = &integer_chip.neg(&mut region, &a, offset)?;
                        let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                        assert_eq!(rns.make_aux(a.max_vals()).value(), c_0.max_val());
                        integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;
                    }

                    {
                        // mul2 in unreduced range
                        let a = rns.rand_in_unreduced_range();
                        let c = (a.value() * 2usize) % rns.wrong_modulus.clone();
                        let c = rns.new_from_big(c);

                        let a = integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;

                        let c_0 = &integer_chip.mul2(&mut region, &a, offset)?;
                        let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                        assert_eq!(a.max_val() * 2usize, c_0.max_val());
                        integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;
                    }

                    {
                        // mul3 in unreduced range
                        let a = rns.rand_in_unreduced_range();
                        let c = (a.value() * 3usize) % rns.wrong_modulus.clone();
                        let c = rns.new_from_big(c);

                        let a = integer_chip.assign_integer_no_check(&mut region, a.into(), offset)?;
                        let c_0 = &integer_chip.mul3(&mut region, &a, offset)?;
                        let c_1 = integer_chip.range_assign_integer(&mut region, c.into(), Range::Remainder, offset)?;
                        assert_eq!(a.max_val() * 3usize, c_0.max_val());
                        integer_chip.assert_equal(&mut region, c_0, &c_1, offset)?;
                    }

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_addition() {
        let (rns, k) = setup();
        let circuit = TestCircuitAddition::<Wrong, Native> { rns };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitConditionals<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitConditionals<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    // select second operand when condision is zero

                    let a = rns.rand_in_remainder_range().into();
                    let b = rns.rand_in_remainder_range().into();
                    let cond = N::zero();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let b = integer_chip.range_assign_integer(&mut region, b, Range::Remainder, offset)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, offset)?.into();
                    let selected = integer_chip.select(&mut region, &a, &b, &cond, offset)?;
                    integer_chip.assert_equal(&mut region, &b, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &b, &selected, offset)?;
                    assert_eq!(b.max_val(), selected.max_val());

                    // select first operand when condision is one

                    let a = rns.rand_in_remainder_range().into();
                    let b = rns.rand_in_remainder_range().into();
                    let cond = N::one();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let b = integer_chip.range_assign_integer(&mut region, b, Range::Remainder, offset)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, offset)?.into();
                    let selected = integer_chip.select(&mut region, &a, &b, &cond, offset)?;
                    integer_chip.assert_equal(&mut region, &a, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &a, &selected, offset)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select constant operand when condision is zero

                    let a = rns.rand_in_remainder_range().into();
                    let b = rns.rand_in_remainder_range();
                    let cond = N::zero();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, offset)?.into();
                    let selected = integer_chip.select_or_assign(&mut region, &a, &b, &cond, offset)?;
                    let b_assigned = integer_chip.assign_integer(&mut region, b.into(), offset)?;
                    integer_chip.assert_equal(&mut region, &b_assigned, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &b_assigned, &selected, offset)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select non constant operand when condision is zero

                    let a = rns.rand_in_remainder_range().into();
                    let b = rns.rand_in_remainder_range();
                    let cond = N::one();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, offset)?.into();
                    let selected = integer_chip.select_or_assign(&mut region, &a, &b, &cond, offset)?;
                    integer_chip.assert_equal(&mut region, &a, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &a, &selected, offset)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_condition_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitConditionals::<Wrong, Native> { rns };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitDecomposition<W: WrongExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: WrongExt, N: FieldExt> Circuit<N> for TestCircuitDecomposition<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_chip_config(), self.rns.clone());
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer = rns.rand_in_field();
                    let integer_big = integer.value();
                    let assigned = integer_chip.range_assign_integer(&mut region, integer.into(), Range::Remainder, offset)?;
                    let decomposed = integer_chip.decompose(&mut region, &assigned, offset)?;
                    let expected = decompose_big::<W>(integer_big, rns.bit_len_wrong_modulus, 1);
                    assert_eq!(expected.len(), decomposed.len());
                    for (c, expected) in decomposed.iter().zip(expected.into_iter()) {
                        if expected != W::zero() {
                            main_gate.assert_one(&mut region, c, offset)?;
                        } else {
                            main_gate.assert_zero(&mut region, c, offset)?;
                        }
                    }
                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_decomposition_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitDecomposition::<Wrong, Native> { rns };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
