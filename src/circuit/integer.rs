use super::main_gate::MainGate;
use super::{AssignedCondition, AssignedInteger, AssignedValue, UnassignedInteger};
use crate::circuit::main_gate::{MainGateConfig, MainGateInstructions};
use crate::circuit::range::{RangeChip, RangeConfig};
use crate::circuit::AssignedLimb;
use crate::rns::{Common, Integer, Rns};
use crate::{NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::{ConstraintSystem, Error};

mod add;
mod assert_in_field;
mod assert_not_zero;
mod assert_zero;
mod assign;
mod div;
mod invert;
mod mul;
mod neg;
mod reduce;
mod square;
mod sub;

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

#[derive(Clone, Debug)]
pub struct IntegerChip<Wrong: FieldExt, Native: FieldExt> {
    config: IntegerConfig,
    pub rns: Rns<Wrong, Native>,
}

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn new_assigned_integer(&self, limbs: Vec<AssignedLimb<N>>, native_value: AssignedValue<N>) -> AssignedInteger<N> {
        AssignedInteger::new(limbs, native_value, self.rns.bit_len_limb)
    }
}

pub trait IntegerInstructions<N: FieldExt> {
    fn assign_integer(&self, region: &mut Region<'_, N>, integer: Option<Integer<N>>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn range_assign_integer(
        &self,
        region: &mut Region<'_, N>,
        integer: UnassignedInteger<N>,
        range: Range,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;
    fn add(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn add_constant(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &Integer<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn sub(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn neg(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn mul(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn square(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn div(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error>;
    fn invert(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error>;
    fn reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
    fn assert_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_strict_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_not_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn is_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_not_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn assert_in_field(&self, region: &mut Region<'_, N>, input: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error>;
    fn cond_select(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;

    fn cond_select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &Integer<N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error>;

    fn reduce_if_necessary(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error>;
}

impl<W: FieldExt, N: FieldExt> IntegerInstructions<N> for IntegerChip<W, N> {
    fn add(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self.reduce_if_necessary(region, b, offset)?;
        self._add(region, a, b, offset)
    }

    fn add_constant(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &Integer<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self._add_constant(region, a, b, offset)
    }

    fn sub(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self.reduce_if_necessary(region, b, offset)?;
        self._sub(region, a, b, offset)
    }

    fn neg(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._neg(region, a, offset)
    }

    fn mul(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self.reduce_if_necessary(region, b, offset)?;
        self._mul(region, a, b, offset)
    }

    fn square(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self._square(region, a, offset)
    }

    fn div(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self.reduce_if_necessary(region, b, offset)?;
        self._div(region, a, b, offset)
    }

    fn invert(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self._invert(region, a, offset)
    }

    fn reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._reduce(region, a, offset)
    }

    fn range_assign_integer(
        &self,
        region: &mut Region<'_, N>,
        integer: UnassignedInteger<N>,
        range: Range,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        self._range_assign_integer(region, integer, range, offset)
    }

    fn assign_integer(&self, region: &mut Region<'_, N>, integer: Option<Integer<N>>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._assign_integer(region, integer, offset)
    }

    fn assert_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let c = &self.sub(region, a, b, offset)?;
        self._assert_zero(region, c, offset)?;
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

    fn is_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        self.assert_in_field(region, a, offset)?;
        self.assert_in_field(region, b, offset)?;
        let main_gate = self.main_gate();
        for idx in 0..NUMBER_OF_LIMBS {
            main_gate.is_equal(region, a.limb(idx), b.limb(idx), offset)?;
        }
        Ok(())
    }

    fn assert_not_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self._assert_not_zero(region, a, offset)?;
        Ok(())
    }

    fn assert_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        self._assert_zero(region, a, offset)
    }

    fn cond_select(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        self.reduce_if_necessary(region, a, offset)?;
        self.reduce_if_necessary(region, b, offset)?;

        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let res = main_gate.cond_select(region, a.limb(i), b.limb(i), cond, offset)?;

            let max_val = if a.limbs[i].max_val > b.limbs[i].max_val {
                a.limbs[i].max_val.clone()
            } else {
                b.limbs[i].max_val.clone()
            };

            limbs.push(res.to_limb(max_val));
        }

        let native_value = main_gate.cond_select(region, a.native(), b.native(), cond, offset)?;

        Ok(self.new_assigned_integer(limbs, native_value))
    }

    fn cond_select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &Integer<N>,
        cond: &AssignedCondition<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        self.reduce_if_necessary(region, a, offset)?;

        let main_gate = self.main_gate();

        let mut limbs: Vec<AssignedLimb<N>> = Vec::with_capacity(NUMBER_OF_LIMBS);
        for i in 0..NUMBER_OF_LIMBS {
            let b_limb = b.limb(i);

            let res = main_gate.cond_select_or_assign(region, a.limb(i), b_limb.fe(), cond, offset)?;

            // here we assume given constant is always in field
            let max_val = a.limb(i).max_val();
            limbs.push(res.to_limb(max_val));
        }

        let native_value = main_gate.cond_select_or_assign(region, a.native(), b.native(), cond, offset)?;

        Ok(self.new_assigned_integer(limbs, native_value))
    }

    fn assert_in_field(&self, region: &mut Region<'_, N>, input: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        self.reduce_if_necessary(region, input, offset)?;
        self._assert_in_field(region, input, offset)
    }

    fn reduce_if_necessary(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let exceeds_max_limb_value = a.limbs.iter().fold(false, |a, b| a | (b.max_val() > self.rns.max_unreduced_limb));
        let exceeds_max_value = a.max_val() > self.rns.max_operand;

        if exceeds_max_limb_value | exceeds_max_value {
            let a = self.reduce(region, a, offset)?;
            Ok(a.clone())
        } else {
            Ok(a.clone())
        }
    }
}

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub fn new(config: IntegerConfig, rns: Rns<W, N>) -> Self {
        IntegerChip { config, rns }
    }

    pub fn configure(_: &mut ConstraintSystem<N>, range_config: &RangeConfig, main_gate_config: &MainGateConfig) -> IntegerConfig {
        IntegerConfig {
            range_config: range_config.clone(),
            main_gate_config: main_gate_config.clone(),
        }
    }

    fn range_chip(&self) -> RangeChip<N> {
        let bit_len_lookup = self.rns.bit_len_limb / NUMBER_OF_LOOKUP_LIMBS;
        RangeChip::<N>::new(self.config.range_config.clone(), bit_len_lookup)
    }

    fn main_gate(&self) -> MainGate<N> {
        let main_gate_config = self.config.main_gate_config.clone();
        MainGate::<N>::new(main_gate_config)
    }
}

#[cfg(test)]
mod tests {
    use super::{IntegerChip, IntegerConfig, IntegerInstructions, Range};
    use crate::circuit::main_gate::{MainGate, MainGateColumn, MainGateConfig, MainGateInstructions};
    use crate::circuit::range::{RangeChip, RangeInstructions};
    use crate::circuit::{AssignedCondition, UnassignedInteger, UnassignedValue};
    use crate::rns::{Common, Integer, Limb, Rns};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    use halo2::pasta::Fp as Wrong;
    use halo2::pasta::Fq as Native;

    fn rns<W: FieldExt, N: FieldExt>() -> Rns<W, N> {
        let bit_len_limb = 68;
        Rns::<W, N>::construct(bit_len_limb)
    }

    fn setup<W: FieldExt, N: FieldExt>() -> (Rns<W, N>, u32) {
        let rns = rns();
        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;
        (rns, k)
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        integer_config: IntegerConfig,
    }

    impl TestCircuitConfig {
        fn new<W: FieldExt, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = rns::<W, N>().overflow_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_config = IntegerChip::<W, N>::configure(meta, &range_config, &main_gate_config);
            TestCircuitConfig {
                integer_config,
                main_gate_config,
            }
        }

        fn config_range<W: FieldExt, N: FieldExt>(&self, layouter: &mut impl Layouter<N>, rns: Rns<W, N>) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.integer_config.range_config.clone(), rns.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(layouter)?;

            Ok(())
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitEquality<W: FieldExt, N: FieldExt> {
        integer_0: Option<Integer<N>>,
        integer_1: Option<Integer<N>>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitEquality<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer_0 = &integer_chip.assign_integer(&mut region, self.integer_0.clone(), offset)?;
                    let integer_1 = &integer_chip.assign_integer(&mut region, self.integer_1.clone(), offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_0, integer_1, offset)?;
                    let integer_0 = &integer_chip.assign_integer(&mut region, self.integer_0.clone(), offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_0, integer_1, offset)?;
                    let integer_1 = &integer_chip.assign_integer(&mut region, self.integer_0.clone(), offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_0, integer_1, offset)?;
                    integer_chip.assert_equal(&mut region, integer_0, integer_1, offset)?;
                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_equality_circuit() {
        let (rns, k) = setup();

        let integer_0 = rns.rand_in_remainder_range();
        let integer_1 = integer_0.clone();

        let circuit = TestCircuitEquality::<Wrong, Native> {
            integer_0: Some(integer_0),
            integer_1: Some(integer_1),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));

        let integer_0 = rns.rand_in_remainder_range();
        let integer_1 = rns.rand_in_remainder_range();

        let circuit = TestCircuitEquality::<Wrong, Native> {
            integer_0: Some(integer_0),
            integer_1: Some(integer_1),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_ne!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitReduction<W: FieldExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitReduction<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let overflows = rns.rand_with_limb_bit_size(rns.bit_len_limb + 5);
                    let reduced = rns.reduce(&overflows).result;

                    let overflows = &integer_chip.assign_integer(&mut region, Some(overflows), offset)?;
                    let reduced_0 = &integer_chip.range_assign_integer(&mut region, Some(reduced).into(), Range::Remainder, offset)?;
                    let reduced_1 = &integer_chip.reduce(&mut region, overflows, offset)?;
                    assert_eq!(reduced_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, reduced_0, reduced_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, reduced_0, reduced_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_reduction_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitReduction::<Wrong, Native> { rns };
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitMultiplication<W: FieldExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitMultiplication<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = rns.rand_in_operand_range();
                    let b = rns.rand_in_operand_range();
                    let c = (a.value() * b.value()) % &rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a = &integer_chip.range_assign_integer(&mut region, Some(a).into(), Range::Operand, offset)?.clone();
                    let b = &integer_chip.range_assign_integer(&mut region, Some(b).into(), Range::Operand, offset)?.clone();
                    let c_0 = &integer_chip.range_assign_integer(&mut region, Some(c).into(), Range::Remainder, offset)?;
                    let c_1 = &integer_chip.mul(&mut region, a, b, offset)?;
                    assert_eq!(c_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, c_0, c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, c_0, c_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_multiplication_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitMultiplication::<Wrong, Native> { rns };
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitSquaring<W: FieldExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitSquaring<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = rns.rand_in_operand_range();
                    let c = (a.value() * a.value()) % &rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a = &integer_chip.range_assign_integer(&mut region, Some(a).into(), Range::Operand, offset)?;
                    let c_0 = &integer_chip.range_assign_integer(&mut region, Some(c).into(), Range::Remainder, offset)?;
                    let c_1 = &integer_chip.square(&mut region, a, offset)?;
                    assert_eq!(c_1.max_val(), rns.max_remainder);

                    integer_chip.assert_equal(&mut region, c_0, c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, c_0, c_1, offset)?;

                    Ok(())
                },
            )?;

            let range_chip = RangeChip::<N>::new(config.integer_config.range_config, self.rns.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_squaring_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitSquaring::<Wrong, Native> { rns };
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitInField<W: FieldExt, N: FieldExt> {
        input: Option<Integer<N>>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitInField<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer = &integer_chip.assign_integer(&mut region, self.input.clone(), offset)?;
                    integer_chip.assert_in_field(&mut region, integer, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_assert_in_field_circuit() {
        let (rns, k) = setup();

        for i in 0..2 {
            let integer_in_field = if i == 0 {
                rns.wrong_modulus_minus_one.clone().into()
            } else {
                rns.rand_in_field()
            };

            let circuit = TestCircuitInField::<Wrong, Native> {
                input: Some(integer_in_field),
                rns: rns.clone(),
            };

            let prover = match MockProver::run(k, &circuit, vec![]) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };

            assert_eq!(prover.verify(), Ok(()));
        }

        let integer_not_in_field = Integer::new(
            rns.wrong_modulus_decomposed.iter().map(|limb| Limb::<Native>::new(*limb)).collect(),
            rns.bit_len_limb,
        );

        let circuit = TestCircuitInField::<Wrong, Native> {
            input: Some(integer_not_in_field),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_ne!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitInvert<W: FieldExt, N: FieldExt> {
        integer_a: Option<Integer<N>>,
        integer_b: Option<Integer<N>>,
        cond: Option<N>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitInvert<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer_a_0 = &integer_chip.assign_integer(&mut region, self.integer_a.clone(), offset)?.clone();
                    let integer_b_0 = &integer_chip.assign_integer(&mut region, self.integer_b.clone(), offset)?.clone();
                    let cond_0 = integer_chip.main_gate().assign_bit(&mut region, self.cond.clone(), offset)?.clone();
                    let integer_a_1 = &integer_a_0.clone();
                    let (integer_b_1, cond_1) = &integer_chip.invert(&mut region, integer_a_0, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_a_0, integer_a_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_b_0, integer_b_1, offset)?;
                    integer_chip.main_gate().assert_equal(&mut region, cond_0, cond_1.clone(), offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_invert_circuit() {
        let (rns, k) = setup();

        let integer_a_cand = rns.rand_in_remainder_range();
        let integer_a = if rns.value(&integer_a_cand) % &rns.wrong_modulus == 0u32.into() {
            rns.new_from_big(1u32.into())
        } else {
            integer_a_cand
        };
        let integer_b = rns.invert(&integer_a);

        let circuit = TestCircuitInvert::<Wrong, Native> {
            integer_a: Some(integer_a),
            integer_b: integer_b,
            cond: Some(Native::zero()),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_zero_invert_circuit() {
        let rns = rns();

        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        let integer_a = rns.new_from_big(0u32.into());
        let integer_b = rns.new_from_big(1u32.into());

        let circuit = TestCircuitInvert::<Wrong, Native> {
            integer_a: Some(integer_a),
            integer_b: Some(integer_b),
            cond: Some(Native::one()),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitDivision<W: FieldExt, N: FieldExt> {
        integer_a: Option<Integer<N>>,
        integer_b: Option<Integer<N>>,
        integer_c: Option<Integer<N>>,
        cond: Option<N>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitDivision<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer_a_0 = &integer_chip.assign_integer(&mut region, self.integer_a.clone(), offset)?.clone();
                    let integer_b_0 = &integer_chip.assign_integer(&mut region, self.integer_b.clone(), offset)?.clone();
                    let integer_c_0 = &integer_chip.assign_integer(&mut region, self.integer_c.clone(), offset)?.clone();
                    let cond_0 = integer_chip.main_gate().assign_bit(&mut region, self.cond.clone(), offset)?.clone();
                    let integer_a_1 = &integer_a_0.clone();
                    let integer_b_1 = &integer_b_0.clone();
                    let (integer_c_1, cond_1) = &integer_chip.div(&mut region, integer_a_0, integer_b_0, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_a_0, integer_a_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_b_0, integer_b_1, offset)?;
                    integer_chip.assert_equal(&mut region, integer_c_0, integer_c_1, offset)?;
                    integer_chip.main_gate().assert_equal(&mut region, cond_0, cond_1.clone(), offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_division_circuit() {
        let (rns, k) = setup();

        let integer_a = rns.rand_in_remainder_range();
        let integer_b_cand = rns.rand_in_remainder_range();
        let integer_b = if rns.value(&integer_b_cand) % &rns.wrong_modulus == 0u32.into() {
            rns.new_from_big(1u32.into())
        } else {
            integer_b_cand
        };
        let integer_c = rns.div(&integer_a, &integer_b);

        let circuit = TestCircuitDivision::<Wrong, Native> {
            integer_a: Some(integer_a.clone()),
            integer_b: Some(integer_b),
            integer_c: integer_c,
            cond: Some(Native::zero()),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_zero_division_circuit() {
        let (rns, k) = setup();

        let integer_a = rns.rand_in_remainder_range();
        let integer_b = rns.new_from_big(0u32.into());
        let integer_c = integer_a.clone();

        let circuit = TestCircuitDivision::<Wrong, Native> {
            integer_a: Some(integer_a),
            integer_b: Some(integer_b),
            integer_c: Some(integer_c),
            cond: Some(Native::one()),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitAssertNotZero<W: FieldExt, N: FieldExt> {
        integer_a: Option<Integer<N>>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitAssertNotZero<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer_a_0 = &integer_chip.assign_integer(&mut region, self.integer_a.clone(), offset)?.clone();
                    integer_chip.assert_not_zero(&mut region, integer_a_0, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_invert_assert_not_zero() {
        let (rns, k) = setup();

        let integer_a = rns.rand_in_remainder_range();

        let circuit = TestCircuitAssertNotZero::<Wrong, Native> {
            integer_a: Some(integer_a.clone()),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        if rns.value(&integer_a) % rns.wrong_modulus == 0u32.into() {
            assert_ne!(prover.verify(), Ok(()));
        } else {
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[test]
    fn test_invert_zero_assert_not_zero() {
        let (rns, k) = setup();

        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        let integer_a = rns.new_from_big(0u32.into());

        let circuit = TestCircuitAssertNotZero::<Wrong, Native> {
            integer_a: Some(integer_a.clone()),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_ne!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invert_wrong_modulus_assert_not_zero() {
        let (rns, k) = setup();

        let integer_a = rns.new_from_limbs(rns.wrong_modulus_decomposed.clone());

        let circuit = TestCircuitAssertNotZero::<Wrong, Native> {
            integer_a: Some(integer_a.clone()),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_ne!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitAddition<W: FieldExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitAddition<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = rns.rand_in_remainder_range();
                    let b = rns.rand_in_remainder_range();
                    let c = a.value() + b.value();
                    let c = rns.new_from_big(c);

                    let a_int = integer_chip.range_assign_integer(&mut region, Some(a.clone()).into(), Range::Remainder, offset)?;
                    let b_int = integer_chip.range_assign_integer(&mut region, Some(b.clone()).into(), Range::Remainder, offset)?;
                    let c_1 = integer_chip.range_assign_integer(&mut region, Some(c).into(), Range::Operand, offset)?;
                    let c_0 = &integer_chip.add(&mut region, &a_int, &b_int, offset)?;
                    assert_eq!(a_int.max_val() + b_int.max_val(), c_0.max_val());
                    integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;

                    let c = (a.value() + b.value()) % &self.rns.wrong_modulus;
                    let c = rns.new_from_big(c);
                    let c_1 = integer_chip.range_assign_integer(&mut region, Some(c).into(), Range::Operand, offset)?;
                    let c_0 = integer_chip.reduce(&mut region, c_0, offset)?;
                    integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &c_0, &c_1, offset)?;

                    let a = rns.rand_in_remainder_range();
                    let b = rns.rand_in_remainder_range();
                    let c = a.value() + b.value();
                    let c = rns.new_from_big(c);

                    let a_int = integer_chip.range_assign_integer(&mut region, Some(a.clone()).into(), Range::Remainder, offset)?;
                    let c_1 = integer_chip.range_assign_integer(&mut region, Some(c).into(), Range::Operand, offset)?;
                    let c_0 = &integer_chip.add_constant(&mut region, &a_int, &b, offset)?;
                    assert_eq!(a_int.max_val() + b.value(), c_0.max_val());
                    integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;

                    let c = (a.value() + b.value()) % &self.rns.wrong_modulus;
                    let c = rns.new_from_big(c);
                    let c_1 = integer_chip.range_assign_integer(&mut region, Some(c).into(), Range::Operand, offset)?;
                    let c_0 = integer_chip.reduce(&mut region, c_0, offset)?;
                    integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &c_0, &c_1, offset)?;

                    let a = rns.rand_in_field();
                    let b = rns.rand_in_field();
                    let c = ((&self.rns.wrong_modulus + a.value()) - b.value()) % &self.rns.wrong_modulus;
                    let c = rns.new_from_big(c);

                    let a_int = integer_chip.range_assign_integer(&mut region, Some(a.clone()).into(), Range::Remainder, offset)?;
                    let b_int = integer_chip.range_assign_integer(&mut region, Some(b.clone()).into(), Range::Remainder, offset)?;
                    let c_1 = integer_chip.range_assign_integer(&mut region, Some(c).into(), Range::Operand, offset)?;
                    let c_0 = &integer_chip.sub(&mut region, &a_int, &b_int, offset)?;
                    assert_eq!(a_int.max_val() + rns.aux.value(), c_0.max_val());
                    integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;

                    let c_0 = integer_chip.reduce(&mut region, c_0, offset)?;
                    integer_chip.assert_equal(&mut region, &c_0, &c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &c_0, &c_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_addition() {
        let (rns, k) = setup();
        let circuit = TestCircuitAddition::<Wrong, Native> { rns };
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitConditionals<W: FieldExt, N: FieldExt> {
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitConditionals<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<W, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());
            let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            let rns = self.rns.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    // select second operand when condision is zero

                    let a = Some(rns.rand_in_remainder_range()).into();
                    let b = Some(rns.rand_in_remainder_range()).into();
                    let cond = N::zero();
                    let cond = Some(cond).into();

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let b = integer_chip.range_assign_integer(&mut region, b, Range::Remainder, offset)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, MainGateColumn::A, offset)?.into();
                    let selected = integer_chip.cond_select(&mut region, &a, &b, &cond, offset)?;
                    integer_chip.assert_equal(&mut region, &b, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &b, &selected, offset)?;
                    assert_eq!(b.max_val(), selected.max_val());

                    // select first operand when condision is one

                    let a = Some(rns.rand_in_remainder_range()).into();
                    let b = Some(rns.rand_in_remainder_range()).into();
                    let cond = N::one();
                    let cond = UnassignedValue::new(Some(cond));

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let b = integer_chip.range_assign_integer(&mut region, b, Range::Remainder, offset)?;

                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, MainGateColumn::A, offset)?.into();
                    let selected = integer_chip.cond_select(&mut region, &a, &b, &cond, offset)?;
                    integer_chip.assert_equal(&mut region, &a, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &a, &selected, offset)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select constant operand when condision is zero

                    let a = Some(rns.rand_in_remainder_range()).into();
                    let b = rns.rand_in_remainder_range();
                    let cond = N::zero();
                    let cond = UnassignedValue::new(Some(cond));

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, MainGateColumn::A, offset)?.into();
                    let selected = integer_chip.cond_select_or_assign(&mut region, &a, &b, &cond, offset)?;
                    let b_assigned = integer_chip.assign_integer(&mut region, Some(b), offset)?;
                    integer_chip.assert_equal(&mut region, &b_assigned, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &b_assigned, &selected, offset)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    // select non constant operand when condision is zero

                    let a = Some(rns.rand_in_remainder_range()).into();
                    let b = rns.rand_in_remainder_range();
                    let cond = N::one();
                    let cond = UnassignedValue::new(Some(cond));

                    let a = integer_chip.range_assign_integer(&mut region, a, Range::Remainder, offset)?;
                    let cond: AssignedCondition<N> = main_gate.assign_value(&mut region, &cond, MainGateColumn::A, offset)?.into();
                    let selected = integer_chip.cond_select_or_assign(&mut region, &a, &b, &cond, offset)?;
                    integer_chip.assert_equal(&mut region, &a, &selected, offset)?;
                    integer_chip.assert_strict_equal(&mut region, &a, &selected, offset)?;
                    assert_eq!(a.max_val(), selected.max_val());

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter, self.rns.clone())?;

            Ok(())
        }
    }

    #[test]
    fn test_condition_circuit() {
        let (rns, k) = setup();
        let circuit = TestCircuitConditionals::<Wrong, Native> { rns };
        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
