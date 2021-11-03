use super::main_gate::MainGate;
use super::{AssignedCondition, AssignedInteger, UnassignedInteger};
use crate::circuit::main_gate::{CombinationOption, MainGateConfig, MainGateInstructions, Term};
use crate::circuit::range::{RangeChip, RangeConfig, RangeInstructions};
use crate::circuit::{AssignedLimb, AssignedValue};
use crate::rns::{Common, Integer, Rns};
use crate::{NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::{ConstraintSystem, Error};
use num_bigint::BigUint as big_uint;
use num_traits::One;

mod add;
mod assert_in_field;
mod assert_zero;
mod mul;
mod reduce;
mod square;
mod sub;

#[derive(Clone, Debug)]
pub struct IntegerConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

pub struct IntegerChip<Wrong: FieldExt, Native: FieldExt> {
    config: IntegerConfig,
    rns: Rns<Wrong, Native>,
}

trait IntegerInstructions<F: FieldExt> {
    fn assign_integer(&self, region: &mut Region<'_, F>, integer: Option<Integer<F>>, offset: &mut usize) -> Result<AssignedInteger<F>, Error>;
    fn range_assign_integer(
        &self,
        region: &mut Region<'_, F>,
        integer: UnassignedInteger<F>,
        most_significant_limb_bit_len: usize,
        offset: &mut usize,
    ) -> Result<AssignedInteger<F>, Error>;
    fn add(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, b: &AssignedInteger<F>, offset: &mut usize) -> Result<AssignedInteger<F>, Error>;
    fn sub(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, b: &AssignedInteger<F>, offset: &mut usize) -> Result<AssignedInteger<F>, Error>;
    fn mul(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, b: &AssignedInteger<F>, offset: &mut usize) -> Result<AssignedInteger<F>, Error>;
    fn square(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, offset: &mut usize) -> Result<AssignedInteger<F>, Error>;
    fn reduce(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, offset: &mut usize) -> Result<AssignedInteger<F>, Error>;
    fn assert_strict_equal(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, b: &AssignedInteger<F>, offset: &mut usize) -> Result<(), Error>;
    fn assert_equal(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, b: &AssignedInteger<F>, offset: &mut usize) -> Result<(), Error>;
    fn assert_not_equal(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, b: &AssignedInteger<F>, offset: &mut usize) -> Result<(), Error>;
    fn assert_not_zero(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, offset: &mut usize) -> Result<(), Error>;
    fn assert_in_field(&self, region: &mut Region<'_, F>, input: &AssignedInteger<F>, offset: &mut usize) -> Result<(), Error>;
    fn cond_select(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedInteger<F>,
        b: &AssignedInteger<F>,
        cond: &AssignedCondition<F>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<F>, Error>;
}

impl<W: FieldExt, N: FieldExt> IntegerInstructions<N> for IntegerChip<W, N> {
    fn add(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._add(region, a, b, offset)
    }

    fn sub(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._sub(region, a, b, offset)
    }

    fn mul(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._mul(region, a, b, offset)
    }

    fn square(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._square(region, a, offset)
    }

    fn reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        self._reduce(region, a, offset)
    }

    fn range_assign_integer(
        &self,
        region: &mut Region<'_, N>,
        integer: UnassignedInteger<N>,
        most_significant_limb_bit_len: usize,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let range_chip = self.range_chip();
        let max_val = (big_uint::one() << self.rns.bit_len_limb) - 1usize;
        assert!(most_significant_limb_bit_len <= self.rns.bit_len_limb);

        let assigned = range_chip.range_value(region, &integer.limb(0), self.rns.bit_len_limb, offset)?;
        let limb_0 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val.clone());

        let assigned = range_chip.range_value(region, &integer.limb(1), self.rns.bit_len_limb, offset)?;
        let limb_1 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val.clone());

        let assigned = range_chip.range_value(region, &integer.limb(2), self.rns.bit_len_limb, offset)?;
        let limb_2 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val.clone());

        let max_val = (big_uint::one() << most_significant_limb_bit_len) - 1usize;
        let assigned = range_chip.range_value(region, &integer.limb(3), most_significant_limb_bit_len, offset)?;
        let limb_3 = &mut AssignedLimb::new(assigned.cell, assigned.value, max_val);

        // find the native value
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let r = self.rns.left_shifter_r;
        let rr = self.rns.left_shifter_2r;
        let rrr = self.rns.left_shifter_3r;

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(limb_0, one),
            Term::Assigned(limb_1, r),
            Term::Assigned(limb_2, rr),
            Term::Assigned(limb_3, rrr),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        let native_value = integer.native();
        let (_, _, _, native_value_cell) = main_gate.combine(
            region,
            Term::Zero,
            Term::Zero,
            Term::Zero,
            Term::Unassigned(native_value.value, zero),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        let native_value = native_value.assign(native_value_cell);

        Ok(AssignedInteger {
            limbs: vec![limb_0.clone(), limb_1.clone(), limb_2.clone(), limb_3.clone()],
            native_value,
        })
    }

    fn assign_integer(&self, region: &mut Region<'_, N>, integer: Option<Integer<N>>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let (zero, one) = (N::zero(), N::one());
        let r = self.rns.left_shifter_r;
        let rr = self.rns.left_shifter_2r;
        let rrr = self.rns.left_shifter_3r;

        let (cell_0, cell_1, cell_2, cell_3) = main_gate.combine(
            region,
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(0)), one),
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(1)), r),
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(2)), rr),
            Term::Unassigned(integer.as_ref().map(|e| e.limb_value(3)), rrr),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        let native_value = integer.as_ref().map(|integer| integer.native());

        let (_, _, _, native_value_cell) = main_gate.combine(
            region,
            Term::Zero,
            Term::Zero,
            Term::Zero,
            Term::Unassigned(native_value, zero),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        let cells = vec![cell_0, cell_1, cell_2, cell_3];

        let limbs = cells
            .iter()
            .enumerate()
            .map(|(i, cell)| AssignedLimb {
                value: integer.as_ref().map(|integer| integer.limb(i)),
                cell: *cell,
                max_val: self.rns.limb_max_val.clone(),
            })
            .collect();

        let native_value = AssignedValue {
            value: native_value,
            cell: native_value_cell,
        };
        let assigned_integer = AssignedInteger { limbs, native_value };

        Ok(assigned_integer)
    }

    fn assert_equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let c = &self._sub(region, a, b, offset)?;
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
        self.assert_in_field(region, a, offset)?;
        self.assert_in_field(region, b, offset)?;
        let main_gate = self.main_gate();
        for idx in 0..NUMBER_OF_LIMBS {
            main_gate.assert_not_equal(region, a.limb(idx), b.limb(idx), offset)?;
        }
        Ok(())
    }

    fn assert_not_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        self.assert_in_field(region, a, offset)?;
        let main_gate = self.main_gate();
        for idx in 0..NUMBER_OF_LIMBS {
            main_gate.assert_not_zero(region, a.limb(idx), offset)?;
        }
        Ok(())
    }

    fn cond_select(
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
            let res = main_gate.cond_select(region, a.limb(i), b.limb(i), cond, offset)?;

            let max_val = if a.limbs[i].max_val > b.limbs[i].max_val {
                a.limbs[i].max_val.clone()
            } else {
                b.limbs[i].max_val.clone()
            };

            limbs.push(res.to_limb(max_val));
        }

        let native_value = main_gate.cond_select(region, a.native(), b.native(), cond, offset)?;

        Ok(AssignedInteger::new(limbs, native_value))
    }

    fn assert_in_field(&self, region: &mut Region<'_, N>, input: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        self._assert_in_field(region, input, offset)
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

    use super::{IntegerChip, IntegerConfig, IntegerInstructions};
    use crate::circuit::main_gate::{MainGate, MainGateConfig};
    use crate::circuit::range::{RangeChip, RangeInstructions};
    use crate::rns::{Integer, Limb, Rns};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        integer_config: IntegerConfig,
    }

    impl TestCircuitConfig {
        fn overflow_bit_lengths() -> Vec<usize> {
            vec![2, 3]
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
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = TestCircuitConfig::overflow_bit_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_config = IntegerChip::<W, N>::configure(meta, &range_config, &main_gate_config);
            TestCircuitConfig {
                integer_config,
                main_gate_config,
            }
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

            let range_chip = RangeChip::<N>::new(config.integer_config.range_config, self.rns.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_equality_circuit() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;
        let bit_len_limb = 64;

        let rns = Rns::<Wrong, Native>::construct(bit_len_limb);

        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        let rns = Rns::<Wrong, Native>::construct(bit_len_limb);
        let integer_0 = rns.rand_prenormalized();
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

        let integer_0 = rns.rand_prenormalized();
        let integer_1 = rns.rand_prenormalized();

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
        integer_overflows: Option<Integer<N>>,
        integer_reduced: Option<Integer<N>>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitReduction<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = TestCircuitConfig::overflow_bit_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_config = IntegerChip::<W, N>::configure(meta, &range_config, &main_gate_config);
            TestCircuitConfig {
                integer_config,
                main_gate_config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer_overflows_0 = &integer_chip.assign_integer(&mut region, self.integer_overflows.clone(), offset)?;
                    let integer_overflows_1 = &integer_overflows_0.clone();
                    let integer_reduced_0 = &integer_chip.assign_integer(&mut region, self.integer_reduced.clone(), offset)?;
                    let integer_reduced_1 = &integer_chip.reduce(&mut region, integer_overflows_0, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_reduced_0, integer_reduced_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_overflows_0, integer_overflows_1, offset)?;

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
    fn test_reduction_circuit() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;

        let bit_len_limb = 64;

        let rns = Rns::<Wrong, Native>::construct(bit_len_limb);

        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        // let input = vec![
        //     "1dfce0ed73516265cde2b9496841f18c",
        //     "e56d9ccbbd4467843028fd719fd3e5a",
        //     "1b58b2726b1799e1087cccc4141b7844",
        //     "1876df29d0028f331735ea718df8acb9",
        // ];
        // let integer_overflows = rns.new_from_str_limbs(input);

        let integer_overflows = rns.rand_with_limb_bit_size(rns.bit_len_limb + 5);

        let integer_reduced = rns.reduce(&integer_overflows).result;

        let circuit = TestCircuitReduction::<Wrong, Native> {
            integer_overflows: Some(integer_overflows),
            integer_reduced: Some(integer_reduced),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitMultiplication<W: FieldExt, N: FieldExt> {
        integer_a: Option<Integer<N>>,
        integer_b: Option<Integer<N>>,
        integer_c: Option<Integer<N>>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitMultiplication<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = TestCircuitConfig::overflow_bit_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_config = IntegerChip::<W, N>::configure(meta, &range_config, &main_gate_config);
            TestCircuitConfig {
                integer_config,
                main_gate_config,
            }
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
                    let integer_a_1 = &integer_a_0.clone();
                    let integer_b_1 = &integer_b_0.clone();
                    let integer_c_1 = &integer_chip.mul(&mut region, integer_a_0, integer_b_0, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_c_0, integer_c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_a_0, integer_a_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_b_0, integer_b_1, offset)?;

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
    fn test_multiplication_circuit() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;

        let bit_len_limb = 64;
        let rns = Rns::<Wrong, Native>::construct(bit_len_limb);

        #[cfg(not(feature = "no_lookup"))]
        let K: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let K: u32 = 8;

        let integer_a = rns.rand_prenormalized();
        let integer_b = rns.rand_prenormalized();

        let integer_c = rns.mul(&integer_a, &integer_b).result;

        let circuit = TestCircuitMultiplication::<Wrong, Native> {
            integer_a: Some(integer_a),
            integer_b: Some(integer_b),
            integer_c: Some(integer_c),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitSquaring<W: FieldExt, N: FieldExt> {
        integer_a: Option<Integer<N>>,
        integer_c: Option<Integer<N>>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitSquaring<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = TestCircuitConfig::overflow_bit_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_config = IntegerChip::<W, N>::configure(meta, &range_config, &main_gate_config);
            TestCircuitConfig {
                integer_config,
                main_gate_config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let integer_a_0 = &integer_chip.assign_integer(&mut region, self.integer_a.clone(), offset)?.clone();
                    let integer_c_0 = &integer_chip.assign_integer(&mut region, self.integer_c.clone(), offset)?.clone();
                    let integer_a_1 = &integer_a_0.clone();
                    let integer_c_1 = &integer_chip.square(&mut region, integer_a_0, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_c_0, integer_c_1, offset)?;
                    integer_chip.assert_strict_equal(&mut region, integer_a_0, integer_a_1, offset)?;

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
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;

        let bit_len_limb = 64;
        let rns = Rns::<Wrong, Native>::construct(bit_len_limb);

        #[cfg(not(feature = "no_lookup"))]
        let K: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let K: u32 = 8;

        let integer_a = rns.rand_prenormalized();

        let integer_c = rns.mul(&integer_a, &integer_a).result;

        let circuit = TestCircuitSquaring::<Wrong, Native> {
            integer_a: Some(integer_a),
            integer_c: Some(integer_c),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
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
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = TestCircuitConfig::overflow_bit_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_config = IntegerChip::<W, N>::configure(meta, &range_config, &main_gate_config);
            TestCircuitConfig {
                integer_config,
                main_gate_config,
            }
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

            let range_chip = RangeChip::<N>::new(config.integer_config.range_config, self.rns.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_assert_in_field_circuit() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;

        let bit_len_limb = 64;

        let rns = &Rns::<Wrong, Native>::construct(bit_len_limb);

        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        for i in 0..1 {
            let integer_in_field = if i == 0 {
                rns.wrong_modulus_minus_one.clone().into()
            } else {
                rns.rand_normalized()
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

        let integer_not_in_field = Integer::new(rns.wrong_modulus_decomposed.iter().map(|limb| Limb::<Native>::new(*limb)).collect());

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
}
