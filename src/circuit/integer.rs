use super::main_gate::MainGate;
use super::{AssignedCondition, AssignedInteger};
use crate::circuit::main_gate::{MainGateConfig, MainGateInstructions};
use crate::circuit::range::{RangeChip, RangeConfig};
use crate::circuit::AssignedValue;
use crate::rns::{Common, Integer, Limb, Rns};
use crate::NUMBER_OF_LOOKUP_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
use halo2::plonk::{ConstraintSystem, Error};

mod add;
mod assert_zero;
mod mul;
mod reduce;
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
    fn add(&self, region: &mut Region<'_, F>, a: &mut AssignedInteger<F>, b: &mut AssignedInteger<F>) -> Result<AssignedInteger<F>, Error>;
    fn sub(&self, region: &mut Region<'_, F>, a: &mut AssignedInteger<F>, b: &mut AssignedInteger<F>) -> Result<AssignedInteger<F>, Error>;
    fn mul(&self, region: &mut Region<'_, F>, a: &mut AssignedInteger<F>, b: &mut AssignedInteger<F>) -> Result<AssignedInteger<F>, Error>;
    fn reduce(&self, region: &mut Region<'_, F>, a: &mut AssignedInteger<F>) -> Result<AssignedInteger<F>, Error>;
    fn assign(&self, region: &mut Region<'_, F>, integer: Option<Integer<F>>, offset: &mut usize) -> Result<AssignedInteger<F>, Error>;
    fn assert_strict_equal(&self, region: &mut Region<'_, F>, a: &mut AssignedInteger<F>, b: &mut AssignedInteger<F>) -> Result<(), Error>;
    fn assert_equal(&self, region: &mut Region<'_, F>, a: &mut AssignedInteger<F>, b: &mut AssignedInteger<F>) -> Result<(), Error>;
    fn assert_in_field(&self, region: &mut Region<'_, F>, input: &mut AssignedInteger<F>) -> Result<(), Error>;
    fn cond_swap(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedInteger<F>,
        b: &mut AssignedInteger<F>,
        cond: &mut AssignedCondition<F>,
    ) -> Result<AssignedInteger<F>, Error>;

    // fn in_field(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>) -> Result<AssignedInteger<F>, Error>;
}

impl<W: FieldExt, N: FieldExt> IntegerInstructions<N> for IntegerChip<W, N> {
    fn add(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        self._add(region, a, b)
    }

    fn mul(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        self._mul(region, a, b)
    }

    fn reduce(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        self._reduce(region, a)
    }

    fn sub(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        self._sub(region, a, b)
    }

    fn assign(&self, region: &mut Region<'_, N>, integer: Option<Integer<N>>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate_config();

        let u_0 = integer.as_ref().map(|e| e.limb(0));
        let u_1 = integer.as_ref().map(|e| e.limb(1));
        let u_2 = integer.as_ref().map(|e| e.limb(2));
        let u_3 = integer.as_ref().map(|e| e.limb(3));

        let cell_0 = region.assign_advice(|| "a", main_gate.a, *offset, || Ok(u_0.ok_or(Error::SynthesisError)?))?;
        let cell_1 = region.assign_advice(|| "b", main_gate.b, *offset, || Ok(u_1.ok_or(Error::SynthesisError)?))?;
        let cell_2 = region.assign_advice(|| "c", main_gate.c, *offset, || Ok(u_2.ok_or(Error::SynthesisError)?))?;
        let cell_3 = region.assign_advice(|| "d", main_gate.d, *offset, || Ok(u_3.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "sa", main_gate.sa, *offset, || Ok(N::one()))?;
        region.assign_fixed(|| "sb", main_gate.sb, *offset, || Ok(self.rns.left_shifter_r))?;
        region.assign_fixed(|| "sc", main_gate.sc, *offset, || Ok(self.rns.left_shifter_2r))?;
        region.assign_fixed(|| "sd", main_gate.sd, *offset, || Ok(self.rns.left_shifter_3r))?;
        region.assign_fixed(|| "sd_next", main_gate.sd_next, *offset, || Ok(-N::one()))?;

        region.assign_fixed(|| "s_mul", main_gate.s_mul, *offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, *offset, || Ok(N::zero()))?;

        *offset = *offset + 1;

        let native_value = integer.as_ref().map(|integer| integer.native());

        let _ = region.assign_advice(|| "a", main_gate.a, *offset, || Ok(N::zero()))?;
        let _ = region.assign_advice(|| "b", main_gate.b, *offset, || Ok(N::zero()))?;
        let _ = region.assign_advice(|| "c", main_gate.c, *offset, || Ok(N::zero()))?;
        let native_value_cell = region.assign_advice(|| "d", main_gate.d, *offset, || Ok(native_value.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "sa", main_gate.sa, *offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "sb", main_gate.sb, *offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "sc", main_gate.sc, *offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "sd", main_gate.sd, *offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "sd_next", main_gate.sd_next, *offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_mul", main_gate.s_mul, *offset, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, *offset, || Ok(N::zero()))?;

        let cells = vec![cell_0, cell_1, cell_2, cell_3];
        let assigned_integer = AssignedInteger::<_>::new(cells, integer, native_value_cell);

        *offset = *offset + 1;

        Ok(assigned_integer)
    }

    fn assert_strict_equal(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<(), Error> {
        // TODO: strict equality can be constained only using permutation?
        let main_gate = self.main_gate_config();

        let mut a_updated_cells: Vec<Cell> = a.cells.clone();
        let mut b_updated_cells: Vec<Cell> = b.cells.clone();

        let a_integer: Option<Vec<N>> = a.value.as_ref().map(|e| e.limbs());
        let b_integer: Option<Vec<N>> = b.value.as_ref().map(|e| e.limbs());

        let mut offset = 0;

        for idx in 0..NUMBER_OF_LOOKUP_LIMBS {
            let a_new_cell = region.assign_advice(|| "a", main_gate.a, offset, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let b_new_cell = region.assign_advice(|| "b", main_gate.b, offset, || Ok(b_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;

            region.assign_fixed(|| "a", main_gate.sa, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "b", main_gate.sb, offset, || Ok(-N::one()))?;

            region.assign_fixed(|| "c", main_gate.sc, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "d", main_gate.sd, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", main_gate.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", main_gate.s_mul, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", main_gate.s_constant, offset, || Ok(N::zero()))?;

            a.cycle_cell(region, idx, a_new_cell)?;
            b.cycle_cell(region, idx, b_new_cell)?;
            offset += 1;
        }

        let a = a.update_cells(Some(a_updated_cells), Some(a.native_value_cell));
        let b = b.update_cells(Some(b_updated_cells), Some(b.native_value_cell));

        Ok(())
    }

    fn assert_equal(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<(), Error> {
        let c = &mut self._sub(region, a, b)?;
        self._assert_zero(region, c)?;
        Ok(())
    }

    fn cond_swap(
        &self,
        region: &mut Region<'_, N>,
        a: &mut AssignedInteger<N>,
        b: &mut AssignedInteger<N>,
        cond: &mut AssignedCondition<N>,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let a_values: &mut Vec<AssignedValue<N>> = &mut a.values();
        let b_values: &mut Vec<AssignedValue<N>> = &mut b.values();
        let native_value_a = &mut a.native();
        let native_value_b = &mut a.native();

        let res_0 = main_gate.cond_swap(region, &mut a_values[0], &mut b_values[0], cond)?;
        let res_1 = main_gate.cond_swap(region, &mut a_values[1], &mut b_values[1], cond)?;
        let res_2 = main_gate.cond_swap(region, &mut a_values[2], &mut b_values[2], cond)?;
        let res_3 = main_gate.cond_swap(region, &mut a_values[3], &mut b_values[3], cond)?;
        let res_native_value = main_gate.cond_swap(region, native_value_a, native_value_b, cond)?;

        let a_new_cells: Vec<Cell> = a_values.iter().map(|a_new_i| a_new_i.cell).collect();
        let b_new_cells: Vec<Cell> = b_values.iter().map(|b_new_i| b_new_i.cell).collect();

        let res = vec![res_0, res_1, res_2, res_3];
        let res_cells: Vec<Cell> = res.iter().map(|res| res.cell).collect();
        let res: Option<Vec<Limb<N>>> = res[0].value.map(|_| res.iter().map(|res_i| Limb::from_fe(res_i.value.unwrap())).collect());
        let res = res.map(|res| self.rns.new_from_limbs(res));

        a.update_cells(Some(a_new_cells), Some(a.native_value_cell));
        b.update_cells(Some(b_new_cells), Some(b.native_value_cell));
        let r = AssignedInteger::new(res_cells, res, res_native_value.cell);

        Ok(r)
    }

    fn assert_in_field(&self, region: &mut Region<'_, N>, input: &mut AssignedInteger<N>) -> Result<(), Error> {
        // p - a
        //  p = [p_3,p_2,p_1,p_0]
        //  a = [a_3,a_2,a_1,a_0]

        // c0 = p0 - a0 + b0 * R
        // c1 = p1 - a1 - b0 + b1 * R
        // c2 = p2 - a2 - b1 + b2 * R
        // c3 = p3 - a3 - b2

        // c0 = d0 + b0 * R
        // b0 = (c0 - p0 + a0) / R
        // b0 = (c0 - p0 + a0) ***

        // c1 = d1 - b0 + b1 * R
        // b1 = (c1 - d1 + b0) / R
        // b1 = (c1 - d1 + (c0 - d0) / R) / R
        // b1 = (c1 - p1 + a1 + b0) ***

        // c2 = d2 - b1 + b2 * R
        // b2 = (c2 - d2 + b1 ) / R
        // b2 = (c2 - d2 + (c1 - d1 + (c0 - d0) / R) / R) / R
        // b2 = (c2 - p2 + a1 + b1) ***

        // c3 = d3 - b2
        // b2 = d3 - c3
        // b2 = p3 - a3 - c3 ***

        // 0 = c3 - d3 + (c2 - d2 + (c1 - d1 + (c0 - d0) / R) / R) / R
        // 0 = (c3 - d3) + (c2 - d2) / R + (c1 - d1) / RR + (c0 - d0) / RRR
        // 0 = (c3 - p3 + a3) * RRR
        //   + (c2 - p2 + a2) * RR
        //   + (c1 - p1 + a1) * R
        //   + (c0 - p0 + a0)

        // b2 = d3 - c3
        // c3 = p3 - a3 - b2

        // b0 = (c0 - p0 + a0)
        // b1 = (c1 - p1 + a1 + b0)
        // b2 = (c2 - p2 + a2 + b1)
        // b2 = p3 - a3 - c3

        let main_gate = self.main_gate_config();

        unimplemented!()
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
        RangeChip::<N>::new(self.config.range_config.clone())
    }

    fn main_gate_config(&self) -> MainGateConfig {
        self.config.main_gate_config.clone()
    }

    fn main_gate(&self) -> MainGate<N> {
        MainGate::<N>::new(self.config.main_gate_config.clone())
    }
}

#[cfg(test)]
mod tests {

    use super::{IntegerChip, IntegerConfig, IntegerInstructions};
    use crate::circuit::main_gate::{MainGate, MainGateConfig};
    use crate::circuit::range::{RangeChip, RangeInstructions};
    use crate::rns::{Integer, Rns};
    use crate::BIT_LEN_LIMB;
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

            let integer_0 = &mut layouter.assign_region(|| "region 0", |mut region| integer_chip.assign(&mut region, self.integer_0.clone(), &mut 0))?;
            let integer_1 = &mut layouter.assign_region(|| "region 1", |mut region| integer_chip.assign(&mut region, self.integer_1.clone(), &mut 0))?;
            layouter.assign_region(|| "region 2", |mut region| integer_chip.assert_strict_equal(&mut region, integer_0, integer_1))?;
            let integer_2 = &mut integer_0.clone();
            let integer_3 = &mut integer_1.clone();
            layouter.assign_region(|| "region 3", |mut region| integer_chip.assert_strict_equal(&mut region, integer_0, integer_1))?;
            layouter.assign_region(|| "region 4", |mut region| integer_chip.assert_strict_equal(&mut region, integer_0, integer_2))?;
            layouter.assign_region(|| "region 2", |mut region| integer_chip.assert_strict_equal(&mut region, integer_1, integer_3))?;

            // TODO: think we should move table loading somewhere else?
            let range_chip = RangeChip::<N>::new(config.integer_config.range_config);
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
        const BIT_LEN_LOOKUP_LIMB: usize = 16;

        #[cfg(not(feature = "no_lookup"))]
        const K: u32 = (BIT_LEN_LOOKUP_LIMB + 1) as u32;
        #[cfg(feature = "no_lookup")]
        const K: u32 = 5;

        let rns = Rns::<Wrong, Native>::construct();
        let integer_0 = rns.rand_in_max();
        let integer_1 = integer_0.clone();

        let circuit = TestCircuitEquality::<Wrong, Native> {
            integer_0: Some(integer_0),
            integer_1: Some(integer_1),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        #[cfg(feature = "print_prover")]
        println!("{:#?}", prover);

        assert_eq!(prover.verify(), Ok(()));

        let integer_0 = rns.rand_in_max();
        let integer_1 = rns.rand_in_max();

        let circuit = TestCircuitEquality::<Wrong, Native> {
            integer_0: Some(integer_0),
            integer_1: Some(integer_1),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
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

            let integer_overflows_0 = &mut layouter.assign_region(
                || "region 0",
                |mut region| integer_chip.assign(&mut region, self.integer_overflows.clone(), &mut 0),
            )?;
            let integer_reduced_0 = &mut layouter.assign_region(
                || "region 1",
                |mut region| integer_chip.assign(&mut region, self.integer_reduced.clone(), &mut 0),
            )?;

            let integer_overflows_1 = &mut integer_overflows_0.clone();
            let integer_reduced_1 = &mut layouter.assign_region(|| "region 2", |mut region| integer_chip.reduce(&mut region, integer_overflows_1))?;

            layouter.assign_region(
                || "region 3",
                |mut region| integer_chip.assert_strict_equal(&mut region, integer_reduced_0, integer_reduced_1),
            )?;

            layouter.assign_region(
                || "region 4",
                |mut region| integer_chip.assert_strict_equal(&mut region, integer_overflows_0, integer_overflows_1),
            )?;

            let range_chip = RangeChip::<N>::new(config.integer_config.range_config);
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
        const BIT_LEN_LOOKUP_LIMB: usize = 16;

        #[cfg(not(feature = "no_lookup"))]
        const K: u32 = (BIT_LEN_LOOKUP_LIMB + 1) as u32;
        #[cfg(feature = "no_lookup")]
        const K: u32 = 6;

        let rns = Rns::<Wrong, Native>::construct();

        // let input = vec![
        //     "1dfce0ed73516265cde2b9496841f18c",
        //     "e56d9ccbbd4467843028fd719fd3e5a",
        //     "1b58b2726b1799e1087cccc4141b7844",
        //     "1876df29d0028f331735ea718df8acb9",
        // ];
        // let integer_overflows = rns.new_from_str_limbs(input);

        let integer_overflows = rns.rand_with_limb_bit_size(BIT_LEN_LIMB + 5);

        let integer_reduced = rns.reduce(&integer_overflows).result;

        let circuit = TestCircuitReduction::<Wrong, Native> {
            integer_overflows: Some(integer_overflows),
            integer_reduced: Some(integer_reduced),
            rns: rns.clone(),
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        #[cfg(feature = "print_prover")]
        println!("{:#?}", prover);

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

            let integer_a_0 = &mut layouter.assign_region(|| "region 0", |mut region| integer_chip.assign(&mut region, self.integer_a.clone(), &mut 0))?;
            let integer_b_0 = &mut layouter.assign_region(|| "region 1", |mut region| integer_chip.assign(&mut region, self.integer_b.clone(), &mut 0))?;
            let integer_c_0 = &mut layouter.assign_region(|| "region 2", |mut region| integer_chip.assign(&mut region, self.integer_c.clone(), &mut 0))?;

            let integer_c_1 = &mut layouter.assign_region(|| "region 3", |mut region| integer_chip.mul(&mut region, integer_a_0, integer_b_0))?;
            let integer_a_1 = &mut integer_a_0.clone();
            let integer_b_1 = &mut integer_b_0.clone();

            layouter.assign_region(
                || "region 4",
                |mut region| integer_chip.assert_strict_equal(&mut region, integer_c_0, integer_c_1),
            )?;
            layouter.assign_region(
                || "region 4",
                |mut region| integer_chip.assert_strict_equal(&mut region, integer_a_0, integer_a_1),
            )?;
            layouter.assign_region(
                || "region 5",
                |mut region| integer_chip.assert_strict_equal(&mut region, integer_b_0, integer_b_1),
            )?;

            let range_chip = RangeChip::<N>::new(config.integer_config.range_config);
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
        const BIT_LEN_LOOKUP_LIMB: usize = 16;

        #[cfg(not(feature = "no_lookup"))]
        const K: u32 = (BIT_LEN_LOOKUP_LIMB + 1) as u32;
        #[cfg(feature = "no_lookup")]
        const K: u32 = 8;

        let rns = Rns::<Wrong, Native>::construct();

        let integer_a = rns.rand_in_max();
        let integer_b = rns.rand_in_max();
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

        #[cfg(feature = "print_prover")]
        println!("{:#?}", prover);

        assert_eq!(prover.verify(), Ok(()));
    }
}
