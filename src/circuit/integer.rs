use crate::circuit::main_gate::MainGateConfig;
use crate::circuit::range::{RangeChip, RangeConfig};
use crate::rns::{Integer, Limb, Rns};
use crate::{BIT_LEN_LIMB, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};

mod add;
mod mul;
mod reduce;
mod sub;

#[derive(Clone, Debug)]
pub struct IntegerConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt> {
    pub value: Option<Integer<F>>,
    pub cells: Vec<Cell>,
}

impl<F: FieldExt> AssignedInteger<F> {
    fn empty() -> Self {
        Self { value: None, cells: vec![] }
    }

    pub fn value(&self) -> Option<Integer<F>> {
        self.value.clone()
    }

    fn new(cells: Vec<Cell>, value: Option<Integer<F>>) -> Self {
        Self { value, cells }
    }

    pub fn clone_with_cells(&self, cells: Vec<Cell>) -> Self {
        Self {
            value: self.value.clone(),
            cells: cells,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt> {
    pub value: Option<Limb<F>>,
    pub cell: Cell,
}

impl<F: FieldExt> AssignedLimb<F> {
    pub fn clone_with_cell(&self, cell: Cell) -> Self {
        Self {
            value: self.value.clone(),
            cell,
        }
    }

    fn new(cell: Cell, value: Option<Limb<F>>) -> Self {
        AssignedLimb { value, cell }
    }
}

pub struct IntegerChip<Wrong: FieldExt, Native: FieldExt> {
    config: IntegerConfig,
    rns: Rns<Wrong, Native>,
}

trait IntegerInstructions<F: FieldExt> {
    fn add(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedInteger<F>,
        b: &AssignedInteger<F>,
    ) -> Result<(AssignedInteger<F>, AssignedInteger<F>, AssignedInteger<F>), Error>;

    fn sub(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedInteger<F>,
        b: &AssignedInteger<F>,
    ) -> Result<(AssignedInteger<F>, AssignedInteger<F>, AssignedInteger<F>), Error>;

    fn mul(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedInteger<F>,
        b: &AssignedInteger<F>,
    ) -> Result<(AssignedInteger<F>, AssignedInteger<F>, AssignedInteger<F>), Error>;

    fn reduce(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>) -> Result<(AssignedInteger<F>, AssignedInteger<F>), Error>;

    fn assign_input(&self, region: &mut Region<'_, F>, integer: Option<Integer<F>>) -> Result<AssignedInteger<F>, Error>;

    fn equal(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>, b: &AssignedInteger<F>) -> Result<(AssignedInteger<F>, AssignedInteger<F>), Error>;
}

impl<W: FieldExt, N: FieldExt> IntegerInstructions<N> for IntegerChip<W, N> {
    fn add(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._add(region, a, b)
    }

    fn mul(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._mul(region, a, b)
    }

    fn reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>) -> Result<(AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._reduce(region, a)
    }

    fn sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._sub(region, a, b)
    }

    fn assign_input(&self, region: &mut Region<'_, N>, integer: Option<Integer<N>>) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();

        let u_0 = integer.as_ref().map(|e| e.get_limb(0));
        let u_1 = integer.as_ref().map(|e| e.get_limb(1));
        let u_2 = integer.as_ref().map(|e| e.get_limb(2));
        let u_3 = integer.as_ref().map(|e| e.get_limb(3));
        let cell_0 = region.assign_advice(|| "a", main_gate.a, 0, || Ok(u_0.ok_or(Error::SynthesisError)?))?;
        let cell_1 = region.assign_advice(|| "a", main_gate.a, 0, || Ok(u_1.ok_or(Error::SynthesisError)?))?;
        let cell_2 = region.assign_advice(|| "a", main_gate.a, 0, || Ok(u_2.ok_or(Error::SynthesisError)?))?;
        let cell_3 = region.assign_advice(|| "a", main_gate.a, 0, || Ok(u_3.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "sa", main_gate.sa, 0, || Ok(N::zero()))?;
        region.assign_fixed(|| "sb", main_gate.sb, 0, || Ok(N::zero()))?;
        region.assign_fixed(|| "sc", main_gate.sc, 0, || Ok(N::zero()))?;
        region.assign_fixed(|| "sd", main_gate.sd, 0, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_mul", main_gate.s_mul, 0, || Ok(N::zero()))?;
        region.assign_fixed(|| "sd_next", main_gate.sd_next, 0, || Ok(N::zero()))?;
        region.assign_fixed(|| "s_constant", main_gate.s_constant, 0, || Ok(N::zero()))?;

        let cells = vec![cell_0, cell_1, cell_2, cell_3];
        let assigned_integer = AssignedInteger::<_>::new(cells, integer);

        Ok(assigned_integer)
    }

    fn equal(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>) -> Result<(AssignedInteger<N>, AssignedInteger<N>), Error> {
        let main_gate = self.main_gate();

        let mut a_updated_cells: Vec<Cell> = a.cells.clone();
        let mut b_updated_cells: Vec<Cell> = b.cells.clone();

        let a_integer: Option<Vec<N>> = a.value.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());
        let b_integer: Option<Vec<N>> = b.value.as_ref().map(|integer| integer.limbs().iter().map(|limb| limb.fe()).collect());

        for idx in 0..NUMBER_OF_LOOKUP_LIMBS {
            let a_new_cell = region.assign_advice(|| "a", main_gate.a, 0, || Ok(a_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;
            let b_new_cell = region.assign_advice(|| "b", main_gate.b, 0, || Ok(b_integer.as_ref().ok_or(Error::SynthesisError)?[idx]))?;

            region.assign_fixed(|| "a", main_gate.sa, 0, || Ok(N::one()))?;
            region.assign_fixed(|| "b", main_gate.sb, 0, || Ok(-N::one()))?;

            region.assign_fixed(|| "c", main_gate.sc, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "d", main_gate.sd, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "d_next", main_gate.sd_next, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "a * b", main_gate.s_mul, 0, || Ok(N::zero()))?;
            region.assign_fixed(|| "constant", main_gate.s_constant, 0, || Ok(N::zero()))?;

            region.constrain_equal(a.cells[idx], a_new_cell)?;
            region.constrain_equal(b.cells[idx], b_new_cell)?;

            a_updated_cells[idx] = a_new_cell;
            b_updated_cells[idx] = b_new_cell;
        }

        let a = a.clone_with_cells(a_updated_cells);
        let b = b.clone_with_cells(b_updated_cells);
        Ok((a, b))
    }
}

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub fn new(config: IntegerConfig, rns: Rns<W, N>) -> Self {
        IntegerChip { config, rns }
    }

    pub fn configure(meta: &mut ConstraintSystem<N>, range_config: &RangeConfig, main_gate_config: &MainGateConfig) -> IntegerConfig {
        IntegerConfig {
            range_config: range_config.clone(),
            main_gate_config: main_gate_config.clone(),
        }
    }

    fn range_chip(&self) -> RangeChip<N> {
        RangeChip::<N>::new(self.config.range_config.clone())
    }

    fn main_gate(&self) -> MainGateConfig {
        self.config.main_gate_config.clone()
    }
}

#[cfg(test)]
mod tests {

    use super::{IntegerChip, IntegerConfig, IntegerInstructions};
    use crate::circuit::main_gate::{MainGate, MainGateConfig};
    use crate::circuit::range::{RangeChip, RangeInstructions};
    use crate::rns::{Integer, Rns};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        integer_config: IntegerConfig,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitEquality<W: FieldExt, N: FieldExt> {
        integer_0: Option<Integer<N>>,
        integer_1: Option<Integer<N>>,
        rns: Rns<W, N>,
    }

    impl<W: FieldExt, N: FieldExt> TestCircuitEquality<N, W> {
        fn overflow_bit_lengths() -> Vec<usize> {
            vec![2, 3]
        }
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuitEquality<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = Self::overflow_bit_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_config = IntegerChip::<W, N>::configure(meta, &range_config, &main_gate_config);
            TestCircuitConfig {
                integer_config,
                main_gate_config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

            let integer_0 = layouter.assign_region(|| "region 0", |mut region| integer_chip.assign_input(&mut region, self.integer_0.clone()))?;
            let integer_1 = layouter.assign_region(|| "region 1", |mut region| integer_chip.assign_input(&mut region, self.integer_1.clone()))?;
            let (integer_0, integer_1) = layouter.assign_region(|| "region 2", |mut region| integer_chip.equal(&mut region, &integer_0, &integer_1))?;
            let (integer_0, integer_1) = layouter.assign_region(|| "region 3", |mut region| integer_chip.equal(&mut region, &integer_0, &integer_1))?;
            let (integer_0, integer_1) = layouter.assign_region(|| "region 4", |mut region| integer_chip.equal(&mut region, &integer_0, &integer_1))?;
            let (integer_0, integer_1) = layouter.assign_region(|| "region 5", |mut region| integer_chip.equal(&mut region, &integer_0, &integer_1))?;
            let (_, _) = layouter.assign_region(|| "region 6", |mut region| integer_chip.equal(&mut region, &integer_0, &integer_1))?;

            // TODO: think we should move table loading somewhere else?
            let range_chip = RangeChip::<N>::new(config.integer_config.range_config);
            range_chip.load_limb_range_table(&mut layouter)?;
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_equality_circuit() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;
        const BIT_LEN_LOOKUP_LIMB: usize = 16;
        const K: u32 = (BIT_LEN_LOOKUP_LIMB + 1) as u32;

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

    // #[derive(Clone, Debug)]
    // struct TestCircuitConfig {
    //     main_gate_config: MainGateConfig,
    //     integer_config: IntegerConfig,
    // }

    // #[derive(Default, Clone, Debug)]
    // struct TestCircuit<W: FieldExt, N: FieldExt> {
    //     integer: Option<Integer<N>>,
    //     reduced_integer: Option<Integer<N>>,
    //     rns: Rns<W, N>,
    // }

    // impl<W: FieldExt, N: FieldExt> TestCircuit<N, W> {
    //     fn overflow_bit_lengths() -> Vec<usize> {
    //         vec![2, 3]
    //     }
    // }

    // impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuit<W, N> {
    //     type Config = TestCircuitConfig;
    //     type FloorPlanner = SimpleFloorPlanner;

    //     fn without_witnesses(&self) -> Self {
    //         Self::default()
    //     }

    //     fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
    //         let main_gate_config = MainGate::<N>::configure(meta);
    //         let overflow_bit_lengths = Self::overflow_bit_lengths();
    //         let range_config = RangeChip::<N>::configure(meta, main_gate_config.clone(), overflow_bit_lengths);
    //         let integer_config = IntegerChip::<W, N>::configure(meta, range_config.clone(), main_gate_config.clone());
    //         TestCircuitConfig {
    //             integer_config,
    //             main_gate_config,
    //         }
    //     }

    //     fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
    //         let integer_chip = IntegerChip::<W, N>::new(config.integer_config.clone(), self.rns.clone());

    //         let integer_input = &layouter.assign_region(|| "region 0", |mut region| integer_chip.assign_input(&mut region, self.integer.clone()))?;
    //         let (_, reduced_integer) = &layouter.assign_region(|| "region 1", |mut region| integer_chip.reduce(&mut region, integer_input))?;
    //         let reduced_integer_input =
    //             &layouter.assign_region(|| "region 2", |mut region| integer_chip.assign_input(&mut region, self.reduced_integer.clone()))?;
    //         let _ = &layouter.assign_region(
    //             || "region 3",
    //             |mut region| integer_chip.equal(&mut region, reduced_integer, reduced_integer_input),
    //         )?;

    //         let range_chip = RangeChip::<N>::new(config.integer_config.range_config);
    //         range_chip.load_limb_range_table(&mut layouter)?;
    //         range_chip.load_overflow_range_tables(&mut layouter)?;

    //         Ok(())
    //     }
    // }
}
