use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};
use std::marker::PhantomData;

use crate::main_gate::MainGateConfig;

use super::range::{RangeChip, RangeConfig, RangeInstructions};
use super::{Integer, LOOKUP_LIMB_SIZE};

#[derive(Clone, Debug)]
pub struct IntegerConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

pub struct IntegerChip<F: FieldExt> {
    config: IntegerConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for IntegerChip<F> {
    type Config = IntegerConfig;
    type Loaded = ();
    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

trait IntegerInstructions<Wrong: FieldExt, Native: FieldExt>: Chip<Native> {
    fn assign_integer(
        &self,
        region: &mut Region<'_, Native>,
        integer: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<(), Error>;

    fn assert_equal(
        &self,
        region: &mut Region<'_, Native>,
        integer_0: Option<&Integer<Wrong, Native>>,
        integer_1: Option<&Integer<Wrong, Native>>,
    ) -> Result<(), Error>;

    fn add(
        &self,
        region: &mut Region<'_, Native>,
        integer_0: Option<&Integer<Wrong, Native>>,
        integer_1: Option<&Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error>;

    fn mul(
        &self,
        region: &mut Region<'_, Native>,
        integer_0: Option<&Integer<Wrong, Native>>,
        integer_1: Option<&Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error>;
}

impl<Wrong: FieldExt, Native: FieldExt> IntegerInstructions<Wrong, Native> for IntegerChip<Native> {
    fn assign_integer(
        &self,
        region: &mut Region<'_, Native>,
        integer: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<(), Error> {
        let range_chip = self.range_chip();

        let integer = integer.ok_or(Error::SynthesisError)?;
        for limb in integer.decomposed.limbs.iter_mut() {
            range_chip.range_limb(region, Some(limb)).unwrap();
        }
        Ok(())
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, Native>,
        integer_0: Option<&Integer<Wrong, Native>>,
        integer_1: Option<&Integer<Wrong, Native>>,
    ) -> Result<(), Error> {
        let limbs_0 = &integer_0.ok_or(Error::SynthesisError)?.decomposed.limbs;
        let limbs_1 = &integer_1.ok_or(Error::SynthesisError)?.decomposed.limbs;

        for (limb_0, limb_1) in limbs_0.iter().zip(limbs_1.iter()) {
            let cell_0 = limb_0.cell.ok_or(Error::SynthesisError)?;
            let cell_1 = limb_1.cell.ok_or(Error::SynthesisError)?;
            region.constrain_equal(cell_0, cell_1)?;
        }
        Ok(())
    }

    fn add(
        &self,
        _: &mut Region<'_, Native>,
        _: Option<&Integer<Wrong, Native>>,
        _: Option<&Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error> {
        unimplemented!();
    }

    fn mul(
        &self,
        _: &mut Region<'_, Native>,
        _: Option<&Integer<Wrong, Native>>,
        _: Option<&Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error> {
        unimplemented!();
    }
}

impl<F: FieldExt> IntegerChip<F> {
    pub fn new(config: IntegerConfig) -> Self {
        IntegerChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    ) -> IntegerConfig {
        IntegerConfig {
            main_gate_config,
            range_config,
        }
    }

    fn range_chip(&self) -> RangeChip<F> {
        RangeChip::<F>::new(self.config.range_config.clone())
    }
}

#[cfg(test)]
mod tests {

    use crate::main_gate::MainGate;
    use crate::wrong::range::{RangeChip, RangeInstructions};
    use crate::wrong::{Integer, Rns, LOOKUP_LIMB_SIZE};

    use super::{IntegerChip, IntegerConfig, IntegerInstructions};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::pasta::{Fp, Fq};
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        integer_config: IntegerConfig,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit<W: FieldExt, N: FieldExt> {
        a: Option<Integer<W, N>>,
        b: Option<Integer<W, N>>,
    }

    impl<W: FieldExt, N: FieldExt> Circuit<N> for TestCircuit<W, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            let main_gate_config = MainGate::<N>::configure(meta);
            let range_config = RangeChip::<N>::configure(meta, main_gate_config.clone(), LOOKUP_LIMB_SIZE);
            let integer_config = IntegerChip::<N>::configure(meta, main_gate_config, range_config);
            TestCircuitConfig { integer_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let integer_chip = IntegerChip::<N>::new(config.integer_config);

            let mut a = self.a.clone().ok_or(Error::SynthesisError)?;
            let mut b = self.b.clone().ok_or(Error::SynthesisError)?;

            layouter.assign_region(
                || "assign a",
                |mut region| {
                    integer_chip.assign_integer(&mut region, Some(&mut a))?;
                    Ok(())
                },
            )?;

            let range_chip = integer_chip.range_chip();
            range_chip.load_small_range_table(&mut layouter)?;

            layouter.assign_region(
                || "assign b",
                |mut region| {
                    integer_chip.assign_integer(&mut region, Some(&mut b))?;
                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "assign b",
                |mut region| {
                    integer_chip.assert_equal(&mut region, Some(&a), Some(&b))?;
                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_integer_circuit() {
        const K: u32 = (LOOKUP_LIMB_SIZE + 1) as u32;
        let rns = Rns::default();

        let a = rns.rand();
        let b = a.clone();

        let circuit = TestCircuit::<Fp, Fq> {
            a: Some(a),
            b: Some(b),
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));

        let a = rns.rand();
        let b = rns.rand();

        let circuit = TestCircuit::<Fp, Fq> {
            a: Some(a),
            b: Some(b),
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_ne!(prover.verify(), Ok(()));
    }
}
