use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Chip, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct BitnessConfig {
    d: Column<Advice>,
    s_bitness: Selector,
}

pub struct BitnessChip<F: FieldExt> {
    config: BitnessConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for BitnessChip<F> {
    type Config = BitnessConfig;
    type Loaded = ();
    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

pub trait BitnessInstructions<F: FieldExt>: Chip<F> {
    fn constraint_bit(&self, region: &mut Region<'_, F>, el: Option<F>) -> Result<Cell, Error>;
}

impl<F: FieldExt> BitnessInstructions<F> for BitnessChip<F> {
    fn constraint_bit(&self, region: &mut Region<'_, F>, el: Option<F>) -> Result<Cell, Error> {
        let el = el.ok_or(Error::SynthesisError)?;
        self.config.s_bitness.enable(region, 0)?;
        Ok(region.assign_advice(|| "limb {}", self.config.d, 0, || Ok(el))?)
    }
}

impl<F: FieldExt> BitnessChip<F> {
    pub fn new(config: BitnessConfig) -> Self {
        BitnessChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>, d: Column<Advice>) -> BitnessConfig {
        let s_bitness = meta.selector();

        meta.create_gate("range", |meta| {
            let s_bitness = meta.query_selector(s_bitness);
            let d = meta.query_advice(d, Rotation::cur());

            let one = F::one();

            let expression = s_bitness * (d.clone() * (d - Expression::Constant(one)));

            vec![expression]
        });

        BitnessConfig { d, s_bitness }
    }
}

#[cfg(test)]
mod tests {

    use super::{BitnessChip, BitnessConfig, BitnessInstructions};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::pasta::Fp;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        bitness_config: BitnessConfig,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit<F: FieldExt> {
        a: F,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let d = meta.advice_column();
            let bitness_config = BitnessChip::<F>::configure(meta, d);
            TestCircuitConfig { bitness_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let bitness_chip = BitnessChip::<F>::new(config.bitness_config);

            let el = self.a;
            layouter.assign_region(
                || "bitness check",
                |mut region| {
                    bitness_chip.constraint_bit(&mut region, Some(el))?;
                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_range_circuit() {
        const K: u32 = 5;

        let a = Fp::one();
        let circuit = TestCircuit::<Fp> { a };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));

        let a = Fp::zero();
        let circuit = TestCircuit::<Fp> { a };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));

        let a = Fp::one() + Fp::one();
        let circuit = TestCircuit::<Fp> { a };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_ne!(prover.verify(), Ok(()));
    }
}
