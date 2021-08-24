use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Layouter, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn};
use halo2::poly::Rotation;
use std::marker::PhantomData;

use crate::wrong::{Common, Decomposed, Limb};
use crate::wrong::{LOOKUP_LIMB_SIZE, NUMBER_OF_LOOKUP_LIMBS};

#[derive(Clone, Debug)]
pub struct RangeConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
    s_range: Selector,

    small_range_table: TableColumn,
    lookup_limb_size: usize,
}

pub struct RangeChip<F: FieldExt> {
    config: RangeConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for RangeChip<F> {
    type Config = RangeConfig;
    type Loaded = ();
    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

pub trait RangeInstructions<F: FieldExt>: Chip<F> {
    fn range_limb(
        &self,
        region: &mut Region<'_, F>,
        limb: Option<&mut Limb<F>>,
    ) -> Result<(), Error>;

    fn load_small_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: FieldExt> RangeInstructions<F> for RangeChip<F> {
    fn range_limb(
        &self,
        region: &mut Region<'_, F>,
        limb: Option<&mut Limb<F>>,
    ) -> Result<(), Error> {
        let limb = limb.ok_or(Error::SynthesisError)?;

        let zero = F::zero();

        let offset_limb = 0;
        let offset_decomposed = offset_limb + 1;

        let decomposed: Vec<F> = Decomposed::<F>::new(
            limb.value(),
            self.config.lookup_limb_size,
            NUMBER_OF_LOOKUP_LIMBS,
        )
        .limbs
        .iter()
        .map(|limb| limb.fe())
        .collect();
        let limb_value = limb.fe();

        let _ = region.assign_advice(|| "limb zero a", self.config.a, offset_limb, || Ok(zero))?;
        let _ = region.assign_advice(|| "limb zero b", self.config.b, offset_limb, || Ok(zero))?;
        let _ = region.assign_advice(|| "limb zero c", self.config.c, offset_limb, || Ok(zero))?;
        let cell =
            region.assign_advice(|| "limb {}", self.config.d, offset_limb, || Ok(limb_value))?;

        self.config.s_range.enable(region, offset_decomposed)?;

        let _ = region.assign_advice(
            || "limb decomposed 0",
            self.config.a,
            offset_decomposed,
            || Ok(decomposed[0]),
        )?;
        let _ = region.assign_advice(
            || "limb decomposed 1",
            self.config.b,
            offset_decomposed,
            || Ok(decomposed[1]),
        )?;
        let _ = region.assign_advice(
            || "limb decomposed 2",
            self.config.c,
            offset_decomposed,
            || Ok(decomposed[2]),
        )?;
        let _ = region.assign_advice(
            || "limb decomposed 3",
            self.config.d,
            offset_decomposed,
            || Ok(decomposed[3]),
        )?;

        limb.cell = Some(cell);

        Ok(())
    }

    fn load_small_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let small_range_table_values: Vec<F> =
            (0..1 << LOOKUP_LIMB_SIZE).map(|e| F::from_u64(e)).collect();

        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in small_range_table_values.iter().enumerate() {
                    table.assign_cell(
                        || "small range table",
                        self.config.small_range_table,
                        index,
                        || Ok(value),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

impl<F: FieldExt> RangeChip<F> {
    pub fn new(config: RangeConfig) -> Self {
        RangeChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_columns: &[Column<Advice>],
        lookup_limb_size: usize,
    ) -> RangeConfig {
        assert_eq!(NUMBER_OF_LOOKUP_LIMBS, advice_columns.len());

        let a = advice_columns[0];
        let b = advice_columns[1];
        let c = advice_columns[2];
        let d = advice_columns[3];

        let s_range = meta.complex_selector();
        let small_range_table = meta.lookup_table_column();

        meta.lookup(|meta| {
            let a_ = meta.query_advice(a.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(a_ * s_range, small_range_table)]
        });

        meta.lookup(|meta| {
            let b_ = meta.query_advice(b.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(b_ * s_range, small_range_table)]
        });

        meta.lookup(|meta| {
            let c_ = meta.query_advice(c.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(c_ * s_range, small_range_table)]
        });

        meta.lookup(|meta| {
            let d_ = meta.query_advice(c.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(d_ * s_range, small_range_table)]
        });

        meta.create_gate("range", |meta| {
            let s_range = meta.query_selector(s_range);

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d_next = meta.query_advice(d, Rotation::prev());
            let d = meta.query_advice(d, Rotation::cur());

            let u1 = F::from_u64((1u64 << LOOKUP_LIMB_SIZE) as u64);
            let u2 = F::from_u64((1u64 << (2 * LOOKUP_LIMB_SIZE)) as u64);
            let u3 = F::from_u64((1u64 << (3 * LOOKUP_LIMB_SIZE)) as u64);

            let expression = s_range * (a + b * u1 + c * u2 + d * u3 - d_next);

            vec![expression]
        });

        RangeConfig {
            a,
            b,
            c,
            d,
            s_range,
            small_range_table,
            lookup_limb_size,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::wrong::{Limb, LOOKUP_LIMB_SIZE};

    use super::{RangeChip, RangeConfig, RangeInstructions};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::pasta::Fp;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        range_config: RangeConfig,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit<F: FieldExt> {
        limb: Option<Limb<F>>,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let a = meta.advice_column();
            let b = meta.advice_column();
            let c = meta.advice_column();
            let d = meta.advice_column();

            let range_config = RangeChip::<F>::configure(meta, &[a, b, c, d], LOOKUP_LIMB_SIZE);
            TestCircuitConfig { range_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let range_chip = RangeChip::<F>::new(config.range_config);

            let limb = self.limb.clone();
            let mut limb = limb.ok_or(Error::SynthesisError)?;

            layouter.assign_region(
                || "decomposition",
                |mut region| {
                    range_chip.range_limb(&mut region, Some(&mut limb))?;
                    Ok(())
                },
            )?;

            range_chip.load_small_range_table(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_range_circuit() {
        const K: u32 = (LOOKUP_LIMB_SIZE + 1) as u32;

        let limb = Some(Limb::from_fe(Fp::from_u64(0xffffffffffffffff)));
        let circuit = TestCircuit::<Fp> { limb };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));

        let limb = Some(Limb::from_fe(Fp::rand()));

        let circuit = TestCircuit::<Fp> { limb };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_ne!(prover.verify(), Ok(()));
    }
}
