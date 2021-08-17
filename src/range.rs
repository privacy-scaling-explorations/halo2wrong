#![allow(clippy::many_single_char_names)]
#![allow(clippy::op_ref)]

use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Layouter, SimpleFloorPlanner};
use halo2::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector, TableColumn};
use halo2::poly::Rotation;
use std::marker::PhantomData;

// | A   | B   | C   | D       |
// | --- | --- | --- | ------- |
// |     |     |     | d_(i-1) |
// | a_i | b_i | c_i | d_i     |

// __Goal__:

// * `a_i + b_i + c_i + d_i == d_(i-1)`
// * `a_i < 2^4`, `b_i < 2^4`, `c_i < 2^4`, `d_i < 2^4`

#[cfg(test)]
mod tests {

    use super::MyCircuit;
    use halo2::arithmetic::FieldExt;
    use halo2::dev::MockProver;
    use halo2::pasta::Fp;

    #[test]
    fn test_range() {
        const K: u32 = 6;
        const BASE: usize = 4;

        let small_range_table: Vec<Fp> = (0..1 << BASE).map(|e| Fp::from_u64(e)).collect();

        let integer = Fp::from_u64(10);
        let limb_0 = Fp::from_u64(1);
        let limb_1 = Fp::from_u64(2);
        let limb_2 = Fp::from_u64(3);
        let limb_3 = Fp::from_u64(4);

        let circuit: MyCircuit<Fp> = MyCircuit {
            integer: Some(integer),
            limb_0: Some(limb_0),
            limb_1: Some(limb_1),
            limb_2: Some(limb_2),
            limb_3: Some(limb_3),
            small_range_table,
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        println!("{:?}", prover);
        assert_eq!(prover.verify(), Ok(()));
    }
}

/// This represents an advice column at a certain row in the ConstraintSystem
#[derive(Copy, Clone, Debug)]
pub struct Variable(Column<Advice>, usize);

#[derive(Clone, Debug)]
struct RangeConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,
    s_range: Selector,
    small_range_table: TableColumn,
}

trait RangeInstructions<FF: FieldExt>: Chip<FF> {
    fn small_range_table(
        &self,
        layouter: &mut impl Layouter<FF>,
        values: &[FF],
    ) -> Result<(), Error>;
    fn integer<F>(&self, layouter: &mut impl Layouter<FF>, f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<FF, Error>;
    fn decomposition<F>(&self, layouter: &mut impl Layouter<FF>, f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<(FF, FF, FF, FF), Error>;
}

struct RangePlonk<F: FieldExt> {
    config: RangeConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for RangePlonk<F> {
    type Config = RangeConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<FF: FieldExt> RangePlonk<FF> {
    fn new(config: RangeConfig) -> Self {
        RangePlonk {
            config,
            _marker: PhantomData,
        }
    }
}

impl<FF: FieldExt> RangeInstructions<FF> for RangePlonk<FF> {
    fn integer<F>(&self, layouter: &mut impl Layouter<FF>, mut f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<FF, Error>,
    {
        layouter.assign_region(
            || "assign integer",
            |mut region| {
                let mut value = None;
                let _ = region.assign_advice(
                    || "integer",
                    self.config.d,
                    0,
                    || {
                        value = Some(f()?);
                        Ok(value.ok_or(Error::SynthesisError)?)
                    },
                )?;
                Ok(())
            },
        )
    }

    fn decomposition<F>(&self, layouter: &mut impl Layouter<FF>, mut f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<(FF, FF, FF, FF), Error>,
    {
        layouter.assign_region(
            || "assign decomposition",
            |mut region| {
                self.config.s_range.enable(&mut region, 0)?;

                let mut value = None;
                let _ = region.assign_advice(
                    || "limb 0",
                    self.config.a,
                    0,
                    || {
                        value = Some(f()?);
                        Ok(value.ok_or(Error::SynthesisError)?.0)
                    },
                )?;
                let _ = region.assign_advice(
                    || "limb 1",
                    self.config.b,
                    0,
                    || Ok(value.ok_or(Error::SynthesisError)?.1),
                )?;
                let _ = region.assign_advice(
                    || "limb 2",
                    self.config.c,
                    0,
                    || Ok(value.ok_or(Error::SynthesisError)?.2),
                )?;
                let _ = region.assign_advice(
                    || "limb 3",
                    self.config.d,
                    0,
                    || Ok(value.ok_or(Error::SynthesisError)?.3),
                )?;
                Ok(())
            },
        )
    }

    fn small_range_table(
        &self,
        layouter: &mut impl Layouter<FF>,
        values: &[FF],
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in values.iter().enumerate() {
                    table.assign_cell(
                        || "table 1",
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

#[derive(Clone)]
struct MyCircuit<F: FieldExt> {
    integer: Option<F>,
    limb_0: Option<F>,
    limb_1: Option<F>,
    limb_2: Option<F>,
    limb_3: Option<F>,
    small_range_table: Vec<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = RangeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            integer: None,
            limb_0: None,
            limb_1: None,
            limb_2: None,
            limb_3: None,
            small_range_table: self.small_range_table.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> RangeConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();

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
            let d_prev = meta.query_advice(d, Rotation::prev());
            let d = meta.query_advice(d, Rotation::cur());

            let expression = s_range * (a + b + c + d - d_prev);
            vec![expression]
        });

        RangeConfig {
            a,
            b,
            c,
            d,
            s_range,
            small_range_table,
        }
    }

    fn synthesize(&self, config: RangeConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let cs = RangePlonk::new(config);

        cs.integer(&mut layouter, || {
            Ok(self.integer.ok_or(Error::SynthesisError)?)
        })?;

        cs.decomposition(&mut layouter, || {
            Ok((
                self.limb_0.ok_or(Error::SynthesisError)?,
                self.limb_1.ok_or(Error::SynthesisError)?,
                self.limb_2.ok_or(Error::SynthesisError)?,
                self.limb_3.ok_or(Error::SynthesisError)?,
            ))
        })?;

        cs.small_range_table(&mut layouter, &self.small_range_table)?;

        Ok(())
    }
}
