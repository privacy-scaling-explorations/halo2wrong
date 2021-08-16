#![allow(clippy::many_single_char_names)]
#![allow(clippy::op_ref)]

use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Layouter, SimpleFloorPlanner};
use halo2::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector, TableColumn};
use halo2::poly::Rotation;
use std::marker::PhantomData;

#[cfg(test)]
mod tests {

    use super::MyCircuit;
    use halo2::arithmetic::FieldExt;
    use halo2::dev::MockProver;
    use halo2::pasta::Fp;

    #[test]
    fn test_range() {
        const K: u32 = 4;
        // let params: Params<EqAffine> = Params::new(K);

        let a = Fp::from_u64(0xff);
        let b = Fp::from_u64(0xaa);
        let instance = Fp::zero();
        let lookup_table = vec![a, b, instance];

        let circuit: MyCircuit<Fp> = MyCircuit {
            a: Some(a),
            b: Some(b),
            lookup_table,
        };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        // println!("{:?}", prover);
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
    sa: Selector,
    sb: Selector,
    table: TableColumn,
}

trait RangeInstructions<FF: FieldExt>: Chip<FF> {
    fn assign<F>(&self, layouter: &mut impl Layouter<FF>, f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<(FF, FF), Error>;
    fn lookup_table(&self, layouter: &mut impl Layouter<FF>, values: &[FF]) -> Result<(), Error>;
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
    fn assign<F>(&self, layouter: &mut impl Layouter<FF>, mut f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<(FF, FF), Error>,
    {
        layouter.assign_region(
            || "assign cells",
            |mut region| {
                let mut value = None;

                self.config.sa.enable(&mut region, 0)?;
                self.config.sb.enable(&mut region, 0)?;

                let _ = region.assign_advice(
                    || "a",
                    self.config.a,
                    0,
                    || {
                        value = Some(f()?);
                        Ok(value.ok_or(Error::SynthesisError)?.0)
                    },
                )?;

                let _ = region.assign_advice(
                    || "b",
                    self.config.b,
                    0,
                    || Ok(value.ok_or(Error::SynthesisError)?.1),
                )?;
                Ok(())
            },
        )
    }

    fn lookup_table(&self, layouter: &mut impl Layouter<FF>, values: &[FF]) -> Result<(), Error> {
        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in values.iter().enumerate() {
                    table.assign_cell(|| "table", self.config.table, index, || Ok(value))?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[derive(Clone)]
struct MyCircuit<F: FieldExt> {
    a: Option<F>,
    b: Option<F>,
    lookup_table: Vec<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = RangeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: None,
            b: None,
            lookup_table: self.lookup_table.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> RangeConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();

        let sa = meta.complex_selector();
        let sb = meta.complex_selector();
        let table = meta.lookup_table_column();

        meta.lookup(|meta| {
            let a_ = meta.query_advice(a.into(), Rotation::cur());
            let b_ = meta.query_advice(b.into(), Rotation::cur());
            let sa = meta.query_selector(sa);
            let sb = meta.query_selector(sb);

            vec![(a_ * sa, table), (b_ * sb, table)]
        });

        RangeConfig {
            a,
            b,
            sa,
            sb,
            table,
        }
    }

    fn synthesize(&self, config: RangeConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let cs = RangePlonk::new(config);

        for _ in 0..1 {
            let mut a = None;
            let mut b = None;

            cs.assign(&mut layouter, || {
                a = self.a.map(|a| a);
                b = self.b.map(|b| b);

                Ok((
                    a.ok_or(Error::SynthesisError)?,
                    b.ok_or(Error::SynthesisError)?,
                ))
            })?;
        }

        cs.lookup_table(&mut layouter, &self.lookup_table)?;

        Ok(())
    }
}
