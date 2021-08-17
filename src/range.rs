#![allow(clippy::many_single_char_names)]
#![allow(clippy::op_ref)]

use halo2::arithmetic::FieldExt;
use halo2::circuit::Layouter;
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn};
use halo2::poly::Rotation;
use std::marker::PhantomData;

// | A   | B   | C   | D       |
// | --- | --- | --- | ------- |
// |     |     |     | d_(i-1) |
// | a_i | b_i | c_i | d_i     |

// __Goal__:
// b: bit len of a limb

// * `a_i + b_i << b + c_i << 2b + d_i << 3b == d_(i-1)`
// * `a_i < 2^b`, `b_i < 2^b`, `c_i < 2^b`, `d_i < 2^b`

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

trait RangeInstructions<FF: FieldExt> {
    fn load(&self, layouter: &mut impl Layouter<FF>) -> Result<(), Error>;
    fn decomposition<F>(&self, layouter: &mut impl Layouter<FF>, f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<(FF, FF, FF, FF, FF), Error>;
    fn no_op(&self, layouter: &mut impl Layouter<FF>) -> Result<(), Error>;
}

pub struct RangeChip<F: FieldExt, const BASE: usize> {
    config: RangeConfig,
    small_range_table: Vec<F>,
    _marker: PhantomData<F>,
}

impl<FF: FieldExt, const BASE: usize> RangeInstructions<FF> for RangeChip<FF, BASE> {
    fn decomposition<F>(&self, layouter: &mut impl Layouter<FF>, mut f: F) -> Result<(), Error>
    where
        F: FnMut() -> Result<(FF, FF, FF, FF, FF), Error>,
    {
        layouter.assign_region(
            || "assign decomposition",
            |mut region| {
                let offset = 0;

                self.config.s_range.enable(&mut region, offset)?;

                let mut value = None;

                let _ = region.assign_advice(
                    || "integer",
                    self.config.d,
                    offset - 1,
                    || {
                        value = Some(f()?);
                        Ok(value.ok_or(Error::SynthesisError)?.0)
                    },
                )?;

                let _ = region.assign_advice(
                    || "limb 0",
                    self.config.a,
                    offset,
                    || {
                        value = Some(f()?);
                        Ok(value.ok_or(Error::SynthesisError)?.1)
                    },
                )?;
                let _ = region.assign_advice(
                    || "limb 1",
                    self.config.b,
                    offset,
                    || Ok(value.ok_or(Error::SynthesisError)?.2),
                )?;
                let _ = region.assign_advice(
                    || "limb 2",
                    self.config.c,
                    offset,
                    || Ok(value.ok_or(Error::SynthesisError)?.3),
                )?;
                let _ = region.assign_advice(
                    || "limb 3",
                    self.config.d,
                    offset,
                    || Ok(value.ok_or(Error::SynthesisError)?.4),
                )?;
                Ok(())
            },
        )
    }

    fn no_op(&self, layouter: &mut impl Layouter<FF>) -> Result<(), Error> {
        layouter.assign_region(
            || "no op",
            |mut region| {
                let zero = FF::zero();
                let _ = region.assign_advice(|| "0 a", self.config.a, 0, || Ok(zero))?;
                let _ = region.assign_advice(|| "0 b", self.config.b, 0, || Ok(zero))?;
                let _ = region.assign_advice(|| "0 c", self.config.c, 0, || Ok(zero))?;

                Ok(())
            },
        )
    }

    fn load(&self, layouter: &mut impl Layouter<FF>) -> Result<(), Error> {
        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in self.small_range_table.iter().enumerate() {
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

impl<F: FieldExt, const BASE: usize> RangeChip<F, BASE> {
    fn new(config: RangeConfig) -> Self {
        let small_range_table: Vec<F> = (0..1 << BASE).map(|e| F::from_u64(e)).collect();

        RangeChip {
            config,
            small_range_table,
            _marker: PhantomData,
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
            let d_next = meta.query_advice(d, Rotation::prev());
            let d = meta.query_advice(d, Rotation::cur());

            let u1 = F::from_u64((1 << BASE) as u64);
            let u2 = F::from_u64((1 << (2 * BASE)) as u64);
            let u3 = F::from_u64((1 << (3 * BASE)) as u64);

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
        }
    }
}

#[cfg(test)]
mod tests {

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

    #[derive(Default)]
    struct TestCircuit<F: FieldExt, const BASE: usize> {
        integer: Option<F>,
    }

    impl<F: FieldExt, const BASE: usize> Circuit<F> for TestCircuit<F, BASE> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let range_config = RangeChip::<F, BASE>::configure(meta);
            TestCircuitConfig { range_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let decompose = |e: F, base: usize| -> (F, F, F, F) {
                use num_bigint::BigUint;
                const LIMB_SIZE: usize = 4;
                let mut e = BigUint::from_bytes_le(&e.to_bytes()[..]);
                let n = (1 << base) as usize;
                let mut limbs: Vec<F> = Vec::new();
                for _ in 0..LIMB_SIZE {
                    let u = BigUint::from(n - 1) & e.clone();
                    let u = F::from_str(&u.to_str_radix(10)).unwrap();
                    limbs.push(u);
                    e = e >> base;
                }
                let a0 = limbs[0];
                let a1 = limbs[1];
                let a2 = limbs[2];
                let a3 = limbs[3];
                (a0, a1, a2, a3)
            };

            let range_chip = RangeChip::<F, BASE>::new(config.range_config);
            range_chip.load(&mut layouter)?;

            range_chip.no_op(&mut layouter)?;

            let integer = self.integer.ok_or(Error::SynthesisError)?;
            let limbs = decompose(integer, BASE);

            range_chip.decomposition(&mut layouter, || {
                Ok((integer, limbs.0, limbs.1, limbs.2, limbs.3))
            })?;

            Ok(())
        }
    }

    #[test]
    fn test_range() {
        const K: u32 = 5;
        const BASE: usize = 4;

        let integer = Some(Fp::from_u64(21554));
        let circuit = TestCircuit::<Fp, BASE> { integer };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        // println!("{:?}", prover);
        assert_eq!(prover.verify(), Ok(()));

        let integer = Some(Fp::from_u64(1 << (BASE * 4)));
        let circuit = TestCircuit::<Fp, BASE> { integer };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_ne!(prover.verify(), Ok(()));
    }
}
