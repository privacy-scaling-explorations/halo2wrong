use crate::circuit::main_gate::MainGateConfig;
use crate::rns::{Common, Decomposed, Limb};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Chip, Layouter, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector, TableColumn};
use halo2::poly::Rotation;
use std::marker::PhantomData;

pub(crate) const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

#[derive(Clone, Debug)]
pub struct RangeConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    s_range: Selector,
    s_overflow: Selector,

    sa: Column<Fixed>,
    sb: Column<Fixed>,
    sc: Column<Fixed>,
    sd: Column<Fixed>,
    sd_next: Column<Fixed>,
    s_mul: Column<Fixed>,
    s_constant: Column<Fixed>,

    limb_range_table: TableColumn,
    limb_bit_len: usize,
    overflow_range_table: TableColumn,
    overflow_bit_len: usize,
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
    fn range_limb(&self, region: &mut Region<'_, F>, limb: Option<&mut Limb<F>>) -> Result<Cell, Error>;
    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
    fn load_overflow_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: FieldExt> RangeInstructions<F> for RangeChip<F> {
    fn range_limb(&self, region: &mut Region<'_, F>, limb: Option<&mut Limb<F>>) -> Result<Cell, Error> {
        let limb = limb.ok_or(Error::SynthesisError)?;

        let limb_bit_len = self.config.limb_bit_len;
        let overflow_bit_len = self.config.overflow_bit_len;

        let has_overflow = overflow_bit_len == 0;

        let number_of_limbs = if has_overflow { NUMBER_OF_LOOKUP_LIMBS } else { NUMBER_OF_LOOKUP_LIMBS + 1 };

        let offset_limb = 0;
        let offset_overflow = offset_limb + 1;

        let decomposed = Decomposed::<F>::from_limb(limb, number_of_limbs, limb_bit_len);
        assert!((decomposed.value().bits() as usize) < NUMBER_OF_LOOKUP_LIMBS * limb_bit_len + overflow_bit_len);

        let decomposed: Vec<F> = decomposed.limbs.iter().map(|limb| limb.fe()).collect();

        let limb_value = limb.fe();
        let overflow_value = if has_overflow { decomposed[4] } else { F::zero() };
        let limb_wo_overflow_value = limb_value - overflow_value;

        self.config.s_range.enable(region, offset_limb)?;
        let _ = region.assign_advice(|| "limb decomposed 0", self.config.a, offset_limb, || Ok(decomposed[0]))?;
        let _ = region.assign_advice(|| "limb decomposed 1", self.config.b, offset_limb, || Ok(decomposed[1]))?;
        let _ = region.assign_advice(|| "limb decomposed 2", self.config.c, offset_limb, || Ok(decomposed[2]))?;
        let _ = region.assign_advice(|| "limb decomposed 3", self.config.d, offset_limb, || Ok(decomposed[3]))?;

        self.config.s_overflow.enable(region, offset_overflow)?;
        let cell = region.assign_advice(|| "limb zero a", self.config.a, offset_limb, || Ok(limb_value))?;
        let _ = region.assign_advice(|| "limb zero b", self.config.b, offset_limb, || Ok(overflow_value))?;
        // let _ = region.assign_advice(|| "limb zero c", self.config.c, offset_limb, || Ok(zero))?;
        let _ = region.assign_advice(|| "limb wo overflow", self.config.d, offset_limb, || Ok(limb_wo_overflow_value))?;

        // value = value_without_overflow + overflow
        region.assign_fixed(|| "a", self.config.sa, 0, || Ok(-F::one()))?;
        region.assign_fixed(|| "d", self.config.sc, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "b", self.config.sb, 0, || Ok(if has_overflow { F::one() } else { F::zero() }))?;

        // zeroize unused selectors
        region.assign_fixed(|| "c", self.config.sd, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "a * b", self.config.s_mul, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(F::zero()))?;

        Ok(cell)
    }

    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let bit_len = self.config.limb_bit_len;
        let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from_u64(e)).collect();

        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in table_values.iter().enumerate() {
                    table.assign_cell(|| "small range table", self.config.limb_range_table, index, || Ok(value))?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn load_overflow_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let bit_len = self.config.overflow_bit_len;
        let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from_u64(e)).collect();

        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in table_values.iter().enumerate() {
                    table.assign_cell(|| "small range table", self.config.limb_range_table, index, || Ok(value))?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

impl<F: FieldExt> RangeChip<F> {
    pub fn new(config: RangeConfig) -> Self {
        RangeChip { config, _marker: PhantomData }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>, main_gate_config: MainGateConfig, limb_bit_len: usize, overflow_bit_len: usize) -> RangeConfig {
        let a = main_gate_config.a;
        let b = main_gate_config.b;
        let c = main_gate_config.c;
        let d = main_gate_config.d;

        let s_range = meta.complex_selector();
        let s_overflow = meta.complex_selector();
        let limb_range_table = meta.lookup_table_column();
        let overflow_range_table = meta.lookup_table_column();

        meta.lookup(|meta| {
            let a_ = meta.query_advice(a.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(a_ * s_range, limb_range_table)]
        });

        meta.lookup(|meta| {
            let b_ = meta.query_advice(b.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(b_ * s_range, limb_range_table)]
        });

        meta.lookup(|meta| {
            let c_ = meta.query_advice(c.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(c_ * s_range, limb_range_table)]
        });

        meta.lookup(|meta| {
            let d_ = meta.query_advice(d.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(d_ * s_range, limb_range_table)]
        });

        if overflow_bit_len > 0 {
            meta.lookup(|meta| {
                let b_ = meta.query_advice(b.into(), Rotation::cur());
                let s_overflow = meta.query_selector(s_overflow);
                vec![(b_ * s_overflow, overflow_range_table)]
            });
        }

        meta.create_gate("range", |meta| {
            let s_range = meta.query_selector(s_range);

            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d_next = meta.query_advice(d, Rotation::next());
            let d = meta.query_advice(d, Rotation::cur());

            // NOTICE: we could also use main gate selectors to combine limbs.
            let u1 = F::from_u64((1u64 << limb_bit_len) as u64);
            let u2 = F::from_u64((1u64 << (2 * limb_bit_len)) as u64);
            let u3 = F::from_u64((1u64 << (3 * limb_bit_len)) as u64);

            let expression = s_range * (a + b * u1 + c * u2 + d * u3 - d_next);

            vec![expression]
        });

        let sa = main_gate_config.sa;
        let sb = main_gate_config.sb;
        let sc = main_gate_config.sc;
        let sd = main_gate_config.sd;
        let sd_next = main_gate_config.sd_next;
        let s_mul = main_gate_config.s_mul;
        let s_constant = main_gate_config.s_constant;

        RangeConfig {
            a,
            b,
            c,
            d,

            s_range,
            s_overflow,

            sa,
            sb,
            sc,
            sd,
            sd_next,
            s_mul,
            s_constant,

            limb_range_table,
            overflow_range_table,
            limb_bit_len,
            overflow_bit_len,
        }
    }
}

// #[cfg(test)]
// mod tests {

//     use crate::circuit::main_gate::MainGate;
//     use crate::rns::{Limb, Rns, BIT_LEN_LIMB};

//     use super::{RangeChip, RangeConfig, RangeInstructions};
//     use halo2::arithmetic::FieldExt;
//     use halo2::circuit::{Layouter, SimpleFloorPlanner};
//     use halo2::dev::MockProver;
//     use halo2::pasta::Fp;
//     use halo2::plonk::{Circuit, ConstraintSystem, Error};

//     #[derive(Clone, Debug)]
//     struct TestCircuitConfig {
//         range_config: RangeConfig,
//     }

//     #[derive(Default, Clone, Debug)]
//     struct TestCircuit<F: FieldExt> {
//         limb: Option<Limb<F>>,
//     }

//     impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
//         type Config = TestCircuitConfig;
//         type FloorPlanner = SimpleFloorPlanner;

//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }

//         fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//             let main_gate_config = MainGate::<F>::configure(meta);
//             let range_config = RangeChip::<F>::configure(meta, main_gate_config, BIT_LEN_LIMB, 0);
//             TestCircuitConfig { range_config }
//         }

//         fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
//             let range_chip = RangeChip::<F>::new(config.range_config);

//             let limb = self.limb.clone();
//             let mut limb = limb.ok_or(Error::SynthesisError)?;

//             layouter.assign_region(
//                 || "decomposition",
//                 |mut region| {
//                     range_chip.range_limb(&mut region, Some(&mut limb))?;
//                     Ok(())
//                 },
//             )?;

//             range_chip.load_small_range_table(&mut layouter)?;

//             Ok(())
//         }
//     }

//     #[test]
//     fn test_range_circuit() {
//         const K: u32 = (BIT_LEN_LOOKUP_LIMB + 1) as u32;

//         let limb = Some(Limb::from_fe(Fp::from_u64(0xffffffffffffffff)));
//         let circuit = TestCircuit::<Fp> { limb };

//         let prover = match MockProver::run(K, &circuit, vec![]) {
//             Ok(prover) => prover,
//             Err(e) => panic!("{:#?}", e),
//         };

//         assert_eq!(prover.verify(), Ok(()));

//         let limb = Some(Limb::from_fe(Fp::rand()));

//         let circuit = TestCircuit::<Fp> { limb };

//         let prover = match MockProver::run(K, &circuit, vec![]) {
//             Ok(prover) => prover,
//             Err(e) => panic!("{:#?}", e),
//         };
//         assert_ne!(prover.verify(), Ok(()));
//     }
// }
