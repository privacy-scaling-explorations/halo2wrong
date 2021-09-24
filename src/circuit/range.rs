use crate::circuit::integer::AssignedLimb;
use crate::circuit::main_gate::MainGateConfig;
use crate::rns::{Common, Decomposed, Limb};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Layouter, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector, TableColumn};
use halo2::poly::Rotation;

pub(crate) const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

// TODO: give circuit dev to control overflow selector

#[derive(Clone, Debug)]
pub struct RangeConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    s_range: Selector,
    limb_range_table: TableColumn,
    s_overflow: Selector,
    overflow_range_table: TableColumn,

    sa: Column<Fixed>,
    sb: Column<Fixed>,
    sc: Column<Fixed>,
    sd: Column<Fixed>,
    sd_next: Column<Fixed>,
    s_mul: Column<Fixed>,
    s_constant: Column<Fixed>,
}

pub struct RangeChip<F: FieldExt> {
    config: RangeConfig,

    limb_bit_len: usize,
    overflow_bit_len: usize,

    left_shifter_r: F,
    left_shifter_2r: F,
    left_shifter_3r: F,
    left_shifter_4r: F,
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
    fn range_limb(&self, region: &mut Region<'_, F>, limb: &AssignedLimb<F>) -> Result<AssignedLimb<F>, Error>;
    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
    fn load_overflow_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: FieldExt> RangeInstructions<F> for RangeChip<F> {
    fn range_limb(&self, region: &mut Region<'_, F>, limb: &AssignedLimb<F>) -> Result<AssignedLimb<F>, Error> {
        let limb_bit_len = self.limb_bit_len;
        let overflow_bit_len = self.overflow_bit_len;
        let has_overflow = overflow_bit_len != 0;
        let number_of_limbs = if has_overflow { NUMBER_OF_LOOKUP_LIMBS + 1 } else { NUMBER_OF_LOOKUP_LIMBS };
        let offset_limb = 0;
        let offset_overflow = offset_limb + 1;

        let value = limb.value.as_ref().map(|value| value);
        let decomposed = value.map(|limb| Decomposed::<F>::from_limb(&limb.clone(), number_of_limbs, limb_bit_len));

        let get_limb = |idx: usize| -> Result<F, Error> {
            // let decomposed = decomposed.clone();
            let decomposed = decomposed.as_ref().ok_or(Error::SynthesisError)?;
            Ok(decomposed.limbs[idx].fe())
        };

        let get_value = || -> Result<F, Error> {
            let value = value.ok_or(Error::SynthesisError)?;
            Ok(value.fe())
        };

        let get_overflow_value = || -> Result<F, Error> {
            let decomposed = decomposed.as_ref().ok_or(Error::SynthesisError)?;
            Ok(if has_overflow {
                decomposed.limbs[number_of_limbs - 1].fe()
            } else {
                F::zero()
            })
        };

        let get_value_wo_overflow = || -> Result<F, Error> {
            let value = get_value()?;
            let overflow_value = get_overflow_value()?;
            Ok(value - overflow_value * self.left_shifter_4r)
        };

        {
            self.config.s_range.enable(region, offset_limb)?;

            let _ = region.assign_advice(|| "limb decomposed 0", self.config.a, offset_limb, || get_limb(0))?;
            let _ = region.assign_advice(|| "limb decomposed 1", self.config.b, offset_limb, || get_limb(1))?;
            let _ = region.assign_advice(|| "limb decomposed 2", self.config.c, offset_limb, || get_limb(2))?;
            let _ = region.assign_advice(|| "limb decomposed 3", self.config.d, offset_limb, || get_limb(3))?;

            region.assign_fixed(|| "a", self.config.sa, offset_limb, || Ok(F::one()))?;
            region.assign_fixed(|| "b", self.config.sb, offset_limb, || Ok(self.left_shifter_r))?;
            region.assign_fixed(|| "c", self.config.sc, offset_limb, || Ok(self.left_shifter_2r))?;
            region.assign_fixed(|| "d", self.config.sd, offset_limb, || Ok(self.left_shifter_3r))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, offset_limb, || Ok(-F::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "a * b", self.config.s_mul, offset_limb, || Ok(F::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, offset_limb, || Ok(F::zero()))?;
        }

        let cur_cell = {
            if has_overflow {
                self.config.s_overflow.enable(region, offset_overflow)?;
            }

            let cell = region.assign_advice(|| "limb value", self.config.a, offset_overflow, || get_value())?;
            let _ = region.assign_advice(|| "overflow value", self.config.b, offset_overflow, || get_overflow_value())?;
            let _ = region.assign_advice(|| "zero", self.config.c, offset_overflow, || Ok(F::zero()))?;
            let _ = region.assign_advice(|| "limb w/o overflow", self.config.d, offset_overflow, || get_value_wo_overflow())?;

            region.assign_fixed(|| "a", self.config.sa, offset_overflow, || Ok(-F::one()))?;
            region.assign_fixed(
                || "b",
                self.config.sb,
                offset_overflow,
                || Ok(if has_overflow { self.left_shifter_4r } else { F::zero() }),
            )?;
            region.assign_fixed(|| "d", self.config.sd, offset_overflow, || Ok(F::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "c", self.config.sc, offset_overflow, || Ok(F::zero()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, offset_overflow, || Ok(F::zero()))?;
            region.assign_fixed(|| "a * b", self.config.s_mul, offset_overflow, || Ok(F::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, offset_overflow, || Ok(F::zero()))?;
            cell
        };

        let prev_cell = limb.cell.clone();

        region.constrain_equal(cur_cell, prev_cell)?;

        Ok(limb.clone_with_cell(cur_cell))
    }

    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let bit_len = self.limb_bit_len;
        let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from_u64(e)).collect();

        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in table_values.iter().enumerate() {
                    table.assign_cell(|| "limb range table", self.config.limb_range_table, index, || Ok(value))?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn load_overflow_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let bit_len = self.overflow_bit_len;
        let has_overflow = bit_len != 0;

        if has_overflow {
            let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from_u64(e)).collect();

            layouter.assign_table(
                || "",
                |mut table| {
                    for (index, &value) in table_values.iter().enumerate() {
                        table.assign_cell(|| "overflow table", self.config.overflow_range_table, index, || Ok(value))?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }
}

impl<F: FieldExt> RangeChip<F> {
    pub fn new(config: RangeConfig, limb_bit_len: usize, overflow_bit_len: usize) -> Self {
        let two = F::from_u64(2);
        let left_shifter_r = two.pow(&[limb_bit_len as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[(limb_bit_len * 2) as u64, 0, 0, 0]);
        let left_shifter_3r = two.pow(&[(limb_bit_len * 3) as u64, 0, 0, 0]);
        let left_shifter_4r = two.pow(&[(limb_bit_len * 4) as u64, 0, 0, 0]);

        RangeChip {
            config,

            limb_bit_len,
            overflow_bit_len,

            left_shifter_r,
            left_shifter_2r,
            left_shifter_3r,
            left_shifter_4r,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>, main_gate_config: MainGateConfig, has_overflow: bool) -> RangeConfig {
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

        if has_overflow {
            meta.lookup(|meta| {
                let b_ = meta.query_advice(b.into(), Rotation::cur());
                let s_overflow = meta.query_selector(s_overflow);
                vec![(b_ * s_overflow, overflow_range_table)]
            });
        }

        // meta.create_gate("range", |meta| {
        //     let s_range = meta.query_selector(s_range);

        //     let a = meta.query_advice(a, Rotation::cur());
        //     let b = meta.query_advice(b, Rotation::cur());
        //     let c = meta.query_advice(c, Rotation::cur());
        //     let d_next = meta.query_advice(d, Rotation::next());
        //     let d = meta.query_advice(d, Rotation::cur());

        //     // NOTICE: we could also use main gate selectors to combine limbs.
        //     let u1 = F::from_u64((1u64 << limb_bit_len) as u64);
        //     let u2 = F::from_u64((1u64 << (2 * limb_bit_len)) as u64);
        //     let u3 = F::from_u64((1u64 << (3 * limb_bit_len)) as u64);

        //     let expression = s_range * (a + b * u1 + c * u2 + d * u3 - d_next);

        //     vec![expression]
        // });

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
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{RangeChip, RangeConfig, RangeInstructions};
    use crate::circuit::integer::AssignedLimb;
    use crate::circuit::main_gate::{MainGate, MainGateConfig};
    use crate::rns::Limb;
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::pasta::Fp;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit<F: FieldExt, const LIMB_BIT_LEN: usize, const OVERFLOW_BIT_LEN: usize> {
        value: Option<F>,
    }

    impl<F: FieldExt, const LIMB_BIT_LEN: usize, const OVERFLOW_BIT_LEN: usize> Circuit<F> for TestCircuit<F, LIMB_BIT_LEN, OVERFLOW_BIT_LEN> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);
            let range_config = RangeChip::<F>::configure(meta, main_gate_config.clone(), OVERFLOW_BIT_LEN > 0);
            TestCircuitConfig {
                main_gate_config,
                range_config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let range_chip = RangeChip::<F>::new(config.range_config.clone(), LIMB_BIT_LEN, OVERFLOW_BIT_LEN);

            // assign the value
            let get_value = || -> Result<F, Error> {
                let value = self.value.ok_or(Error::SynthesisError)?;
                Ok(value)
            };

            let limb = &layouter.assign_region(
                || "region 0",
                |mut region| {
                    let cell = region.assign_advice(|| "a", config.main_gate_config.a, 0, get_value)?;
                    let _ = region.assign_advice(|| "b", config.main_gate_config.b, 0, || Ok(F::zero()))?;
                    let _ = region.assign_advice(|| "c", config.main_gate_config.c, 0, || Ok(F::zero()))?;
                    let _ = region.assign_advice(|| "d", config.main_gate_config.d, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sa", config.main_gate_config.sa, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sb", config.main_gate_config.sb, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sc", config.main_gate_config.sc, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sd", config.main_gate_config.sd, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_mul", config.main_gate_config.s_mul, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sd_next", config.main_gate_config.sd_next, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_constant", config.main_gate_config.s_constant, 0, || Ok(F::zero()))?;

                    // Ok(cell)

                    let limb = AssignedLimb {
                        cell,
                        value: self.value.map(|value| Limb::from_fe(value)),
                    };

                    Ok(limb)
                },
            )?;

            layouter.assign_region(
                || "region 1",
                |mut region| {
                    range_chip.range_limb(&mut region, limb)?;
                    Ok(())
                },
            )?;

            range_chip.load_limb_range_table(&mut layouter)?;
            range_chip.load_overflow_range_table(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_range_circuit() {
        const BIT_LEN_LOOKUP_LIMB: usize = 16;
        const NO_OVERFLOW: usize = 0;
        const BIT_LEN_OVERFLOW: usize = 4;
        const K: u32 = (BIT_LEN_LOOKUP_LIMB + 1) as u32;
        // const K: u32 = 5;

        let value = Some(Fp::from_u64(0xffffffffffffffff));
        let circuit = TestCircuit::<Fp, BIT_LEN_LOOKUP_LIMB, NO_OVERFLOW> { value };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));

        let circuit = TestCircuit::<Fp, BIT_LEN_LOOKUP_LIMB, BIT_LEN_OVERFLOW> { value };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }
}
