use crate::circuit::main_gate::MainGateConfig;
use crate::circuit::{AssignedInteger, AssignedLimb};
use crate::rns::Decomposed;
use crate::{BIT_LEN_LIMB_LOOKUP, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Layouter, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector, TableColumn};
use halo2::poly::Rotation;

#[cfg(not(feature = "no_lookup"))]
#[derive(Clone, Debug)]
pub struct TableConfig {
    selector: Selector,
    column: TableColumn,
    bit_len: usize,
}

#[derive(Clone, Debug)]
pub struct RangeConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    d: Column<Advice>,

    s_range: Selector,

    #[cfg(not(feature = "no_lookup"))]
    limb_range_table: TableColumn,

    #[cfg(not(feature = "no_lookup"))]
    overflow_tables: Vec<TableConfig>,

    sa: Column<Fixed>,
    sb: Column<Fixed>,
    sc: Column<Fixed>,
    sd: Column<Fixed>,
    sd_next: Column<Fixed>,
    s_mul: Column<Fixed>,
    s_constant: Column<Fixed>,
}

pub enum Overflow {
    NoOverflow,
    Size(usize),
}

pub struct RangeChip<F: FieldExt> {
    config: RangeConfig,

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

impl<F: FieldExt> RangeChip<F> {
    #[cfg(not(feature = "no_lookup"))]
    fn get_table(&self, bit_len: usize) -> Result<&TableConfig, Error> {
        let table_config = self
            .config
            .overflow_tables
            .iter()
            .find(|&table_config| table_config.bit_len == bit_len)
            .ok_or(Error::SynthesisError)?;
        Ok(table_config)
    }
}

pub trait RangeInstructions<F: FieldExt>: Chip<F> {
    fn range_integer(&self, region: &mut Region<'_, F>, integer: &mut AssignedInteger<F>, offset: &mut usize) -> Result<(), Error>;
    fn range_limb(&self, region: &mut Region<'_, F>, limb: &mut AssignedLimb<F>, overflow: Overflow, offset: &mut usize) -> Result<(), Error>;

    #[cfg(not(feature = "no_lookup"))]
    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
    #[cfg(not(feature = "no_lookup"))]
    fn load_overflow_range_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: FieldExt> RangeInstructions<F> for RangeChip<F> {
    fn range_integer(&self, region: &mut Region<'_, F>, integer: &mut AssignedInteger<F>, offset: &mut usize) -> Result<(), Error> {
        let limb = integer.value.as_ref().map(|e| e.limb(0));
        let limb = &mut AssignedLimb::new(integer.cells[0], limb);
        self.range_limb(region, limb, Overflow::NoOverflow, offset)?;
        let limb = integer.value.as_ref().map(|e| e.limb(1));
        let limb = &mut AssignedLimb::new(integer.cells[1], limb);
        self.range_limb(region, limb, Overflow::NoOverflow, offset)?;
        let limb = integer.value.as_ref().map(|e| e.limb(2));
        let limb = &mut AssignedLimb::new(integer.cells[2], limb);
        self.range_limb(region, limb, Overflow::NoOverflow, offset)?;
        let limb = integer.value.as_ref().map(|e| e.limb(3));
        let limb = &mut AssignedLimb::new(integer.cells[3], limb);
        self.range_limb(region, limb, Overflow::NoOverflow, offset)?;

        Ok(())
    }

    fn range_limb(&self, region: &mut Region<'_, F>, limb: &mut AssignedLimb<F>, overflow: Overflow, offset: &mut usize) -> Result<(), Error> {
        let number_of_limbs = match overflow {
            Overflow::NoOverflow => NUMBER_OF_LOOKUP_LIMBS,
            _ => NUMBER_OF_LOOKUP_LIMBS + 1,
        };

        let offset_limb = *offset;
        let offset_overflow = offset_limb + 1;

        let value = limb.value.as_ref().map(|value| value);
        let decomposed = value.map(|limb| Decomposed::<F>::from_limb(&limb.clone(), number_of_limbs, BIT_LEN_LIMB_LOOKUP));

        let get_limb = |idx: usize| -> Result<F, Error> {
            // let decomposed = decomposed.clone();
            let decomposed = decomposed.as_ref().ok_or(Error::SynthesisError)?;
            Ok(decomposed.limb_value(idx))
        };

        let get_value = || -> Result<F, Error> {
            let value = value.ok_or(Error::SynthesisError)?;
            Ok(value.fe())
        };

        let get_overflow_value = || -> Result<F, Error> {
            let decomposed = decomposed.as_ref().ok_or(Error::SynthesisError)?;

            Ok(match overflow {
                Overflow::NoOverflow => F::zero(),
                _ => decomposed.limb_value(number_of_limbs - 1),
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

        let new_cell = {
            #[cfg(not(feature = "no_lookup"))]
            match overflow {
                Overflow::Size(bit_len) => self.get_table(bit_len)?.selector.enable(region, offset_overflow)?,
                _ => {}
            };

            let cell = region.assign_advice(|| "limb value", self.config.a, offset_overflow, || get_value())?;
            let _ = region.assign_advice(|| "overflow value", self.config.b, offset_overflow, || get_overflow_value())?;
            let _ = region.assign_advice(|| "zero", self.config.c, offset_overflow, || Ok(F::zero()))?;
            let _ = region.assign_advice(|| "limb w/o overflow", self.config.d, offset_overflow, || get_value_wo_overflow())?;

            region.assign_fixed(|| "a", self.config.sa, offset_overflow, || Ok(-F::one()))?;
            region.assign_fixed(
                || "b",
                self.config.sb,
                offset_overflow,
                || {
                    Ok(match overflow {
                        Overflow::NoOverflow => F::zero(),
                        _ => self.left_shifter_4r,
                    })
                },
            )?;
            region.assign_fixed(|| "d", self.config.sd, offset_overflow, || Ok(F::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "c", self.config.sc, offset_overflow, || Ok(F::zero()))?;
            region.assign_fixed(|| "d_next", self.config.sd_next, offset_overflow, || Ok(F::zero()))?;
            region.assign_fixed(|| "a * b", self.config.s_mul, offset_overflow, || Ok(F::zero()))?;
            region.assign_fixed(|| "constant", self.config.s_constant, offset_overflow, || Ok(F::zero()))?;
            cell
        };

        limb.cycle_cell(region, new_cell)?;

        *offset = *offset + 2;
        Ok(())
    }

    #[cfg(not(feature = "no_lookup"))]
    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let table_values: Vec<F> = (0..1 << BIT_LEN_LIMB_LOOKUP).map(|e| F::from_u64(e)).collect();

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

    #[cfg(not(feature = "no_lookup"))]
    fn load_overflow_range_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for overflow_table in self.config.overflow_tables.iter() {
            let bit_len = overflow_table.bit_len;
            let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from_u64(e)).collect();

            layouter.assign_table(
                || "",
                |mut table| {
                    for (index, &value) in table_values.iter().enumerate() {
                        table.assign_cell(|| "overflow table", overflow_table.column, index, || Ok(value))?;
                    }
                    Ok(())
                },
            )?;
        }

        Ok(())
    }
}

impl<F: FieldExt> RangeChip<F> {
    pub fn new(config: RangeConfig) -> Self {
        let two = F::from_u64(2);
        let left_shifter_r = two.pow(&[BIT_LEN_LIMB_LOOKUP as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[(BIT_LEN_LIMB_LOOKUP * 2) as u64, 0, 0, 0]);
        let left_shifter_3r = two.pow(&[(BIT_LEN_LIMB_LOOKUP * 3) as u64, 0, 0, 0]);
        let left_shifter_4r = two.pow(&[(BIT_LEN_LIMB_LOOKUP * 4) as u64, 0, 0, 0]);

        RangeChip {
            config,

            left_shifter_r,
            left_shifter_2r,
            left_shifter_3r,
            left_shifter_4r,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>, main_gate_config: &MainGateConfig, overflow_bit_lengths: Vec<usize>) -> RangeConfig {
        let a = main_gate_config.a;
        let b = main_gate_config.b;
        let c = main_gate_config.c;
        let d = main_gate_config.d;

        let s_range = meta.complex_selector();

        #[cfg(not(feature = "no_lookup"))]
        let limb_range_table = meta.lookup_table_column();

        #[cfg(not(feature = "no_lookup"))]
        meta.lookup(|meta| {
            let a_ = meta.query_advice(a.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(a_ * s_range, limb_range_table)]
        });

        #[cfg(not(feature = "no_lookup"))]
        meta.lookup(|meta| {
            let b_ = meta.query_advice(b.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(b_ * s_range, limb_range_table)]
        });

        #[cfg(not(feature = "no_lookup"))]
        meta.lookup(|meta| {
            let c_ = meta.query_advice(c.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(c_ * s_range, limb_range_table)]
        });

        #[cfg(not(feature = "no_lookup"))]
        meta.lookup(|meta| {
            let d_ = meta.query_advice(d.into(), Rotation::cur());
            let s_range = meta.query_selector(s_range);
            vec![(d_ * s_range, limb_range_table)]
        });

        #[cfg(not(feature = "no_lookup"))]
        let overflow_tables = overflow_bit_lengths
            .iter()
            .map(|bit_len| {
                let selector = meta.complex_selector();
                let column = meta.lookup_table_column();

                meta.lookup(|meta| {
                    let b_ = meta.query_advice(b.into(), Rotation::cur());
                    let selector = meta.query_selector(selector);
                    vec![(b_ * selector, column)]
                });

                let table_config = TableConfig {
                    selector,
                    column,
                    bit_len: *bit_len,
                };
                table_config
            })
            .collect();

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
            sa,
            sb,
            sc,
            sd,
            sd_next,
            s_mul,
            s_constant,
            #[cfg(not(feature = "no_lookup"))]
            limb_range_table,
            #[cfg(not(feature = "no_lookup"))]
            overflow_tables,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{Overflow, RangeChip, RangeConfig, RangeInstructions};
    use crate::circuit::main_gate::{MainGate, MainGateConfig};
    use crate::circuit::AssignedLimb;
    use crate::rns::Limb;
    use crate::BIT_LEN_LIMB_LOOKUP;
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
    struct TestCircuit<F: FieldExt> {
        value: Option<F>,
    }

    impl<F: FieldExt> TestCircuit<F> {
        fn overflow_bit_lengths() -> Vec<usize> {
            vec![1, 4, 8]
        }
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);

            let overflow_bit_lengths = Self::overflow_bit_lengths();
            let range_config = RangeChip::<F>::configure(meta, &main_gate_config, overflow_bit_lengths);

            TestCircuitConfig {
                main_gate_config,
                range_config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let range_chip = RangeChip::<F>::new(config.range_config.clone());

            // assign the value
            let get_value = || -> Result<F, Error> {
                let value = self.value.ok_or(Error::SynthesisError)?;
                Ok(value)
            };

            let limb = &mut layouter.assign_region(
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
                    range_chip.range_limb(&mut region, limb, Overflow::NoOverflow, &mut 0)?;
                    Ok(())
                },
            )?;

            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_range_circuit() {
        const K: u32 = (BIT_LEN_LIMB_LOOKUP + 1) as u32;

        let value = Some(Fp::from_u64(0xffffffffffffffff));
        let circuit = TestCircuit::<Fp> { value };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
