use crate::circuit::main_gate::{CombinationOption, MainGate, MainGateColumn, MainGateConfig, MainGateInstructions};
use crate::circuit::{AssignedInteger, AssignedValue};
use crate::{NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Layouter, Region};
use halo2::plonk::{ConstraintSystem, Error, Selector, TableColumn};
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
    main_gate_config: MainGateConfig,

    #[cfg(not(feature = "no_lookup"))]
    s_dense_limb_range: Selector,

    #[cfg(not(feature = "no_lookup"))]
    dense_limb_range_table: TableColumn,

    #[cfg(not(feature = "no_lookup"))]
    fine_tune_tables: Vec<TableConfig>,
}

#[derive(Clone, Debug)]
pub enum RangeTune {
    Fits,
    Overflow(usize),
    Fine(usize),
}

pub struct RangeChip<F: FieldExt> {
    config: RangeConfig,
    base_bit_len: usize,
    left_shifter: Vec<F>,
}

impl<F: FieldExt> RangeChip<F> {
    #[cfg(not(feature = "no_lookup"))]
    fn get_table(&self, bit_len: usize) -> Result<&TableConfig, Error> {
        let table_config = self
            .config
            .fine_tune_tables
            .iter()
            .find(|&table_config| table_config.bit_len == bit_len)
            .ok_or(Error::SynthesisError)?;
        Ok(table_config)
    }

    fn main_gate_config(&self) -> MainGateConfig {
        self.config.main_gate_config.clone()
    }

    fn main_gate(&self) -> MainGate<F> {
        MainGate::<F>::new(self.main_gate_config())
    }

    fn range_value_fits(&self, region: &mut Region<'_, F>, input: &mut AssignedValue<F>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let number_of_limbs = NUMBER_OF_LOOKUP_LIMBS;

        // Layout of RangeTune::Fits
        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | a_0 | a_1 | a_2 | a_3 |
        // | -   | -   | -   | in  |

        // first row must constain
        // a_0 + a_1 * R + a_2 * R^2 + a_3 * R^3 - in = 0

        // enable dense decomposion range check
        self.config.s_dense_limb_range.enable(region, *offset)?;

        // input is decomposed insto smaller limbs
        let limbs = input.decompose(number_of_limbs, self.base_bit_len);

        // limbs.clone().map(|limbs| {
        //     for e in limbs {
        //         println!("limb fits: {:?}", e);
        //     }
        // });

        // make first combination witness values
        let coeffs = limbs;

        // make fixed bases of first combination
        let bases = vec![F::one(), self.left_shifter[0], self.left_shifter[1], self.left_shifter[2]];

        // enable further wire for intermediate sum
        let combination_option = CombinationOption::CombineToNext(-F::one());

        // combine limbs into the next row
        let _ = main_gate.combine(region, coeffs, bases, offset, combination_option)?;

        // proceeed to next row

        // cycle the input before proceeding the next row
        main_gate.cycle_to(region, input, MainGateColumn::D, *offset)?;

        // proceed to the next row
        main_gate.no_operation(region, offset)?;

        Ok(())
    }

    fn range_value_overflow(&self, region: &mut Region<'_, F>, input: &mut AssignedValue<F>, offset: &mut usize, bit_len: usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let number_of_limbs = NUMBER_OF_LOOKUP_LIMBS + 1;

        // Layout of RangeTune::Overflow
        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | a_0 | a_1 | a_2 | a_3 |
        // | -   | a_4 | in  | t   |

        // first row must constain
        // a_0 + a_1 * R + a_2 * R^2 + a_3 * R^3 - t = 0

        // enable dense decomposion range check
        self.config.s_dense_limb_range.enable(region, *offset)?;

        // input is decomposed insto smaller limbs
        let limbs = input.decompose(number_of_limbs, self.base_bit_len);

        // make first combination witness values
        let coeffs = limbs.as_ref().map(|limbs| limbs[0..NUMBER_OF_LOOKUP_LIMBS].to_vec());

        // make fixed bases of first combination
        let bases = vec![F::one(), self.left_shifter[0], self.left_shifter[1], self.left_shifter[2]];

        // enable further wire for intermediate sum
        let combination_option = CombinationOption::CombineToNext(-F::one());

        // combine limbs into the next row
        // ignore returned cells
        let _ = main_gate.combine(region, coeffs, bases, offset, combination_option)?;

        // proceeed to next row

        // second row must constain
        // a_4 * R^4 - input + t  = 0

        // enable fine decomposion range check of main gate B column
        self.get_table(bit_len)?.selector.enable(region, *offset)?;

        // get most significant shifter for overflow value
        let msb_shifter = *self.left_shifter.last().unwrap();

        // make first combination witness values
        let coeffs = limbs.as_ref().map(|limbs| {
            // last limb is the overflow value
            let overflow_value = limbs[number_of_limbs - 1];
            // input value must exist if limbs do
            let input_value = input.value().unwrap();
            // combination of previous row must go to column 'D'
            let intermediate_combination = input_value - overflow_value * msb_shifter;
            vec![F::zero(), overflow_value, input_value, intermediate_combination]
        });

        // make fixed bases of final combination
        let bases = vec![F::zero(), msb_shifter, -F::one(), F::one()];

        // cycle the input before proceeding the next row
        main_gate.cycle_to(region, input, MainGateColumn::C, *offset)?;

        // combine overflow value with intermadiate result
        let _ = main_gate.combine(region, coeffs, bases, offset, CombinationOption::SingleLiner)?;

        Ok(())
    }

    fn range_value_fine(&self, region: &mut Region<'_, F>, input: &mut AssignedValue<F>, offset: &mut usize, bit_len: usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let number_of_limbs = NUMBER_OF_LOOKUP_LIMBS;

        // Layout of RangeTune::Fine
        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | a_0 | a_1 | a_2 | -   |
        // | -   | a_3 | in  | t   |

        // first row must constain
        // a_0 + a_1 * R + a_2 * R^2 - t = 0

        // enable dense decomposion range check
        self.config.s_dense_limb_range.enable(region, *offset)?;

        // input is decomposed insto smaller limbs
        let limbs = input.decompose(number_of_limbs, self.base_bit_len);

        // make first combination witness values
        // it contains first 3 term of the combination
        let coeffs = limbs.as_ref().map(|limbs| {
            let mut coeffs = limbs[0..number_of_limbs - 1].to_vec();
            coeffs.push(F::zero()); // it just can be any value in the dense range since selector D is zero
            coeffs
        });

        // make fixed bases of first combination
        // we delay the last limb since dense range selector is open at this row
        let bases = vec![F::one(), self.left_shifter[0], self.left_shifter[1], F::zero()];

        // enable further wire for intermediate sum
        let combination_option = CombinationOption::CombineToNext(-F::one());

        // combine first three limbs into the next row
        // ignore returned cells
        let _ = main_gate.combine(region, coeffs, bases, offset, combination_option)?;

        // proceeed to next row

        // second row must constain
        // a_3 * R^3 - input + t  = 0

        // enable fine decomposion range check of main gate B column
        self.get_table(bit_len)?.selector.enable(region, *offset)?;

        // get most significant shifter for a_3 i.e R^3
        let msb_shifter = self.left_shifter[2];

        // make first combination witness values
        let coeffs = limbs.as_ref().map(|limbs| {
            // last limb is the overflow value
            let fine_tune_value = limbs[number_of_limbs - 1];
            // input value must exist if limbs do
            let input_value = input.value().unwrap();
            // combination of previous row must go to column 'D'
            let intermediate_combination = input_value - fine_tune_value * msb_shifter;
            vec![F::zero(), fine_tune_value, input_value, intermediate_combination]
        });

        // make fixed bases of final combination
        let bases = vec![F::zero(), msb_shifter, -F::one(), F::one()];

        // cycle the input before proceeding the next row
        main_gate.cycle_to(region, input, MainGateColumn::C, *offset)?;

        // // combine overflow value with intermadiate result
        let _ = main_gate.combine(region, coeffs, bases, offset, CombinationOption::SingleLiner)?;

        Ok(())
    }
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
    fn range_integer(&self, region: &mut Region<'_, F>, integer: &mut AssignedInteger<F>, tune: RangeTune, offset: &mut usize) -> Result<(), Error>;
    fn range_value(&self, region: &mut Region<'_, F>, input: &mut AssignedValue<F>, tune: RangeTune, offset: &mut usize) -> Result<(), Error>;
    #[cfg(not(feature = "no_lookup"))]
    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
    #[cfg(not(feature = "no_lookup"))]
    fn load_overflow_range_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: FieldExt> RangeInstructions<F> for RangeChip<F> {
    fn range_integer(&self, region: &mut Region<'_, F>, integer: &mut AssignedInteger<F>, tune: RangeTune, offset: &mut usize) -> Result<(), Error> {
        for i in 0..NUMBER_OF_LIMBS {
            let tune = if i == NUMBER_OF_LIMBS - 1 { RangeTune::Fits } else { tune.clone() };
            let limb_value = integer.value.as_ref().map(|e| e.limb_value(i));
            let limb = &mut AssignedValue::new(integer.cells[i], limb_value);
            self.range_value(region, limb, tune, offset)?;
            integer.cycle_cell(region, i, limb.cell)?;
        }
        Ok(())
    }

    fn range_value(&self, region: &mut Region<'_, F>, input: &mut AssignedValue<F>, tune: RangeTune, offset: &mut usize) -> Result<(), Error> {
        match tune {
            RangeTune::Overflow(bit_len) => self.range_value_overflow(region, input, offset, bit_len),
            RangeTune::Fine(bit_len) => self.range_value_fine(region, input, offset, bit_len),
            RangeTune::Fits => self.range_value_fits(region, input, offset),
        }?;
        Ok(())
    }

    #[cfg(not(feature = "no_lookup"))]
    fn load_limb_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let table_values: Vec<F> = (0..1 << self.base_bit_len).map(|e| F::from_u64(e)).collect();

        layouter.assign_table(
            || "",
            |mut table| {
                for (index, &value) in table_values.iter().enumerate() {
                    table.assign_cell(|| "limb range table", self.config.dense_limb_range_table, index, || Ok(value))?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(not(feature = "no_lookup"))]
    fn load_overflow_range_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for overflow_table in self.config.fine_tune_tables.iter() {
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
    pub fn new(config: RangeConfig, base_bit_len: usize) -> Self {
        let two = F::from_u64(2);
        let left_shifter_r = two.pow(&[base_bit_len as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[(base_bit_len * 2) as u64, 0, 0, 0]);
        let left_shifter_3r = two.pow(&[(base_bit_len * 3) as u64, 0, 0, 0]);
        let left_shifter_4r = two.pow(&[(base_bit_len * 4) as u64, 0, 0, 0]);

        RangeChip {
            config,
            base_bit_len,
            left_shifter: vec![left_shifter_r, left_shifter_2r, left_shifter_3r, left_shifter_4r],
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>, main_gate_config: &MainGateConfig, fine_tune_bit_lengths: Vec<usize>) -> RangeConfig {
        let a = main_gate_config.a;
        let b = main_gate_config.b;
        let c = main_gate_config.c;
        let d = main_gate_config.d;

        #[cfg(not(feature = "no_lookup"))]
        let s_dense_limb_range = meta.complex_selector();
        #[cfg(not(feature = "no_lookup"))]
        let dense_limb_range_table = meta.lookup_table_column();

        #[cfg(not(feature = "no_lookup"))]
        {
            meta.lookup(|meta| {
                let exp = meta.query_advice(a.into(), Rotation::cur());
                let s_range = meta.query_selector(s_dense_limb_range);
                vec![(exp * s_range, dense_limb_range_table)]
            });

            meta.lookup(|meta| {
                let exp = meta.query_advice(b.into(), Rotation::cur());
                let s_range = meta.query_selector(s_dense_limb_range);
                vec![(exp * s_range, dense_limb_range_table)]
            });

            meta.lookup(|meta| {
                let exp = meta.query_advice(c.into(), Rotation::cur());
                let s_range = meta.query_selector(s_dense_limb_range);
                vec![(exp * s_range, dense_limb_range_table)]
            });

            meta.lookup(|meta| {
                let exp = meta.query_advice(d.into(), Rotation::cur());
                let s_range = meta.query_selector(s_dense_limb_range);
                vec![(exp * s_range, dense_limb_range_table)]
            });
        }

        #[cfg(not(feature = "no_lookup"))]
        let fine_tune_tables = fine_tune_bit_lengths
            .iter()
            .map(|bit_len| {
                let selector = meta.complex_selector();
                let column = meta.lookup_table_column();

                meta.lookup(|meta| {
                    let exp = meta.query_advice(b.into(), Rotation::cur());
                    let selector = meta.query_selector(selector);
                    vec![(exp * selector, column)]
                });

                let table_config = TableConfig {
                    selector,
                    column,
                    bit_len: *bit_len,
                };
                table_config
            })
            .collect();

        RangeConfig {
            main_gate_config: main_gate_config.clone(),
            #[cfg(not(feature = "no_lookup"))]
            s_dense_limb_range,
            #[cfg(not(feature = "no_lookup"))]
            dense_limb_range_table,
            #[cfg(not(feature = "no_lookup"))]
            fine_tune_tables,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{RangeChip, RangeConfig, RangeInstructions, RangeTune};
    use crate::circuit::main_gate::{MainGate, MainGateColumn, MainGateConfig, MainGateInstructions};
    use crate::NUMBER_OF_LOOKUP_LIMBS;
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
        value_overflow: Option<F>,
        value_fine: Option<F>,
        value_fits: Option<F>,
    }

    impl<F: FieldExt> TestCircuit<F> {
        fn fine_tune_bit_lengths() -> Vec<usize> {
            vec![4]
        }

        fn base_bit_len() -> usize {
            16
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
            let fine_tune_bit_lengths = Self::fine_tune_bit_lengths();
            let range_config = RangeChip::<F>::configure(meta, &main_gate_config, fine_tune_bit_lengths);
            TestCircuitConfig {
                main_gate_config,
                range_config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let range_chip = RangeChip::<F>::new(config.range_config.clone(), Self::base_bit_len());
            let main_gate = MainGate::<F>::new(config.main_gate_config.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let mut offset = 0;
                    let tune_len = Self::fine_tune_bit_lengths()[0];
                    let zero = F::zero();
                    let base = Self::base_bit_len() as u64;
                    let base = 1 << base;
                    let max_limb = base - 1;
                    let three_limb = F::from_u64(max_limb + max_limb * base + max_limb * base * base);

                    // zero must pass all ranges
                    let zero = &mut main_gate.assign_value(&mut region, Some(zero), MainGateColumn::D, offset)?;
                    // proceed to next row
                    main_gate.no_operation(&mut region, &mut offset)?;

                    range_chip.range_value(&mut region, zero, RangeTune::Fits, &mut offset)?;
                    range_chip.range_value(&mut region, zero, RangeTune::Overflow(tune_len), &mut offset)?;
                    range_chip.range_value(&mut region, zero, RangeTune::Fine(tune_len), &mut offset)?;

                    // three limbed value must pass all ranges
                    let three_limb = &mut main_gate.assign_value(&mut region, Some(three_limb), MainGateColumn::D, offset)?;
                    // proceed to next row
                    main_gate.no_operation(&mut region, &mut offset)?;

                    range_chip.range_value(&mut region, three_limb, RangeTune::Fits, &mut offset)?;
                    range_chip.range_value(&mut region, three_limb, RangeTune::Overflow(tune_len), &mut offset)?;
                    range_chip.range_value(&mut region, three_limb, RangeTune::Fine(tune_len), &mut offset)?;

                    // tests against inputs

                    let value_fits = &mut main_gate.assign_value(&mut region, self.value_fits, MainGateColumn::A, offset)?;
                    // proceed to next row
                    main_gate.no_operation(&mut region, &mut offset)?;
                    range_chip.range_value(&mut region, value_fits, RangeTune::Fits, &mut offset)?;

                    let value_fine = &mut main_gate.assign_value(&mut region, self.value_fine, MainGateColumn::A, offset)?;
                    // proceed to next row
                    main_gate.no_operation(&mut region, &mut offset)?;
                    range_chip.range_value(&mut region, value_fine, RangeTune::Fine(tune_len), &mut offset)?;

                    let value_overflow = &mut main_gate.assign_value(&mut region, self.value_overflow, MainGateColumn::A, offset)?;
                    // proceed to next row
                    main_gate.no_operation(&mut region, &mut offset)?;
                    range_chip.range_value(&mut region, value_overflow, RangeTune::Overflow(tune_len), &mut offset)?;

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
        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (TestCircuit::<Fp>::base_bit_len() + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        let fine_tune_shift = TestCircuit::<Fp>::fine_tune_bit_lengths()[0];
        let val_shift_4 = TestCircuit::<Fp>::base_bit_len() * NUMBER_OF_LOOKUP_LIMBS;
        let val_shift_3 = TestCircuit::<Fp>::base_bit_len() * (NUMBER_OF_LOOKUP_LIMBS - 1);

        let value_fits = Some(Fp::from_u128((1 << val_shift_4) - 1));
        let value_overflow = Some(Fp::from_u128((1 << (val_shift_4 + fine_tune_shift)) - 1));
        let value_fine = Some(Fp::from_u128((1 << (val_shift_3 + fine_tune_shift)) - 1));

        // happy path

        let circuit = TestCircuit::<Fp> {
            value_overflow,
            value_fits,
            value_fine,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));

        // bad paths:

        let value_fits_bad = Some(Fp::from_u128(1 << val_shift_4));
        let circuit = TestCircuit::<Fp> {
            value_overflow,
            value_fits: value_fits_bad,
            value_fine,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_ne!(prover.verify(), Ok(()));

        let value_overflow_bad = Some(Fp::from_u128(1 << (val_shift_4 + fine_tune_shift)));
        let circuit = TestCircuit::<Fp> {
            value_overflow: value_overflow_bad,
            value_fits,
            value_fine,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_ne!(prover.verify(), Ok(()));

        let value_fine_bad = Some(Fp::from_u128(1 << (val_shift_3 + fine_tune_shift)));
        let circuit = TestCircuit::<Fp> {
            value_overflow,
            value_fits,
            value_fine: value_fine_bad,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_ne!(prover.verify(), Ok(()));
    }
}
