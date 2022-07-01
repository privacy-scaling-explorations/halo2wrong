use std::collections::BTreeMap;
use std::marker::PhantomData;

use super::main_gate::{MainGate, MainGateConfig};
use crate::halo2::arithmetic::FieldExt;
use crate::halo2::circuit::Chip;
use crate::halo2::circuit::Layouter;
use crate::halo2::circuit::Value;
use crate::halo2::plonk::{ConstraintSystem, Error};
use crate::halo2::plonk::{Selector, TableColumn};
use crate::halo2::poly::Rotation;
use crate::instructions::{MainGateInstructions, Term};
use crate::AssignedValue;
use halo2wrong::utils::decompose;
use halo2wrong::RegionCtx;
use num_integer::Integer;

/// Maximum number of cells in one line enabled with composition selector
pub const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct TableConfig {
    selector: Selector,
    column: TableColumn,
}

impl TableConfig {}

/// Range gate configuration
#[derive(Clone, Debug)]
pub struct RangeConfig {
    main_gate_config: MainGateConfig,
    composition_tables: BTreeMap<usize, TableConfig>,
    overflow_tables: BTreeMap<usize, TableConfig>,
}

/// ['RangeChip'] applies binary range constraints
#[derive(Debug)]
pub struct RangeChip<F: FieldExt> {
    config: RangeConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> RangeChip<F> {
    fn main_gate_config(&self) -> MainGateConfig {
        self.config.main_gate_config.clone()
    }

    fn main_gate(&self) -> MainGate<F> {
        MainGate::<F>::new(self.main_gate_config())
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

/// Generic chip interface for bitwise ranging values
pub trait RangeInstructions<F: FieldExt>: Chip<F> {
    /// Assigns new witness
    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<AssignedValue<F>, Error>;

    /// Decomposes and assign new witness
    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error>;

    /// Appends base limb length table in sythnesis time
    fn load_composition_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
    /// Appends shorter range tables in sythesis time
    fn load_overflow_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: FieldExt> RangeInstructions<F> for RangeChip<F> {
    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let (assigned, _) = self.decompose(ctx, unassigned, limb_bit_len, bit_len)?;
        Ok(assigned)
    }

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        // let number_of_limbs = bit_len % base_bit_len;
        let (number_of_limbs, overflow_bit_len) = bit_len.div_rem(&limb_bit_len);

        let number_of_limbs = number_of_limbs + if overflow_bit_len > 0 { 1 } else { 0 };
        let bases = Self::bases(number_of_limbs, limb_bit_len);
        let decomposed =
            unassigned.map(|unassigned| decompose(unassigned, number_of_limbs, limb_bit_len));

        let terms: Vec<Term<F>> = bases
            .into_iter()
            .enumerate()
            .map(|(i, base)| {
                let limb = decomposed.as_ref().map(|limb| limb[i]);
                Term::Unassigned(limb, base)
            })
            .collect();

        let composition_table = self
            .config
            .composition_tables
            .get(&limb_bit_len)
            .unwrap_or_else(|| {
                panic!("composition table is not set, bit lenght: {}", limb_bit_len)
            });
        let main_gate = self.main_gate();
        main_gate.decompose(ctx, &terms[..], F::zero(), |is_last| {
            if is_last && overflow_bit_len != 0 {
                let overflow_table = self
                    .config
                    .overflow_tables
                    .get(&overflow_bit_len)
                    .unwrap_or_else(|| {
                        panic!(
                            "overflow table is not set, bit lenght: {}",
                            overflow_bit_len
                        )
                    });
                vec![composition_table.selector, overflow_table.selector]
            } else {
                vec![composition_table.selector]
            }
        })
    }

    fn load_composition_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (bit_len, config) in self.config.composition_tables.iter() {
            let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from(e)).collect();
            layouter.assign_table(
                || "",
                |mut table| {
                    for (index, &value) in table_values.iter().enumerate() {
                        table.assign_cell(
                            || "composition table",
                            config.column,
                            index,
                            || Value::known(value),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }

        Ok(())
    }

    fn load_overflow_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (bit_len, config) in self.config.overflow_tables.iter() {
            let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from(e)).collect();
            layouter.assign_table(
                || "",
                |mut table| {
                    for (index, &value) in table_values.iter().enumerate() {
                        table.assign_cell(
                            || "composition table",
                            config.column,
                            index,
                            || Value::known(value),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }

        Ok(())
    }
}

impl<F: FieldExt> RangeChip<F> {
    fn bases(number_of_limbs: usize, bit_len: usize) -> Vec<F> {
        assert!(number_of_limbs * bit_len > 0);
        (0..number_of_limbs)
            .map(|i| F::from(2).pow(&[(bit_len * i) as u64, 0, 0, 0]))
            .collect()
    }

    /// Given config creates new chip that implements ranging
    pub fn new(config: RangeConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// Configures subset argument and returns the
    /// resuiting config
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        main_gate_config: &MainGateConfig,
        composition_bit_lens: Vec<usize>,
        overflow_bit_lens: Vec<usize>,
    ) -> RangeConfig {
        let mut overflow_bit_lens = overflow_bit_lens;
        overflow_bit_lens.sort_unstable();
        overflow_bit_lens.dedup();
        let overflow_bit_lens: Vec<usize> =
            overflow_bit_lens.into_iter().filter(|e| *e != 0).collect();

        let mut composition_bit_lens = composition_bit_lens;
        composition_bit_lens.sort_unstable();
        composition_bit_lens.dedup();
        let composition_bit_lens: Vec<usize> = composition_bit_lens
            .into_iter()
            .filter(|e| *e != 0)
            .collect();

        // TODO: consider for a generic MainGateConfig
        let (a, b, c, d) = (
            main_gate_config.a,
            main_gate_config.b,
            main_gate_config.c,
            main_gate_config.d,
        );

        macro_rules! meta_lookup {
            ($column:expr, $table_config:expr) => {
                // meta.lookup(stringify!($column), |meta| {
                meta.lookup(|meta| {
                    let exp = meta.query_advice($column, Rotation::cur());
                    let s = meta.query_selector($table_config.selector);
                    vec![(exp * s, $table_config.column)]
                });
            };
        }

        let mut composition_tables = BTreeMap::<usize, TableConfig>::new();
        let mut overflow_tables = BTreeMap::<usize, TableConfig>::new();

        for bit_len in composition_bit_lens.iter() {
            let config = TableConfig {
                selector: meta.complex_selector(),
                column: meta.lookup_table_column(),
            };
            meta_lookup!(a, config);
            meta_lookup!(b, config);
            meta_lookup!(c, config);
            meta_lookup!(d, config);
            composition_tables.insert(*bit_len, config);
        }
        for bit_len in overflow_bit_lens.iter() {
            let config = TableConfig {
                selector: meta.complex_selector(),
                column: meta.lookup_table_column(),
            };

            meta_lookup!(a, config);
            overflow_tables.insert(*bit_len, config);
        }

        RangeConfig {
            main_gate_config: main_gate_config.clone(),
            composition_tables,
            overflow_tables,
        }
    }
}

#[cfg(test)]
mod tests {

    use halo2wrong::halo2::circuit::Value;
    use halo2wrong::RegionCtx;

    use super::{RangeChip, RangeConfig, RangeInstructions};
    use crate::curves::pasta::Fp;
    use crate::halo2::arithmetic::FieldExt;
    use crate::halo2::circuit::{Layouter, SimpleFloorPlanner};
    use crate::halo2::dev::MockProver;
    use crate::halo2::plonk::{Circuit, ConstraintSystem, Error};
    use crate::main_gate::MainGate;
    use crate::{MainGateInstructions, Term};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        range_config: RangeConfig,
    }

    impl TestCircuitConfig {
        fn new<F: FieldExt>(
            meta: &mut ConstraintSystem<F>,
            composition_bit_lens: Vec<usize>,
            overflow_bit_lens: Vec<usize>,
        ) -> Self {
            let main_gate_config = MainGate::<F>::configure(meta);

            let range_config = RangeChip::<F>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );
            Self { range_config }
        }

        fn main_gate<F: FieldExt>(&self) -> MainGate<F> {
            MainGate::<F>::new(self.range_config.main_gate_config.clone())
        }

        fn range_chip<F: FieldExt>(&self) -> RangeChip<F> {
            RangeChip::<F>::new(self.range_config.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct Input<F: FieldExt> {
        bit_len: usize,
        limb_bit_len: usize,
        value: Value<F>,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit<F: FieldExt> {
        inputs: Vec<Input<F>>,
    }

    impl<F: FieldExt> TestCircuit<F> {
        fn composition_bit_lens() -> Vec<usize> {
            vec![8]
        }

        fn overflow_bit_lens() -> Vec<usize> {
            vec![3]
        }
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            TestCircuitConfig::new(
                meta,
                Self::composition_bit_lens(),
                Self::overflow_bit_lens(),
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let range_chip = config.range_chip();
            let main_gate = config.main_gate();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    for input in self.inputs.iter() {
                        let value = input.value;
                        let limb_bit_len = input.limb_bit_len;
                        let bit_len = input.bit_len;

                        let a_0 = main_gate.assign_value(ctx, value)?;
                        let (a_1, decomposed) =
                            range_chip.decompose(ctx, value, limb_bit_len, bit_len)?;

                        main_gate.assert_equal(ctx, &a_0, &a_1)?;

                        use num_integer::Integer;
                        let (number_of_limbs, overflow_bit_len) = bit_len.div_rem(&limb_bit_len);
                        let number_of_limbs =
                            number_of_limbs + if overflow_bit_len != 0 { 1 } else { 0 };

                        let bases = RangeChip::<F>::bases(number_of_limbs, limb_bit_len);
                        assert_eq!(bases.len(), decomposed.len());

                        let terms: Vec<Term<F>> = bases
                            .iter()
                            .zip(decomposed.into_iter())
                            .map(|(base, limb)| Term::Assigned(limb, *base))
                            .collect();
                        let a_1 = main_gate.compose(ctx, &terms[..], F::zero())?;
                        main_gate.assert_equal(ctx, &a_0, &a_1)?;
                    }

                    Ok(())
                },
            )?;

            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_range_circuit() {
        const LIMB_BIT_LEN: usize = 8;
        const OVERFLOW_BIT_LEN: usize = 3;
        let k: u32 = (LIMB_BIT_LEN + 1) as u32;

        let inputs = (2..20)
            .map(|number_of_limbs| {
                let bit_len = LIMB_BIT_LEN * number_of_limbs + OVERFLOW_BIT_LEN;
                Input {
                    value: Value::known(Fp::from_u128((1 << bit_len) - 1)),
                    limb_bit_len: LIMB_BIT_LEN,
                    bit_len,
                }
            })
            .collect();

        let circuit = TestCircuit::<Fp> { inputs };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
