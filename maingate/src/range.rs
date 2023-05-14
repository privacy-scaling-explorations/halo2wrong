use super::main_gate::{MainGate, MainGateConfig};
use crate::halo2::circuit::Chip;
use crate::halo2::circuit::Layouter;
use crate::halo2::circuit::Value;
use crate::halo2::halo2curves::ff::PrimeField;
use crate::halo2::plonk::{ConstraintSystem, Error, Expression};
use crate::halo2::plonk::{Selector, TableColumn};
use crate::halo2::poly::Rotation;
use crate::instructions::{MainGateInstructions, Term};
use crate::AssignedValue;
use halo2wrong::halo2::plonk::Advice;
use halo2wrong::halo2::plonk::Column;
use halo2wrong::halo2::plonk::Fixed;
use halo2wrong::utils::decompose;
use halo2wrong::RegionCtx;
use num_integer::Integer;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Maximum number of cells in one line enabled with composition selector
pub const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

/// Range gate configuration
#[derive(Clone, Debug)]
pub struct RangeConfig {
    main_gate_config: MainGateConfig,
    bit_len_tag: BTreeMap<usize, usize>,
    t_tag: TableColumn,
    t_value: TableColumn,
    s_composition: Selector,
    tag_composition: Option<Column<Fixed>>,
    s_overflow: Option<Selector>,
    tag_overflow: Option<Column<Fixed>>,
}

/// ['RangeChip'] applies binary range constraints
#[derive(Clone, Debug)]
pub struct RangeChip<F: PrimeField> {
    config: RangeConfig,
    main_gate: MainGate<F>,
    bases: BTreeMap<usize, Vec<F>>,
}

impl<F: PrimeField> RangeChip<F> {
    fn main_gate(&self) -> &MainGate<F> {
        &self.main_gate
    }
}

impl<F: PrimeField> Chip<F> for RangeChip<F> {
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
pub trait RangeInstructions<F: PrimeField>: Chip<F> {
    /// Assigns new witness
    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<AssignedValue<F>, Error>;

    /// Decomposes and assign new witness
    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error>;

    /// Load table in sythnesis time
    fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: PrimeField> RangeInstructions<F> for RangeChip<F> {
    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let (assigned, _) = self.decompose(ctx, unassigned, limb_bit_len, bit_len)?;
        Ok(assigned)
    }

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned: Value<F>,
        limb_bit_len: usize,
        bit_len: usize,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        let (number_of_limbs, overflow_bit_len) = bit_len.div_rem(&limb_bit_len);

        let number_of_limbs = number_of_limbs + if overflow_bit_len > 0 { 1 } else { 0 };
        let decomposed = unassigned
            .map(|unassigned| decompose(unassigned, number_of_limbs, limb_bit_len))
            .transpose_vec(number_of_limbs);

        let terms: Vec<Term<F>> = decomposed
            .into_iter()
            .zip(self.bases(limb_bit_len))
            .map(|(limb, base)| Term::Unassigned(limb, *base))
            .collect();

        self.main_gate()
            .decompose(ctx, &terms[..], F::ZERO, |ctx, is_last| {
                let composition_tag =
                    self.config
                        .bit_len_tag
                        .get(&limb_bit_len)
                        .unwrap_or_else(|| {
                            panic!("composition table is not set, bit lenght: {limb_bit_len}")
                        });
                ctx.enable(self.config.s_composition)?;
                if let Some(tag_composition) = self.config.tag_composition {
                    ctx.assign_fixed(
                        || "tag_composition",
                        tag_composition,
                        F::from(*composition_tag as u64),
                    )?;
                }

                if is_last && overflow_bit_len != 0 {
                    let overflow_tag = self
                        .config
                        .bit_len_tag
                        .get(&overflow_bit_len)
                        .unwrap_or_else(|| {
                            panic!("overflow table is not set, bit lenght: {overflow_bit_len}")
                        });
                    ctx.enable(self.config.s_overflow.unwrap())?;
                    if let Some(tag_overflow) = self.config.tag_overflow {
                        ctx.assign_fixed(
                            || "tag_overflow",
                            tag_overflow,
                            F::from(*overflow_tag as u64),
                        )?;
                    }
                }

                Ok(())
            })
    }

    fn load_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "",
            |mut table| {
                let mut offset = 0;

                table.assign_cell(
                    || "table tag",
                    self.config.t_tag,
                    offset,
                    || Value::known(F::ZERO),
                )?;
                table.assign_cell(
                    || "table value",
                    self.config.t_value,
                    offset,
                    || Value::known(F::ZERO),
                )?;
                offset += 1;

                for (bit_len, tag) in self.config.bit_len_tag.iter() {
                    let tag = F::from(*tag as u64);
                    let table_values: Vec<F> = (0..1 << bit_len).map(|e| F::from(e)).collect();
                    for value in table_values.iter() {
                        table.assign_cell(
                            || "table tag",
                            self.config.t_tag,
                            offset,
                            || Value::known(tag),
                        )?;
                        table.assign_cell(
                            || "table value",
                            self.config.t_value,
                            offset,
                            || Value::known(*value),
                        )?;
                        offset += 1;
                    }
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: PrimeField> RangeChip<F> {
    /// Given config creates new chip that implements ranging
    pub fn new(config: RangeConfig) -> Self {
        let main_gate = MainGate::new(config.main_gate_config.clone());
        let bases = config
            .bit_len_tag
            .keys()
            .filter_map(|&bit_len| {
                if bit_len == 0 {
                    None
                } else {
                    let bases = (0..F::NUM_BITS as usize / bit_len)
                        .map(|i| F::from(2).pow(&[(bit_len * i) as u64, 0, 0, 0]))
                        .collect();
                    Some((bit_len, bases))
                }
            })
            .collect();
        Self {
            config,
            main_gate,
            bases,
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
        let [composition_bit_lens, overflow_bit_lens] = [composition_bit_lens, overflow_bit_lens]
            .map(|mut bit_lens| {
                bit_lens.sort_unstable();
                bit_lens.dedup();
                bit_lens
            });

        let bit_len_tag = BTreeMap::from_iter(
            BTreeSet::from_iter(composition_bit_lens.iter().chain(overflow_bit_lens.iter()))
                .into_iter()
                .enumerate()
                .map(|(idx, bit_len)| (*bit_len, idx + 1)),
        );

        let t_tag = meta.lookup_table_column();
        let t_value = meta.lookup_table_column();

        // TODO: consider for a generic MainGateConfig
        let &MainGateConfig { a, b, c, d, .. } = main_gate_config;

        let s_composition = meta.complex_selector();
        let tag_composition = if composition_bit_lens.len() > 1 {
            let tag = meta.fixed_column();
            for (name, value) in [
                ("composition_a", a),
                ("composition_b", b),
                ("composition_c", c),
                ("composition_d", d),
            ] {
                Self::configure_lookup_with_column_tag(
                    meta,
                    name,
                    s_composition,
                    tag,
                    value,
                    t_tag,
                    t_value,
                )
            }
            Some(tag)
        } else {
            for (name, value) in [
                ("composition_a", a),
                ("composition_b", b),
                ("composition_c", c),
                ("composition_d", d),
            ] {
                Self::configure_lookup_with_constant_tag(
                    meta,
                    name,
                    s_composition,
                    bit_len_tag[&composition_bit_lens[0]],
                    value,
                    t_tag,
                    t_value,
                )
            }
            None
        };

        let (s_overflow, tag_overflow) = if !overflow_bit_lens.is_empty() {
            let s_overflow = meta.complex_selector();
            let tag_overflow = if overflow_bit_lens.len() > 1 {
                let tag = meta.fixed_column();
                Self::configure_lookup_with_column_tag(
                    meta,
                    "overflow_a",
                    s_overflow,
                    tag,
                    a,
                    t_tag,
                    t_value,
                );
                Some(tag)
            } else {
                Self::configure_lookup_with_constant_tag(
                    meta,
                    "overflow_a",
                    s_overflow,
                    bit_len_tag[&overflow_bit_lens[0]],
                    a,
                    t_tag,
                    t_value,
                );
                None
            };

            (Some(s_overflow), tag_overflow)
        } else {
            (None, None)
        };

        RangeConfig {
            main_gate_config: main_gate_config.clone(),
            bit_len_tag,
            t_tag,
            t_value,
            s_composition,
            tag_composition,
            s_overflow,
            tag_overflow,
        }
    }

    fn configure_lookup_with_column_tag(
        meta: &mut ConstraintSystem<F>,
        name: &'static str,
        selector: Selector,
        tag: Column<Fixed>,
        value: Column<Advice>,
        t_tag: TableColumn,
        t_value: TableColumn,
    ) {
        meta.lookup(name, |meta| {
            let selector = meta.query_selector(selector);
            let tag = meta.query_fixed(tag, Rotation::cur());
            let value = meta.query_advice(value, Rotation::cur());
            vec![(tag, t_tag), (selector * value, t_value)]
        });
    }

    fn configure_lookup_with_constant_tag(
        meta: &mut ConstraintSystem<F>,
        name: &'static str,
        selector: Selector,
        tag: usize,
        value: Column<Advice>,
        t_tag: TableColumn,
        t_value: TableColumn,
    ) {
        meta.lookup(name, |meta| {
            let selector = meta.query_selector(selector);
            let tag = selector.clone() * Expression::Constant(F::from(tag as u64));
            let value = meta.query_advice(value, Rotation::cur());
            vec![(tag, t_tag), (selector * value, t_value)]
        });
    }

    fn bases(&self, limb_bit_len: usize) -> &[F] {
        self.bases
            .get(&limb_bit_len)
            .unwrap_or_else(|| panic!("composition table is not set, bit lenght: {}", limb_bit_len))
            .as_slice()
    }
}

#[cfg(test)]
mod tests {

    use halo2wrong::halo2::arithmetic::Field;
    use halo2wrong::halo2::circuit::Value;
    use halo2wrong::RegionCtx;

    use super::{RangeChip, RangeConfig, RangeInstructions};
    use crate::curves::{ff::PrimeField, pasta::Fp};
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
        fn new<F: PrimeField>(
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

        fn main_gate<F: PrimeField>(&self) -> MainGate<F> {
            MainGate::<F>::new(self.range_config.main_gate_config.clone())
        }

        fn range_chip<F: PrimeField>(&self) -> RangeChip<F> {
            RangeChip::<F>::new(self.range_config.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct Input<F: PrimeField> {
        bit_len: usize,
        limb_bit_len: usize,
        value: Value<F>,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit<F: PrimeField> {
        inputs: Vec<Input<F>>,
    }

    impl<F: PrimeField> TestCircuit<F> {
        fn composition_bit_lens() -> Vec<usize> {
            vec![8]
        }

        fn overflow_bit_lens() -> Vec<usize> {
            vec![3]
        }
    }

    impl<F: PrimeField> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

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
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    for input in self.inputs.iter() {
                        let value = input.value;
                        let limb_bit_len = input.limb_bit_len;
                        let bit_len = input.bit_len;

                        let a_0 = main_gate.assign_value(ctx, value)?;
                        let (a_1, decomposed) =
                            range_chip.decompose(ctx, value, limb_bit_len, bit_len)?;

                        main_gate.assert_equal(ctx, &a_0, &a_1)?;

                        let terms: Vec<Term<F>> = decomposed
                            .iter()
                            .zip(range_chip.bases(limb_bit_len))
                            .map(|(limb, base)| Term::Assigned(limb, *base))
                            .collect();
                        let a_1 = main_gate.compose(ctx, &terms[..], F::ZERO)?;
                        main_gate.assert_equal(ctx, &a_0, &a_1)?;
                    }

                    Ok(())
                },
            )?;

            range_chip.load_table(&mut layouter)?;

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
                let value = Fp::from(2).pow(&[bit_len as u64, 0, 0, 0]) - Fp::one();
                Input {
                    value: Value::known(value),
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
