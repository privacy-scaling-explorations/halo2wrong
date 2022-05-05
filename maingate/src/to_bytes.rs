//! `ToBytesChip` decomposes an input `AssignedValue` into `byte_len` byte
//! values and checks that those values correspond to the little endian
//! representation of the input value by:
//! - Verifying that each value is in the byte range.
//! - Verifying that the linear combination of all the bytes in base 256 is
//!   equal to the input
//! value.

use super::main_gate::{MainGate, MainGateConfig};
use crate::halo2::arithmetic::FieldExt;
use crate::halo2::circuit::Chip;
use crate::halo2::circuit::Layouter;
use crate::halo2::plonk::{ConstraintSystem, Error};
use crate::halo2::plonk::{Selector, TableColumn};
use crate::halo2::poly::Rotation;
use crate::instructions::{CombinationOptionCommon, MainGateInstructions, Term};
use crate::AssignedValue;
use halo2wrong::RegionCtx;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ToBytesConfig {
    main_gate_config: MainGateConfig,
    /// Selector to enable byte range check in columns a, b, c.  Enabled in all
    /// rows.
    s_abc_byte_range: Selector,
    /// Selector to enable byte range check in column d.  Enabled in all rows
    /// except for the last one, where column d contains the input value.
    s_d_byte_range: Selector,
    /// Table that contains the byte range: [0..255]
    byte_range_table: TableColumn,
}

/// This chip constraints the decomposition of a native integer into little
/// endian bytes.
pub struct ToBytesChip<F: FieldExt> {
    config: ToBytesConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ToBytesChip<F> {
    pub fn new(config: ToBytesConfig) -> Self {
        Self {
            config,
            _marker: PhantomData {},
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        main_gate_config: &MainGateConfig,
    ) -> ToBytesConfig {
        let (a, b, c, d) = (
            main_gate_config.a,
            main_gate_config.b,
            main_gate_config.c,
            main_gate_config.d,
        );
        let byte_range_table = meta.lookup_table_column();
        let s_abc_byte_range = meta.complex_selector();
        let s_d_byte_range = meta.complex_selector();

        macro_rules! meta_lookup {
            ($column:expr, $selector:expr, $table:expr) => {
                #[cfg(not(feature = "kzg"))]
                meta.lookup(|meta| {
                    let exp = meta.query_advice($column, Rotation::cur());
                    let s = meta.query_selector($selector);
                    vec![(exp * s, $table)]
                });
                #[cfg(feature = "kzg")]
                meta.lookup(stringify!($column), |meta| {
                    let exp = meta.query_advice($column, Rotation::cur());
                    let s = meta.query_selector($selector);
                    vec![(exp * s, $table)]
                });
            };
        }

        meta_lookup!(a, s_abc_byte_range, byte_range_table);
        meta_lookup!(b, s_abc_byte_range, byte_range_table);
        meta_lookup!(c, s_abc_byte_range, byte_range_table);
        meta_lookup!(d, s_d_byte_range, byte_range_table);

        ToBytesConfig {
            main_gate_config: main_gate_config.clone(),
            s_abc_byte_range,
            s_d_byte_range,
            byte_range_table,
        }
    }

    fn base(byte_len: usize) -> Vec<F> {
        assert!(byte_len > 0);
        assert!(byte_len < 32);
        (0..byte_len)
            .map(|i| F::from(256).pow(&[i as u64, 0, 0, 0]))
            .collect()
    }

    fn main_gate_config(&self) -> MainGateConfig {
        self.config.main_gate_config.clone()
    }

    fn main_gate(&self) -> MainGate<F> {
        MainGate::<F>::new(self.main_gate_config())
    }

    // acc = acc + sum { from i = index to index + 4 } base[i] * bytes[i]
    fn calc_acc(acc: Option<F>, bytes: &Option<Vec<F>>, index: usize, base: &[F]) -> Option<F> {
        match (acc, bytes.as_ref()) {
            (Some(acc), Some(bytes)) => Some(
                (index..index + 4)
                    .map(|i| base[i] * bytes[i])
                    .fold(acc, |accum, x| accum + x),
            ),
            _ => None,
        }
    }
}

impl<F: FieldExt> Chip<F> for ToBytesChip<F> {
    type Config = ToBytesConfig;
    type Loaded = ();
    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

pub trait ToBytesInstructions<F: FieldExt>: Chip<F> {
    /// Return a list of cells that are constrained to be the `byte_len` little
    /// endian bytes of the `input`
    fn to_bytes(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        input: &AssignedValue<F>,
        byte_len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    /// Load a byte range table in `self.config.byte_range_table`
    fn load_byte_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

impl<F: FieldExt> ToBytesInstructions<F> for ToBytesChip<F> {
    fn to_bytes(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        input: &AssignedValue<F>,
        byte_len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let main_gate = self.main_gate();
        let (one, zero) = (F::one(), F::zero());
        // base panics if byte_len == 0 OR bytelen >= 32
        let base = Self::base(byte_len);

        let bytes: Option<Vec<F>> = input
            .value
            .map(|v| {
                let value_repr = v.to_repr();
                let bytes32 = value_repr.as_ref();
                if bytes32[byte_len..].iter().any(|&b| b != 0) {
                    // `input` doesn't fit in `byte_len`
                    return Err(Error::Synthesis);
                }
                Ok(bytes32[..byte_len]
                    .iter()
                    .map(|b| F::from(*b as u64))
                    .collect())
            })
            .transpose()?;

        let mut bytes_assigned = Vec::new();

        let byte_terms: Vec<Term<F>> = (0..byte_len)
            .map(|i| Term::Unassigned(bytes.as_ref().map(|bytes| bytes[i]), base[i]))
            .collect();
        if byte_terms.len() <= 4 {
            // A. Single row case.  When byte_len is between 1 and 4
            //
            // in = B^0 * b0 + B^1 * b1 + B^2 * b2 + B^3 * b3
            //
            // | A        | B        | C        | D        | E        | E_next |
            // | ---      | ---      | ---      | ---      | ---      | ---    |
            // | B^0 * b0 | B^1 * b1 | B^2 * b2 | B^3 * b3 | -1 * in  | -      |

            let term_0 = byte_terms.get(0).cloned().unwrap_or(Term::Zero);
            let term_1 = byte_terms.get(1).cloned().unwrap_or(Term::Zero);
            let term_2 = byte_terms.get(2).cloned().unwrap_or(Term::Zero);
            let term_3 = byte_terms.get(3).cloned().unwrap_or(Term::Zero);
            let term_4 = Term::Assigned(*input, -F::one());
            ctx.enable(self.config.s_abc_byte_range)?;
            ctx.enable(self.config.s_d_byte_range)?;
            let assigned = main_gate.combine(
                ctx,
                &[term_0, term_1, term_2, term_3, term_4],
                zero,
                CombinationOptionCommon::OneLinerAdd.into(),
            )?;
            bytes_assigned.extend_from_slice(&assigned[..byte_len]);
        } else {
            // B. Multiple row case.  When byte_len is between 5 and 31
            //
            // acc0 = B^0 * b0 + B^1 * b1 + B^2 * b2 + B^3 * b3        (First row)
            // acc1 = B^4 * b4 + B^5 * b5 + B^6 * b6 + B^7 * b7 + acc0 (Intermediate row)
            // in   = B^8 * b8 + B^9 * b9 + B^10 * b10 + acc1          (Last row)
            //
            // | A        | B        | C          | D        | E        | E_next    |
            // | ---      | ---      | ---        | ---      | ---      | ---       |
            // | B^0 * b0 | B^1 * b1 | B^2 * b2   | B^3 * b3 | -        | -1 * acc0 |
            // | B^4 * b4 | B^5 * b5 | B^6 * b6   | B^7 * b7 | 1 * acc0 | -1 * acc1 |
            // | B^8 * b8 | B^9 * b9 | B^10 * b10 | -1 * in  | 1 * acc1 | -         |

            let mut index = 0;

            // First row
            // acc0 = B^0 * b0 + B^1 * b1 + B^2 * b2 + B^3 * b3
            ctx.enable(self.config.s_abc_byte_range)?;
            ctx.enable(self.config.s_d_byte_range)?;
            let assigned = main_gate.combine(
                ctx,
                &[
                    byte_terms[0].clone(),
                    byte_terms[1].clone(),
                    byte_terms[2].clone(),
                    byte_terms[3].clone(),
                    Term::Zero,
                ],
                zero,
                CombinationOptionCommon::CombineToNextAdd(-one).into(),
            )?;
            bytes_assigned.extend_from_slice(&assigned[..4]);
            let mut acc = bytes.as_ref().map(|_| F::zero());
            acc = Self::calc_acc(acc, &bytes, index, &base);
            index += 4;

            // Intermediate rows
            // acc1 = B^4 * b4 + B^5 * b5 + B^6 * b6 + B^7 * b7 + acc0
            while index + 3 < byte_len {
                ctx.enable(self.config.s_abc_byte_range)?;
                ctx.enable(self.config.s_d_byte_range)?;
                let assigned = main_gate.combine(
                    ctx,
                    &[
                        byte_terms[index + 0].clone(),
                        byte_terms[index + 1].clone(),
                        byte_terms[index + 2].clone(),
                        byte_terms[index + 3].clone(),
                        Term::Unassigned(acc, F::one()),
                    ],
                    zero,
                    CombinationOptionCommon::CombineToNextAdd(-one).into(),
                )?;
                bytes_assigned.extend_from_slice(&assigned[..4]);
                acc = Self::calc_acc(acc, &bytes, index, &base);
                index += 4;
            }

            // Last row
            // in   = B^8 * b8 + B^9 * b9 + B^10 * b10 + acc1
            let term_0 = byte_terms.get(index + 0).cloned().unwrap_or(Term::Zero);
            let term_1 = byte_terms.get(index + 1).cloned().unwrap_or(Term::Zero);
            let term_2 = byte_terms.get(index + 2).cloned().unwrap_or(Term::Zero);
            let term_3 = Term::Assigned(*input, -F::one());
            let term_4 = Term::Unassigned(acc, F::one());

            ctx.enable(self.config.s_abc_byte_range)?;
            let assigned = main_gate.combine(
                ctx,
                &[term_0, term_1, term_2, term_3, term_4],
                zero,
                CombinationOptionCommon::OneLinerAdd.into(),
            )?;
            bytes_assigned.extend_from_slice(&assigned[..byte_len - index]);
        }

        Ok(bytes_assigned)
    }

    fn load_byte_range_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "byte range",
            |mut table| {
                for (index, value) in (0..256).enumerate() {
                    table.assign_cell(
                        || "limb range table",
                        self.config.byte_range_table,
                        index,
                        || Ok(F::from(value)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use halo2wrong::RegionCtx;

    use super::*;
    use crate::halo2::arithmetic::FieldExt;
    use crate::halo2::circuit::{Layouter, SimpleFloorPlanner};
    use crate::halo2::dev::MockProver;
    use crate::halo2::plonk::{Circuit, ConstraintSystem, Error};
    use crate::main_gate::MainGate;
    use crate::{MainGateInstructions, UnassignedValue};
    use rand::SeedableRng;
    use rand_core::RngCore;
    use rand_xorshift::XorShiftRng;

    cfg_if::cfg_if! {
        if #[cfg(feature = "kzg")] {
            use crate::halo2::pairing::bn256::Fr as Fp;
        } else {
            use crate::halo2::pasta::Fp;
        }
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        to_bytes_config: ToBytesConfig,
    }

    impl TestCircuitConfig {
        fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
            let main_gate_config = MainGate::<F>::configure(meta);
            let to_bytes_config = ToBytesChip::<F>::configure(meta, &main_gate_config);
            Self {
                main_gate_config,
                to_bytes_config,
            }
        }

        fn main_gate<F: FieldExt>(&self) -> MainGate<F> {
            MainGate::<F>::new(self.main_gate_config.clone())
        }

        fn to_bytes_chip<F: FieldExt>(&self) -> ToBytesChip<F> {
            ToBytesChip::<F>::new(self.to_bytes_config.clone())
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuit<F: FieldExt> {
        input: Vec<(usize, Option<F>)>,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            TestCircuitConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let to_bytes_chip = config.to_bytes_chip();
            let main_gate = config.main_gate();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    for value in self.input.iter() {
                        let byte_len = value.0;
                        let value = value.1;

                        let value_bytes = value.map(|v| v.to_repr().as_ref().to_vec());
                        let bytes_0: Vec<AssignedValue<F>> = (0..byte_len)
                            .map(|i| {
                                main_gate.assign_value(
                                    ctx,
                                    &UnassignedValue(
                                        value_bytes.as_ref().map(|bytes| F::from(bytes[i] as u64)),
                                    ),
                                )
                            })
                            .collect::<Result<_, _>>()?;

                        let v = main_gate.assign_value(ctx, &UnassignedValue(value))?;
                        let bytes_1 = to_bytes_chip.to_bytes(ctx, &v, byte_len)?;

                        for i in 0..byte_len {
                            main_gate.assert_equal(ctx, &bytes_0[i], &bytes_1[i])?;
                        }
                    }

                    Ok(())
                },
            )?;

            to_bytes_chip.load_byte_range_table(&mut layouter)?;

            Ok(())
        }
    }

    fn rand_f<F: FieldExt>(rng: impl RngCore, byte_len: usize) -> F {
        let v = F::random(rng);
        let mut v_repr = v.to_repr();
        let v_bytes = v_repr.as_mut();
        for b in v_bytes[byte_len..].iter_mut() {
            *b = 0
        }
        F::from_repr(v_repr).unwrap()
    }

    #[test]
    fn test_to_bytes_circuit() {
        let min_byte_len = 1;
        let max_byte_len = 31;

        let k: u32 = 12;
        let mut rng = XorShiftRng::seed_from_u64(1);

        let input = (min_byte_len..=max_byte_len)
            .map(|i| {
                let byte_len = i as usize;
                let value = rand_f(&mut rng, byte_len);
                (byte_len, Some(value))
            })
            .collect();

        let circuit = TestCircuit::<Fp> { input };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
