use crate::{
    curves::ff::{FromUniformBytes, PrimeField},
    halo2::{
        circuit::Value,
        dev::MockProver,
        plonk::{
            Advice, Any, Assigned, Assignment, Challenge, Circuit, Column, ConstraintSystem, Error,
            Fixed, FloorPlanner, Instance, Selector,
        },
    },
};
use num_bigint::BigUint as big_uint;
use num_traits::{Num, One, Zero};
use std::{
    cell::RefCell,
    ops::{RangeInclusive, Shl},
};

pub fn modulus<F: PrimeField>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

pub fn power_of_two<F: PrimeField>(n: usize) -> F {
    big_to_fe(big_uint::one() << n)
}

pub fn big_to_fe<F: PrimeField>(e: big_uint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

pub fn fe_to_big<F: PrimeField>(fe: F) -> big_uint {
    big_uint::from_bytes_le(fe.to_repr().as_ref())
}

pub fn decompose<F: PrimeField>(e: F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    decompose_big(fe_to_big(e), number_of_limbs, bit_len)
}

pub fn decompose_big<F: PrimeField>(e: big_uint, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    let mut e = e;
    let mask = big_uint::from(1usize).shl(bit_len) - 1usize;
    let limbs: Vec<F> = (0..number_of_limbs)
        .map(|_| {
            let limb = mask.clone() & e.clone();
            e = e.clone() >> bit_len;
            big_to_fe(limb)
        })
        .collect();

    limbs
}

/// Compute the represented value by a vector of values and a bit length.
///
/// This function is used to compute the value of an integer
/// passing as input its limb values and the bit length used.
/// Returns the sum of all limbs scaled by 2^(bit_len * i)
pub fn compose(input: Vec<big_uint>, bit_len: usize) -> big_uint {
    input
        .iter()
        .rev()
        .fold(big_uint::zero(), |acc, val| (acc << bit_len) + val)
}

pub fn mock_prover_verify<F: FromUniformBytes<64> + Ord, C: Circuit<F>>(
    circuit: &C,
    instance: Vec<Vec<F>>,
) {
    let dimension = DimensionMeasurement::measure(circuit).unwrap();
    let prover = MockProver::run(dimension.k(), circuit, instance)
        .unwrap_or_else(|err| panic!("{:#?}", err));
    assert_eq!(
        prover.verify_at_rows_par(dimension.advice_range(), dimension.advice_range()),
        Ok(())
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dimension {
    blinding_factor: u64,
    instance: u64,
    advice: u64,
    fixed: u64,
}

impl Dimension {
    fn k(&self) -> u32 {
        u64::BITS
            - ([self.instance, self.advice, self.fixed]
                .into_iter()
                .max_by(Ord::cmp)
                .expect("Unexpected empty column iterator")
                + self.blinding_factor)
                .next_power_of_two()
                .leading_zeros()
            - 1
    }

    fn advice_range(&self) -> RangeInclusive<usize> {
        0..=self.advice as usize
    }
}

#[derive(Default)]
pub struct DimensionMeasurement {
    instance: RefCell<u64>,
    advice: RefCell<u64>,
    fixed: RefCell<u64>,
}

impl DimensionMeasurement {
    fn update<C: Into<Any>>(&self, column: C, offset: usize) {
        let mut target = match column.into() {
            Any::Instance => self.instance.borrow_mut(),
            Any::Advice(_advice) => self.advice.borrow_mut(),
            Any::Fixed => self.fixed.borrow_mut(),
        };
        if offset as u64 > *target {
            *target = offset as u64;
        }
    }

    pub fn measure<F: PrimeField, C: Circuit<F>>(circuit: &C) -> Result<Dimension, Error> {
        let mut cs = ConstraintSystem::default();
        let config = C::configure(&mut cs);
        let mut measurement = Self::default();
        C::FloorPlanner::synthesize(&mut measurement, circuit, config, cs.constants().to_vec())?;
        Ok(Dimension {
            blinding_factor: cs.blinding_factors() as u64,
            instance: measurement.instance.take(),
            advice: measurement.advice.take(),
            fixed: measurement.fixed.take(),
        })
    }
}

impl<F: PrimeField> Assignment<F> for DimensionMeasurement {
    fn enter_region<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }

    fn exit_region(&mut self) {}

    fn get_challenge(&self, _challenge: Challenge) -> Value<F> {
        Value::unknown()
    }

    fn enable_selector<A, AR>(&mut self, _: A, _: &Selector, offset: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.update(Fixed, offset);
        Ok(())
    }

    fn query_instance(&self, _: Column<Instance>, offset: usize) -> Result<Value<F>, Error> {
        self.update(Instance, offset);
        Ok(Value::unknown())
    }

    fn annotate_column<A, AR>(&mut self, _annotation: A, _column: Column<Any>)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        // Do nothing.
    }

    fn assign_advice<V, VR, A, AR>(
        &mut self,
        _: A,
        _: Column<Advice>,
        offset: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.update(Any::advice(), offset);
        Ok(())
    }

    fn assign_fixed<V, VR, A, AR>(
        &mut self,
        _: A,
        _: Column<Fixed>,
        offset: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.update(Fixed, offset);
        Ok(())
    }

    fn copy(
        &mut self,
        lhs: Column<Any>,
        offset_lhs: usize,
        rhs: Column<Any>,
        offset_rhs: usize,
    ) -> Result<(), Error> {
        self.update(*lhs.column_type(), offset_lhs);
        self.update(*rhs.column_type(), offset_rhs);
        Ok(())
    }

    fn fill_from_row(
        &mut self,
        _: Column<Fixed>,
        offset: usize,
        _: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.update(Fixed, offset);
        Ok(())
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }

    fn pop_namespace(&mut self, _: Option<String>) {}
}

#[test]
fn test_round_trip() {
    use crate::curves::{ff::Field, pasta::Fp};
    use num_bigint::RandomBits;
    use rand::Rng;
    use rand_core::OsRng;

    for _ in 0..1000 {
        let a: big_uint = OsRng.sample(RandomBits::new(256));
        let modulus = modulus::<Fp>();
        let a_0 = a % modulus;
        let t: Fp = big_to_fe(a_0.clone());
        let a_1 = fe_to_big(t);
        assert_eq!(a_0, a_1);
    }

    for _ in 0..1000 {
        let a_0 = Fp::random(OsRng);
        let t = fe_to_big(a_0);
        let a_1 = big_to_fe(t);
        assert_eq!(a_0, a_1);
    }
}

#[test]
fn test_bit_decomposition() {
    use crate::curves::pasta::Fp;
    use num_bigint::RandomBits;
    use rand::Rng;
    use rand_core::OsRng;

    let bit_size = 256usize;
    let e_0: big_uint = OsRng.sample(RandomBits::new(bit_size as u64));

    let decomposed = decompose_big::<Fp>(e_0.clone(), bit_size, 1);
    let e_1 = compose(decomposed.into_iter().map(fe_to_big).collect(), 1);

    assert_eq!(e_0, e_1);
}

#[test]
fn test_dimension_measurement() {
    use halo2::{
        circuit::{floor_planner::V1, Layouter, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
    };
    use std::marker::PhantomData;

    #[derive(Default)]
    struct TestCircuit<F>(PhantomData<F>);

    impl<F: PrimeField> Circuit<F> for TestCircuit<F> {
        type Config = (Column<Instance>, Column<Fixed>, [Column<Advice>; 2]);
        type FloorPlanner = V1;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            (
                meta.instance_column(),
                meta.fixed_column(),
                [meta.advice_column(), meta.advice_column()],
            )
        }

        fn synthesize(
            &self,
            (i0, f0, [a0, a1]): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    for i in 0..15 {
                        region.assign_fixed(|| "", f0, i, || Value::known(F::ZERO))?;
                    }
                    Ok(())
                },
            )?;
            layouter.assign_region(
                || "",
                |mut region| {
                    for i in 0..10 {
                        region.assign_advice(|| "", a0, i, || Value::known(F::ZERO))?;
                    }
                    Ok(())
                },
            )?;
            layouter.assign_region(
                || "",
                |mut region| {
                    for i in 0..20 {
                        region.assign_advice(|| "", a1, i, || Value::known(F::ZERO))?;
                    }
                    Ok(())
                },
            )?;
            let cell = layouter.assign_region(
                || "",
                |mut region| {
                    let mut cell = None;
                    for i in 0..20 {
                        cell = Some(
                            region
                                .assign_advice(|| "", a0, i, || Value::known(F::ZERO))?
                                .cell(),
                        );
                    }
                    Ok(cell.unwrap())
                },
            )?;
            layouter.constrain_instance(cell, i0, 4)?;
            Ok(())
        }
    }

    let circuit = TestCircuit::<halo2::halo2curves::bn256::Fr>::default();
    assert_eq!(
        DimensionMeasurement::measure(&circuit).unwrap(),
        Dimension {
            blinding_factor: 5,
            instance: 4,
            advice: 29,
            fixed: 14,
        }
    );
}
