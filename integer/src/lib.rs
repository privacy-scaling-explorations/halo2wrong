//! `integer` implements constraints for non native field
//! operations

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

use crate::rns::{Common, Integer, Limb};
use halo2::{circuit::Value, halo2curves::ff::PrimeField};
use maingate::{big_to_fe, compose, fe_to_big, AssignedValue};
use num_bigint::BigUint as big_uint;
use rns::Rns;
use std::rc::Rc;

pub use chip::{IntegerChip, IntegerConfig};
pub use instructions::{IntegerInstructions, Range};
pub use maingate;
pub use maingate::halo2;

#[cfg(test)]
use halo2::halo2curves as curves;

/// Chip for integer constaints
pub mod chip;
/// Commoon instructions for integer operations and assignments
pub mod instructions;
/// Residue number system construction and utilities
pub mod rns;

/// `RangeChip` supports upto four full limbs decomposition of a value
/// `AssignedLimb` is mostly subjected to the range check. Say we have 68-bit
/// limb and it is decomposed to four 17-bit limbs.
pub const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

/// AssignedLimb is a limb of an non native integer
#[derive(Debug, Clone)]
pub struct AssignedLimb<F: PrimeField> {
    // Witness value
    value: AssignedValue<F>,
    // Maximum value to track overflow and reduction flow
    max_val: big_uint,
}

/// `AssignedLimb` can be also represented as `AssignedValue`
impl<F: PrimeField> From<AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: AssignedLimb<F>) -> Self {
        limb.value
    }
}

/// `AssignedLimb` can be also represented as `AssignedValue`
impl<F: PrimeField> From<&AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: &AssignedLimb<F>) -> Self {
        limb.value.clone()
    }
}

impl<F: PrimeField> AsRef<AssignedValue<F>> for AssignedLimb<F> {
    fn as_ref(&self) -> &AssignedValue<F> {
        &self.value
    }
}

impl<F: PrimeField> AssignedLimb<F> {
    fn value(&self) -> Value<F> {
        self.value.value().cloned()
    }
}

impl<F: PrimeField> AssignedLimb<F> {
    /// Given an assigned value and expected maximum value constructs new
    /// `AssignedLimb`
    fn from(value: AssignedValue<F>, max_val: big_uint) -> Self {
        AssignedLimb { value, max_val }
    }

    /// Helper functions for maximum value tracking

    fn limb(&self) -> Value<Limb<F>> {
        self.value.value().map(|value| Limb::new(*value))
    }

    fn max_val(&self) -> big_uint {
        self.max_val.clone()
    }

    fn add(&self, other: &Self) -> big_uint {
        self.max_val.clone() + &other.max_val
    }

    fn add_add(&self, other_0: &Self, other_1: &Self) -> big_uint {
        self.max_val.clone() + &other_0.max_val + &other_1.max_val
    }

    fn mul2(&self) -> big_uint {
        self.max_val.clone() + &self.max_val
    }

    fn mul3(&self) -> big_uint {
        self.max_val.clone() + &self.max_val + &self.max_val
    }

    fn add_big(&self, other: big_uint) -> big_uint {
        self.max_val.clone() + other
    }

    fn add_fe(&self, other: F) -> big_uint {
        self.add_big(fe_to_big(other))
    }
}

/// Witness integer that is about to be assigned.
#[derive(Debug, Clone)]
pub struct UnassignedInteger<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(Value<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>);

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    From<Value<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>
    for UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn from(integer: Value<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        UnassignedInteger(integer)
    }
}

///
#[derive(Debug, Clone)]
pub struct AssignedInteger<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    // Limbs of the emulated integer
    limbs: [AssignedLimb<N>; NUMBER_OF_LIMBS],
    /// Value in the scalar field
    native_value: AssignedValue<N>,
    /// Share rns across all `AssignedIntegers`s
    rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Creates a new [`AssignedInteger`].
    pub fn new(
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
        limbs: &[AssignedLimb<N>; NUMBER_OF_LIMBS],
        native_value: AssignedValue<N>,
    ) -> Self {
        AssignedInteger {
            limbs: limbs.clone(),
            native_value,
            rns,
        }
    }

    /// Returns assigned limbs
    pub fn limbs(&self) -> &[AssignedLimb<N>; NUMBER_OF_LIMBS] {
        &self.limbs
    }

    /// Returns value under native modulus
    pub fn native(&self) -> &AssignedValue<N> {
        &self.native_value
    }

    /// Witness form of the assigned integer that is used to derive further
    /// witnesses
    pub fn integer(&self) -> Value<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        let limbs: Value<Vec<Limb<N>>> = self.limbs.iter().map(|limb| limb.limb()).collect();
        limbs.map(|limbs| Integer::new(limbs, Rc::clone(&self.rns)))
    }

    fn make_aux(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut max_shift = 0usize;
        let max_vals = self.max_vals();
        for (max_val, aux) in max_vals.iter().zip(self.rns.base_aux.iter()) {
            let mut shift = 1;
            let mut aux = aux.clone();
            while *max_val > aux {
                aux <<= 1usize;
                max_shift = std::cmp::max(shift, max_shift);
                shift += 1;
            }
        }

        Integer::from_limbs(
            &self
                .rns
                .base_aux
                .iter()
                .map(|aux_limb| big_to_fe(aux_limb << max_shift))
                .collect::<Vec<N>>()
                .try_into()
                .unwrap(),
            Rc::clone(&self.rns),
        )
    }

    fn max_val(&self) -> big_uint {
        compose(self.max_vals().to_vec(), BIT_LEN_LIMB)
    }

    fn max_vals(&self) -> [big_uint; NUMBER_OF_LIMBS] {
        self.limbs
            .iter()
            .map(|limb| limb.max_val())
            .collect::<Vec<big_uint>>()
            .try_into()
            .unwrap()
    }

    fn limb(&self, idx: usize) -> &AssignedValue<N> {
        self.limbs[idx].as_ref()
    }
}
