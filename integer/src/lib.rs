#![allow(dead_code)]
#![feature(trait_alias)]

use std::rc::Rc;

use crate::rns::{Common, Integer, Limb};
use halo2::{arithmetic::FieldExt, circuit::Cell};
use maingate::{big_to_fe, compose, fe_to_big, Assigned, AssignedValue, UnassignedValue};
use num_bigint::BigUint as big_uint;

pub use maingate;
pub use maingate::halo2;
use rns::Rns;
pub mod integer;
pub use crate::integer::{IntegerChip, IntegerConfig, IntegerInstructions, Range};
pub mod rns;

pub const NUMBER_OF_LIMBS: usize = 4;
pub const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

cfg_if::cfg_if! {
  if #[cfg(feature = "kzg")] {
    pub trait WrongExt = halo2::arithmetic::BaseExt;
  } else {
    pub trait WrongExt = halo2::arithmetic::FieldExt;

  }
}

#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt> {
    value: Option<Limb<F>>,
    cell: Cell,
    max_val: big_uint,
}

impl<F: FieldExt> From<AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: AssignedLimb<F>) -> Self {
        AssignedValue::new(limb.cell(), limb.value())
    }
}

impl<F: FieldExt> Assigned<F> for AssignedLimb<F> {
    fn value(&self) -> Option<F> {
        self.value.as_ref().map(|value| value.fe())
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> Assigned<F> for &AssignedLimb<F> {
    fn value(&self) -> Option<F> {
        self.value.as_ref().map(|value| value.fe())
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> AssignedLimb<F> {
    fn new(cell: Cell, value: Option<F>, max_val: big_uint) -> Self {
        let value = value.map(|value| Limb::<F>::new(value));
        AssignedLimb {
            value,
            cell,
            max_val,
        }
    }

    fn from(assigned: AssignedValue<F>, max_val: big_uint) -> Self {
        let value = assigned.value().map(|value| Limb::<F>::new(value));
        let cell = assigned.cell();
        AssignedLimb {
            value,
            cell,
            max_val,
        }
    }

    fn limb(&self) -> Option<Limb<F>> {
        self.value.clone()
    }

    fn max_val(&self) -> big_uint {
        self.max_val.clone()
    }

    fn add(&self, other: &Self) -> big_uint {
        self.max_val.clone() + other.max_val.clone()
    }

    fn mul2(&self) -> big_uint {
        self.max_val.clone() + self.max_val.clone()
    }

    fn mul3(&self) -> big_uint {
        self.max_val.clone() + self.max_val.clone() + self.max_val.clone()
    }

    fn add_big(&self, other: big_uint) -> big_uint {
        self.max_val.clone() + other
    }

    fn add_fe(&self, other: F) -> big_uint {
        self.add_big(fe_to_big(other))
    }
}

#[derive(Debug, Clone)]
pub struct UnassignedInteger<W: WrongExt, F: FieldExt>(Option<Integer<W, F>>);

impl<W: WrongExt, F: FieldExt> UnassignedInteger<W, F> {
    pub fn new(int: Option<Integer<W, F>>) -> Self {
        Self(int)
    }
}

impl<'a, W: WrongExt, F: FieldExt> From<Option<Integer<W, F>>> for UnassignedInteger<W, F> {
    fn from(integer: Option<Integer<W, F>>) -> Self {
        UnassignedInteger(integer)
    }
}

impl<W: WrongExt, F: FieldExt> UnassignedInteger<W, F> {
    fn value(&self) -> Option<big_uint> {
        self.0.as_ref().map(|e| e.value())
    }

    fn limb(&self, idx: usize) -> UnassignedValue<F> {
        self.0.as_ref().map(|e| e.limb(idx).fe()).into()
    }

    fn native(&self) -> UnassignedValue<F> {
        self.0.as_ref().map(|integer| integer.native()).into()
    }
}

#[derive(Debug, Clone)]
pub struct AssignedInteger<W: WrongExt, N: FieldExt> {
    limbs: Vec<AssignedLimb<N>>,
    native_value: AssignedValue<N>,
    rns: Rc<Rns<W, N>>,
}

impl<'a, W: WrongExt, N: FieldExt> AssignedInteger<W, N> {
    pub fn new(
        rns: Rc<Rns<W, N>>,
        limbs: Vec<AssignedLimb<N>>,
        native_value: AssignedValue<N>,
    ) -> Self {
        AssignedInteger {
            limbs,
            native_value,
            rns,
        }
    }

    fn max_val(&self) -> big_uint {
        compose(self.max_vals(), self.rns.bit_len_limb)
    }

    fn max_vals(&self) -> Vec<big_uint> {
        self.limbs.iter().map(|limb| limb.max_val()).collect()
    }

    fn limb(&self, idx: usize) -> AssignedLimb<N> {
        self.limbs[idx].clone()
    }

    pub fn limbs(&self) -> Vec<AssignedLimb<N>> {
        self.limbs.clone()
    }

    pub fn native(&self) -> AssignedValue<N> {
        self.native_value.clone()
    }

    pub fn integer(&self) -> Option<Integer<W, N>> {
        let has_value = self.limbs[0].value.clone().map(|_| ());
        let limbs: Option<Vec<Limb<N>>> = has_value.map(|_| {
            let limbs = self.limbs.iter().map(|limb| limb.limb().unwrap()).collect();
            limbs
        });
        limbs.map(|limbs| Integer::new(limbs, Rc::clone(&self.rns)))
    }

    pub fn make_aux(&self) -> Integer<W, N> {
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
        let limbs = self
            .rns
            .base_aux
            .iter()
            .map(|aux_limb| big_to_fe(aux_limb << max_shift))
            .collect();
        Integer::from_limbs(limbs, Rc::clone(&self.rns))
    }
}
