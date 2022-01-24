use crate::rns::{Common, Integer, Limb};
use crate::WrongExt;
use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Cell};
use halo2arith::{compose, fe_to_big, halo2, Assigned, AssignedValue, UnassignedValue};
use num_bigint::BigUint as big_uint;

mod ecc;
mod integer;
mod ecdsa;

pub(crate) use integer::IntegerInstructions;

#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt> {
    value: Option<Limb<F>>,
    cell: Cell,
    max_val: big_uint,
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
        AssignedLimb { value, cell, max_val }
    }

    fn from(assigned: AssignedValue<F>, max_val: big_uint) -> Self {
        let value = assigned.value().map(|value| Limb::<F>::new(value));
        let cell = assigned.cell();
        AssignedLimb { value, cell, max_val }
    }

    pub(super) fn limb(&self) -> Option<Limb<F>> {
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
pub struct UnassignedInteger<'a, W: WrongExt, F: FieldExt>(Option<Integer<'a, W, F>>);

impl<'a, W: WrongExt, F: FieldExt> From<Option<Integer<'a, W, F>>> for UnassignedInteger<'a, W, F> {
    fn from(integer: Option<Integer<'a, W, F>>) -> Self {
        UnassignedInteger(integer)
    }
}

impl<'a, W: WrongExt, F: FieldExt> UnassignedInteger<'a, W, F> {
    fn value(&self) -> Option<big_uint> {
        self.0.as_ref().map(|e| e.value())
    }

    fn limb(&self, idx: usize) -> UnassignedValue<F> {
        self.0.as_ref().map(|e| e.limb_value(idx)).into()
    }

    fn native(&self) -> UnassignedValue<F> {
        self.0.as_ref().map(|integer| integer.native()).into()
    }
}

#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt> {
    limbs: Vec<AssignedLimb<F>>,
    native_value: AssignedValue<F>,
    bit_len_limb: usize,
}

impl<F: FieldExt> AssignedInteger<F> {
    pub fn new(limbs: Vec<AssignedLimb<F>>, native_value: AssignedValue<F>, bit_len_limb: usize) -> Self {
        AssignedInteger {
            limbs,
            native_value,
            bit_len_limb,
        }
    }

    pub fn max_val(&self) -> big_uint {
        compose(self.max_vals(), self.bit_len_limb)
    }

    pub fn max_vals(&self) -> Vec<big_uint> {
        self.limbs.iter().map(|limb| limb.max_val()).collect()
    }

    pub fn limb_value(&self, idx: usize) -> Result<F, Error> {
        Ok(self.limbs[idx].value.as_ref().ok_or(Error::Synthesis)?.fe())
    }

    pub fn limb(&self, idx: usize) -> AssignedLimb<F> {
        self.limbs[idx].clone()
    }

    pub fn limbs(&self) -> Option<Vec<Limb<F>>> {
        self.has_value().map(|_| {
            let limbs = self.limbs.iter().map(|limb| limb.limb().unwrap()).collect();
            limbs
        })
    }

    pub fn native(&self) -> AssignedValue<F> {
        self.native_value.clone()
    }

    fn has_value(&self) -> Option<()> {
        self.limbs[0].value.clone().map(|_| ())
    }
}
