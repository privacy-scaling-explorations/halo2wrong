use crate::rns::{decompose_fe as decompose, fe_to_big, Common, Integer, Limb};
use halo2::plonk::Error;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Region},
};
use num_bigint::BigUint as big_uint;
use std::marker::PhantomData;

mod ecc;
mod integer;
mod main_gate;
mod range;

pub trait Assigned<F: FieldExt> {
    fn value(&self) -> Option<F>;
    fn cycle_cell(&self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        region.constrain_equal(self.cell(), new_cell)?;
        Ok(())
    }
    fn cell(&self) -> Cell;
    fn decompose(&self, number_of_limbs: usize, bit_len: usize) -> Option<Vec<F>> {
        self.value().map(|e| decompose(e, number_of_limbs, bit_len))
    }
}

#[derive(Debug, Clone)]
pub struct AssignedCondition<F: FieldExt> {
    bool_value: Option<bool>,
    cell: Cell,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AssignedCondition<F> {
    fn new(cell: Cell, value: Option<F>) -> Self {
        let bool_value = value.map(|value| if value == F::zero() { false } else { true });
        AssignedCondition {
            bool_value,
            cell,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt> Assigned<F> for AssignedCondition<F> {
    fn value(&self) -> Option<F> {
        self.bool_value.map(|value| if value { F::one() } else { F::zero() })
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

type AssignedBit<F> = AssignedCondition<F>;

#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt> {
    value: Option<Limb<F>>,
    cell: Cell,
    pub max_val: big_uint,
}

impl<F: FieldExt> Assigned<F> for AssignedLimb<F> {
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

    fn add(&self, other: &Self) -> big_uint {
        self.max_val.clone() + other.max_val.clone()
    }

    fn add_big(&self, other: big_uint) -> big_uint {
        self.max_val.clone() + other
    }

    fn add_fe(&self, other: F) -> big_uint {
        self.add_big(fe_to_big(other))
    }
}

#[derive(Debug, Clone)]
pub struct UnassignedInteger<F: FieldExt> {
    pub integer: Option<Integer<F>>,
}

impl<F: FieldExt> From<Option<Integer<F>>> for UnassignedInteger<F> {
    fn from(integer: Option<Integer<F>>) -> Self {
        UnassignedInteger { integer }
    }
}

impl<F: FieldExt> UnassignedInteger<F> {
    fn limb(&self, idx: usize) -> UnassignedValue<F> {
        UnassignedValue::new(self.integer.as_ref().map(|e| e.limb_value(idx)))
    }

    fn native(&self) -> UnassignedValue<F> {
        UnassignedValue::new(self.integer.as_ref().map(|integer| integer.native()))
    }
}

#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt> {
    limbs: Vec<AssignedLimb<F>>,
    native_value: AssignedValue<F>,
}

impl<F: FieldExt> AssignedInteger<F> {
    pub fn new(limbs: Vec<AssignedLimb<F>>, native_value: AssignedValue<F>) -> Self {
        AssignedInteger { limbs, native_value }
    }

    pub fn integer(&self) -> Option<Integer<F>> {
        self.limbs[0].value.as_ref().map(|_| {
            let limbs = self.limbs.iter().map(|limb| limb.value.clone().unwrap()).collect();
            Integer::new(limbs)
        })
    }

    pub fn limb_value(&self, idx: usize) -> Result<F, Error> {
        Ok(self.limbs[idx].value.as_ref().ok_or(Error::SynthesisError)?.fe())
    }

    pub fn limb(&self, idx: usize) -> AssignedLimb<F> {
        self.limbs[idx].clone()
    }

    pub fn native(&self) -> AssignedValue<F> {
        self.native_value.clone()
    }
}

#[derive(Debug, Clone)]
pub struct AssignedValue<F: FieldExt> {
    pub value: Option<F>,
    cell: Cell,
}

impl<F: FieldExt> From<AssignedCondition<F>> for AssignedValue<F> {
    fn from(cond: AssignedCondition<F>) -> Self {
        AssignedValue {
            value: (&cond).value(),
            cell: cond.cell,
        }
    }
}

impl<F: FieldExt> Assigned<F> for AssignedValue<F> {
    fn value(&self) -> Option<F> {
        self.value
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> AssignedValue<F> {
    fn new(cell: Cell, value: Option<F>) -> Self {
        AssignedValue { value, cell }
    }

    fn to_limb(&self, max_val: big_uint) -> AssignedLimb<F> {
        let value = self.value.map(|value| Limb::<F>::new(value));
        let cell = self.cell;
        AssignedLimb { value, cell, max_val }
    }
}

#[derive(Debug, Clone)]
pub struct UnassignedValue<F: FieldExt> {
    pub value: Option<F>,
}

impl<F: FieldExt> From<Option<F>> for UnassignedValue<F> {
    fn from(value: Option<F>) -> Self {
        UnassignedValue { value }
    }
}

impl<F: FieldExt> UnassignedValue<F> {
    fn new(value: Option<F>) -> Self {
        UnassignedValue { value }
    }

    pub fn value(&self) -> Result<F, Error> {
        Ok(self.value.clone().ok_or(Error::SynthesisError)?)
    }

    pub fn decompose(&self, number_of_limbs: usize, bit_len: usize) -> Option<Vec<F>> {
        self.value.map(|e| decompose(e, number_of_limbs, bit_len))
    }

    pub fn assign(&self, cell: Cell) -> AssignedValue<F> {
        AssignedValue::new(cell, self.value)
    }
}
