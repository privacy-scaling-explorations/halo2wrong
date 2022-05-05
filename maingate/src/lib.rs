//! `maingate` defines basic instructions for a starndart like PLONK gate and
//! implments a 5 width gate with two multiplication and one rotation
//! customisation

use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Cell};
use halo2wrong::utils::decompose;
use std::marker::PhantomData;

#[macro_use]
mod instructions;
mod main_gate;
mod range;
mod to_bytes;

pub use halo2wrong::{halo2, utils::*, RegionCtx};
pub use instructions::{CombinationOptionCommon, MainGateInstructions, Term};
pub use main_gate::*;
pub use range::*;
pub use to_bytes::*;

/// Helper trait for assigned values across halo2stack.
pub trait Assigned<F: FieldExt> {
    // Returns witness value
    fn value(&self) -> Option<F>;
    // Applies copy constraion to the given `Assigned` witness
    fn constrain_equal(&self, ctx: &mut RegionCtx<'_, '_, F>, other: &Self) -> Result<(), Error> {
        ctx.region.constrain_equal(self.cell(), other.cell())
    }
    // Returns cell of the assigned value
    fn cell(&self) -> Cell;
    // Decomposes witness values as
    // `W = a_0 + a_1 * R + a_1 * R^2 + ...`
    // where
    // `R = 2 ** bit_len`
    fn decompose(&self, number_of_limbs: usize, bit_len: usize) -> Option<Vec<F>> {
        self.value().map(|e| decompose(e, number_of_limbs, bit_len))
    }
}

/// `AssignedCondition` is expected to be a witness their assigned value is `1`
/// or `0`.
#[derive(Debug, Copy, Clone)]
pub struct AssignedCondition<F: FieldExt> {
    bool_value: Option<bool>,
    cell: Cell,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> From<AssignedValue<F>> for AssignedCondition<F> {
    fn from(assigned: AssignedValue<F>) -> Self {
        AssignedCondition::new(assigned.cell, assigned.value)
    }
}

impl<F: FieldExt> AssignedCondition<F> {
    pub fn new(cell: Cell, value: Option<F>) -> Self {
        let bool_value = value.map(|value| value != F::zero());
        AssignedCondition {
            bool_value,
            cell,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt> Assigned<F> for AssignedCondition<F> {
    fn value(&self) -> Option<F> {
        self.bool_value
            .map(|value| if value { F::one() } else { F::zero() })
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> Assigned<F> for &AssignedCondition<F> {
    fn value(&self) -> Option<F> {
        self.bool_value
            .map(|value| if value { F::one() } else { F::zero() })
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

/// `AssignedValue` is a witness value we enforce their validity in gates and
/// apply equality constraint between other assigned values.
#[derive(Debug, Copy, Clone)]
pub struct AssignedValue<F: FieldExt> {
    // Witness value. shoulde be `None` at synthesis time must be `Some ` at prover time.
    value: Option<F>,
    // `cell` is where this witness accomadates. `cell` will be needed to constrain equality
    // between assigned values.
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

impl<F: FieldExt> From<&AssignedCondition<F>> for AssignedValue<F> {
    fn from(cond: &AssignedCondition<F>) -> Self {
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

impl<F: FieldExt> Assigned<F> for &AssignedValue<F> {
    fn value(&self) -> Option<F> {
        self.value
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> AssignedValue<F> {
    pub fn new(cell: Cell, value: Option<F>) -> Self {
        AssignedValue { value, cell }
    }
}

/// `UnassignedValue` is value is about to be assigned.
#[derive(Debug, Clone)]
pub struct UnassignedValue<F: FieldExt>(Option<F>);

impl<F: FieldExt> From<Option<F>> for UnassignedValue<F> {
    fn from(value: Option<F>) -> Self {
        UnassignedValue(value)
    }
}

impl<F: FieldExt> From<UnassignedValue<F>> for Option<F> {
    fn from(value: UnassignedValue<F>) -> Self {
        value.0
    }
}

impl<F: FieldExt> UnassignedValue<F> {
    pub fn value(&self) -> Option<F> {
        self.0
    }

    pub fn decompose(&self, number_of_limbs: usize, bit_len: usize) -> Option<Vec<F>> {
        self.0.map(|e| decompose(e, number_of_limbs, bit_len))
    }

    pub fn assign(&self, cell: Cell) -> AssignedValue<F> {
        AssignedValue::new(cell, self.0)
    }
}
