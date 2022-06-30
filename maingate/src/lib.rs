//! `maingate` defines basic instructions for a starndart like PLONK gate and
//! implments a 5 width gate with two multiplication and one rotation
//! customisation

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

use halo2::plonk::Error;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Value},
};
use halo2wrong::utils::decompose;
use std::marker::PhantomData;

#[macro_use]
mod instructions;
mod main_gate;
mod range;

pub use halo2wrong::{halo2, utils::*, RegionCtx};
pub use instructions::{CombinationOptionCommon, MainGateInstructions, Term};
pub use main_gate::*;
pub use range::*;

#[cfg(test)]
use halo2wrong::curves;

/// Helper trait for assigned values across halo2stack.
pub trait Assigned<F: FieldExt> {
    /// Returns witness value
    fn value(&self) -> Value<F>;
    /// Applies copy constraion to the given `Assigned` witness
    fn constrain_equal(&self, ctx: &mut RegionCtx<'_, '_, F>, other: &Self) -> Result<(), Error> {
        ctx.region.constrain_equal(self.cell(), other.cell())
    }
    /// Returns cell of the assigned value
    fn cell(&self) -> Cell;
    /// Decomposes witness values as
    /// `W = a_0 + a_1 * R + a_1 * R^2 + ...`
    /// where
    /// `R = 2 ** bit_len`
    fn decompose(&self, number_of_limbs: usize, bit_len: usize) -> Value<Vec<F>> {
        self.value().map(|e| decompose(e, number_of_limbs, bit_len))
    }
}

/// `AssignedCondition` is expected to be a witness their assigned value is `1`
/// or `0`.
#[derive(Debug, Copy, Clone)]
pub struct AssignedCondition<F: FieldExt> {
    bool_value: Value<bool>,
    cell: Cell,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> From<AssignedValue<F>> for AssignedCondition<F> {
    fn from(assigned: AssignedValue<F>) -> Self {
        AssignedCondition::new(assigned.cell, assigned.value)
    }
}

impl<F: FieldExt> AssignedCondition<F> {
    /// Creates a new [`AssignedCondition`] from a field element.
    /// It will have false value if the provided element is zero
    /// and true otherwise
    pub fn new(cell: Cell, value: Value<F>) -> Self {
        let bool_value = value.map(|value| value != F::zero());
        AssignedCondition {
            bool_value,
            cell,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt> Assigned<F> for AssignedCondition<F> {
    fn value(&self) -> Value<F> {
        self.bool_value
            .map(|value| if value { F::one() } else { F::zero() })
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> Assigned<F> for &AssignedCondition<F> {
    fn value(&self) -> Value<F> {
        self.bool_value
            .map(|value| if value { F::one() } else { F::zero() })
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

/// [`AssignedValue`] is a witness value we enforce their validity in gates and
/// apply equality constraint between other assigned values.
#[derive(Debug, Copy, Clone)]
pub struct AssignedValue<F: FieldExt> {
    // Witness value. shoulde be `None` at synthesis time must be `Some ` at prover time.
    value: Value<F>,
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
    fn value(&self) -> Value<F> {
        self.value
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> Assigned<F> for &AssignedValue<F> {
    fn value(&self) -> Value<F> {
        self.value
    }
    fn cell(&self) -> Cell {
        self.cell
    }
}

impl<F: FieldExt> AssignedValue<F> {
    /// Creates a new [`AssignedValue`] from a field element
    pub fn new(cell: Cell, value: Value<F>) -> Self {
        AssignedValue { value, cell }
    }
}
