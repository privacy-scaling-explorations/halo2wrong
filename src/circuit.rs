use crate::{
    rns::{Integer, Limb},
    NUMBER_OF_LIMBS,
};
use halo2::{arithmetic::FieldExt, circuit::Cell};
use std::marker::PhantomData;

mod integer;
mod main_gate;
mod range;

#[derive(Debug, Clone)]
pub struct AssignedCondition<F: FieldExt> {
    _value: Option<bool>,
    cell: Cell,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AssignedCondition<F> {
    pub fn value(&self) -> Option<F> {
        self._value.map(|value| if value { F::one() } else { F::zero() })
    }

    pub fn clone_with_cell(&self, cell: Cell) -> Self {
        Self {
            _value: self._value.clone(),
            cell,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt> {
    pub value: Option<Integer<F>>,
    pub cells: Vec<Cell>,
}

impl<F: FieldExt> AssignedInteger<F> {
    pub fn value(&self) -> Option<Integer<F>> {
        self.value.clone()
    }

    fn new(cells: Vec<Cell>, value: Option<Integer<F>>) -> Self {
        Self { value, cells }
    }

    pub fn clone_with_cells(&self, cells: Vec<Cell>) -> Self {
        Self {
            value: self.value.clone(),
            cells: cells,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt> {
    pub value: Option<Limb<F>>,
    pub cell: Cell,
}

impl<F: FieldExt> From<AssignedValue<F>> for AssignedLimb<F> {
    fn from(assigned_value: AssignedValue<F>) -> Self {
        Self {
            value: assigned_value.value.map(|e| Limb::<F>::from_fe(e)),
            cell: assigned_value.cell,
        }
    }
}

impl<F: FieldExt> AssignedLimb<F> {
    pub fn clone_with_cell(&self, cell: Cell) -> Self {
        Self {
            value: self.value.clone(),
            cell,
        }
    }

    fn new(cell: Cell, value: Option<Limb<F>>) -> Self {
        AssignedLimb { value, cell }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedValue<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Cell,
}

impl<F: FieldExt> From<AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: AssignedLimb<F>) -> Self {
        Self {
            value: limb.value.map(|e| e.fe()),
            cell: limb.cell,
        }
    }
}

impl<F: FieldExt> From<&AssignedInteger<F>> for Vec<AssignedValue<F>> {
    fn from(integer: &AssignedInteger<F>) -> Self {
        let limbs = integer.value().map(|integer| integer.limbs());
        let cells = integer.cells.clone();

        let res = (0..NUMBER_OF_LIMBS)
            .map(|i| AssignedValue {
                value: limbs.as_ref().map(|limbs| limbs[i].fe()),
                cell: cells[i],
            })
            .collect();

        res
    }
}

impl<F: FieldExt> AssignedValue<F> {
    pub fn clone_with_cell(&self, cell: Cell) -> Self {
        Self {
            value: self.value.clone(),
            cell,
        }
    }

    fn new(cell: Cell, value: Option<F>) -> Self {
        AssignedValue { value, cell }
    }
}
