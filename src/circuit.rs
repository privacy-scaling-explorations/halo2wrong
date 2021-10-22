use crate::rns::{Common, Decomposed, Integer};
use halo2::plonk::Error;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Region},
};
use std::marker::PhantomData;

mod integer;
mod main_gate;
mod range;

#[derive(Debug, Clone)]
pub struct AssignedCondition<F: FieldExt> {
    bool_value: Option<bool>,
    cell: Cell,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AssignedCondition<F> {
    fn new(cell: Cell, value: Option<F>) -> Self {
        // bool_value is true when value is non zero
        // we want to keep it not too strict with no assertation to be able to test bad paths of bitness check
        let bool_value = value.map(|value| if value == F::zero() { false } else { true });
        AssignedCondition {
            bool_value,
            cell,
            _marker: PhantomData,
        }
    }

    pub fn value(&self) -> Option<F> {
        self.bool_value.map(|value| if value { F::one() } else { F::zero() })
    }

    pub fn cycle_cell(&mut self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        region.constrain_equal(self.cell, new_cell)?;
        self.cell = new_cell;
        Ok(())
    }
}

type AssignedBit<F> = AssignedCondition<F>;

#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt> {
    value: Option<Integer<F>>,
    cells: Vec<Cell>,
    native_value_cell: Cell,
}

impl<F: FieldExt> AssignedInteger<F> {
    fn new(cells: Vec<Cell>, value: Option<Integer<F>>, native_value_cell: Cell) -> Self {
        Self {
            value,
            cells,
            native_value_cell,
        }
    }
    pub fn value(&self) -> Result<Integer<F>, Error> {
        Ok(self.value.clone().ok_or(Error::SynthesisError)?)
    }

    pub fn integer(&self) -> Option<Integer<F>> {
        self.value.clone()
    }

    pub fn limb_value(&self, idx: usize) -> Result<F, Error> {
        let limbs = self.value.as_ref().map(|e| e.limbs());
        Ok(limbs.ok_or(Error::SynthesisError)?[idx])
    }

    pub fn limbs(&self) -> Vec<AssignedValue<F>> {
        self.cells
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let limb = self.value.as_ref().map(|e| e.limb_value(i));
                AssignedValue::new(*cell, limb)
            })
            .collect()
    }

    pub fn limb(&self, idx: usize) -> AssignedValue<F> {
        let limb = self.value.as_ref().map(|e| e.limb_value(idx));
        AssignedValue::new(self.cells[idx], limb)
    }

    pub fn native_value(&self) -> Result<F, Error> {
        let native_value = self.value.as_ref().map(|e| e.native());
        Ok(native_value.ok_or(Error::SynthesisError)?)
    }

    pub fn native(&self) -> AssignedValue<F> {
        AssignedValue::new(self.native_value_cell, self.value.as_ref().map(|e| e.native()))
    }

    pub fn update_cells(&mut self, cells: Option<Vec<Cell>>, native_value_cell: Option<Cell>) {
        match cells {
            Some(cells) => self.cells = cells,
            _ => {}
        }

        match native_value_cell {
            Some(native_value_cell) => self.native_value_cell = native_value_cell,
            _ => {}
        }
    }

    pub fn update_limb_cell(&mut self, idx: usize, new_cell: Cell) {
        self.cells[idx] = new_cell;
    }

    pub fn update_native_cell(&mut self, new_cell: Cell) {
        self.native_value_cell = new_cell;
    }

    pub fn cycle_cell(&mut self, region: &mut Region<'_, F>, idx: usize, new_cell: Cell) -> Result<(), Error> {
        region.constrain_equal(self.cells[idx], new_cell)?;
        self.cells[idx] = new_cell;
        Ok(())
    }

    pub fn cycle_native_cell(&mut self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        region.constrain_equal(self.native_value_cell, new_cell)?;
        self.native_value_cell = new_cell;
        Ok(())
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
            value: cond.value(),
            cell: cond.cell,
        }
    }
}

impl<F: FieldExt> AssignedValue<F> {
    fn new(cell: Cell, value: Option<F>) -> Self {
        AssignedValue { value, cell }
    }

    pub fn value(&self) -> Result<F, Error> {
        Ok(self.value.clone().ok_or(Error::SynthesisError)?)
    }

    pub fn cycle_cell(&mut self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        region.constrain_equal(self.cell, new_cell)?;
        self.cell = new_cell;
        Ok(())
    }

    pub fn decompose(&self, number_of_limbs: usize, bit_len: usize) -> Option<Vec<F>> {
        self.value.map(|e| Decomposed::<F>::from_fe(e, number_of_limbs, bit_len).limbs())
    }

    pub fn negate(&mut self) {
        self.value = self.value.map(|value| -value);
    }
}

#[derive(Debug, Clone)]
pub struct UnassignedValue<F: FieldExt> {
    pub value: Option<F>,
}
