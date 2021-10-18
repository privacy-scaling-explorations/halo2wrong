use crate::{
    rns::{Common, Integer, Limb},
    NUMBER_OF_LIMBS,
};
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
    _value: Option<bool>,
    cell: Cell,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AssignedCondition<F> {
    pub fn value(&self) -> Option<F> {
        self._value.map(|value| if value { F::one() } else { F::zero() })
    }

    pub fn cycle_cell(&mut self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        region.constrain_equal(self.cell, new_cell)?;
        self.cell = new_cell;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt> {
    pub value: Option<Integer<F>>,
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

    pub fn native_value(&self) -> Result<F, Error> {
        let native_value = self.value.as_ref().map(|e| e.native());
        Ok(native_value.ok_or(Error::SynthesisError)?)
    }

    pub fn limb(&self, idx: usize) -> AssignedLimb<F> {
        let limb = self.value.as_ref().map(|e| e.limb(idx));
        AssignedLimb::new(self.cells[idx], limb)
    }

    pub fn native(&self) -> AssignedValue<F> {
        AssignedValue {
            value: self.value.as_ref().map(|e| e.native()),
            cell: self.native_value_cell,
        }
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

    pub fn to_assigned_limbs(&self) -> Vec<AssignedLimb<F>> {
        (0..NUMBER_OF_LIMBS).map(|i| self.limb(i)).collect()
    }

    pub fn to_assigned_values(&self) -> Vec<AssignedValue<F>> {
        self.to_assigned_limbs().iter().map(|limb| limb.into()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct AssignedLimb<F: FieldExt> {
    pub value: Option<Limb<F>>,
    cell: Cell,
}

impl<F: FieldExt> From<AssignedValue<F>> for AssignedLimb<F> {
    fn from(assigned_value: AssignedValue<F>) -> Self {
        Self {
            value: assigned_value.value.map(|e| Limb::<F>::from_fe(e)),
            cell: assigned_value.cell,
        }
    }
}

impl<F: FieldExt> From<&AssignedValue<F>> for AssignedLimb<F> {
    fn from(assigned_value: &AssignedValue<F>) -> Self {
        Self {
            value: assigned_value.value.map(|e| Limb::<F>::from_fe(e)),
            cell: assigned_value.cell,
        }
    }
}

impl<F: FieldExt> AssignedLimb<F> {
    pub fn new(cell: Cell, value: Option<Limb<F>>) -> Self {
        AssignedLimb { value, cell }
    }

    pub fn value(&self) -> Result<F, Error> {
        Ok(self.value.clone().ok_or(Error::SynthesisError)?.fe())
    }

    pub fn cycle_cell(&mut self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        region.constrain_equal(self.cell, new_cell)?;
        self.cell = new_cell;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AssignedValue<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Cell,
}

impl<F: FieldExt> From<&AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: &AssignedLimb<F>) -> Self {
        Self {
            value: limb.value.clone().map(|e| e.fe()),
            cell: limb.cell.clone(),
        }
    }
}

impl<F: FieldExt> From<AssignedLimb<F>> for AssignedValue<F> {
    fn from(limb: AssignedLimb<F>) -> Self {
        Self {
            value: limb.value.map(|e| e.fe()),
            cell: limb.cell,
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
}
