use halo2::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Column, Error, Fixed, Selector},
};

pub mod utils;
pub use halo2;
pub use halo2::halo2curves as curves;

pub struct RegionCtx<'a, 'b, F: FieldExt> {
    pub region: &'a mut Region<'b, F>,
    pub offset: &'a mut usize,
}

impl<'a, 'b, F: FieldExt> RegionCtx<'a, 'b, F> {
    pub fn new(region: &'a mut Region<'b, F>, offset: &'a mut usize) -> RegionCtx<'a, 'b, F> {
        RegionCtx { region, offset }
    }

    pub fn assign_fixed(
        &mut self,
        annotation: &str,
        column: Column<Fixed>,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.region
            .assign_fixed(|| annotation, column, *self.offset, || Value::known(value))
    }

    pub fn assign_advice(
        &mut self,
        annotation: &str,
        column: Column<Advice>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.region
            .assign_advice(|| annotation, column, *self.offset, || value)
    }

    pub fn constrain_equal(&mut self, cell_0: Cell, cell_1: Cell) -> Result<(), Error> {
        self.region.constrain_equal(cell_0, cell_1)
    }

    pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
        selector.enable(self.region, *self.offset)
    }

    pub fn next(&mut self) {
        *self.offset += 1
    }
}
