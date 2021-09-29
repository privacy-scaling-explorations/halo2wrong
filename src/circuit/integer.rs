use crate::circuit::range::{RangeChip, RangeConfig};
use crate::rns::{Integer, Limb, Rns};
use crate::BIT_LEN_LIMB;
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};

mod add;
mod mul;
mod reduce;
mod sub;

#[derive(Clone, Debug)]
pub struct IntegerConfig {
    range_config: RangeConfig,

    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub d: Column<Advice>,

    pub sa: Column<Fixed>,
    pub sb: Column<Fixed>,
    pub sc: Column<Fixed>,
    pub sd: Column<Fixed>,
    pub sd_next: Column<Fixed>,
    pub s_mul: Column<Fixed>,
    pub s_constant: Column<Fixed>,
}

#[derive(Debug, Clone)]
pub struct AssignedInteger<F: FieldExt> {
    pub value: Option<Integer<F>>,
    pub cells: Vec<Cell>,
}

impl<F: FieldExt> AssignedInteger<F> {
    fn empty() -> Self {
        Self { value: None, cells: vec![] }
    }

    pub fn value(&self) -> Option<Integer<F>> {
        self.value.clone()
    }

    fn new(cells: Vec<Cell>, value: Option<Integer<F>>) -> Self {
        Self { value: None, cells: vec![] }
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

pub struct IntegerChip<Wrong: FieldExt, Native: FieldExt> {
    config: IntegerConfig,
    rns: Rns<Wrong, Native>,
}

trait IntegerInstructions<F: FieldExt> {
    fn add(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedInteger<F>,
        b: &AssignedInteger<F>,
    ) -> Result<(AssignedInteger<F>, AssignedInteger<F>, AssignedInteger<F>), Error>;

    fn sub(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedInteger<F>,
        b: &AssignedInteger<F>,
    ) -> Result<(AssignedInteger<F>, AssignedInteger<F>, AssignedInteger<F>), Error>;

    fn mul(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedInteger<F>,
        b: &AssignedInteger<F>,
    ) -> Result<(AssignedInteger<F>, AssignedInteger<F>, AssignedInteger<F>), Error>;

    fn reduce(&self, region: &mut Region<'_, F>, a: &AssignedInteger<F>) -> Result<(AssignedInteger<F>, AssignedInteger<F>), Error>;
}

impl<W: FieldExt, N: FieldExt> IntegerInstructions<N> for IntegerChip<W, N> {
    fn add(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._add(region, a, b)
    }

    fn mul(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._mul(region, a, b)
    }

    fn reduce(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>) -> Result<(AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._reduce(region, a)
    }

    fn sub(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
    ) -> Result<(AssignedInteger<N>, AssignedInteger<N>, AssignedInteger<N>), Error> {
        self._sub(region, a, b)
    }
}

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub fn new(config: IntegerConfig, rns: Rns<W, N>) -> Self {
        IntegerChip { config, rns }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<N>,
        range_config: RangeConfig,
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,
        sa: Column<Fixed>,
        sb: Column<Fixed>,
        sc: Column<Fixed>,
        sd: Column<Fixed>,
        sd_next: Column<Fixed>,
        s_mul: Column<Fixed>,
        s_constant: Column<Fixed>,
    ) -> IntegerConfig {
        IntegerConfig {
            range_config,
            a,
            b,
            c,
            d,
            sa,
            sb,
            sc,
            sd,
            sd_next,
            s_mul,
            s_constant,
        }
    }

    fn range_chip(&self) -> RangeChip<N> {
        RangeChip::<N>::new(self.config.range_config.clone(), BIT_LEN_LIMB)
    }
}
