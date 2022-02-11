use crate::halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter, Region},
    plonk::Error,
};

use crate::{Assigned, AssignedBit, AssignedCondition, AssignedValue, UnassignedValue};

pub mod five;
pub mod four;
use std::fmt;

#[derive(Copy, Clone)]
pub enum Term<'a, F: FieldExt> {
    Assigned(&'a dyn Assigned<F>, F),
    Unassigned(Option<F>, F),
    Zero,
}

impl<'a, F: FieldExt> fmt::Debug for Term<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assigned(coeff, base) => f
                .debug_struct("Assigned")
                .field("cell", &coeff.cell())
                .field("value", &coeff.value())
                .field("base", base)
                .finish(),
            Self::Unassigned(coeff, base) => f.debug_struct("Unassigned").field("coeff", coeff).field("base", base).finish(),
            Self::Zero => f.debug_struct("Zero").finish(),
        }
    }
}

impl<'a, F: FieldExt> Term<'a, F> {
    fn assigned_to_mul(e: &'a impl Assigned<F>) -> Self {
        Term::Assigned(e, F::zero())
    }

    fn assigned_to_add(e: &'a impl Assigned<F>) -> Self {
        Term::Assigned(e, F::one())
    }

    fn assigned_to_sub(e: &'a impl Assigned<F>) -> Self {
        Term::Assigned(e, -F::one())
    }

    fn unassigned_to_mul(e: Option<F>) -> Self {
        Term::Unassigned(e, F::zero())
    }

    fn unassigned_to_add(e: Option<F>) -> Self {
        Term::Unassigned(e, F::one())
    }

    fn unassigned_to_sub(e: Option<F>) -> Self {
        Term::Unassigned(e, -F::one())
    }

    fn coeff(&self) -> Option<F> {
        match self {
            Self::Assigned(assigned, _) => assigned.value(),
            Self::Unassigned(unassigned, _) => *unassigned,
            Self::Zero => Some(F::zero()),
        }
    }

    fn base(&self) -> F {
        match self {
            Self::Assigned(_, base) => *base,
            Self::Unassigned(_, base) => *base,
            Self::Zero => F::zero(),
        }
    }

    fn constrain_equal(&self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        match self {
            Self::Assigned(assigned, _) => assigned.constrain_equal(region, new_cell),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum CombinationOptionCommon<F: FieldExt> {
    OneLinerMul,
    OneLinerAdd,
    CombineToNextMul(F),
    CombineToNextScaleMul(F, F),
    CombineToNextAdd(F),
}

pub trait MainGateInstructions<F: FieldExt, const WIDTH: usize>: Chip<F> {
    type CombinationOption: From<CombinationOptionCommon<F>>;
    type CombinedValues;
    type MainGateColumn;

    fn expose_public(&self, layouter: impl Layouter<F>, value: AssignedValue<F>, row: usize) -> Result<(), Error>;

    fn assign_constant(&self, region: &mut Region<'_, F>, constant: F, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn assign_value(&self, region: &mut Region<'_, F>, value: &UnassignedValue<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn assign_to_column(
        &self,
        region: &mut Region<'_, F>,
        value: &UnassignedValue<F>,
        column: Self::MainGateColumn,
        offset: &mut usize,
    ) -> Result<AssignedValue<F>, Error>;

    fn assign_to_acc(&self, region: &mut Region<'_, F>, value: &UnassignedValue<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn assign_bit(&self, region: &mut Region<'_, F>, value: &UnassignedValue<F>, offset: &mut usize) -> Result<AssignedBit<F>, Error>;

    fn assert_bit(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn one_or_one(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn or(&self, region: &mut Region<'_, F>, c1: &AssignedCondition<F>, c2: &AssignedCondition<F>, offset: &mut usize) -> Result<AssignedCondition<F>, Error>;

    fn and(&self, region: &mut Region<'_, F>, c1: &AssignedCondition<F>, c2: &AssignedCondition<F>, offset: &mut usize) -> Result<AssignedCondition<F>, Error>;

    fn not(&self, region: &mut Region<'_, F>, c: &AssignedCondition<F>, offset: &mut usize) -> Result<AssignedCondition<F>, Error>;

    fn select(
        &self,
        region: &mut Region<'_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
        cond: &AssignedCondition<F>,
        offset: &mut usize,
    ) -> Result<AssignedValue<F>, Error>;

    fn select_or_assign(
        &self,
        region: &mut Region<'_, F>,
        to_be_selected: impl Assigned<F>,
        to_be_assigned: F,
        cond: &AssignedCondition<F>,
        offset: &mut usize,
    ) -> Result<AssignedValue<F>, Error>;

    fn div_unsafe(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn div(
        &self,
        region: &mut Region<'_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
        offset: &mut usize,
    ) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error>;

    fn invert_unsafe(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn invert(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error>;

    fn assert_equal_to_constant(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: F, offset: &mut usize) -> Result<(), Error>;

    fn assert_equal(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn assert_not_equal(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn is_equal(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<AssignedCondition<F>, Error>;

    fn assert_zero(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn assert_not_zero(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn is_zero(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<AssignedCondition<F>, Error>;

    fn assert_one(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn add(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn add_with_constant(
        &self,
        region: &mut Region<'_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
        constant: F,
        offset: &mut usize,
    ) -> Result<AssignedValue<F>, Error>;

    fn add_constant(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, constant: F, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn sub(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn sub_with_constant(
        &self,
        region: &mut Region<'_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
        constant: F,
        offset: &mut usize,
    ) -> Result<AssignedValue<F>, Error>;

    fn sub_sub_with_constant(
        &self,
        region: &mut Region<'_, F>,
        a: impl Assigned<F>,
        b_0: impl Assigned<F>,
        b_1: impl Assigned<F>,
        constant: F,
        offset: &mut usize,
    ) -> Result<AssignedValue<F>, Error>;

    fn neg_with_constant(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, constant: F, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn mul2(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn mul3(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn mul(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<AssignedValue<F>, Error>;

    fn combine(
        &self,
        region: &mut Region<'_, F>,
        terms: [Term<F>; WIDTH],
        constant: F,
        offset: &mut usize,
        options: Self::CombinationOption,
    ) -> Result<Self::CombinedValues, Error>;

    fn nand(&self, region: &mut Region<'_, F>, a: impl Assigned<F>, b: impl Assigned<F>, offset: &mut usize) -> Result<(), Error>;

    fn decompose(
        &self,
        region: &mut Region<'_, F>,
        composed: impl Assigned<F>,
        number_of_bits: usize,
        offset: &mut usize,
    ) -> Result<Vec<AssignedBit<F>>, Error>;

    fn no_operation(&self, region: &mut Region<'_, F>, offset: &mut usize) -> Result<(), Error>;

    fn break_here(&self, region: &mut Region<'_, F>, offset: &mut usize) -> Result<(), Error> {
        self.combine(region, [Term::Zero; WIDTH], F::one(), offset, CombinationOptionCommon::OneLinerAdd.into())?;
        Ok(())
    }
}
