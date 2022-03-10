use halo2wrong::RegionCtx;

use crate::halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter, Region},
    plonk::Error,
};

use crate::{Assigned, AssignedBit, AssignedCondition, AssignedValue, UnassignedValue};

#[derive(Copy, Clone)]
pub enum Term<'a, F: FieldExt> {
    Assigned(&'a dyn Assigned<F>, F),
    Unassigned(Option<F>, F),
    Zero,
}

impl<'a, F: FieldExt> std::fmt::Debug for Term<'a, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assigned(coeff, base) => f
                .debug_struct("Assigned")
                .field("cell", &coeff.cell())
                .field("value", &coeff.value())
                .field("base", base)
                .finish(),
            Self::Unassigned(coeff, base) => f
                .debug_struct("Unassigned")
                .field("coeff", coeff)
                .field("base", base)
                .finish(),
            Self::Zero => f.debug_struct("Zero").finish(),
        }
    }
}

impl<'a, F: FieldExt> Term<'a, F> {
    pub fn assigned_to_mul(e: &'a impl Assigned<F>) -> Self {
        Term::Assigned(e, F::zero())
    }

    pub fn assigned_to_add(e: &'a impl Assigned<F>) -> Self {
        Term::Assigned(e, F::one())
    }

    pub fn assigned_to_sub(e: &'a impl Assigned<F>) -> Self {
        Term::Assigned(e, -F::one())
    }

    pub fn unassigned_to_mul(e: Option<F>) -> Self {
        Term::Unassigned(e, F::zero())
    }

    pub fn unassigned_to_add(e: Option<F>) -> Self {
        Term::Unassigned(e, F::one())
    }

    pub fn unassigned_to_sub(e: Option<F>) -> Self {
        Term::Unassigned(e, -F::one())
    }

    pub fn coeff(&self) -> Option<F> {
        match self {
            Self::Assigned(assigned, _) => assigned.value(),
            Self::Unassigned(unassigned, _) => *unassigned,
            Self::Zero => Some(F::zero()),
        }
    }

    pub fn base(&self) -> F {
        match self {
            Self::Assigned(_, base) => *base,
            Self::Unassigned(_, base) => *base,
            Self::Zero => F::zero(),
        }
    }

    pub fn constrain_equal(&self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
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

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        value: AssignedValue<F>,
        row: usize,
    ) -> Result<(), Error>;

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: &UnassignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn assign_to_column(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: &UnassignedValue<F>,
        column: Self::MainGateColumn,
    ) -> Result<AssignedValue<F>, Error>;

    fn assign_to_acc(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: &UnassignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn assign_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: &UnassignedValue<F>,
    ) -> Result<AssignedBit<F>, Error>;

    fn assert_bit(&self, ctx: &mut RegionCtx<'_, '_, F>, a: impl Assigned<F>) -> Result<(), Error>;

    fn one_or_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<(), Error>;

    fn or(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c1: &AssignedCondition<F>,
        c2: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error>;

    fn and(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c1: &AssignedCondition<F>,
        c2: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error>;

    fn not(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error>;

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        to_be_selected: impl Assigned<F>,
        to_be_assigned: F,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn div_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn div(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error>;

    fn invert_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
    ) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error>;

    fn assert_equal_to_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: F,
    ) -> Result<(), Error>;

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<(), Error>;

    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<(), Error>;

    fn is_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<AssignedCondition<F>, Error>;

    fn assert_zero(&self, ctx: &mut RegionCtx<'_, '_, F>, a: impl Assigned<F>)
        -> Result<(), Error>;

    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
    ) -> Result<(), Error>;

    fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
    ) -> Result<AssignedCondition<F>, Error>;

    fn assert_one(&self, ctx: &mut RegionCtx<'_, '_, F>, a: impl Assigned<F>) -> Result<(), Error>;

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn add_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn sub_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    fn sub_sub_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b_0: impl Assigned<F>,
        b_1: impl Assigned<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    fn neg_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn combine(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        terms: [Term<F>; WIDTH],
        constant: F,

        options: Self::CombinationOption,
    ) -> Result<Self::CombinedValues, Error>;

    fn nand(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: impl Assigned<F>,
        b: impl Assigned<F>,
    ) -> Result<(), Error>;

    fn decompose(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        composed: impl Assigned<F>,
        number_of_bits: usize,
    ) -> Result<Vec<AssignedBit<F>>, Error>;

    fn no_operation(&self, ctx: &mut RegionCtx<'_, '_, F>) -> Result<(), Error>;

    fn break_here(&self, ctx: &mut RegionCtx<'_, '_, F>) -> Result<(), Error> {
        self.combine(
            ctx,
            [Term::Zero; WIDTH],
            F::one(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;
        Ok(())
    }
}
