use super::{Assignments, AssignmentsInternal, ColumnID, ConstantAssignments};
use crate::{
    maingate::{config::ExtendedGate, operations::ConstantOperation},
    RegionCtx,
};
use halo2::{
    halo2curves::FieldExt,
    plonk::{Advice, Column, Error, Fixed},
};

impl<F: FieldExt> AssignmentsInternal<F> for ExtendedGate<F> {
    fn enable_scaled_mul(&self, ctx: &mut RegionCtx<'_, F>, factor: F) -> Result<(), Error> {
        ctx.assign_fixed(|| "", self.s_mul, factor).map(|_| ())
    }
    fn enable_next(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.assign_fixed(|| "", self.s_next, F::one()).map(|_| ())
    }
    fn disable_next(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.assign_fixed(|| "", self.s_next, F::zero()).map(|_| ())
    }
    fn set_constant(&self, ctx: &mut RegionCtx<'_, F>, constant: F) -> Result<(), Error> {
        ctx.assign_fixed(|| "", self.constant, constant).map(|_| ())
    }
    fn column(&self, id: ColumnID) -> (Column<Fixed>, Column<Advice>) {
        match id {
            ColumnID::A => (self.sa, self.a),
            ColumnID::B => (self.sb, self.b),
            ColumnID::C => (self.sc, self.c),
            ColumnID::NEXT => (self.s_next, self.c),
        }
    }
    fn no_op(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.disable_constant(ctx)?;
        self.disable_mul(ctx)?;
        self.disable_next(ctx)?;
        ctx.assign_fixed(|| "", self.sa, F::zero())?;
        ctx.assign_fixed(|| "", self.sb, F::zero())?;
        ctx.assign_fixed(|| "", self.sc, F::zero())?;
        Ok(())
    }
}
impl<F: FieldExt> Assignments<F> for ExtendedGate<F> {}
impl<F: FieldExt> ConstantAssignments<F> for ExtendedGate<F> {}
impl<F: FieldExt> ExtendedGate<F> {
    pub(crate) fn assign_constant_op(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        op: &ConstantOperation<F>,
    ) -> Result<(), Error> {
        match op {
            ConstantOperation::AddConstant { w0, constant, u } => {
                self.add_constant(ctx, w0, *constant, u)
            }
            ConstantOperation::SubFromConstant { constant, w1, u } => {
                self.sub_from_constant(ctx, *constant, w1, u)
            }
            ConstantOperation::SubAndAddConstant {
                w0,
                w1,
                constant,
                u,
            } => self.sub_and_add_constant(ctx, w0, w1, *constant, u),
            ConstantOperation::MulAddConstantScaled {
                factor,
                w0,
                w1,
                constant,
                u,
            } => self.mul_add_constant_scaled(ctx, *factor, w0, w1, *constant, u),
            ConstantOperation::EqualToConstant { w0, constant } => {
                self.equal_to_constant(ctx, w0, *constant)
            }
        }
    }
}
