use super::{Assignments, AssignmentsInternal, ColumnID};
use crate::{maingate::config::SimpleGate, RegionCtx};
use halo2::{
    halo2curves::FieldExt,
    plonk::{Advice, Column, Error, Fixed},
};

impl<F: FieldExt> Assignments<F> for SimpleGate<F> {}
impl<F: FieldExt> AssignmentsInternal<F> for SimpleGate<F> {
    fn enable_scaled_mul(&self, ctx: &mut RegionCtx<'_, F>, factor: F) -> Result<(), Error> {
        ctx.assign_fixed(|| "", self.s_mul, factor).map(|_| ())
    }
    fn enable_next(&self, _: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        Ok(())
    }
    fn disable_next(&self, _: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        Ok(())
    }
    fn set_constant(&self, _: &mut RegionCtx<'_, F>, _: F) -> Result<(), Error> {
        Ok(())
    }
    fn column(&self, id: ColumnID) -> (Column<Fixed>, Column<Advice>) {
        match id {
            ColumnID::A => (self.sa, self.a),
            ColumnID::B => (self.sb, self.b),
            ColumnID::C => (self.sc, self.c),
            ColumnID::NEXT => unreachable!("simple gate has no further rotation"),
        }
    }
    fn no_op(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.disable_constant(ctx)?;
        self.disable_mul(ctx)?;
        ctx.assign_fixed(|| "", self.sa, F::zero())?;
        ctx.assign_fixed(|| "", self.sb, F::zero())?;
        ctx.assign_fixed(|| "", self.sc, F::zero())?;
        Ok(())
    }
}
