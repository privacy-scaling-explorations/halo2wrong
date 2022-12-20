use super::operations::Operation;
use crate::{Composable, RegionCtx, Scaled, SecondDegreeScaled, Term, Witness};
use halo2::{
    circuit::Value,
    halo2curves::FieldExt,
    plonk::{Advice, Column, Error, Fixed},
};
mod extended_gate;
mod main_gate;
mod simple_gate;
pub enum ColumnID {
    A,
    B,
    C,
    NEXT,
}
pub trait AssignmentsInternal<F: FieldExt> {
    fn column(&self, id: ColumnID) -> (Column<Fixed>, Column<Advice>);
    fn enable_scaled_mul(&self, ctx: &mut RegionCtx<'_, F>, factor: F) -> Result<(), Error>;
    fn assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        column: ColumnID,
        e: &Scaled<F>,
    ) -> Result<(), Error> {
        // resolve column
        let (fixed, advice) = self.column(column);
        // assign fixed
        ctx.assign_fixed(|| "", fixed, e.factor())?;
        // assigne witness
        let witness = e.witness();
        let new_cell = ctx.assign_advice(|| "", advice, witness.value())?;
        // if already assigned enfoce copy constraint
        // if not add as the root of this witness
        // id == 0 should signal for no copy
        ctx.copy_chain(witness.id(), new_cell)
    }
    fn empty_cell(&self, ctx: &mut RegionCtx<'_, F>, column: ColumnID) -> Result<(), Error> {
        let (fixed, advice) = self.column(column);
        ctx.assign_fixed(|| "", fixed, F::zero())?;
        ctx.assign_advice(|| "", advice, Value::known(F::zero()))?;
        Ok(())
    }
    fn no_op(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error>;
    fn no_witness(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.empty_cell(ctx, ColumnID::A)?;
        self.empty_cell(ctx, ColumnID::B)?;
        self.empty_cell(ctx, ColumnID::C).map(|_| ())
    }

    fn empty(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.no_op(ctx)?;
        self.no_witness(ctx)
    }
    fn assign_scaled_mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        e: &SecondDegreeScaled<F>,
    ) -> Result<(), Error> {
        self.enable_scaled_mul(ctx, e.factor())?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(&e.w0()))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(&e.w1()))?;
        Ok(())
    }
    fn enable_mul(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.enable_scaled_mul(ctx, F::one())
    }
    fn disable_mul(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.enable_scaled_mul(ctx, F::zero())
    }
    fn enable_next(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error>;
    fn disable_next(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error>;
    fn set_constant(&self, ctx: &mut RegionCtx<'_, F>, constant: F) -> Result<(), Error>;
    fn disable_constant(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.set_constant(ctx, F::zero())
    }
}
pub trait Assignments<F: FieldExt>: AssignmentsInternal<F> {
    #[cfg(test)]
    // arithmetic equality constrait. only for testing.
    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        other: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.disable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::add(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::sub(other))?;
        self.empty_cell(ctx, ColumnID::C).map(|_| ())
    }
    #[cfg(test)]
    // arithmetic assignment of a value. only for testing.
    fn assign_only(&self, ctx: &mut RegionCtx<'_, F>, w: &Witness<F>) -> Result<(), Error> {
        self.no_op(ctx)?;
        self.empty_cell(ctx, ColumnID::B)?;
        self.empty_cell(ctx, ColumnID::C)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w))
    }
    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        inv: &Witness<F>,
        one: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(inv))?;
        self.assign(ctx, ColumnID::C, &Scaled::result(one))
    }
    fn add_scaled(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Scaled<F>,
        w1: &Scaled<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.disable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, w0)?;
        self.assign(ctx, ColumnID::B, w1)?;
        self.assign(ctx, ColumnID::C, &Scaled::result(u))
    }
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.add_scaled(ctx, &Scaled::add(w0), &Scaled::add(w1), u)
    }
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.add_scaled(ctx, &Scaled::add(w0), &Scaled::sub(w1), u)
    }
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_constant(ctx)?;
        self.disable_next(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(w1))?;
        self.assign(ctx, ColumnID::C, &Scaled::result(u))
    }
    fn scale(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w: &Scaled<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_constant(ctx)?;
        self.disable_next(ctx)?;
        self.disable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::new(&w.witness(), w.factor()))?;
        self.empty_cell(ctx, ColumnID::B)?;
        self.assign(ctx, ColumnID::C, &Scaled::result(u))
    }
    fn div_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w1))?;
        self.assign(ctx, ColumnID::C, &Scaled::result(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(u))
    }
    fn inv_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w: &Witness<F>,
        one: &Witness<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w))?;
        self.assign(ctx, ColumnID::C, &Scaled::result(one))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(u))
    }
    fn assert_bit(&self, ctx: &mut RegionCtx<'_, F>, bit: &Witness<F>) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(bit))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(bit))?;
        self.assign(ctx, ColumnID::C, &Scaled::sub(bit))
    }
    fn or(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::sub(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::sub(w1))?;
        self.assign(ctx, ColumnID::C, &Scaled::add(u))
    }
    fn assert_one_xor_any(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &Witness<F>,
        one_xor_any: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(cond))?;
        self.assign(ctx, ColumnID::C, &Scaled::result(cond))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(one_xor_any))
    }
    fn assert_nand(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.enable_mul(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(w1))?;
        self.empty_cell(ctx, ColumnID::C)
    }
    fn assign_op(&self, ctx: &mut RegionCtx<'_, F>, op: &Operation<F>) -> Result<(), Error> {
        match op {
            #[cfg(test)]
            Operation::AssertEqual { w0, w1 } => self.assert_equal(ctx, w0, w1),
            #[cfg(test)]
            Operation::Assign { w } => self.assign_only(ctx, w),
            Operation::Add { w0, w1, u } => self.add(ctx, w0, w1, u),
            Operation::AddScaled { w0, w1, u } => self.add_scaled(ctx, w0, w1, u),
            Operation::Sub { w0, w1, u } => self.sub(ctx, w0, w1, u),
            Operation::Mul { w0, w1, u } => self.mul(ctx, w0, w1, u),
            Operation::Scale { w, u } => self.scale(ctx, w, u),
            Operation::DivUnsafe { w0, w1, u } => self.div_unsafe(ctx, w0, w1, u),
            Operation::InvUnsafe { w, one, u } => self.inv_unsafe(ctx, w, one, u),
            Operation::AssertNotZero { w, inv, one } => self.assert_not_zero(ctx, w, inv, one),
            Operation::AssertBit { bit } => self.assert_bit(ctx, bit),
            Operation::AssertOneXorAny { bit, one_xor_any } => {
                self.assert_one_xor_any(ctx, bit, one_xor_any)
            }
            Operation::Or { w0, w1, u } => self.or(ctx, w0, w1, u),
            Operation::AssertNand { w0, w1 } => self.assert_nand(ctx, w0, w1),
        }
    }
}
pub trait ConstantAssignments<F: FieldExt>: Assignments<F> {
    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        constant: F,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_mul(ctx)?;
        self.set_constant(ctx, constant)?;
        self.assign(ctx, ColumnID::A, &Scaled::add(w0))?;
        self.empty_cell(ctx, ColumnID::B)?;
        self.assign(ctx, ColumnID::C, &Scaled::result(u))
    }
    fn sub_from_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: F,
        w1: &Witness<F>,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_mul(ctx)?;
        self.set_constant(ctx, constant)?;
        self.assign(ctx, ColumnID::A, &Scaled::sub(w1))?;
        self.empty_cell(ctx, ColumnID::B)?;
        self.assign(ctx, ColumnID::C, &Scaled::result(u))
    }
    fn sub_and_add_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        constant: F,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_mul(ctx)?;
        self.set_constant(ctx, constant)?;
        self.assign(ctx, ColumnID::A, &Scaled::add(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::sub(w1))?;
        self.assign(ctx, ColumnID::C, &Scaled::result(u))
    }
    fn mul_add_constant_scaled(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        factor: F,
        w0: &Witness<F>,
        w1: &Witness<F>,
        constant: F,
        u: &Witness<F>,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.enable_scaled_mul(ctx, factor)?;
        self.set_constant(ctx, constant)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(w1))?;
        self.assign(ctx, ColumnID::C, &Scaled::result(u))
    }
    fn equal_to_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        w0: &Witness<F>,
        constant: F,
    ) -> Result<(), Error> {
        self.disable_next(ctx)?;
        self.disable_mul(ctx)?;
        self.set_constant(ctx, -constant)?;
        self.empty_cell(ctx, ColumnID::B)?;
        self.empty_cell(ctx, ColumnID::C)?;
        self.assign(ctx, ColumnID::A, &Scaled::add(w0))
    }
}
trait ComplexAssignements<F: FieldExt> {
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &Witness<F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        selected: &Witness<F>,
    ) -> Result<(), Error>;
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &Witness<F>,
        w: &Witness<F>,
        constant: F,
        selected: &Witness<F>,
    ) -> Result<(), Error>;
    fn compose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: &[Scaled<F>],
        result: &Scaled<F>,
        constant: F,
    ) -> Result<(), Error>;
    fn compose_second_degree(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: &[Term<F>],
        result: &Scaled<F>,
        constant: F,
    ) -> Result<(), Error>;
}
