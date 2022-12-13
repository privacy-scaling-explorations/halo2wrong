use super::{
    config::{ExtendedGate, MainGate, SimpleGate},
    operations::{ExtendedOperation, Operation, ShortedOperation},
};
use crate::{Composable, RegionCtx, Scaled, SecondDegreeScaled, Witness};
use halo2::{
    circuit::Value,
    halo2curves::FieldExt,
    plonk::{Advice, Column, Error, Fixed},
};
pub enum ColumnID {
    A,
    B,
    C,
    NEXT,
}
pub(crate) trait AssignmentsInternal<F: FieldExt> {
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
pub(crate) trait Assignments<F: FieldExt>: AssignmentsInternal<F> {
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
        self.disable_next(ctx)?;
        ctx.assign_fixed(|| "", self.sa, F::zero())?;
        ctx.assign_fixed(|| "", self.sb, F::zero())?;
        ctx.assign_fixed(|| "", self.sc, F::zero())?;
        Ok(())
    }
}
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
impl<F: FieldExt> ExtendedGate<F> {
    pub(crate) fn assign_extended_op(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        op: &ExtendedOperation<F>,
    ) -> Result<(), Error> {
        match op {
            ExtendedOperation::AddConstant { w0, constant, u } => {
                self.add_constant(ctx, w0, *constant, u)
            }
            ExtendedOperation::SubFromConstant { constant, w1, u } => {
                self.sub_from_constant(ctx, *constant, w1, u)
            }
            ExtendedOperation::SubAndAddConstant {
                w0,
                w1,
                constant,
                u,
            } => self.sub_and_add_constant(ctx, w0, w1, *constant, u),
            ExtendedOperation::MulAddConstantScaled {
                factor,
                w0,
                w1,
                constant,
                u,
            } => self.mul_add_constant_scaled(ctx, *factor, w0, w1, *constant, u),
            ExtendedOperation::EqualToConstant { w0, constant } => {
                self.equal_to_constant(ctx, w0, *constant)
            }
        }
    }
    pub(crate) fn add_constant(
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
    pub(crate) fn sub_from_constant(
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
    pub(crate) fn sub_and_add_constant(
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
    pub(crate) fn mul_add_constant_scaled(
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
    pub(crate) fn equal_to_constant(
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

impl<F: FieldExt, const LOOKUP_WIDTH: usize> MainGate<F, LOOKUP_WIDTH> {
    pub(crate) fn assign_shorted_op(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        op: &ShortedOperation<F>,
    ) -> Result<(), Error> {
        match op {
            ShortedOperation::Select {
                cond,
                w0,
                w1,
                selected,
            } => {
                // c*w0 - c*w1 + w1 - res = 0
                self.short_gates(ctx)?;
                self.disable_next(ctx)?;
                self.disable_constant(ctx)?;
                self.simple_gate.enable_mul(ctx)?;
                self.extended_gate.enable_scaled_mul(ctx, -F::one())?;
                // c*w0 - c*w1 + w1 - res = 0
                // simple gate
                self.simple_gate
                    .assign(ctx, ColumnID::A, &Scaled::mul(cond))?;
                self.simple_gate
                    .assign(ctx, ColumnID::B, &Scaled::mul(w0))?;
                self.simple_gate
                    .assign(ctx, ColumnID::C, &Scaled::add(w1))?;
                // extended gate
                self.extended_gate
                    .assign(ctx, ColumnID::A, &Scaled::mul(cond))?;
                self.extended_gate
                    .assign(ctx, ColumnID::B, &Scaled::mul(w1))?;
                self.extended_gate
                    .assign(ctx, ColumnID::C, &Scaled::sub(selected))?;
                ctx.next();
                Ok(())
            }
            ShortedOperation::SelectOrAssign {
                cond,
                w,
                constant,
                selected,
            } => {
                // * c*w0 - c*constant + constant - selected = 0
                self.short_gates(ctx)?;
                self.disable_next(ctx)?;
                self.set_constant(ctx, *constant)?;
                self.simple_gate.enable_mul(ctx)?;
                self.extended_gate.disable_mul(ctx)?;
                // simple gate
                self.simple_gate
                    .assign(ctx, ColumnID::A, &Scaled::mul(cond))?;
                self.simple_gate.assign(ctx, ColumnID::B, &Scaled::mul(w))?;
                self.simple_gate
                    .assign(ctx, ColumnID::C, &Scaled::new(cond, -*constant))?;
                // extended gate
                self.extended_gate.empty_cell(ctx, ColumnID::A)?;
                self.extended_gate.empty_cell(ctx, ColumnID::B)?;
                self.extended_gate
                    .assign(ctx, ColumnID::C, &Scaled::sub(selected))?;
                ctx.next();
                Ok(())
            }
            ShortedOperation::Compose {
                terms,
                constant,
                result,
            } => self.compose(ctx, terms, result, *constant),
            ShortedOperation::ComposeSecondDegree {
                terms,
                constant,
                result,
            } => self.compose_second_degree(ctx, terms, result, *constant),
        }
    }
}
