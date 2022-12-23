use super::{Assignments, AssignmentsInternal, ColumnID, ComplexAssignements, ConstantAssignments};
use crate::{
    maingate::{
        config::ExtendedGate,
        operations::{ComplexOperation, ConstantOperation},
    },
    Composable, RegionCtx, Scaled, SecondDegreeScaled, Term, Witness,
};
use halo2::{
    halo2curves::FieldExt,
    plonk::{Advice, Column, Error, Fixed},
};

impl<F: FieldExt, const LOOKUP_WIDTH: usize> AssignmentsInternal<F>
    for ExtendedGate<F, LOOKUP_WIDTH>
{
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
impl<F: FieldExt, const LOOKUP_WIDTH: usize> Assignments<F> for ExtendedGate<F, LOOKUP_WIDTH> {}
impl<F: FieldExt, const LOOKUP_WIDTH: usize> ConstantAssignments<F>
    for ExtendedGate<F, LOOKUP_WIDTH>
{
}
impl<F: FieldExt, const LOOKUP_WIDTH: usize> ExtendedGate<F, LOOKUP_WIDTH> {
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
    pub(crate) fn assign_complex_op(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        op: &ComplexOperation<F>,
    ) -> Result<(), Error> {
        match op {
            ComplexOperation::Select {
                cond,
                w0,
                w1,
                selected,
            } => self.select(ctx, cond, w0, w1, selected),
            ComplexOperation::SelectOrAssign {
                cond,
                w,
                constant,
                selected,
            } => self.select_or_assign(ctx, cond, w, *constant, selected),
            ComplexOperation::Compose {
                terms,
                constant,
                result,
            } => self.compose(ctx, terms, result, *constant),
            ComplexOperation::ComposeSecondDegree {
                terms,
                constant,
                result,
            } => self.compose_second_degree(ctx, terms, result, *constant),
        }
    }
}
impl<F: FieldExt, const LOOKUP_WIDTH: usize> ComplexAssignements<F>
    for ExtendedGate<F, LOOKUP_WIDTH>
{
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &Witness<F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        selected: &Witness<F>,
    ) -> Result<(), Error> {
        // c*w0 - c*w1 + w1 - res = 0
        // * first row
        // -c*w1 + w1 - res = tmp
        // tmp = c * w0
        self.enable_scaled_mul(ctx, -F::one())?;
        self.enable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::add(w1))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(cond))?;
        self.assign(ctx, ColumnID::C, &Scaled::sub(selected))?;
        ctx.next();
        // * second row
        // c * w0 = -tmp
        // find the temp witenss
        let c_w0 = cond.value() * w0.value();
        let c_w0 = Scaled::no_copy(c_w0, -F::one());
        self.enable_mul(ctx)?;
        self.disable_next(ctx)?;
        self.disable_constant(ctx)?;
        self.assign(ctx, ColumnID::A, &Scaled::mul(w0))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(cond))?;
        self.assign(ctx, ColumnID::C, &c_w0)?;
        ctx.next();
        Ok(())
    }
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &Witness<F>,
        w: &Witness<F>,
        constant: F,
        selected: &Witness<F>,
    ) -> Result<(), Error> {
        // c*w0 - c*constant + constant - selected = 0
        self.enable_mul(ctx)?;
        self.disable_next(ctx)?;
        self.set_constant(ctx, constant)?;
        self.assign(ctx, ColumnID::A, &Scaled::new(cond, -constant))?;
        self.assign(ctx, ColumnID::B, &Scaled::mul(w))?;
        self.assign(ctx, ColumnID::C, &Scaled::sub(selected))?;
        ctx.next();
        Ok(())
    }
    fn compose(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: &[Scaled<F>],
        result: &Scaled<F>,
        constant: F,
    ) -> Result<(), Error> {
        let number_of_chunks = ((terms.len() - 1) / 2) + 1;
        let mut remaining = result.value();
        for (i, chunk) in terms.chunks(2).enumerate() {
            // always disable multiplication in first degree composition
            self.disable_mul(ctx)?;
            // assign first term
            self.assign(ctx, ColumnID::A, &chunk[0])?;
            // assign the second if chunk has two terms
            if chunk.len() == 2 {
                self.assign(ctx, ColumnID::B, &chunk[1])?;
            } else {
                self.empty_cell(ctx, ColumnID::B)?;
            }
            // * assign the aux constant at first iter of composition
            // * running subtraction is the result in first iter and remaining values in the rest
            let (t, constant) = if i == 0 {
                self.set_constant(ctx, constant)?;
                (result.neg(), constant)
            } else {
                self.disable_constant(ctx)?;
                (Scaled::no_copy(remaining, -F::one()), F::zero())
            };
            self.assign(ctx, ColumnID::C, &t)?;
            // update remaining value
            remaining = remaining - Scaled::compose(chunk, constant);
            // at last iter cancel next rotation otherwise enable it for runnning subtraction
            if i == number_of_chunks - 1 {
                self.disable_next(ctx)?;
                #[cfg(feature = "sanity-check")]
                remaining.map(|remaining_should_be_zero| {
                    assert_eq!(remaining_should_be_zero, F::zero())
                });
            } else {
                self.enable_next(ctx)?;
            }
            ctx.next();
        }

        Ok(())
    }
    fn compose_second_degree(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        terms: &[Term<F>],
        result: &Scaled<F>,
        constant: F,
    ) -> Result<(), Error> {
        let first_degree_terms: Vec<Scaled<F>> = terms
            .iter()
            .filter_map(|term| match term {
                Term::First(term) => Some(*term),
                _ => None,
            })
            .collect();
        let second_degree_terms: Vec<SecondDegreeScaled<F>> = terms
            .iter()
            .filter_map(|term| match term {
                Term::Second(term) => Some(*term),
                _ => None,
            })
            .collect();
        let mut remaining = result.value();
        for (i, term) in second_degree_terms.iter().enumerate() {
            self.enable_scaled_mul(ctx, term.factor())?;
            self.assign(ctx, ColumnID::A, &Scaled::mul(&term.w0()))?;
            self.assign(ctx, ColumnID::B, &Scaled::mul(&term.w1()))?;
            // * assign the aux constant at first iter of composition
            // * running subtraction is the result in first iter and remaining values in the rest
            let (t, constant) = if i == 0 {
                self.set_constant(ctx, constant)?;
                (result.neg(), constant)
            } else {
                self.disable_constant(ctx)?;
                (Scaled::no_copy(remaining, -F::one()), F::zero())
            };
            self.assign(ctx, ColumnID::C, &t)?;
            // update remaining value
            remaining = remaining
                .zip(term.value())
                .map(|(remaining, term)| remaining - term - constant);
            // at last iter cancel next rotation otherwise enable it for runnning subtraction
            if i == second_degree_terms.len() - 1 {
                if !first_degree_terms.is_empty() {
                    self.enable_next(ctx)?;
                } else {
                    self.disable_next(ctx)?;
                    #[cfg(feature = "sanity-check")]
                    remaining.map(|remaining_should_be_zero| {
                        assert_eq!(remaining_should_be_zero, F::zero())
                    });
                }
            } else {
                self.enable_next(ctx)?;
            }
            ctx.next()
        }
        if !first_degree_terms.is_empty() {
            self.compose(
                ctx,
                &first_degree_terms,
                &Scaled::no_copy(remaining, F::one()),
                F::zero(),
            )?;
        }
        Ok(())
    }
}
