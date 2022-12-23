use super::{AssignmentsInternal, ColumnID, ComplexAssignements};
use crate::{
    maingate::{config::MainGate, operations::ComplexOperation},
    Composable, RegionCtx, Scaled, SecondDegreeScaled, Term, Witness,
};
use halo2::{circuit::Value, halo2curves::FieldExt, plonk::Error};

impl<F: FieldExt, const LOOKUP_WIDTH: usize> MainGate<F, LOOKUP_WIDTH> {
    fn assign_with_horizontal_offset(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        term: &Scaled<F>,
        offset: usize,
    ) -> Result<(), Error> {
        assert!(offset < 6);
        if offset == 0 {
            self.simple_gate.assign(ctx, ColumnID::A, term)
        } else if offset == 1 {
            self.simple_gate.assign(ctx, ColumnID::B, term)
        } else if offset == 2 {
            self.simple_gate.assign(ctx, ColumnID::C, term)
        } else if offset == 3 {
            self.extended_gate.assign(ctx, ColumnID::A, term)
        } else if offset == 4 {
            self.extended_gate.assign(ctx, ColumnID::B, term)
        } else {
            self.extended_gate.assign(ctx, ColumnID::C, term)
        }
    }
}

impl<F: FieldExt, const LOOKUP_WIDTH: usize> ComplexAssignements<F> for MainGate<F, LOOKUP_WIDTH> {
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &Witness<F>,
        w0: &Witness<F>,
        w1: &Witness<F>,
        selected: &Witness<F>,
    ) -> Result<(), Error> {
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
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        cond: &Witness<F>,
        w: &Witness<F>,
        constant: F,
        selected: &Witness<F>,
    ) -> Result<(), Error> {
        // * c*w0 - c*constant + constant - selected = 0
        self.short_gates(ctx)?;
        self.disable_next(ctx)?;
        self.set_constant(ctx, constant)?;
        self.simple_gate.enable_mul(ctx)?;
        self.extended_gate.disable_mul(ctx)?;
        // simple gate
        self.simple_gate
            .assign(ctx, ColumnID::A, &Scaled::mul(cond))?;
        self.simple_gate.assign(ctx, ColumnID::B, &Scaled::mul(w))?;
        self.simple_gate
            .assign(ctx, ColumnID::C, &Scaled::new(cond, -constant))?;
        // extended gate
        self.extended_gate.empty_cell(ctx, ColumnID::A)?;
        self.extended_gate.empty_cell(ctx, ColumnID::B)?;
        self.extended_gate
            .assign(ctx, ColumnID::C, &Scaled::sub(selected))?;
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
        let terms: Vec<Scaled<F>> = terms.iter().filter(|e| !e.is_empty()).cloned().collect();
        assert!(!terms.is_empty());
        const CHUNK_SIZE: usize = 5;
        let number_of_terms = terms.len();
        let number_of_chunks = (number_of_terms - 1) / CHUNK_SIZE + 1;
        let mut remaining = result.value();
        for (i, chunk) in terms.chunks(CHUNK_SIZE).enumerate() {
            let constant = if i == 0 { constant } else { F::zero() };
            self.set_constant(ctx, constant)?;
            // assign intermediate value
            // first one is the composition result
            let intermediate = if i == 0 {
                result.neg()
            } else {
                Scaled::no_copy(remaining, -F::one())
            };
            self.assign_with_horizontal_offset(ctx, &intermediate, CHUNK_SIZE)?;
            // calculate running subtraction
            remaining = Scaled::compose(chunk, constant)
                .zip(remaining)
                .map(|(chunk_composed, remaining)| remaining - chunk_composed);
            // fix the shape of the gate
            {
                self.short_gates(ctx)?;
                self.disable_mul(ctx)?;
                if i == number_of_chunks - 1 {
                    self.disable_next(ctx)?;
                    #[cfg(feature = "sanity-check")]
                    remaining.map(|remaining_should_be_zero| {
                        assert_eq!(remaining_should_be_zero, F::zero())
                    });
                } else {
                    self.enable_next(ctx)?;
                }
            }
            // assign the current chunk
            for (j, e) in chunk
                .iter()
                .cloned()
                .chain(std::iter::repeat(Scaled::dummy()))
                .take(CHUNK_SIZE)
                .enumerate()
            {
                self.assign_with_horizontal_offset(ctx, &e, j)?;
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
        assert!(!second_degree_terms.is_empty(), "use `compose` instead");
        let number_of_sd_terms = second_degree_terms.len();
        let number_of_fd_terms = first_degree_terms.len();
        // potentially
        let processed_fd_terms =
            ((number_of_sd_terms + 1) / 2) + if number_of_sd_terms % 2 == 1 { 2 } else { 0 };
        let remaining_fd_terms = number_of_fd_terms.saturating_sub(processed_fd_terms);
        let number_of_sd_chunks = (number_of_sd_terms - 1) / 2 + 1;
        let first_degree_terms_padded = first_degree_terms
            .iter()
            .cloned()
            .chain(std::iter::repeat(Scaled::dummy()))
            .take(processed_fd_terms + 2 /* a little workaround */)
            .collect::<Vec<Scaled<F>>>();
        let mut remaining = result.value();
        let remaining = second_degree_terms
            .chunks(2)
            .zip(first_degree_terms_padded.windows(3))
            .enumerate()
            .map(|(i, (second_degree_terms, first_degree_terms))| {
                let constant = if i == 0 { constant } else { F::zero() };
                self.set_constant(ctx, constant)?;
                // fix the shape of the gate
                {
                    self.short_gates(ctx)?;
                    if i == number_of_sd_chunks - 1 && remaining_fd_terms == 0 {
                        self.disable_next(ctx)?;
                    } else {
                        self.enable_next(ctx)?;
                    }
                }
                let intermediate = if i == 0 {
                    result.neg()
                } else {
                    Scaled::no_copy(remaining, -F::one())
                };
                // running subtraction, first one is the sum
                self.extended_gate.assign(ctx, ColumnID::C, &intermediate)?;
                let first_degree_composition = if second_degree_terms.len() == 2 {
                    // two terms to mul
                    let u0 = &second_degree_terms[0];
                    self.simple_gate.assign_scaled_mul(ctx, u0)?;
                    let u1 = &second_degree_terms[1];
                    self.extended_gate.assign_scaled_mul(ctx, u1)?;
                    // term to add
                    self.simple_gate
                        .assign(ctx, ColumnID::C, &first_degree_terms[0])?;
                    first_degree_terms[0].value()
                } else {
                    // single term to mul
                    let u0 = &second_degree_terms[0];
                    self.simple_gate.assign_scaled_mul(ctx, u0)?;
                    self.simple_gate
                        .assign(ctx, ColumnID::C, &first_degree_terms[0])?;
                    // rest are goes as addition
                    self.extended_gate.disable_mul(ctx)?;
                    self.extended_gate
                        .assign(ctx, ColumnID::A, &first_degree_terms[1])?;
                    self.extended_gate
                        .assign(ctx, ColumnID::B, &first_degree_terms[2])?;
                    Scaled::compose(first_degree_terms, F::zero())
                };
                // calculate new remaning
                remaining = SecondDegreeScaled::compose(second_degree_terms, constant)
                    .zip(first_degree_composition)
                    .zip(remaining)
                    .map(|((w0, w1), remaining)| remaining - w0 - w1);
                ctx.next();
                #[cfg(feature = "sanity-check")]
                if i == number_of_sd_chunks - 1 && remaining_fd_terms == 0 {
                    remaining.map(|remaining_should_be_zero| {
                        assert_eq!(remaining_should_be_zero, F::zero())
                    });
                }
                Ok(remaining)
            })
            .collect::<Result<Vec<Value<F>>, Error>>()?;
        let remaining = remaining.last().unwrap();
        if remaining_fd_terms > 0 {
            self.compose(
                ctx,
                &first_degree_terms[first_degree_terms.len() - remaining_fd_terms..],
                &Scaled::no_copy(*remaining, F::one()),
                F::zero(),
            )?;
        }
        Ok(())
    }
}
impl<F: FieldExt, const LOOKUP_WIDTH: usize> MainGate<F, LOOKUP_WIDTH> {
    pub(crate) fn assign_complex_operation(
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
