use halo2::{
    circuit::{Layouter, Value},
    halo2curves::FieldExt,
    plonk::Error,
};

use crate::{
    maingate::{assignments::ColumnID, operations::Operation},
    Composable, RegionCtx, Scaled, SecondDegreeScaled, Term,
};

use self::{
    assignments::{Assignments, AssignmentsInternal},
    config::{LookupGate, MainGate},
    operations::Collector,
};

pub mod assignments;
pub mod config;
pub mod lookup;
pub mod operations;
#[cfg(test)]
mod tests;

// Fixed column helpers
impl<F: FieldExt, const LOOKUP_WIDTH: usize> MainGate<F, LOOKUP_WIDTH> {
    #[allow(dead_code)]
    pub(crate) fn empty_extended_gate(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.extended_gate.no_op(ctx)?;
        self.extended_gate.no_witness(ctx)
    }
    #[allow(dead_code)]
    pub(crate) fn empty_simple_gate(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.simple_gate.no_op(ctx)?;
        self.simple_gate.no_witness(ctx)
    }
    #[allow(dead_code)]
    pub(crate) fn empty_gate(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.empty_extended_gate(ctx)?;
        self.empty_simple_gate(ctx)
    }
    pub(crate) fn enable_simple(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.enable(self.q_isolate_simple)
    }
    pub(crate) fn enable_extended(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.enable(self.q_isolate_extended)
    }
    pub(crate) fn short_gates(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.enable(self.q_short)
    }
    pub(crate) fn disable_mul(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.simple_gate.disable_mul(ctx)?;
        self.extended_gate.disable_mul(ctx)
    }
    pub(crate) fn enable_next(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.extended_gate.disable_next(ctx)?;
        self.extended_gate.enable_next(ctx)
    }
    pub(crate) fn disable_next(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.extended_gate.disable_next(ctx)?;
        self.simple_gate.disable_next(ctx)
    }
    pub(crate) fn set_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        constant: F,
    ) -> Result<(), Error> {
        self.extended_gate.set_constant(ctx, constant)
    }
    pub(crate) fn disable_constant(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.extended_gate.disable_constant(ctx)
    }
}
impl<F: FieldExt, const LOOKUP_WIDTH: usize> MainGate<F, LOOKUP_WIDTH> {
    pub fn layout(
        &mut self,
        ly: &mut impl Layouter<F>,
        collector: Collector<F>,
    ) -> Result<(), Error> {
        let cell_map = ly.assign_region(
            || "",
            |region| {
                let ctx = &mut RegionCtx::new(region);
                let offset = std::cmp::min(
                    collector.simple_operations.len(),
                    collector.extended_operations.len(),
                );
                // 1. run two gates in parallel until one kind of operation exausted
                for (simple_op, extended_op) in collector
                    .simple_operations
                    .iter()
                    .zip(collector.extended_operations.iter())
                {
                    self.simple_gate.assign_op(ctx, simple_op)?;
                    self.enable_simple(ctx)?;
                    self.extended_gate.assign_extended_op(ctx, extended_op)?;
                    self.enable_extended(ctx)?;
                    ctx.next()
                }
                // 2. only extended operations are left, use only extended gate
                if collector.simple_operations.len() < collector.extended_operations.len() {
                    for op in collector.extended_operations.iter().skip(offset) {
                        self.extended_gate.assign_extended_op(ctx, op)?;
                        self.enable_extended(ctx)?;
                        self.simple_gate.empty(ctx)?;
                        ctx.next()
                    }
                }
                // 3. only simple operations left use both gate
                if collector.simple_operations.len() > collector.extended_operations.len() {
                    for chunk in collector
                        .simple_operations
                        .iter()
                        .skip(offset)
                        .cloned()
                        .collect::<Vec<Operation<F>>>()
                        .chunks(2)
                    {
                        self.enable_extended(ctx)?;
                        self.extended_gate.assign_op(ctx, &chunk[0])?;
                        if chunk.len() == 2 {
                            self.enable_simple(ctx)?;
                            self.simple_gate.assign_op(ctx, &chunk[1])?;
                        } else {
                            self.simple_gate.empty(ctx)?;
                        }
                        ctx.next();
                    }
                }
                // 4. assign shorted operations
                for op in collector.shorted_opeartions.iter() {
                    self.assign_shorted_op(ctx, op)?;
                }
                // 5. to espace from unassigned next cell error
                self.simple_gate.empty(ctx)?;
                self.extended_gate.empty(ctx)?;
                // 6 .apply indirect copy constraints
                for (id0, id1) in collector.copies.iter() {
                    ctx.copy(*id0, *id1)?;
                }
                Ok(ctx.cell_map())
            },
        )?;
        // finally layout lookup gate
        self.lookup_gate.layout(ly, &cell_map, &collector.lookups)?;
        Ok(())
    }
    fn assign_with_horizontal_offset(
        &mut self,
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
    pub fn compose(
        &mut self,
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

    pub fn compose_second_degree(
        &mut self,
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

impl<F: FieldExt, const LOOKUP_WIDTH: usize> LookupGate<F, LOOKUP_WIDTH> {}
