use self::{
    assignments::{Assignments, AssignmentsInternal},
    config::{LookupGate, MainGate},
    operations::Collector,
};
use crate::{
    maingate::{assignments::ColumnID, operations::Operation},
    RegionCtx, Scaled,
};
use halo2::{circuit::Layouter, halo2curves::FieldExt, plonk::Error};

pub mod assignments;
pub mod config;
pub mod lookup;
pub mod operations;
#[cfg(test)]
mod tests;

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
        self.extended_gate.enable_next(ctx)
    }
    pub(crate) fn disable_next(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        self.extended_gate.disable_next(ctx)
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
        collector: &Collector<F>,
    ) -> Result<(), Error> {
        let cell_map = ly.assign_region(
            || "",
            |region| {
                let ctx = &mut RegionCtx::new(region);
                let offset = std::cmp::min(
                    collector.simple_operations.len(),
                    collector.constant_operations.len(),
                );
                // 1. run two gates in parallel until one kind of operation exausted
                for (simple_op, extended_op) in collector
                    .simple_operations
                    .iter()
                    .zip(collector.constant_operations.iter())
                {
                    self.simple_gate.assign_op(ctx, simple_op)?;
                    self.enable_simple(ctx)?;
                    self.extended_gate.assign_constant_op(ctx, extended_op)?;
                    self.enable_extended(ctx)?;
                    ctx.next()
                }
                // 2. only extended operations are left, use only extended gate
                if collector.simple_operations.len() < collector.constant_operations.len() {
                    for op in collector.constant_operations.iter().skip(offset) {
                        self.extended_gate.assign_constant_op(ctx, op)?;
                        self.enable_extended(ctx)?;
                        self.simple_gate.empty(ctx)?;
                        ctx.next()
                    }
                }
                // 3. only simple operations left use both gate
                if collector.simple_operations.len() > collector.constant_operations.len() {
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

impl<F: FieldExt, const LOOKUP_WIDTH: usize> LookupGate<F, LOOKUP_WIDTH> {}
