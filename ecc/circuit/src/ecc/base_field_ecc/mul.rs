use super::{AssignedPoint, BaseFieldEccChip};
use crate::ecc::{Selector, Table, Windowed};
use crate::halo2;
use crate::maingate::{AssignedCondition, AssignedValue, MainGateInstructions};
use group::ff::PrimeField;
use halo2::arithmetic::CurveAffine;
use halo2::plonk::Error;
use integer::maingate::RegionCtx;

impl< C: CurveAffine> BaseFieldEccChip< C> {
    fn pad(&self, ctx: &mut RegionCtx<'_, '_, C::Scalar>, bits: &mut Vec<AssignedCondition<C::Scalar>>, window_size: usize) -> Result<(), Error> {
        use group::ff::Field;
        assert_eq!(bits.len(), C::Scalar::NUM_BITS as usize);

        // TODO: This is a tmp workaround. Instead of padding with zeros we can use a shorter ending window.
        let padding_offset = (window_size - (bits.len() % window_size)) % window_size;
        let zeros: Vec<AssignedCondition<C::Scalar>> = (0..padding_offset)
            .map(|_| Ok(self.main_gate().assign_constant(ctx, C::Scalar::zero())?.into()))
            .collect::<Result<_, Error>>()?;
        bits.extend(zeros);
        bits.reverse();

        Ok(())
    }

    fn window(bits: Vec<AssignedCondition<C::Scalar>>, window_size: usize) -> Windowed<C::Scalar> {
        assert_eq!(bits.len() % window_size, 0);
        let number_of_windows = bits.len() / window_size;
        Windowed(
            (0..number_of_windows)
                .map(|i| {
                    let mut selector: Vec<AssignedCondition<C::Scalar>> = (0..window_size).map(|j| bits[i * window_size + j].clone()).collect();
                    selector.reverse();
                    Selector(selector)
                })
                .collect(),
        )
    }

    fn make_incremental_table(
        &self,
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        aux: &AssignedPoint< C::Base, C::Scalar>,
        point: &AssignedPoint< C::Base, C::Scalar>,
        window_size: usize,
    ) -> Result<Table< C::Base, C::Scalar>, Error> {
        let table_size = 1 << window_size;
        let mut table = vec![aux.clone()];
        for i in 0..(table_size - 1) {
            table.push(self.add(ctx, &table[i], point)?);
        }
        Ok(Table(table))
    }

    fn select_multi(
        &self,
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        selector: &Selector<C::Scalar>,
        table: &Table< C::Base, C::Scalar>,
    ) -> Result<AssignedPoint< C::Base, C::Scalar>, Error> {
        let number_of_points = table.0.len();
        let number_of_selectors = selector.0.len();
        assert_eq!(number_of_points, 1 << number_of_selectors);

        let mut reducer = table.0.clone();
        for (i, selector) in selector.0.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(ctx, selector, &reducer[k + 1], &reducer[k])?;
            }
        }
        Ok(reducer[0].clone())
    }

    pub(super) fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        point: &AssignedPoint< C::Base, C::Scalar>,
        scalar: &AssignedValue<C::Scalar>,
        window_size: usize,
    ) -> Result<AssignedPoint< C::Base, C::Scalar>, Error> {
        assert!(window_size > 0);
        let aux = self.get_mul_aux(window_size, 1)?;

        let main_gate = self.main_gate();
        let decomposed = &mut main_gate.decompose(ctx, scalar, C::Scalar::NUM_BITS as usize)?;

        self.pad(ctx, decomposed, window_size)?;
        let windowed = Self::window(decomposed.to_vec(), window_size);
        let table = &self.make_incremental_table(ctx, &aux.to_add, point, window_size)?;

        let mut acc = self.select_multi(ctx, &windowed.0[0], table)?;
        acc = self.double_n(ctx, &acc, window_size)?;

        let to_add = self.select_multi(ctx, &windowed.0[1], table)?;
        acc = self.add(ctx, &acc, &to_add)?;

        for selector in windowed.0.iter().skip(2) {
            acc = self.double_n(ctx, &acc, window_size - 1)?;
            let to_add = self.select_multi(ctx, selector, table)?;
            acc = self.ladder(ctx, &acc, &to_add)?;
        }

        self.add(ctx, &acc, &aux.to_sub)
    }

    pub(super) fn mul_batch_1d_horizontal(
        &self,
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        pairs: Vec<(AssignedPoint< C::Base, C::Scalar>, AssignedValue<C::Scalar>)>,
        window_size: usize,
    ) -> Result<AssignedPoint< C::Base, C::Scalar>, Error> {
        assert!(window_size > 0);
        assert!(pairs.len() > 0);
        let aux = self.get_mul_aux(window_size, pairs.len())?;

        let main_gate = self.main_gate();

        let mut decomposed_scalars: Vec<Vec<AssignedCondition<C::Scalar>>> = pairs
            .iter()
            .map(|(_, scalar)| main_gate.decompose(ctx, scalar, C::Scalar::NUM_BITS as usize))
            .collect::<Result<_, Error>>()?;

        for decomposed in decomposed_scalars.iter_mut() {
            self.pad(ctx, decomposed, window_size)?;
        }

        let windowed_scalars: Vec<Windowed<C::Scalar>> = decomposed_scalars
            .iter()
            .map(|decomposed| Self::window(decomposed.to_vec(), window_size))
            .collect();
        let number_of_windows = windowed_scalars[0].0.len();

        let mut binary_aux = aux.to_add.clone();
        let tables: Vec<Table<C::Base, C::Scalar>> = pairs
            .iter()
            .enumerate()
            .map(|(i, (point, _))| {
                let table = self.make_incremental_table(ctx, &binary_aux, point, window_size);
                if i != pairs.len() - 1 {
                    binary_aux = self.double(ctx, &binary_aux)?;
                }
                table
            })
            .collect::<Result<_, Error>>()?;

        // preparation for the first round
        // initialize accumulator
        let mut acc = self.select_multi(ctx, &windowed_scalars[0].0[0], &tables[0])?;
        // add first contributions other point scalar
        for (table, windowed) in tables.iter().skip(1).zip(windowed_scalars.iter().skip(1)) {
            let selector = &windowed.0[0];
            let to_add = self.select_multi(ctx, selector, table)?;
            acc = self.add(ctx, &acc, &to_add)?;
        }

        for i in 1..number_of_windows {
            acc = self.double_n(ctx, &acc, window_size)?;
            for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
                let selector = &windowed.0[i];
                let to_add = self.select_multi(ctx, selector, table)?;
                acc = self.add(ctx, &acc, &to_add)?;
            }
        }

        self.add(ctx, &acc, &aux.to_sub)
    }
}
