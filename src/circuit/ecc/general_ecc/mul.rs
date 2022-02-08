use super::AssignedPoint;
use crate::circuit::ecc::general_ecc::GeneralEccChip;
use crate::circuit::{AssignedInteger, IntegerInstructions};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::{halo2, Assigned, AssignedCondition, MainGateInstructions};
use std::fmt;

#[derive(Default)]
struct Selector<F: FieldExt>(Vec<AssignedCondition<F>>);

impl<F: FieldExt> fmt::Debug for Selector<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Selector");
        for (i, bit) in self.0.iter().enumerate() {
            debug.field("window_index", &i).field("bit", bit);
        }
        debug.finish()?;
        Ok(())
    }
}

struct Windowed<F: FieldExt>(Vec<Selector<F>>);

impl<F: FieldExt> fmt::Debug for Windowed<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Window");
        for (i, selector) in self.0.iter().enumerate() {
            debug.field("selector_index", &i).field("selector", selector);
        }
        debug.finish()?;
        Ok(())
    }
}

struct Table<F: FieldExt>(Vec<AssignedPoint<F>>);

impl<F: FieldExt> fmt::Debug for Table<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Table");
        for (i, entry) in self.0.iter().enumerate() {
            debug
                .field("entry_index", &i)
                .field("xn", &entry.x.native().value())
                .field("yn", &entry.y.native().value());
        }
        debug.finish()?;
        Ok(())
    }
}

pub(super) struct MulAux<F: FieldExt> {
    to_add: AssignedPoint<F>,
    to_sub: AssignedPoint<F>,
}

impl<F: FieldExt> MulAux<F> {
    pub(super) fn new(to_add: AssignedPoint<F>, to_sub: AssignedPoint<F>) -> Self {
        MulAux { to_add, to_sub }
    }
}

impl<Emulated: CurveAffine, F: FieldExt> GeneralEccChip<Emulated, F> {
    fn pad(&self, region: &mut Region<'_, F>, bits: &mut Vec<AssignedCondition<F>>, window_size: usize, offset: &mut usize) -> Result<(), Error> {
        use group::ff::PrimeField;
        assert_eq!(bits.len(), Emulated::ScalarExt::NUM_BITS as usize);

        // TODO: This is a tmp workaround. Instead of padding with zeros we can use a shorter ending window.
        let padding_offset = (window_size - (bits.len() % window_size)) % window_size;
        let main_gate = self.main_gate();
        let mut zeros = Vec::with_capacity(padding_offset);
        for _ in 0..padding_offset {
            zeros.push(main_gate.assign_constant(region, F::zero(), offset)?.into());
        }
        bits.extend(zeros);
        bits.reverse();

        Ok(())
    }

    fn window(bits: Vec<AssignedCondition<F>>, window_size: usize) -> Windowed<F> {
        assert_eq!(bits.len() % window_size, 0);

        let number_of_windows = bits.len() / window_size;
        let mut windowed: Windowed<F> = Windowed(Vec::new());

        for i in 0..number_of_windows {
            let mut selector: Selector<F> = Selector(Vec::new());
            for j in 0..window_size {
                selector.0.push(bits[i * window_size + j].clone());
            }
            selector.0.reverse();
            windowed.0.push(selector);
        }

        windowed
    }

    fn make_incremental_table(
        &self,
        region: &mut Region<'_, F>,
        aux: &AssignedPoint<F>,
        point: &AssignedPoint<F>,
        window_size: usize,
        offset: &mut usize,
    ) -> Result<Table<F>, Error> {
        let table_size = 1 << window_size;
        let mut table = vec![aux.clone()];
        for i in 0..(table_size - 1) {
            let entry = self.add(region, &table[i], point, offset)?;
            table.push(entry);
        }
        Ok(Table(table))
    }

    fn select_multi(&self, region: &mut Region<'_, F>, selector: &Selector<F>, table: &Table<F>, offset: &mut usize) -> Result<AssignedPoint<F>, Error> {
        let number_of_points = table.0.len();
        let number_of_selectors = selector.0.len();
        assert_eq!(number_of_points, 1 << number_of_selectors);

        let mut reducer = table.0.clone();
        for (i, selector) in selector.0.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(region, selector, &reducer[k + 1], &reducer[k], offset)?;
            }
        }
        Ok(reducer[0].clone())
    }

    pub(super) fn mul_var(
        &self,
        region: &mut Region<'_, F>,
        point: &AssignedPoint<F>,
        scalar: &AssignedInteger<F>,
        aux: &MulAux<F>,
        window_size: usize,
        offset: &mut usize,
    ) -> Result<AssignedPoint<F>, Error> {
        let scalar_chip = self.scalar_field_chip();
        let decomposed = &mut scalar_chip.decompose(region, scalar, offset)?;
        self.pad(region, decomposed, window_size, offset)?;
        let windowed = Self::window(decomposed.to_vec(), window_size);
        let table = &self.make_incremental_table(region, &aux.to_add, point, window_size, offset)?;

        let mut acc = self.select_multi(region, &windowed.0[0], table, offset)?;
        acc = self.double_n(region, &acc, window_size, offset)?;
        let to_add = self.select_multi(region, &windowed.0[1], table, offset)?;
        acc = self.add(region, &acc, &to_add, offset)?;

        for selector in windowed.0.iter().skip(2) {
            acc = self.double_n(region, &acc, window_size - 1, offset)?;
            let to_add = self.select_multi(region, selector, table, offset)?;
            acc = self.ladder(region, &acc, &to_add, offset)?;
        }
        self.add(region, &acc, &aux.to_sub, offset)
    }
}
