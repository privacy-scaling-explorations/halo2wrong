use super::{AssignedPoint, BaseFieldEccChip};
use crate::maingate::{AssignedCondition, AssignedValue, MainGateInstructions};
use crate::{halo2, Selector, Table, Windowed};
use halo2::arithmetic::CurveAffine;
use halo2::halo2curves::ff::{Field, PrimeField};
use halo2::plonk::Error;
use integer::maingate::RegionCtx;

impl<C: CurveAffine, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Splits the bit representation of a scalar into windows
    fn window(bits: Vec<AssignedCondition<C::Scalar>>, window_size: usize) -> Windowed<C::Scalar> {
        let last = bits.len() % window_size;
        let num = bits.len() / window_size;

        let mut windows: Vec<_> = (0..num)
            .map(|i| {
                let k = i * window_size;
                Selector(bits[k..k + window_size].to_vec())
            })
            .collect();

        if last != 0 {
            let last_start = bits.len() - last;
            windows.push(Selector(bits[last_start..].to_vec()));
        }

        windows.reverse();

        Windowed(windows)
    }

    /// Constructs table for efficient multiplication algorithm
    /// The table contains precomputed point values that allow to trade
    /// additions for selections
    /// [2]P, [3]P, ..., [2^w + 1]P
    fn make_incremental_table(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let table_size = 1 << window_size;
        let double = self.double(ctx, point)?;
        let mut table = vec![double];
        for i in 0..(table_size - 1) {
            table.push(self.add(ctx, &table[i], point)?);
        }
        Ok(Table(table))
    }

    /// Selects a point in > 2 sized table using a selector
    fn select_multi(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        selector: &Selector<C::Scalar>,
        table: &Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
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

    /// Scalar multiplication of a point in the EC
    /// Performed with the sliding-window algorithm
    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        scalar: &AssignedValue<C::Scalar>,
        window_size: usize,
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        assert!(window_size > 1);
        let num_bits = C::Scalar::NUM_BITS as usize;
        let number_of_windows = (num_bits + window_size - 1) / window_size;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let window_last: usize = 1 << last;

        let (scalar_correction, aux) = self.get_mul_correction(window_size)?;
        let main_gate = self.main_gate();
        let scalar_adjusted = &main_gate.add_constant(ctx, scalar, scalar_correction)?;

        let decomposed = main_gate.to_bits(ctx, &scalar_adjusted, num_bits)?;
        let windowed = Self::window(decomposed, window_size);

        let table = &self.make_incremental_table(ctx, point, window_size)?;
        let last_table = &Table(table.0[0..window_last].to_vec());

        let mut acc = self.select_multi(ctx, &windowed.0[0], last_table)?;
        acc = self.double_n(ctx, &acc, window_size)?;
        let q = self.select_multi(ctx, &windowed.0[1], table)?;
        acc = self._add_incomplete_unsafe(ctx, &acc, &q)?;

        for i in 2..number_of_windows - 2 {
            acc = self.double_n(ctx, &acc, window_size - 1)?;
            let q = self.select_multi(ctx, &windowed.0[i], table)?;
            acc = self._ladder_incomplete(ctx, &acc, &q)?;
        }

        // The last two rows use auxiliary generator
        // aux_1 = (2^w aux_2 + aux_generator) + Q_1
        // aux_0 = 2^w aux_1 + Q_0 - 2^w aux_generator
        acc = self.double_n(ctx, &acc, window_size)?;
        acc = self.add(ctx, &acc, &aux.to_add)?;
        let q1 = self.select_multi(ctx, &windowed.0[number_of_windows - 2], table)?;
        acc = self.add(ctx, &acc, &q1)?;

        acc = self.double_n(ctx, &acc, window_size)?;
        let q0 = self.select_multi(ctx, &windowed.0[number_of_windows - 1], table)?;
        acc = self.add(ctx, &acc, &q0)?;

        self.add(ctx, &acc, &aux.to_sub)
    }

    /// Computes multi-product
    ///
    /// Given a vector of point, scalar pairs
    /// `[(P_0, e_0), (P_1, e_1), ..., (P_k, e_k)]`
    /// Returns
    /// ` P_0 * e_0 + P_1 * e_1 + ...+ P_k * e_k`
    #[allow(clippy::type_complexity)]
    pub fn mul_batch_1d_horizontal(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        pairs: Vec<(
            AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedValue<C::Scalar>,
        )>,
        window_size: usize,
    ) -> Result<AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        assert!(window_size > 1);
        assert!(!pairs.is_empty());

        let num_bits = C::Scalar::NUM_BITS as usize;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let window_last: usize = 1 << last;

        let main_gate = self.main_gate();

        let (scalar_correction, aux) = self.get_mul_correction(window_size)?;
        let decomposed_scalars: Vec<Vec<AssignedCondition<C::Scalar>>> = pairs
            .iter()
            .map(|(_, scalar)| {
                let scalar_adjusted = main_gate.add_constant(ctx, scalar, scalar_correction)?;
                main_gate.to_bits(ctx, &scalar_adjusted, C::Scalar::NUM_BITS as usize)
            })
            .collect::<Result<_, Error>>()?;

        let windowed_scalars: Vec<Windowed<C::Scalar>> = decomposed_scalars
            .iter()
            .map(|decomposed| Self::window(decomposed.to_vec(), window_size))
            .collect();
        let number_of_windows = windowed_scalars[0].0.len();

        let tables: Vec<Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = pairs
            .iter()
            .map(|(point, _)| self.make_incremental_table(ctx, point, window_size))
            .collect::<Result<_, Error>>()?;

        // preparation for the first round
        // initialize accumulator
        let last_table = &Table(tables[0].0[0..window_last].to_vec());
        let mut acc = self.select_multi(ctx, &windowed_scalars[0].0[0], last_table)?;
        // add first contributions other point scalar
        for (table, windowed) in tables.iter().skip(1).zip(windowed_scalars.iter().skip(1)) {
            let last_table = &Table(table.0[0..window_last].to_vec());
            let selector = &windowed.0[0];
            let q = self.select_multi(ctx, selector, last_table)?;
            acc = self.add(ctx, &acc, &q)?;
        }

        for i in 1..number_of_windows - 2 {
            acc = self.double_n(ctx, &acc, window_size)?;
            for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
                let selector = &windowed.0[i];
                let q = self.select_multi(ctx, selector, table)?;
                acc = self.add(ctx, &acc, &q)?;
            }
        }

        acc = self.double_n(ctx, &acc, window_size)?;
        acc = self.add(ctx, &acc, &aux.to_add)?;
        for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
            let selector = &windowed.0[number_of_windows - 2];
            let q = self.select_multi(ctx, selector, table)?;
            acc = self.add(ctx, &acc, &q)?;
        }

        acc = self.double_n(ctx, &acc, window_size)?;
        for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
            let selector = &windowed.0[number_of_windows - 1];
            let q = self.select_multi(ctx, selector, table)?;
            acc = self.add(ctx, &acc, &q)?;
        }

        self.add(ctx, &acc, &aux.to_sub)
    }
}
