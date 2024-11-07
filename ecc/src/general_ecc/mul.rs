use super::{AssignedPoint, GeneralEccChip};
use crate::integer::{AssignedInteger, IntegerInstructions};
use crate::maingate::{AssignedCondition, MainGateInstructions};
use crate::{halo2, Selector, Table, Windowed};
use halo2::arithmetic::CurveAffine;
use halo2::halo2curves::ff::PrimeField;
use halo2::plonk::Error;
use integer::maingate::RegionCtx;

impl<
        Emulated: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > GeneralEccChip<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Splits the bit representation of a scalar into windows
    fn window(bits: Vec<AssignedCondition<N>>, window_size: usize) -> Windowed<N> {
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
        ctx: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<Table<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
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
        region: &mut RegionCtx<'_, N>,
        selector: &Selector<N>,
        table: &Table<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let number_of_points = table.0.len();
        let number_of_selectors = selector.0.len();
        assert_eq!(number_of_points, 1 << number_of_selectors);

        let mut reducer = table.0.clone();
        for (i, selector) in selector.0.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(region, selector, &reducer[k + 1], &reducer[k])?;
            }
        }
        Ok(reducer[0].clone())
    }

    /// Scalar multiplication of a point in the EC
    /// Performed with the sliding-window algorithm
    pub fn mul(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        scalar: &AssignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        assert!(window_size > 1);
        let num_bits = Emulated::Scalar::NUM_BITS as usize;
        let number_of_windows = (num_bits + window_size - 1) / window_size;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let window_last: usize = 1 << last;

        let scalar_chip = self.scalar_field_chip();

        let (scalar_correction, aux) = self.get_mul_correction(window_size)?;
        let scalar_adjusted = &scalar_chip.add_constant(ctx, scalar, &scalar_correction)?;
        let scalar_reduced = &scalar_chip.reduce(ctx, scalar_adjusted)?;
        let decomposed = scalar_chip.decompose(ctx, scalar_reduced)?;
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
    /// `[(P_0, e_0), (P_1, e_1), ..., (P_k, e_k)] `
    /// Returns:
    /// `P_0 * e_0 + P_1 * e_1 + ...+ P_k * e_k`
    #[allow(clippy::type_complexity)]
    pub fn mul_batch_1d_horizontal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        pairs: Vec<(
            AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        )>,
        window_size: usize,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        assert!(window_size > 1);
        assert!(!pairs.is_empty());

        let num_bits = Emulated::Scalar::NUM_BITS as usize;
        let mut last = num_bits % window_size;
        if last == 0 {
            last = window_size;
        }
        let window_last: usize = 1 << last;

        let scalar_chip = self.scalar_field_chip();
        let (scalar_correction, aux) = self.get_mul_correction(window_size)?;

        // 1. Decompose scalars in bits
        let decomposed_scalars: Vec<Vec<AssignedCondition<N>>> = pairs
            .iter()
            .map(|(_, scalar)| {
                let scalar_adjusted = &scalar_chip.add_constant(ctx, scalar, &scalar_correction)?;
                let scalar_reduced = &scalar_chip.reduce(ctx, scalar_adjusted)?;
                scalar_chip.decompose(ctx, scalar_reduced)
            })
            .collect::<Result<_, Error>>()?;

        // 2. Split scalar bits into windows
        let windowed_scalars: Vec<Windowed<N>> = decomposed_scalars
            .into_iter()
            .map(|decomposed| Self::window(decomposed, window_size))
            .collect();
        let number_of_windows = windowed_scalars[0].0.len();

        let tables: Vec<Table<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = pairs
            .iter()
            .map(|(point, _)| self.make_incremental_table(ctx, point, window_size))
            .collect::<Result<_, Error>>()?;

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
