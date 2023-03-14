use super::{AssignedPoint, GeneralEccChip};
use crate::integer::{AssignedInteger, IntegerInstructions};
use crate::maingate::{AssignedCondition, MainGateInstructions};
use crate::{halo2, Selector, Table, Windowed};
use halo2::arithmetic::CurveAffine;
use halo2::plonk::Error;
use integer::halo2::ff::PrimeField;
use integer::maingate::RegionCtx;

impl<
        Emulated: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > GeneralEccChip<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Pads scalar up to the next window_size mul
    fn pad(
        &self,
        region: &mut RegionCtx<'_, N>,
        bits: &mut Vec<AssignedCondition<N>>,
        window_size: usize,
    ) -> Result<(), Error> {
        assert_eq!(bits.len(), Emulated::ScalarExt::NUM_BITS as usize);

        // TODO: This is a tmp workaround. Instead of padding with zeros we can use a
        // shorter ending window.
        let padding_offset = (window_size - (bits.len() % window_size)) % window_size;
        let zeros: Vec<AssignedCondition<N>> = (0..padding_offset)
            .map(|_| self.main_gate().assign_constant(region, N::ZERO))
            .collect::<Result<_, Error>>()?;
        bits.extend(zeros);
        bits.reverse();

        Ok(())
    }

    /// Splits the bit representation of a scalar into windows
    fn window(bits: Vec<AssignedCondition<N>>, window_size: usize) -> Windowed<N> {
        assert_eq!(bits.len() % window_size, 0);
        let number_of_windows = bits.len() / window_size;
        Windowed(
            (0..number_of_windows)
                .map(|i| {
                    let mut selector: Vec<AssignedCondition<N>> = (0..window_size)
                        .map(|j| bits[i * window_size + j].clone())
                        .collect();
                    selector.reverse();
                    Selector(selector)
                })
                .collect(),
        )
    }

    /// Constructs table for efficient multiplication algorithm
    /// The table contains precomputed point values that allow to trade
    /// additions for selections
    fn make_incremental_table(
        &self,
        region: &mut RegionCtx<'_, N>,
        aux: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<Table<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let table_size = 1 << window_size;
        let mut table = vec![aux.clone()];
        for i in 0..(table_size - 1) {
            table.push(self.add(region, &table[i], point)?);
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
        region: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        scalar: &AssignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        assert!(window_size > 0);
        let aux = self.get_mul_aux(window_size, 1)?;

        let scalar_chip = self.scalar_field_chip();
        let decomposed = &mut scalar_chip.decompose(region, scalar)?;
        self.pad(region, decomposed, window_size)?;
        let windowed = Self::window(decomposed.to_vec(), window_size);
        let table = &self.make_incremental_table(region, &aux.to_add, point, window_size)?;

        let mut acc = self.select_multi(region, &windowed.0[0], table)?;
        acc = self.double_n(region, &acc, window_size)?;

        let to_add = self.select_multi(region, &windowed.0[1], table)?;
        acc = self.add(region, &acc, &to_add)?;

        for selector in windowed.0.iter().skip(2) {
            acc = self.double_n(region, &acc, window_size - 1)?;
            let to_add = self.select_multi(region, selector, table)?;
            acc = self.ladder(region, &acc, &to_add)?;
        }

        self.add(region, &acc, &aux.to_sub)
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
        region: &mut RegionCtx<'_, N>,
        pairs: Vec<(
            AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        )>,
        window_size: usize,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        assert!(window_size > 0);
        assert!(!pairs.is_empty());
        let aux = self.get_mul_aux(window_size, pairs.len())?;

        let scalar_chip = self.scalar_field_chip();
        // 1. Decompose scalars in bits
        let mut decomposed_scalars: Vec<Vec<AssignedCondition<N>>> = pairs
            .iter()
            .map(|(_, scalar)| scalar_chip.decompose(region, scalar))
            .collect::<Result<_, Error>>()?;

        // 2. Pad scalars bit representations
        for decomposed in decomposed_scalars.iter_mut() {
            self.pad(region, decomposed, window_size)?;
        }

        // 3. Split scalar bits into windows
        let windowed_scalars: Vec<Windowed<N>> = decomposed_scalars
            .into_iter()
            .map(|decomposed| Self::window(decomposed, window_size))
            .collect();
        let number_of_windows = windowed_scalars[0].0.len();

        let mut binary_aux = aux.to_add.clone();
        let tables: Vec<Table<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = pairs
            .iter()
            .enumerate()
            .map(|(i, (point, _))| {
                let table = self.make_incremental_table(region, &binary_aux, point, window_size);
                if i != pairs.len() - 1 {
                    binary_aux = self.double(region, &binary_aux)?;
                }
                table
            })
            .collect::<Result<_, Error>>()?;

        // preparation for the first round
        // initialize accumulator
        let mut acc = self.select_multi(region, &windowed_scalars[0].0[0], &tables[0])?;
        // add first contributions other point scalar
        for (table, windowed) in tables.iter().skip(1).zip(windowed_scalars.iter().skip(1)) {
            let selector = &windowed.0[0];
            let to_add = self.select_multi(region, selector, table)?;
            acc = self.add(region, &acc, &to_add)?;
        }

        for i in 1..number_of_windows {
            acc = self.double_n(region, &acc, window_size)?;
            for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
                let selector = &windowed.0[i];
                let to_add = self.select_multi(region, selector, table)?;
                acc = self.add(region, &acc, &to_add)?;
            }
        }

        self.add(region, &acc, &aux.to_sub)
    }
}
