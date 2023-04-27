use super::{AssignedPoint, GeneralEccChip};
use crate::integer::{AssignedInteger, IntegerInstructions};
use crate::maingate::{AssignedCondition, MainGateInstructions};
use crate::{halo2, AssignedDecompScalar, GeneralEndoEccChip, Selector, Table, Windowed};
use halo2::arithmetic::CurveAffine;
use halo2::plonk::Error;
use integer::halo2::curves::{CurveEndo, CurveExt};
use integer::halo2::ff::{Field, PrimeField, WithSmallOrderMulGroup};
use integer::maingate::{big_to_fe, RegionCtx};
use integer::rns::{Common, Integer};
use integer::Range;

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
        // assert_eq!(bits.len(), Emulated::ScalarExt::NUM_BITS as usize);

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
    /// Performed with the windowed algorithm
    pub fn mul(
        &self,
        region: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        scalar: &AssignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        assert!(window_size > 0);

        let scalar_chip = self.scalar_field_chip();

        // Generate a random aux point (and its final offset) for the window size and n pairs.
        let aux = self.get_mul_aux(window_size, 1)?;

        // Decompose the scalar in bits and pad it to a multiple of window size
        let decomposed = &mut scalar_chip.decompose(region, scalar)?;
        self.pad(region, decomposed, window_size)?;

        // Split the decomposed scalar in windows
        let windowed = Self::window(decomposed.to_vec(), window_size);

        // Construct the table with the input point and the random accumulator
        let table = &self.make_incremental_table(region, &aux.to_add, point, window_size)?;

        // First (2) iteration of double-select-add
        let mut acc = self.select_multi(region, &windowed.0[0], table)?;
        acc = self.double_n(region, &acc, window_size)?;

        let to_add = self.select_multi(region, &windowed.0[1], table)?;
        acc = self.add(region, &acc, &to_add)?;

        // Rest of the iterations
        for selector in windowed.0.iter().skip(2) {
            acc = self.double_n(region, &acc, window_size - 1)?;
            let to_add = self.select_multi(region, selector, table)?;
            acc = self.ladder(region, &acc, &to_add)?;
        }

        // Compensate the offset introduced by the random point
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

impl<
        Emulated: CurveEndo,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > GeneralEndoEccChip<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Split a scalar k in 128-bit scalars k1, k2 such that:
    /// k = k1 - C::lambda * k2
    fn split_scalar(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        scalar: &AssignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedDecompScalar<N>, Error> {
        let maingate = self.ecc_chip.main_gate();
        let scalar_chip = &self.ecc_chip.scalar_field_chip;

        let pos = |neg: bool| if neg { N::ZERO } else { N::ONE };

        // Compute decomposition
        let decomposed = scalar.integer().map(|i| {
            let val = big_to_fe(i.value());
            Emulated::decompose_scalar(&val)
        });

        let k1 = decomposed.map(|decomp| Emulated::Scalar::from_u128(decomp.0));
        let k1_pos = decomposed.map(|decomp| pos(decomp.1));
        let k2 = decomposed.map(|decomp| Emulated::Scalar::from_u128(decomp.2));
        let k2_pos = decomposed.map(|decomp| pos(decomp.3));

        // Assign decomposition values
        let k1 = k1.map(|v| Integer::from_fe(v, scalar_chip.rns()));
        let k1 = scalar_chip.assign_integer(ctx, k1.into(), Range::Operand)?;

        let k1_pos = maingate.assign_bit(ctx, k1_pos)?;

        let k2 = k2.map(|v| Integer::from_fe(v, scalar_chip.rns()));
        let k2 = scalar_chip.assign_integer(ctx, k2.into(), Range::Operand)?;

        let k2_pos = maingate.assign_bit(ctx, k2_pos)?;

        // Sanity check
        // scalar.value().map(|s| dbg!(s));
        // decomposed.map(|(k1, k1_neg, k2, k2_neg)| {
        //     let k1 = C::Scalar::from_u128(k1);
        //     let k2 = C::Scalar::from_u128(k2);
        //     let k1_sig = sig(k1_neg);
        //     let k2_sig = sig(k2_neg);
        //     dbg!(k1, k2, k1_sig, k2_sig);
        //     scalar
        //         .value()
        //         .map(|k| assert_eq!(k1 * k1_sig - C::ScalarExt::ZETA * k2 * k2_sig, *k));
        // });

        // Add decomoposition constraint
        // k1 * k1_sig - C::LAMBDA * k2 * k2_sig - k = 0
        // k1_sig i {-1, 1}
        // k2_sig i {-1, 1}

        let minus_one = Integer::from_fe(-Emulated::Scalar::ONE, scalar_chip.rns());
        // Constraint k = k1* k1_sig - k2* k2_sig * zeta
        let minus_k1 = scalar_chip.mul_constant(ctx, &k1, &minus_one)?;
        let minus_k2 = scalar_chip.mul_constant(ctx, &k2, &minus_one)?;
        let signed_k1 = scalar_chip.select(ctx, &k1, &minus_k1, &k1_pos)?;
        let signed_k2 = scalar_chip.select(ctx, &k2, &minus_k2, &k2_pos)?;
        let minus_zeta = Integer::from_fe(-Emulated::ScalarExt::ZETA, scalar_chip.rns());
        let signed_k2_zeta = scalar_chip.mul_constant(ctx, &signed_k2, &minus_zeta)?;

        let result = scalar_chip.add(ctx, &signed_k1, &signed_k2_zeta)?;
        scalar_chip.assert_equal(ctx, &result, &scalar)?;

        Ok([
            (k1.native().clone(), k1_pos.clone()),
            (k2.native().clone(), k2_pos.clone()),
        ])
    }

    /// Scalar multiplication of a point in the EC
    /// Performed with the sliding-window algorithm
    pub fn glv_mul(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<
            <<Emulated as CurveExt>::AffineExt as CurveAffine>::Base,
            N,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
        >,
        scalar: &AssignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<
        AssignedPoint<
            <<Emulated as CurveExt>::AffineExt as CurveAffine>::Base,
            N,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
        >,
        Error,
    > {
        assert!(window_size > 0);
        let ecc = &self.ecc_chip;
        let aux = ecc.get_mul_aux(window_size, 2)?;

        // 1. Decompose scalar k -> k1, k2
        let split = self.split_scalar(ctx, scalar)?;

        // 2. Decompose scalars into AssignedCondition
        let main_gate = ecc.main_gate();
        let decomp_k1 = &mut main_gate.to_bits(ctx, &split[0].0, 128usize)?;
        let decomp_k2 = &mut main_gate.to_bits(ctx, &split[1].0, 128usize)?;

        // 2.1 Convert signs into Integers
        let minus_point = ecc.neg(ctx, point)?;
        let k1_point = ecc.select(ctx, &split[0].1, point, &minus_point)?;
        let k2_point = ecc.select(ctx, &split[1].1, &minus_point, point)?;
        let k2_point = ecc.endo(ctx, &k2_point)?;

        // 3. Pad to window size and chunk in windows
        ecc.pad(ctx, decomp_k1, window_size)?;
        ecc.pad(ctx, decomp_k2, window_size)?;

        let windowed_k1 =
            GeneralEccChip::<Emulated::AffineExt, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::window(
                decomp_k1.to_vec(),
                window_size,
            );
        let windowed_k2 =
            GeneralEccChip::<Emulated::AffineExt, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::window(
                decomp_k2.to_vec(),
                window_size,
            );
        let number_of_windows = windowed_k1.0.len();

        // 4. Generate aux acc point + Generate table
        let mut binary_aux = aux.to_add.clone();
        let tables: Vec<Table<_, _, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = vec![k1_point, k2_point]
            .iter()
            .enumerate()
            .map(|(i, point)| {
                let table = ecc.make_incremental_table(ctx, &binary_aux, point, window_size);
                if i != 1 {
                    binary_aux = ecc.double(ctx, &binary_aux)?;
                }
                table
            })
            .collect::<Result<_, Error>>()?;

        // 5. Mul double-and-add algorithm
        let windowed_scalars = vec![windowed_k1, windowed_k2];

        let mut acc = ecc.select_multi(ctx, &windowed_scalars[0].0[0], &tables[0])?;
        // add first contributions other point scalar
        for (table, windowed) in tables.iter().skip(1).zip(windowed_scalars.iter().skip(1)) {
            let selector = &windowed.0[0];
            let to_add = ecc.select_multi(ctx, selector, table)?;
            acc = ecc.add(ctx, &acc, &to_add)?;
        }

        for i in 1..number_of_windows {
            acc = ecc.double_n(ctx, &acc, window_size)?;
            for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
                let selector = &windowed.0[i];
                let to_add = ecc.select_multi(ctx, selector, table)?;
                acc = ecc.add(ctx, &acc, &to_add)?;
            }
        }
        ecc.add(ctx, &acc, &aux.to_sub)
    }
}
