use super::{AssignedPoint, BaseFieldEccChip, BaseFieldEndoEccChip};
use crate::maingate::{AssignedCondition, AssignedValue, MainGateInstructions};
use crate::{halo2, AssignedDecompScalar, Selector, Table, Windowed};
use halo2::arithmetic::CurveAffine;
use halo2::arithmetic::CurveEndo;
use halo2::plonk::Error;
use integer::halo2::curves::CurveExt;
use integer::halo2::ff::{Field, PrimeField, WithSmallOrderMulGroup};
use integer::maingate::{CombinationOption, RegionCtx, Term};
use integer::rns::Integer;
use integer::{IntegerInstructions, Range};

impl<C: CurveAffine, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Pads scalar up to the next window_size mul
    fn pad(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        bits: &mut Vec<AssignedCondition<C::Scalar>>,
        window_size: usize,
    ) -> Result<(), Error> {
        // assert_eq!(bits.len(), C::Scalar::NUM_BITS as usize);

        // TODO: This is a tmp workaround. Instead of padding with zeros we can use a
        // shorter ending window.
        let padding_offset = (window_size - (bits.len() % window_size)) % window_size;
        let zeros: Vec<AssignedCondition<C::Scalar>> = (0..padding_offset)
            .map(|_| self.main_gate().assign_constant(ctx, C::Scalar::ZERO))
            .collect::<Result<_, Error>>()?;
        bits.extend(zeros);
        bits.reverse();

        Ok(())
    }

    /// Splits the bit representation of a scalar into windows
    fn window(bits: Vec<AssignedCondition<C::Scalar>>, window_size: usize) -> Windowed<C::Scalar> {
        assert_eq!(bits.len() % window_size, 0);
        let number_of_windows = bits.len() / window_size;
        Windowed(
            (0..number_of_windows)
                .map(|i| {
                    let mut selector: Vec<AssignedCondition<C::Scalar>> = (0..window_size)
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
        ctx: &mut RegionCtx<'_, C::Scalar>,
        aux: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Result<Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let table_size = 1 << window_size;
        let mut table = vec![aux.clone()];
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
        assert!(window_size > 0);
        let aux = self.get_mul_aux(window_size, 1)?;

        let main_gate = self.main_gate();
        let decomposed = &mut main_gate.to_bits(ctx, scalar, C::Scalar::NUM_BITS as usize)?;

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
        assert!(window_size > 0);
        assert!(!pairs.is_empty());
        let aux = self.get_mul_aux(window_size, pairs.len())?;

        let main_gate = self.main_gate();

        let mut decomposed_scalars: Vec<Vec<AssignedCondition<C::Scalar>>> = pairs
            .iter()
            .map(|(_, scalar)| main_gate.to_bits(ctx, scalar, C::Scalar::NUM_BITS as usize))
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
        let tables: Vec<Table<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = pairs
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

impl<C: CurveEndo, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    BaseFieldEndoEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Split a scalar k in 128-bit scalars k1, k2 such that:
    /// k = k1 + C::lambda * k2
    fn split_scalar(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        scalar: &AssignedValue<C::Scalar>,
    ) -> Result<AssignedDecompScalar<C::Scalar>, Error> {
        let maingate = self.ecc_chip.main_gate();
        let sig = |neg: bool| if neg { -C::Scalar::ONE } else { C::Scalar::ONE };
        let positive = |neg: bool| if neg { C::Scalar::ZERO } else { C::Scalar::ONE };

        let decomposed = scalar.value().map(|v| C::decompose_scalar(v));

        let k1 = decomposed.map(|decomp| C::Scalar::from_u128(decomp.0));
        // let k1_pos = decomposed.map(|decomp| positive(decomp.1));
        let k1_sig = decomposed.map(|decomp| sig(decomp.1));

        let k2 = decomposed.map(|decomp| C::Scalar::from_u128(decomp.2));
        // let k2_pos = decomposed.map(|decomp| positive(decomp.3));
        let k2_sig = decomposed.map(|decomp| sig(decomp.3));

        // Sanity check
        scalar.value().map(|s| dbg!(s));
        decomposed.map(|(k1, k1_neg, k2, k2_neg)| {
            let k1 = C::Scalar::from_u128(k1);
            let k2 = C::Scalar::from_u128(k2);
            let k1_sig = sig(k1_neg);
            let k2_sig = sig(k2_neg);
            dbg!(k1, k2, k1_sig, k2_sig);
            scalar
                .value()
                .map(|k| assert_eq!(k1 * k1_sig - C::ScalarExt::ZETA * k2 * k2_sig, *k));
        });

        // Add decomoposition constraint
        // k1 * k1_sig - C::LAMBDA * k2 * k2_sig - k = 0
        // k1_sig i {-1, 1}
        // k2_sig i {-1, 1}

        // Maingate can be used directly, C::Scalar is the native field
        let assigned = maingate.apply(
            ctx,
            [
                Term::unassigned_to_mul(k1),
                Term::unassigned_to_mul(k1_sig),
                Term::unassigned_to_mul(k2),
                Term::unassigned_to_mul(k2_sig),
                Term::assigned_to_sub(scalar),
            ],
            C::Scalar::ZERO,
            CombinationOption::OneLinerDoubleMul(-C::ScalarExt::ZETA),
        )?;
        let (k1, k1_sig, k2, k2_sig) = (&assigned[0], &assigned[1], &assigned[2], &assigned[3]);
        maingate.assert_sign(ctx, &k1_sig)?;
        maingate.assert_sign(ctx, &k2_sig)?;

        let k1_pos = maingate.sign_to_cond(ctx, k1_sig)?;
        let k2_pos = maingate.sign_to_cond(ctx, k2_sig)?;

        Ok([(k1.clone(), k1_pos.clone()), (k2.clone(), k2_pos.clone())])
    }

    /// Scalar multiplication of a point in the EC
    /// Performed with the sliding-window algorithm
    pub fn glv_mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        point: &AssignedPoint<
            <C::AffineExt as CurveAffine>::Base,
            <C::AffineExt as CurveAffine>::ScalarExt,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
        >,
        scalar: &AssignedValue<C::Scalar>,
        window_size: usize,
    ) -> Result<
        AssignedPoint<
            <C::AffineExt as CurveAffine>::Base,
            <C::AffineExt as CurveAffine>::ScalarExt,
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

        let windowed_k1 = BaseFieldEccChip::<C::AffineExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::window(
            decomp_k1.to_vec(),
            window_size,
        );
        let windowed_k2 = BaseFieldEccChip::<C::AffineExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::window(
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
