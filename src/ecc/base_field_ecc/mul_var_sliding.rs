use super::BaseFieldEccChip;
use crate::{ecc::Point, utils::big_to_fe, Witness};
use group::Curve;
use halo2::halo2curves::{CurveAffine, FieldExt};
use num_bigint::BigUint;
use num_traits::One;

fn make_mul_aux<C: CurveAffine>(generator: C, window_size: usize, number_of_pairs: usize) -> C {
    assert!(window_size > 0);
    assert!(number_of_pairs > 0);
    use group::ff::PrimeField;
    let n = C::Scalar::NUM_BITS as usize;
    let mut number_of_selectors = n / window_size;
    if n % window_size != 0 {
        number_of_selectors += 1;
    }
    let mut k0 = BigUint::one();
    let one = BigUint::one();
    for i in 0..number_of_selectors {
        k0 |= &one << (i * window_size);
    }
    let k1 = (one << number_of_pairs) - 1usize;
    // k = k0* 2^n_pairs
    let k = k0 * k1;
    (-generator * big_to_fe::<C::Scalar>(k)).to_affine()
}
#[derive(Debug, Clone)]
pub(crate) struct MulAux<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    generator: Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    correction: Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn get_mul_aux(
        &mut self,
        window_size: usize,
        number_of_pairs: usize,
    ) -> MulAux<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        assert!(number_of_pairs > 0);
        let generator = self.register_constant(self.aux_generator);
        let aux = make_mul_aux(self.aux_generator, window_size, number_of_pairs);
        let correction = self.register_constant(aux);
        // to_add the equivalent of AuxInit and to_sub AuxFin
        // see https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMgview
        MulAux {
            generator,
            correction,
        }
    }
    fn window(bits: &[Witness<C::Scalar>], window_size: usize) -> Vec<Vec<Witness<C::Scalar>>> {
        bits.chunks(window_size)
            .rev()
            .map(|chunk| chunk.to_vec())
            .collect()
    }
    fn make_incremental_table(
        &mut self,
        aux: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Vec<Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        let table_size = 1 << window_size;
        let mut table = vec![aux.clone()];
        for i in 0..(table_size - 1) {
            table.push(self.add(&table[i], point));
        }
        table
    }
    fn select_multi(
        &mut self,
        selector: &[Witness<C::Scalar>],
        table: &[Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let number_of_selectors = selector.len();
        let mut reducer = table.to_vec();
        for (i, selector) in selector.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(selector, &reducer[k + 1], &reducer[k]);
            }
        }
        reducer[0].clone()
    }
    pub fn mul(
        &mut self,
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        scalar: &Witness<C::Scalar>,
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        let aux = self.get_mul_aux(window_size, 1);
        let decomposed = &mut self.integer_chip.to_bits(scalar);
        let windowed = Self::window(decomposed, window_size);
        let table = &self.make_incremental_table(&aux.generator, point, window_size);
        let mut acc = self.select_multi(&windowed[0], table);
        acc = self.double_n(&acc, window_size);
        let to_add = self.select_multi(&windowed[1], table);
        acc = self.add(&acc, &to_add);
        for selector in windowed.iter().skip(2) {
            acc = self.double_n(&acc, window_size - 1);
            let to_add = self.select_multi(selector, table);
            acc = self.ladder(&acc, &to_add);
        }
        self.add(&acc, &aux.correction)
    }
    pub(crate) fn msm_1d_horizontal(
        &mut self,
        points: &[Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
        scalars: &[Witness<C::Scalar>],
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        let number_of_points = points.len();
        assert!(number_of_points > 0);
        assert_eq!(number_of_points, scalars.len());
        let aux = self.get_mul_aux(window_size, number_of_points);
        let decomposed_scalars: Vec<Vec<Witness<C::Scalar>>> = scalars
            .iter()
            .map(|scalar| self.integer_chip.to_bits(scalar))
            .collect();
        let windowed_scalars: Vec<Vec<Vec<Witness<C::Scalar>>>> = decomposed_scalars
            .iter()
            .map(|decomposed| Self::window(decomposed, window_size))
            .collect();
        let number_of_windows = windowed_scalars[0].len();
        let mut running_aux = aux.generator.clone();
        let tables: Vec<Vec<Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>> = points
            .iter()
            .enumerate()
            .map(|(i, point)| {
                let table = self.make_incremental_table(&running_aux, point, window_size);
                if i != number_of_points - 1 {
                    running_aux = self.double(&running_aux);
                }
                table
            })
            .collect();
        // preparation for the first round
        // initialize accumulator
        let mut acc = self.select_multi(&windowed_scalars[0][0], &tables[0]);
        // add first contributions other point scalar
        for (table, windowed) in tables.iter().skip(1).zip(windowed_scalars.iter().skip(1)) {
            let selector = &windowed[0];
            let to_add = self.select_multi(selector, table);
            acc = self.add(&acc, &to_add);
        }
        for i in 1..number_of_windows {
            acc = self.double_n(&acc, window_size);
            for (table, windowed) in tables.iter().zip(windowed_scalars.iter()) {
                let selector = &windowed[i];
                let to_add = self.select_multi(selector, table);
                acc = self.add(&acc, &to_add);
            }
        }
        self.add(&acc, &aux.correction)
    }
}
