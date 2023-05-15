use crate::{
    ecc::{
        base_field_ecc::{BaseFieldEccChip, Point},
        ConstantPoint,
    },
    utils::big_to_fe,
    Witness,
};
use halo2curves::{
    group::{ff::PrimeField, Curve, Group},
    CurveAffine,
};
use num_bigint::BigUint;
use num_traits::One;

fn batch_affine<C: CurveAffine>(table: Vec<C::CurveExt>) -> Vec<C> {
    let mut affine_table = (0..table.len()).map(|_| C::identity()).collect::<Vec<C>>();
    C::CurveExt::batch_normalize(&table, &mut affine_table);
    affine_table
}
macro_rules! div_ceil {
    ($a:expr, $b:expr) => {
        (($a - 1) / $b) + 1
    };
}
fn window<C: CurveAffine>(point: C, window: usize, aux: C) -> Vec<Vec<C::CurveExt>> {
    fn incremental_table<C: CurveAffine>(
        point: C::CurveExt,
        window_size: usize,
        aux: C::CurveExt,
    ) -> Vec<C::CurveExt> {
        assert!(window_size > 0);
        let mut acc: C::CurveExt = aux;
        (0..window_size)
            .map(|i| {
                if i != 0 {
                    acc += point;
                }
                acc
            })
            .collect()
    }
    let number_of_windows = div_ceil!(C::ScalarExt::NUM_BITS as usize, window);
    let mut acc: C::CurveExt = point.into();
    let mut aux: C::CurveExt = aux.into();
    (0..number_of_windows)
        .map(|i| {
            let table: Vec<C::CurveExt> = incremental_table::<C>(acc, 1 << window, aux);
            if i != number_of_windows - 1 {
                aux = aux.double();
                acc = (0..window).fold(acc, |acc, _| acc.double());
            }
            table
        })
        .collect()
}
impl<
        'a,
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<'a, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn correction_point(
        &mut self,
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        let _ = self.register_constant(self.aux_generator);
        let number_of_selectors = div_ceil!(C::Scalar::NUM_BITS as usize, window_size);
        let k = (BigUint::one() << number_of_selectors) - BigUint::one();
        let correction = (self.aux_generator * big_to_fe::<C::Scalar>(k)).to_affine();
        self.register_constant(-correction)
    }
    pub fn mul_fix(
        &mut self,
        point: C,
        scalar: &Witness<C::Scalar>,
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        let table: Vec<Vec<C::CurveExt>> = window::<C>(point, window_size, self.aux_generator);
        let table = table.into_iter().map(batch_affine::<C>).collect::<Vec<_>>();
        let table = table.iter().map(|row| {
            row.iter()
                .map(|e| {
                    ConstantPoint::<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(*e)
                })
                .collect::<Vec<_>>()
        });
        let scalar = &mut self
            .operations
            .to_bits(scalar, C::Scalar::NUM_BITS as usize);
        let acc: Option<Point<C::Base, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = scalar
            .chunks(window_size)
            .zip(table.into_iter())
            .fold(None, |acc, (slice, table)| {
                let acc: Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = match acc {
                    Some(acc) => {
                        let selected = self.select_constant_multi(slice, &table[..]);
                        self.add(&acc, &selected)
                    }
                    None => self.select_constant_multi(slice, &table[..]),
                };
                Some(acc)
            });
        let acc = acc.unwrap();
        let correction_point = self.correction_point(window_size);
        self.add(&acc, &correction_point)
    }
}
