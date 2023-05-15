use crate::{
    ecc::{
        general_ecc::{GeneralEccChip, Point},
        ConstantPoint,
    },
    integer::{chip::IntegerChip, Integer},
    utils::big_to_fe,
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
        Emulated: CurveAffine,
        N: PrimeField + Ord,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > GeneralEccChip<'a, Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn correction_point(
        &mut self,
        window_size: usize,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);

        let _ = self.register_constant_point(&self.aux_generator.clone());
        let number_of_selectors = div_ceil!(Emulated::Scalar::NUM_BITS as usize, window_size);
        let k = (BigUint::one() << number_of_selectors) - BigUint::one();
        let correction = (self.aux_generator * big_to_fe::<Emulated::Scalar>(k)).to_affine();
        self.register_constant_point(&-correction)
    }
    pub fn mul_fix(
        &mut self,
        point: Emulated,
        scalar: Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        window_size: usize,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        assert!(window_size > 0);
        let table: Vec<Vec<Emulated::CurveExt>> =
            window::<Emulated>(point, window_size, self.aux_generator);
        let table = table
            .into_iter()
            .map(batch_affine::<Emulated>)
            .collect::<Vec<_>>();
        let table = table.iter().map(|row| {
            row.iter()
                .map(|e| ConstantPoint::<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(*e))
                .collect::<Vec<_>>()
        });
        let mut ch = IntegerChip::new(self.operations, self.rns_scalar_field);
        let scalar = ch.to_bits(&scalar);
        let acc: Option<Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> = scalar
            .chunks(window_size)
            .zip(table.into_iter())
            .fold(None, |acc, (slice, table)| {
                let acc: Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> = match acc {
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
