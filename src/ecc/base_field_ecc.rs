use super::{ConstantPoint, Point};
use crate::{
    integer::{
        chip::{IntegerChip, Range},
        rns::Rns,
        ConstantInteger,
    },
    maingate::operations::Collector,
    Scaled, Witness,
};
use halo2::{arithmetic::Field, circuit::Value, halo2curves::CurveAffine};

mod add;
mod mul_fix;
#[allow(dead_code)]
mod mul_var_bucket;
mod mul_var_sliding;
#[derive(Debug, Clone)]
pub struct BaseFieldEccChip<
    C: CurveAffine,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
> {
    pub(crate) integer_chip:
        IntegerChip<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    aux_generator: C,
}
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn new(
        integer_chip: IntegerChip<
            C::Base,
            C::Scalar,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
            NUMBER_OF_SUBLIMBS,
        >,
        aux_generator: C,
    ) -> Self {
        Self {
            integer_chip,
            aux_generator,
        }
    }
    pub fn rns(
        &self,
    ) -> &Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS> {
        self.integer_chip.rns()
    }
    pub fn integer_chip(
        &mut self,
    ) -> &mut IntegerChip<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
    {
        &mut self.integer_chip
    }
    pub fn operations(&self) -> &Collector<C::Scalar> {
        self.integer_chip.operations()
    }
    fn parameter_b() -> ConstantInteger<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        C::b().into()
    }
}
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn get_constant(
        &mut self,
        point: C,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.register_constant(point)
    }
    pub fn register_constant(
        &mut self,
        point: C,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let ch = self.integer_chip();
        let coords = point.coordinates();
        // disallow point of infinity
        // it will not pass assing point enforcement
        let coords = coords.unwrap();
        let x = coords.x();
        let y = coords.y();
        let x = &ch.register_constant(*x);
        let y = &ch.register_constant(*y);
        Point::new(x, y)
    }
    pub fn assign_point(
        &mut self,
        point: Value<C>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let ch = self.integer_chip();
        let rns = ch.rns();
        let (x, y) = point
            .map(|point| {
                let coords = point.coordinates();
                // disallow point of infinity
                // it will not pass assing point enforcement
                let coords = coords.unwrap();
                let x = coords.x();
                let y = coords.y();
                (*x, *y)
            })
            .unzip();
        let x = rns.from_fe(x);
        let y = rns.from_fe(y);
        let x = &ch.range(x, Range::Remainder);
        let y = &ch.range(y, Range::Remainder);
        let point = Point::new(x, y);
        self.assert_is_on_curve(&point);
        point
    }
    #[cfg(test)]
    pub fn assign_scalar(&mut self, scalar: Value<C::Scalar>) -> Witness<C::Scalar> {
        self.integer_chip.assign_native(scalar)
    }
}
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn assert_is_on_curve(
        &mut self,
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        let integer_chip = self.integer_chip();
        let y_square = &integer_chip.square(point.y());
        let x_square = &integer_chip.square(point.x());
        let x_cube = &integer_chip.mul(point.x(), x_square);
        let x_cube_b = &integer_chip.add_constant(x_cube, &Self::parameter_b());
        integer_chip.assert_equal(x_cube_b, y_square);
    }
    pub fn assert_equal(
        &mut self,
        p0: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p1: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        let ch = self.integer_chip();
        ch.assert_equal(p0.x(), p1.x());
        ch.assert_equal(p0.y(), p1.y());
    }
    pub fn select(
        &mut self,
        c: &Witness<C::Scalar>,
        p1: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let integer_chip = self.integer_chip();
        let x = &integer_chip.select(p1.x(), p2.x(), c);
        let y = &integer_chip.select(p1.y(), p2.y(), c);
        Point::new(x, y)
    }
    pub fn select_or_assign(
        &mut self,
        c: &Witness<C::Scalar>,
        p1: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: C,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let integer_chip = self.integer_chip();
        let p2 = ConstantPoint::<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(p2);
        let x = &integer_chip.select_or_assign(p1.x(), p2.x(), c);
        let y = &integer_chip.select_or_assign(p1.y(), p2.y(), c);
        Point::new(x, y)
    }
    pub fn select_multi(
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
    pub fn select_constant(
        &mut self,
        c: &Witness<C::Scalar>,
        p1: &ConstantPoint<C::Base, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: &ConstantPoint<C::Base, C::ScalarExt, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let integer_chip = self.integer_chip();
        let x = &integer_chip.select_constant(c, p1.x(), p2.x());
        let y = &integer_chip.select_constant(c, p1.y(), p2.y());
        Point::new(x, y)
    }
    pub fn select_constant_multi(
        &mut self,
        selector: &[Witness<C::Scalar>],
        table: &[ConstantPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let number_of_selectors = selector.len();
        let n = 1 << (number_of_selectors - 1);
        let mut reducer = (0..n)
            .map(|j| {
                let k = 2 * j;
                self.select_constant(&selector[0], &table[k + 1], &table[k])
            })
            .collect::<Vec<Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>();
        for (i, selector) in selector.iter().skip(1).enumerate() {
            let n = 1 << (number_of_selectors - 2 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(selector, &reducer[k + 1], &reducer[k]);
            }
        }
        reducer[0].clone()
    }
    // pub fn select_multi_constant(
    //     &mut self,
    //     selector: &[Witness<C::Scalar>],
    //     table: &[C],
    // ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
    //     let number_of_selectors = selector.len();
    //     let mut reducer = table.to_vec();
    //     for (i, selector) in selector.iter().enumerate() {
    //         let n = 1 << (number_of_selectors - 1 - i);
    //         for j in 0..n {
    //             let k = 2 * j;
    //             reducer[j] = self.select(selector, &reducer[k + 1], &reducer[k]);
    //         }
    //     }
    //     reducer[0].clone()
    // }
    fn update_table(
        &mut self,
        slice: &[Witness<C::Scalar>],
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        table: &mut [Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) {
        let slice: Vec<Scaled<C::Scalar>> = slice
            .iter()
            .enumerate()
            .map(|(i, bit)| Scaled::new(bit, C::Scalar::from(1 << i)))
            .collect();
        let index = self
            .integer_chip
            .o
            .compose(&slice[..], C::Scalar::zero(), C::Scalar::one());
        for (j, bucket) in table.iter_mut().take(1 << slice.len()).enumerate() {
            let j = self.integer_chip.get_constant(C::Scalar::from(j as u64));
            let cond = self.integer_chip.o.is_equal(&index, &j);
            *bucket = self.select(&cond, point, bucket);
        }
    }
    pub fn normalize(
        &mut self,
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let integer_chip = self.integer_chip();
        let x = &integer_chip.reduce(point.x());
        let y = &integer_chip.reduce(point.y());
        Point::new(x, y)
    }
    pub fn add(
        &mut self,
        p0: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p1: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        // guarantees that p0 != p1 or p0 != p1
        // so that we can use unsafe addition formula which assumes operands are not
        // equal addition to that we strictly disallow addition result to be
        // point of infinity
        self.integer_chip().assert_not_equal(p0.x(), p1.x());
        self._add_incomplete(p0, p1)
    }
    pub fn double(
        &mut self,
        p: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        // point must be asserted to be in curve and not infinity
        self._double_incomplete(p)
    }
    pub fn double_n(
        &mut self,
        p: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        logn: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut acc = p.clone();
        for _ in 0..logn {
            acc = self._double_incomplete(&acc);
        }
        acc
    }
    pub fn ladder(
        &mut self,
        to_double: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        to_add: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self._ladder_incomplete(to_double, to_add)
    }
    pub fn msm(
        &mut self,
        points: &[Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
        scalars: &[Witness<C::Scalar>],
        window_size: usize,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.msm_1d_horizontal(points, scalars, window_size)
    }
}
