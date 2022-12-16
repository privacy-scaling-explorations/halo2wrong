use super::BaseFieldEccChip;
use crate::ecc::Point;
use halo2::halo2curves::CurveAffine;

impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn _add_incomplete(
        &mut self,
        a: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let ch = self.integer_chip();
        // lambda = b_y - a_y / b_x - a_x
        let numerator = &ch.sub(&b.y, &a.y);
        let denominator = &ch.sub(&b.x, &a.x);
        let lambda = &ch.div_incomplete(numerator, denominator);
        // c_x =  lambda * lambda - a_x - b_x
        let lambda_square = &ch.square(lambda);
        let t = &ch.add(&a.x, &b.x);
        let x = &ch.sub(lambda_square, t);
        // c_y = lambda * (a_x - c_x) - a_y
        let t = &ch.sub(&a.x, x);
        let t = &ch.mul(t, lambda);
        let y = &ch.sub(t, &a.y);
        Point::new(x, y)
    }

    pub(crate) fn _double_incomplete(
        &mut self,
        point: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let ch = self.integer_chip();
        // lambda = (3 * a_x^2) / 2 * a_y
        let x_0_square = &ch.square(&point.x);
        let numerator = &ch.mul3(x_0_square);
        let denominator = &ch.mul2(&point.y);
        let lambda = &ch.div_incomplete(numerator, denominator);
        // c_x = lambda * lambda - 2 * a_x
        let lambda_square = &ch.square(lambda);
        let xx = &ch.mul2(&point.x);
        let x = &ch.sub(lambda_square, xx);
        // c_y = lambda * (a_x - c_x) - a_y
        let t = &ch.sub(&point.x, x);
        let t = &ch.mul(lambda, t);
        let y = &ch.sub(t, &point.y);
        Point::new(x, y)
    }

    pub(crate) fn _ladder_incomplete(
        &mut self,
        to_double: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        to_add: &Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let ch = self.integer_chip();
        // (P + Q) + P
        // P is to_double (x_1, y_1)
        // Q is to_add (x_2, y_2)
        // lambda_0 = (y_2 - y_1) / (x_2 - x_1)
        let numerator = &ch.sub(&to_add.y, &to_double.y);
        let denominator = &ch.sub(&to_add.x, &to_double.x);
        let lambda_0 = &ch.div_incomplete(numerator, denominator);
        // x_3 = lambda_0 * lambda_0 - x_1 - x_2
        let lambda_0_square = &ch.square(lambda_0);
        let t = &ch.add(&to_add.x, &to_double.x);
        let x_3 = &ch.sub(lambda_0_square, t);
        // lambda_1 = lambda_0 + 2 * y_1 / (x_3 - x_1)
        let numerator = &ch.mul2(&to_double.y);
        let denominator = &ch.sub(x_3, &to_double.x);
        let lambda_1 = &ch.div_incomplete(numerator, denominator);
        let lambda_1 = &ch.add(lambda_0, lambda_1);
        // x_4 = lambda_1 * lambda_1 - x_1 - x_3
        let lambda_1_square = &ch.square(lambda_1);
        let t = &ch.add(x_3, &to_double.x);
        let x_4 = &ch.sub(lambda_1_square, t);
        // y_4 = lambda_1 * (x_4 - x_1) - y_1
        let t = &ch.sub(x_4, &to_double.x);
        let t = &ch.mul(t, lambda_1);
        let y_4 = &ch.sub(t, &to_double.y);
        Point::new(x_4, y_4)
    }
}
