use super::AssignedPoint;
use super::GeneralEccChip;
use crate::halo2;
use crate::integer::IntegerInstructions;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::plonk::Error;
use integer::maingate::RegionCtx;

impl<Emulated: CurveAffine, F: FieldExt> GeneralEccChip<Emulated, F> {
    pub(crate) fn _add_incomplete_unsafe(&self, ctx: &mut RegionCtx<'_, '_, F>, a: &AssignedPoint<F>, b: &AssignedPoint<F>) -> Result<AssignedPoint<F>, Error> {
        let ch = self.base_field_chip();

        // lambda = b_y - a_y / b_x - a_x
        let numerator = &ch.sub(ctx, &b.y, &a.y)?;
        let denominator = &ch.sub(ctx, &b.x, &a.x)?;
        let lambda = &ch.div_incomplete(ctx, numerator, denominator)?;

        // c_x =  lambda * lambda - a_x - b_x
        let lambda_square = &ch.square(ctx, lambda)?;
        let x = &ch.sub_sub(ctx, lambda_square, &a.x, &b.x)?;

        // c_y = lambda * (a_x - c_x) - a_y
        let t = &ch.sub(ctx, &a.x, x)?;
        let t = &ch.mul(ctx, t, lambda)?;
        let y = ch.sub(ctx, t, &a.y)?;

        let p_0 = AssignedPoint::new(x.clone(), y);

        Ok(p_0)
    }

    pub(crate) fn _double_incomplete(&self, ctx: &mut RegionCtx<'_, '_, F>, point: &AssignedPoint<F>) -> Result<AssignedPoint<F>, Error> {
        let ch = self.base_field_chip();

        // lambda = (3 * a_x^2) / 2 * a_y
        let x_0_square = &ch.square(ctx, &point.x)?;
        let numerator = &ch.mul3(ctx, x_0_square)?;
        let denominator = &ch.mul2(ctx, &point.y)?;
        let lambda = &ch.div_incomplete(ctx, numerator, denominator)?;

        // c_x = lambda * lambda - 2 * a_x
        let lambda_square = &ch.square(ctx, lambda)?;
        let x = &ch.sub_sub(ctx, lambda_square, &point.x, &point.x)?;

        // c_y = lambda * (a_x - c_x) - a_y
        let t = &ch.sub(ctx, &point.x, x)?;
        let t = &ch.mul(ctx, lambda, t)?;
        let y = ch.sub(ctx, t, &point.y)?;

        Ok(AssignedPoint::new(x.clone(), y))
    }

    pub(crate) fn _ladder_incomplete(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        to_double: &AssignedPoint<F>,
        to_add: &AssignedPoint<F>,
    ) -> Result<AssignedPoint<F>, Error> {
        let ch = self.base_field_chip();

        // (P + Q) + P
        // P is to_double (x_1, y_1)
        // Q is to_add (x_2, y_2)

        // lambda_0 = (y_2 - y_1) / (x_2 - x_1)
        let numerator = &ch.sub(ctx, &to_add.y, &to_double.y)?;
        let denominator = &ch.sub(ctx, &to_add.x, &to_double.x)?;
        let lambda_0 = &ch.div_incomplete(ctx, numerator, denominator)?;

        // x_3 = lambda_0 * lambda_0 - x_1 - x_2
        let lambda_0_square = &ch.square(ctx, lambda_0)?;
        let x_3 = &ch.sub_sub(ctx, lambda_0_square, &to_add.x, &to_double.x)?;

        // lambda_1 = lambda_0 + 2 * y_1 / (x_3 - x_1)
        let numerator = &ch.mul2(ctx, &to_double.y)?;
        let denominator = &ch.sub(ctx, x_3, &to_double.x)?;
        let lambda_1 = &ch.div_incomplete(ctx, numerator, denominator)?;
        let lambda_1 = &ch.add(ctx, lambda_0, lambda_1)?;

        // x_4 = lambda_1 * lambda_1 - x_1 - x_3
        let lambda_1_square = &ch.square(ctx, lambda_1)?;
        let x_4 = &ch.sub_sub(ctx, lambda_1_square, x_3, &to_double.x)?;

        // y_4 = lambda_1 * (x_4 - x_1) - y_1
        let t = &ch.sub(ctx, x_4, &to_double.x)?;
        let t = &ch.mul(ctx, t, lambda_1)?;
        let y_4 = ch.sub(ctx, t, &to_double.y)?;

        let p_0 = AssignedPoint::new(x_4.clone(), y_4);

        Ok(p_0)
    }
}
