use super::EccChip;
use super::{AssignedPoint};
use super::super::integer::{IntegerConfig, IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{MainGateConfig, MainGateInstructions};
use crate::circuit::{AssignedInteger, AssignedLimb, AssignedCondition};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;


impl<C: CurveAffine, F: FieldExt> EccChip<C, F> {
    fn curvature(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedPoint<C,F>,
        offset: &mut usize
    ) -> Result <AssignedInteger<F>, Error> {
        // (3 * a.x^2 + self.a) / 2 * a.y
        let xsqm = {
            let xsq = self.integer_chip.mul(region, &a.x, &a.x, offset)?;
            let xsq2 = self.integer_chip.add(region, &xsq, &xsq, offset)?;
            self.integer_chip.add(region, &xsq, &xsq2, offset)?
            //self.integer_chip.mul(region, &xsq, cst3, offset)?
        };
        let curvature = {
            let numerator = self.integer_chip.add(region, &xsqm, &self.a, offset)?;
            let denominator = self.integer_chip.add(region, &a.y, &a.y, offset)?;
            let (lambda, _) = self.integer_chip.div(region,
                &numerator,
                &denominator,
                offset
            )?;
            lambda
        };
        Ok(curvature)
    }

    // When calling lambda(a,b), we assume point a anb b are on curve.
    fn lambda(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedPoint<C,F>,
        b: &AssignedPoint<C,F>,
        offset: &mut usize
    ) -> Result<(AssignedInteger<F>, AssignedCondition<F>), Error> {
        let main_gate = self.main_gate();

        /* There are three cases:
         * a.y - b.y = 0 --> means the we need curvature
         * a.y + b.y = 0 || a.y - b.y = 0 && b.y = 0 --> means infinity
         * otherwise --> a.x != b.x --> normal tangent
         */
        let numerator = self.integer_chip.sub(region, &a.y, &b.y, offset)?;
        let (_, eqy_cond) = self.integer_chip.invert(region, &numerator, offset)?;
        let (_, y_is_zero) = self.integer_chip.invert(region, &a.y, offset)?;

        let (lambda_neq, eqx_cond) = {
            let denominator = self.integer_chip.sub(region, &a.x, &b.x, offset)?;
            self.integer_chip.div(region, &numerator, &denominator, offset)?
        };

        // eqx_cond == 1 and (y_is_zero || not_eqy_cond) implies infinity
        let not_eqy_cond = main_gate.cond_not(region, &eqy_cond, offset)?;
        let icond = main_gate.cond_and(
            region,
            &y_is_zero,
            &not_eqy_cond,
            offset,
        )?;
        let infinity_cond = main_gate.cond_and(
            region,
            &icond,
            &eqx_cond,
            offset,
        )?;

        // When eqx_cond == 1, we calculated the tangent curvature
        let lambda_eq = self.curvature(region, a, offset)?;

        let lambda = self.integer_chip.cond_select(region, &lambda_neq, &lambda_eq, &eqx_cond, offset)?;

        Ok((lambda, infinity_cond))
    }

    /* We use affine coordinates since invert cost almost the same as mul in
     * halo circuts gates while projective coordinates involves more multiplication
     * than affine coordinates.
     * Thus coordinate z in point is used as an indicator of whether the point is
     * identity(infinity) or not.
     */
    pub(crate) fn _add(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedPoint<C,F>,
        b: &AssignedPoint<C,F>,
        offset: &mut usize
    ) -> Result<AssignedPoint<C,F>, Error> {
        let main_gate = self.main_gate();

        let (lambda, zero_cond) = self.lambda(region, a, b, offset)?;
        let lambda_square = self.integer_chip._square(region, &lambda, offset)?;

        // cx = λ^2 - a.x - b.x
        let sqsub = self.integer_chip._sub(region, &lambda_square, &a.x, offset)?;
        let cx = self.integer_chip._sub(
            region,
            &sqsub,
            &b.x,
            offset
        )?;

        // cy = λ(a.x - c.x) - a.y
        let xsub = self.integer_chip._sub(region, &a.x, &cx, offset)?;
        let yi = self.integer_chip._mul(
            region,
            &lambda,
            &xsub,
            offset,
        )?;
        let cy = self.integer_chip._sub(region, &yi, &a.y, offset)?;
        let cx_sel = self.integer_chip.cond_select(region,
            &b.x,
            &cx,
            &a.is_identity(),
            offset
        )?;
        let p = AssignedPoint::new(cx, cy, zero_cond);

        /* Now combine the calculation using the following cond table
         * a.is_identity() -> b
         * b.is_identity() -> a
         * zero_cond -> self.identity()
         * otherwise -> p
         */

        let id_sel = main_gate.cond_or(
            region,
            &a.is_identity(),
            &b.is_identity(),
            offset
        )?;

        Ok(p)
    }
}
