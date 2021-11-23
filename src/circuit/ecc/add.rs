use super::super::integer::IntegerInstructions;
use super::AssignedPoint;
use super::{EccChip, GenericEccInstruction};
use crate::circuit::main_gate::MainGateInstructions;
use crate::circuit::{Assigned, AssignedCondition, AssignedInteger};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<C: CurveAffine, F: FieldExt> EccChip<C, F> {
    fn curvature(&self, region: &mut Region<'_, F>, a: &AssignedPoint<C, F>, offset: &mut usize) -> Result<(AssignedInteger<F>, AssignedCondition<F>), Error> {
        // (3 * a.x^2 + self.a) / 2 * a.y
        let xsqm = {
            let xsq = self.integer_chip.mul(region, &a.x, &a.x, offset)?;
            let xsq2 = self.integer_chip.add(region, &xsq, &xsq, offset)?;
            self.integer_chip.add(region, &xsq, &xsq2, offset)?
            //self.integer_chip.mul(region, &xsq, cst3, offset)?
        };
        let (curvature, icond) = {
            let numerator = self.integer_chip.add(region, &xsqm, &self.a, offset)?;
            let denominator = self.integer_chip.add(region, &a.y, &a.y, offset)?;
            let numerator = self.integer_chip.reduce(region, &numerator, offset)?;
            let denominator = self.integer_chip.reduce(region, &denominator, offset)?;
            self.integer_chip.div(region, &numerator, &denominator, offset)?
        };
        Ok((curvature, icond))
    }

    // When calling lambda(a,b), we assume point a anb b are on curve.
    fn lambda(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedPoint<C, F>,
        b: &AssignedPoint<C, F>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<F>, AssignedCondition<F>), Error> {
        let main_gate = self.main_gate();

        /*
         * if (x1 == x2 && y1 == y2) {
         *       curvature
         *  } else {
         *       tangent
         *  }
         */
        let (lambda_neq, lambda_neq_icond, eq_cond) = {
            let numerator = self.integer_chip.sub(region, &a.y, &b.y, offset)?;
            let denominator = self.integer_chip.sub(region, &a.x, &b.x, offset)?;
            let numerator = self.integer_chip.reduce(region, &numerator, offset)?;
            let denominator = self.integer_chip.reduce(region, &denominator, offset)?;
            let (tangent, eqx_cond) = self.integer_chip.div(region, &numerator, &denominator, offset)?;

            let (_, eqy_cond) = self.integer_chip.invert(region, &numerator, offset)?;
            let eq_cond = main_gate.cond_and(region, &eqy_cond, &eqx_cond, offset)?;
            (tangent, eqx_cond, eq_cond)
        };

        let (lambda_eq, lambda_eq_icond) = self.curvature(region, a, offset)?;

        // select according to eq_cond
        let infinity_cond = main_gate.cond_select(region, lambda_eq_icond, lambda_neq_icond, &eq_cond, offset)?;

        let lambda = self.integer_chip.cond_select(region, &lambda_eq, &lambda_neq, &eq_cond, offset)?;

        Ok((lambda, AssignedCondition::new(infinity_cond.cell(), infinity_cond.value())))
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
        a: &AssignedPoint<C, F>,
        b: &AssignedPoint<C, F>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C, F>, Error> {
        let (lambda, zero_cond) = self.lambda(region, a, b, offset)?;

        let lambda_square = self.integer_chip.mul(region, &lambda, &lambda, offset)?;

        // cx = λ^2 - a.x - b.x
        let sqsub = self.integer_chip.sub(region, &lambda_square, &a.x, offset)?;
        let sqsub = self.integer_chip.reduce(region, &sqsub, offset)?;
        let cx = self.integer_chip.sub(region, &sqsub, &b.x, offset)?;
        let cx = self.integer_chip.reduce(region, &cx, offset)?;

        // cy = λ(a.x - c.x) - a.y
        let xsub = self.integer_chip.sub(region, &a.x, &cx, offset)?;
        let xsub = self.integer_chip.reduce(region, &xsub, offset)?;
        let yi = self.integer_chip.mul(region, &lambda, &xsub, offset)?;
        let cy = self.integer_chip.sub(region, &yi, &a.y, offset)?;
        let cy = self.integer_chip.reduce(region, &cy, offset)?;
        let p = AssignedPoint::new(cx, cy, zero_cond.clone());

        /* Now combine the calculation using the following cond table
         * a.is_identity() -> b
         * b.is_identity() -> a
         * zero_cond -> self.identity()
         * otherwise -> p
         */
        let p = self.select(region, &zero_cond, &self.identity, &p, offset)?;
        let p = self.select(region, &b.is_identity(), &a, &p, offset)?;
        let p = self.select(region, &a.is_identity(), &b, &p, offset)?;

        Ok(p)
    }
}
