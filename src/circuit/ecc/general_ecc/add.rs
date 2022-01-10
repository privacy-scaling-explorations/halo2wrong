use super::AssignedPoint;
use crate::circuit::ecc::general_ecc::{GeneralEccChip, GeneralEccInstruction};
use crate::circuit::ecc::AssignedIncompletePoint;
use crate::circuit::AssignedInteger;
use crate::circuit::IntegerInstructions;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::{halo2, AssignedCondition, MainGateInstructions};

impl<Emulated: CurveAffine, F: FieldExt> GeneralEccChip<Emulated, F> {
    fn curvature(&self, region: &mut Region<'_, F>, a: &AssignedPoint<F>, offset: &mut usize) -> Result<(AssignedInteger<F>, AssignedCondition<F>), Error> {
        let base_chip = self.base_field_chip();
        // (3 * a.x^2 + self.a) / 2 * a.y
        let xsqm = {
            let xsq = base_chip.mul(region, &a.x, &a.x, offset)?;
            let xsq2 = base_chip.add(region, &xsq, &xsq, offset)?;
            base_chip.add(region, &xsq, &xsq2, offset)?
            //base_chip.mul(region, &xsq, cst3, offset)?
        };
        let (curvature, icond) = {
            let numerator = base_chip.add_constant(region, &xsqm, &self.parameter_a(), offset)?;
            let denominator = base_chip.add(region, &a.y, &a.y, offset)?;
            base_chip.div(region, &numerator, &denominator, offset)?
        };
        Ok((curvature, icond))
    }

    // When calling lambda(a,b), we assume point a anb b are on curve.
    fn lambda(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedPoint<F>,
        b: &AssignedPoint<F>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<F>, AssignedCondition<F>), Error> {
        let main_gate = self.main_gate();
        let base_chip = self.base_field_chip();

        /*
         * if (x1 == x2 && y1 == y2) {
         *       curvature
         *  } else {
         *       tangent
         *  }
         */
        let (lambda_neq, lambda_neq_icond, eq_cond) = {
            let numerator = base_chip.sub(region, &a.y, &b.y, offset)?;
            let denominator = base_chip.sub(region, &a.x, &b.x, offset)?;
            let (tangent, eqx_cond) = base_chip.div(region, &numerator, &denominator, offset)?;

            let (_, eqy_cond) = base_chip.invert(region, &numerator, offset)?;
            let eq_cond = main_gate.cond_and(region, &eqy_cond, &eqx_cond, offset)?;
            (tangent, eqx_cond, eq_cond)
        };

        let (lambda_eq, lambda_eq_icond) = self.curvature(region, a, offset)?;

        // select according to eq_cond
        let infinity_cond = main_gate.cond_select(region, lambda_eq_icond, lambda_neq_icond, &eq_cond, offset)?;

        let lambda = base_chip.cond_select(region, &lambda_eq, &lambda_neq, &eq_cond, offset)?;

        Ok((lambda, infinity_cond.into()))
    }

    /* We use affine coordinates since invert cost almost the same as mul in
     * halo circuts gates while projective coordinates involves more multiplication
     * than affine coordinates.
     * Thus coordinate z in point is used as an indicator of whether the point is
     * identity(infinity) or not.
     */
    pub(super) fn _add(&self, region: &mut Region<'_, F>, a: &AssignedPoint<F>, b: &AssignedPoint<F>, offset: &mut usize) -> Result<AssignedPoint<F>, Error> {
        let main_gate = self.main_gate();
        let base_chip = self.base_field_chip();

        let (lambda, zero_cond) = self.lambda(region, a, b, offset)?;
        let lambda_square = base_chip.mul(region, &lambda, &lambda, offset)?;

        // cx = λ^2 - a.x - b.x
        let sqsub = base_chip.sub(region, &lambda_square, &a.x, offset)?;
        let cx = base_chip.sub(region, &sqsub, &b.x, offset)?;

        // cy = λ(a.x - c.x) - a.y
        let xsub = base_chip.sub(region, &a.x, &cx, offset)?;
        let yi = base_chip.mul(region, &lambda, &xsub, offset)?;
        let cy = base_chip.sub(region, &yi, &a.y, offset)?;
        let p = AssignedPoint::new(cx, cy, zero_cond.clone());

        /* Now combine the calculation using the following cond table
         * a.is_identity() -> b
         * b.is_identity() -> a
         * zero_cond -> self.identity()
         * otherwise -> p
         */
        let nzero = main_gate.cond_not(region, &zero_cond, offset)?;
        let p = self.select_or_assign(region, &nzero, &p, Emulated::identity(), offset)?;
        let p = self.select(region, &b.is_identity(), &a, &p, offset)?;
        let p = self.select(region, &a.is_identity(), &b, &p, offset)?;

        Ok(p)
    }

    pub(crate) fn _add_incomplete_unsafe(
        &self,
        region: &mut Region<'_, F>,
        a: &AssignedIncompletePoint<F>,
        b: &AssignedIncompletePoint<F>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<F>, Error> {
        let integer_chip = self.base_field_chip();

        let numerator = &integer_chip.sub(region, &b.y, &a.y, offset)?;
        let denominator = &integer_chip.sub(region, &b.x, &a.x, offset)?;
        let lambda = &integer_chip.div_incomplete(region, numerator, denominator, offset)?;

        let lambda_square = &integer_chip.square(region, lambda, offset)?;
        let x = &integer_chip.sub_sub(region, lambda_square, &a.x, &b.x, offset)?;

        let t = &integer_chip.sub(region, &a.x, x, offset)?;
        let t = &integer_chip.mul(region, t, lambda, offset)?;
        let y = integer_chip.sub(region, t, &a.y, offset)?;
        let p_0 = AssignedIncompletePoint::new(x.clone(), y);

        // should this function make safe but still incomplete
        // let t = &integer_chip.sub(region, &b.x, x, offset)?;
        // let t = &integer_chip.mul(region, t, lambda, offset)?;
        // let _y = integer_chip.sub(region, t, &b.y, offset)?;
        // let p_1 = AssignedIncompletePoint::new(x.clone(), _y);
        // self.assert_equal_incomplete(region, &p_0, &p_1, offset)?;

        Ok(p_0)
    }
}
