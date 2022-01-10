use crate::circuit::ecc::general_ecc::GeneralEccChip;
use crate::circuit::ecc::{AssignedIncompletePoint, AssignedPoint};
use crate::circuit::IntegerInstructions;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::{halo2, MainGateInstructions};

use super::GeneralEccInstruction;

impl<Emulated: CurveAffine, F: FieldExt> GeneralEccChip<Emulated, F> {
    pub(crate) fn _double_incomplete(
        &self,
        region: &mut Region<'_, F>,
        point: &AssignedIncompletePoint<F>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<F>, Error> {
        let integer_chip = self.base_field_chip();

        // (3 * a.x^2 + self.a) / 2 * a.y
        let x_0_square = &integer_chip.square(region, &point.x, offset)?;

        let x_0_square = &if !self.is_a_0() {
            integer_chip.add_constant(region, &point.x, &self.parameter_a(), offset)?
        } else {
            x_0_square.clone()
        };

        let numerator = &integer_chip.mul3(region, x_0_square, offset)?;
        let denominator = &integer_chip.mul2(region, &point.y, offset)?;
        let lambda = &integer_chip.div_incomplete(region, numerator, denominator, offset)?;

        let lambda_square = &integer_chip.square(region, lambda, offset)?;
        let x = &integer_chip.sub_sub(region, lambda_square, &point.x, &point.x, offset)?;
        let t = &integer_chip.sub(region, &point.x, x, offset)?;
        let t = &integer_chip.mul(region, lambda, t, offset)?;
        let y = integer_chip.sub(region, t, &point.y, offset)?;

        Ok(AssignedIncompletePoint::new(x.clone(), y))
    }

    pub(crate) fn _double(&self, region: &mut Region<'_, F>, point: &AssignedPoint<F>, offset: &mut usize) -> Result<AssignedPoint<F>, Error> {
        let integer_chip = self.base_field_chip();

        // (3 * x^2 + a) / 2 * y
        let x_0_square = &integer_chip.square(region, &point.x, offset)?;
        let x_0_square = &integer_chip.mul3(region, x_0_square, offset)?;

        let numerator = &if !self.is_a_0() {
            integer_chip.add_constant(region, &point.x, &self.parameter_a(), offset)?
        } else {
            x_0_square.clone()
        };
        let denominator = &integer_chip.mul2(region, &point.y, offset)?;
        let (lambda, _) = &integer_chip.div(region, numerator, denominator, offset)?;

        let lambda_square = &integer_chip.square(region, lambda, offset)?;
        let x = &integer_chip.sub_sub(region, lambda_square, &point.x, &point.x, offset)?;
        let t = &integer_chip.sub(region, &point.x, x, offset)?;
        let t = &integer_chip.mul(region, lambda, t, offset)?;
        let y = integer_chip.sub(region, t, &point.y, offset)?;

        let p = AssignedIncompletePoint::new(x.clone(), y);
        let cond = &self.main_gate().cond_not(region, &point.is_identity(), offset)?;
        let p = self.select_or_assign_incomplete(region, cond, &p, Emulated::identity(), offset)?;

        Ok(AssignedPoint::from_impcomplete(&p, &point.is_identity()))
    }
}
