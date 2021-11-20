use crate::circuit::AssignedInteger;
use halo2::arithmetic::{FieldExt, CurveAffine};
use halo2::circuit::Region;
use halo2::plonk::Error;

use super::{AssignedPoint, EccChip, Point};

pub trait ExternalEccInstruction<External: CurveAffine, Native: FieldExt> {
    fn assign_point(&self, region: &mut Region<'_, Native>, point: Point<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, Native>, point: AssignedPoint<External>, offset: &mut usize) -> Result<(), Error>;

    fn assert_equal(
        &self,
        region: &mut Region<'_, Native>,
        p0: AssignedPoint<External, Native>,
        p1: AssignedPoint<External, Native>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn add(
        &self,
        region: &mut Region<'_, Native>,
        p0: AssignedPoint<External>,
        p1: AssignedPoint<External>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error>;
    fn double(&self, region: &mut Region<'_, Native>, p: AssignedPoint<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, Native>,
        p: AssignedPoint<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error>;
    fn mul_fix(
        &self,
        region: &mut Region<'_, Native>,
        p: Point<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error>;
}

impl<External: CurveAffine, Native: FieldExt> ExternalEccInstruction<External, Native> for EccChip {
    fn assign_point(&self, region: &mut Region<'_, Native>, point: Point<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error> {
        let x = self.integer_chip.assign_integer(region, Some(point.x.clone()), offset)?.clone();
        let y = self.integer_chip.assign_integer(region, Some(point.y.clone()), offset)?.clone();
        let z = self.integer_gate().assign_bit(region, Some(F::zero()), offset)?.clone();
        Ok(AssignedPoint::new(x,y,z))
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, Native>, point: AssignedPoint<External>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, Native>,
        p0: AssignedPoint<External>,
        p1: AssignedPoint<External>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        unimplemented!();
    }

    fn add(
        &self,
        region: &mut Region<'_, Native>,
        p0: AssignedPoint<External>,
        p1: AssignedPoint<External>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, Native>, p: AssignedPoint<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, Native>,
        p: AssignedPoint<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }

    fn mul_fix(
        &self,
        region: &mut Region<'_, Native>,
        p: Point<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }
}


