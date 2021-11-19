use crate::circuit::AssignedInteger;
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;

use super::{AssignedPoint, EccChip, Point};

pub trait ExternalEccInstruction<Native: CurveAffine, External: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, Native::ScalarExt>, point: Point<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, Native::ScalarExt>, point: AssignedPoint<External>, offset: &mut usize) -> Result<(), Error>;

    fn assert_equal(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p0: AssignedPoint<External>,
        p1: AssignedPoint<External>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn add(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p0: AssignedPoint<External>,
        p1: AssignedPoint<External>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error>;
    fn double(&self, region: &mut Region<'_, Native::ScalarExt>, p: AssignedPoint<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p: AssignedPoint<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error>;
    fn mul_fix(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p: Point<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error>;
}

impl<Native: CurveAffine, External: CurveAffine> ExternalEccInstruction<Native, External> for EccChip {
    fn assign_point(&self, region: &mut Region<'_, Native::ScalarExt>, point: Point<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, Native::ScalarExt>, point: AssignedPoint<External>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p0: AssignedPoint<External>,
        p1: AssignedPoint<External>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        unimplemented!();
    }

    fn add(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p0: AssignedPoint<External>,
        p1: AssignedPoint<External>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, Native::ScalarExt>, p: AssignedPoint<External>, offset: &mut usize) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p: AssignedPoint<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }

    fn mul_fix(
        &self,
        region: &mut Region<'_, Native::ScalarExt>,
        p: Point<External>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External>, Error> {
        unimplemented!();
    }
}
