use crate::circuit::AssignedInteger;
use halo2::arithmetic::{FieldExt, CurveAffine};
use halo2::circuit::Region;
use halo2::plonk::Error;

use super::{AssignedPoint, EccChip, Point};

pub trait ExternalEccInstruction<External: CurveAffine, N: FieldExt> {
    fn assert_is_on_curve(
        &self,
        region: &mut Region<'_, N>,
        point: &AssignedPoint<External, N>,
        offset: &mut usize
    ) -> Result<(), Error>;

    fn double(&self, region: &mut Region<'_, N>, p: AssignedPoint<External, N>, offset: &mut usize) -> Result<AssignedPoint<External, N>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, N>,
        p: AssignedPoint<External, N>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External, N>, Error>;

    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<External, N>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External, N>, Error>;
}

impl<External: CurveAffine, N: FieldExt> ExternalEccInstruction<External, N> for EccChip<External, N> {
    fn assert_is_on_curve(&self,
        region: &mut Region<'_, N>,
        point: &AssignedPoint<External, N>,
        offset: &mut usize
    ) -> Result<(), Error> {
        unimplemented!();
    }


    fn double(&self, region: &mut Region<'_, N>, p: AssignedPoint<External, N>, offset: &mut usize) -> Result<AssignedPoint<External, N>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, N>,
        p: AssignedPoint<External, N>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External, N>, Error> {
        unimplemented!();
    }

    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<External, N>,
        e: AssignedInteger<External::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External, N>, Error> {
        unimplemented!();
    }
}
