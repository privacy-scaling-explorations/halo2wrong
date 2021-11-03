use crate::rns::Integer;

use super::{integer::IntegerConfig, AssignedInteger};
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;

pub struct Point<C: CurveAffine> {
    x: Integer<C::ScalarExt>,
    y: Integer<C::ScalarExt>,
}

impl<C: CurveAffine> Point<C> {
    fn new(x: Integer<C::ScalarExt>, y: Integer<C::ScalarExt>) -> Self {
        Point { x, y }
    }
}

pub struct AssignedPoint<C: CurveAffine> {
    x: AssignedInteger<C::ScalarExt>,
    y: AssignedInteger<C::ScalarExt>,
}

/// Linear combination term
pub enum Term<C: CurveAffine> {
    Assigned(AssignedPoint<C>, C::ScalarExt),
    Unassigned(Option<Point<C>>, C::ScalarExt),
}

#[derive(Clone, Debug)]
pub struct EccConfig {
    integer_chip_config: IntegerConfig,
}

pub struct EccChip {
    config: IntegerConfig,
}

pub trait EccInstruction<C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Point<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error>;
    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: AssignedPoint<C>,
        p1: AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;
    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn mul_var(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, e: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn combine(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, u: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
}

impl<C: CurveAffine> EccInstruction<C> for EccChip {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Point<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: AssignedPoint<C>,
        p1: AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_var(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, e: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn combine(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, u: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }
}
