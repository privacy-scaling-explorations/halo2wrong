use crate::circuit::AssignedValue;
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;

use super::{AssignedPoint, EccChip, Point, Term};

pub trait BaseFieldEccInstruction<C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Point<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error>;
    fn assert_equal(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error>;
    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;
    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn combine(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        terms: Vec<Term<C>>,
        u: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;
}

impl<C: CurveAffine> BaseFieldEccInstruction<C> for EccChip {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Point<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn combine(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        terms: Vec<Term<C>>,
        u: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }
}
