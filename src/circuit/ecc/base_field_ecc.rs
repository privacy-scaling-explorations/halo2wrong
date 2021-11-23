use crate::circuit::AssignedValue;
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;

use super::{AssignedPoint, EccChip, Point, Term};

pub trait BaseFieldEccInstruction<C: CurveAffine> {
    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint <C, C::ScalarExt>, offset: &mut usize) -> Result<(), Error>;
    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint <C, C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint <C, C::ScalarExt>, Error>;
    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint <C, C::ScalarExt>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint <C, C::ScalarExt>, Error>;
    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint <C, C::ScalarExt>, Error>;
    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C, C::ScalarExt>>, offset: &mut usize) -> Result<AssignedPoint <C, C::ScalarExt>, Error>;
    fn combine(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        terms: Vec<Term<C, C::ScalarExt>>,
        u: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint <C, C::ScalarExt>, Error>;
}

impl<C: CurveAffine> BaseFieldEccInstruction<C> for EccChip<C, C::ScalarExt> {

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint <C, C::ScalarExt>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint <C, C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint <C, C::ScalarExt>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint <C, C::ScalarExt>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint <C, C::ScalarExt>, Error> {
        unimplemented!();
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint <C, C::ScalarExt>, Error> {
        unimplemented!();
    }

    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C, C::ScalarExt>>, offset: &mut usize) -> Result<AssignedPoint <C, C::ScalarExt>, Error> {
        unimplemented!();
    }

    fn combine(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        terms: Vec<Term<C, C::ScalarExt>>,
        u: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint <C, C::ScalarExt>, Error> {
        unimplemented!();
    }
}
