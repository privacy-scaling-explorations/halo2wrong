use crate::rns::Integer;

use super::{integer::IntegerConfig, AssignedInteger};
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Region;
use halo2::plonk::Error;

mod base_field_ecc;
mod external_ecc;

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
