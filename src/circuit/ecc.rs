use super::integer::IntegerConfig;
use crate::circuit::AssignedInteger;
use crate::rns::Integer;
use halo2::arithmetic::FieldExt;
use halo2arith::main_gate::five::main_gate::MainGateConfig;
use halo2arith::main_gate::five::range::RangeConfig;
use halo2arith::{halo2, AssignedCondition};

/* Shared structure of curve affine points */

#[derive(Clone)]
pub struct IncompletePoint<'a, W: FieldExt, N: FieldExt> {
    x: Integer<'a, W, N>,
    y: Integer<'a, W, N>,
}

#[derive(Clone)]
pub struct Point<'a, W: FieldExt, N: FieldExt> {
    x: Integer<'a, W, N>,
    y: Integer<'a, W, N>,
    is_identity: bool,
}

#[derive(Clone, Debug)]
pub struct AssignedPoint<N: FieldExt> {
    x: AssignedInteger<N>,
    y: AssignedInteger<N>,
    // indicate whether the poinit is the identity point of curve or not
    z: AssignedCondition<N>,
}

impl<N: FieldExt> AssignedPoint<N> {
    fn from_impcomplete(point: &AssignedIncompletePoint<N>, flag: &AssignedCondition<N>) -> Self {
        Self {
            x: point.x.clone(),
            y: point.y.clone(),
            z: flag.clone(),
        }
    }
}

#[derive(Clone, Debug)]
/// point that is assumed to be on curve and not infinity
pub struct AssignedIncompletePoint<N: FieldExt> {
    x: AssignedInteger<N>,
    y: AssignedInteger<N>,
}

impl<N: FieldExt> From<&AssignedPoint<N>> for AssignedIncompletePoint<N> {
    fn from(point: &AssignedPoint<N>) -> Self {
        AssignedIncompletePoint {
            x: point.x.clone(),
            y: point.y.clone(),
        }
    }
}

impl<F: FieldExt> AssignedPoint<F> {
    pub fn new(x: AssignedInteger<F>, y: AssignedInteger<F>, z: AssignedCondition<F>) -> AssignedPoint<F> {
        AssignedPoint { x, y, z }
    }

    pub fn is_identity(&self) -> AssignedCondition<F> {
        self.z.clone()
    }
}

impl<F: FieldExt> AssignedIncompletePoint<F> {
    pub fn new(x: AssignedInteger<F>, y: AssignedInteger<F>) -> AssignedIncompletePoint<F> {
        AssignedIncompletePoint { x, y }
    }
}

mod base_field_ecc;
mod general_ecc;

#[derive(Clone, Debug)]
pub struct EccConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

impl EccConfig {
    fn integer_chip_config(&self) -> IntegerConfig {
        IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }
}
