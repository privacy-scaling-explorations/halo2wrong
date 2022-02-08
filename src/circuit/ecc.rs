use super::integer::IntegerConfig;
use crate::circuit::AssignedInteger;
use crate::rns::{Integer, Rns};
use crate::WrongExt;
use halo2::arithmetic::FieldExt;
use halo2arith::halo2;
use halo2arith::halo2::arithmetic::CurveAffine;
use halo2arith::main_gate::five::main_gate::MainGateConfig;
use halo2arith::main_gate::five::range::RangeConfig;

#[derive(Clone, Debug)]
pub struct Point<'a, W: WrongExt, N: FieldExt> {
    x: Integer<'a, W, N>,
    y: Integer<'a, W, N>,
}

impl<'a, W: WrongExt, N: FieldExt> Point<'a, W, N> {
    fn from(rns: &'a Rns<W, N>, point: impl CurveAffine<Base = W>) -> Self {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();

        let x = rns.new(*coords.x());
        let y = rns.new(*coords.y());
        Point { x, y }
    }

    fn public(&self) -> Vec<N> {
        let mut public_data = Vec::new();
        public_data.extend(self.x.limbs());
        public_data.extend(self.y.limbs());
        public_data
    }
}

#[derive(Clone, Debug)]
/// point that is assumed to be on curve and not infinity
pub struct AssignedPoint<N: FieldExt> {
    x: AssignedInteger<N>,
    y: AssignedInteger<N>,
}

impl<F: FieldExt> AssignedPoint<F> {
    pub fn new(x: AssignedInteger<F>, y: AssignedInteger<F>) -> AssignedPoint<F> {
        AssignedPoint { x, y }
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
