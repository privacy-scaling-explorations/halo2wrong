use super::integer::IntegerConfig;
use crate::circuit::AssignedInteger;
use crate::rns::{Integer, Rns};
use crate::WrongExt;
use group::Curve;
use halo2::arithmetic::FieldExt;
use halo2arith::halo2::arithmetic::CurveAffine;
use halo2arith::main_gate::five::main_gate::MainGateConfig;
use halo2arith::main_gate::five::range::RangeConfig;
use halo2arith::{big_to_fe, halo2, Assigned, AssignedCondition};
use num_bigint::BigUint as big_uint;
use num_traits::One;
use std::fmt;

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

    pub fn get_x(&self) -> AssignedInteger<N> {
        self.x.clone()
    }
}

#[derive(Clone)]
/// point that is assumed to be on curve and not infinity
pub struct AssignedPoint<N: FieldExt> {
    x: AssignedInteger<N>,
    y: AssignedInteger<N>,
}

impl<F: FieldExt> fmt::Debug for AssignedPoint<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AssignedPoint")
            .field("xn", &self.x.native().value())
            .field("yn", &self.y.native().value())
            .finish()?;
        Ok(())
    }
}

impl<F: FieldExt> AssignedPoint<F> {
    pub fn new(x: AssignedInteger<F>, y: AssignedInteger<F>) -> AssignedPoint<F> {
        AssignedPoint { x, y }
    }
}

mod base_field_ecc;
pub mod general_ecc;

#[derive(Clone, Debug)]
pub struct EccConfig {
    pub range_config: RangeConfig,
    pub main_gate_config: MainGateConfig,
}

impl EccConfig {
    fn integer_chip_config(&self) -> IntegerConfig {
        IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }
}

fn make_mul_aux<C: CurveAffine>(aux_to_add: C, window_size: usize, number_of_pairs: usize) -> C {
    assert!(window_size > 0);
    assert!(number_of_pairs > 0);
    use group::ff::PrimeField;

    let n = C::Scalar::NUM_BITS as usize;
    // let n = 256;
    let mut number_of_selectors = n / window_size;
    if n % window_size != 0 {
        number_of_selectors += 1;
    }
    let mut k0 = big_uint::one();
    let one = big_uint::one();
    for i in 0..number_of_selectors {
        k0 |= &one << (i * window_size);
    }
    let k1 = (one << number_of_pairs) - 1usize;
    let k = k0 * k1;
    (-aux_to_add * big_to_fe::<C::Scalar>(k)).to_affine()
}

#[derive(Default)]
struct Selector<F: FieldExt>(Vec<AssignedCondition<F>>);

impl<F: FieldExt> fmt::Debug for Selector<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Selector");
        for (i, bit) in self.0.iter().enumerate() {
            debug.field("window_index", &i).field("bit", bit);
        }
        debug.finish()?;
        Ok(())
    }
}

struct Windowed<F: FieldExt>(Vec<Selector<F>>);

impl<F: FieldExt> fmt::Debug for Windowed<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Window");
        for (i, selector) in self.0.iter().enumerate() {
            debug.field("selector_index", &i).field("selector", selector);
        }
        debug.finish()?;
        Ok(())
    }
}

struct Table<F: FieldExt>(Vec<AssignedPoint<F>>);

impl<F: FieldExt> fmt::Debug for Table<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Table");
        for (i, entry) in self.0.iter().enumerate() {
            debug
                .field("entry_index", &i)
                .field("xn", &entry.x.native().value())
                .field("yn", &entry.y.native().value());
        }
        debug.finish()?;
        Ok(())
    }
}

pub(super) struct MulAux<F: FieldExt> {
    to_add: AssignedPoint<F>,
    to_sub: AssignedPoint<F>,
}

impl<F: FieldExt> MulAux<F> {
    pub(super) fn new(to_add: AssignedPoint<F>, to_sub: AssignedPoint<F>) -> Self {
        MulAux { to_add, to_sub }
    }
}
