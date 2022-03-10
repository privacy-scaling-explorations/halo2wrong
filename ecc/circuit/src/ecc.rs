use crate::halo2::arithmetic::CurveAffine;
use crate::integer::rns::{Integer, Rns};
use crate::integer::AssignedInteger;
use crate::maingate::{big_to_fe, halo2, Assigned, AssignedCondition, MainGateConfig, RangeConfig};
use crate::WrongExt;
use group::Curve;
use halo2::arithmetic::FieldExt;
use integer::IntegerConfig;
use num_bigint::BigUint as big_uint;
use num_traits::One;
use std::fmt;
use std::rc::Rc;

pub use base_field_ecc::*;
pub use general_ecc::*;

#[derive(Clone, Debug)]
pub struct Point<W: WrongExt, N: FieldExt> {
    x: Integer<W, N>,
    y: Integer<W, N>,
}

impl<W: WrongExt, N: FieldExt> Point<W, N> {
    fn from(rns: Rc<Rns<W, N>>, point: impl CurveAffine<Base = W>) -> Self {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();

        let x = Integer::from_fe(*coords.x(), Rc::clone(&rns));
        let y = Integer::from_fe(*coords.y(), Rc::clone(&rns));
        Point { x, y }
    }

    fn public(&self) -> Vec<N> {
        let mut public_data = Vec::new();
        public_data.extend(self.x.limbs());
        public_data.extend(self.y.limbs());
        public_data
    }
}

#[derive(Clone)]
/// point that is assumed to be on curve and not infinity
pub struct AssignedPoint<W: WrongExt, N: FieldExt> {
    x: AssignedInteger<W, N>,
    y: AssignedInteger<W, N>,
}

impl<W: WrongExt, N: FieldExt> fmt::Debug for AssignedPoint<W, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AssignedPoint")
            .field("xn", &self.x.native().value())
            .field("yn", &self.y.native().value())
            .finish()?;
        Ok(())
    }
}

impl<W: WrongExt, N: FieldExt> AssignedPoint<W, N> {
    pub fn new(x: AssignedInteger<W, N>, y: AssignedInteger<W, N>) -> AssignedPoint<W, N> {
        AssignedPoint { x, y }
    }

    pub fn get_x(&self) -> AssignedInteger<W, N> {
        self.x.clone()
    }
}

mod base_field_ecc;
pub mod general_ecc;

#[derive(Clone, Debug)]
pub struct EccConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

impl EccConfig {
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        Self {
            range_config,
            main_gate_config,
        }
    }

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
            debug
                .field("selector_index", &i)
                .field("selector", selector);
        }
        debug.finish()?;
        Ok(())
    }
}

struct Table<W: WrongExt, N: FieldExt>(Vec<AssignedPoint<W, N>>);

impl<W: FieldExt, N: FieldExt> fmt::Debug for Table<W, N> {
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

pub(super) struct MulAux<W: WrongExt, N: FieldExt> {
    to_add: AssignedPoint<W, N>,
    to_sub: AssignedPoint<W, N>,
}

impl<W: WrongExt, N: FieldExt> MulAux<W, N> {
    pub(super) fn new(to_add: AssignedPoint<W, N>, to_sub: AssignedPoint<W, N>) -> Self {
        MulAux { to_add, to_sub }
    }
}
