use crate::halo2::arithmetic::{CurveAffine, PrimeField};
use crate::integer::chip::IntegerConfig;
use crate::integer::rns::{Integer, Rns};
use crate::integer::AssignedInteger;
use crate::maingate::{big_to_fe, Assigned, AssignedCondition, MainGateConfig, RangeConfig};
use crate::PrimeField;
use group::Curve;
use num_bigint::BigUint as big_uint;
use num_traits::One;
use std::fmt;
use std::rc::Rc;

/// Represent a Point in affine coordinates
#[derive(Clone, Debug)]
pub struct Point<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
{
    x: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    y: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Returns `Point` form a point in a EC with W as its base field
    /// Infinity point is not allowed
    pub(crate) fn new(
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
        point: impl CurveAffine<Base = W>,
    ) -> Self {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();

        let x = Integer::from_fe(*coords.x(), Rc::clone(&rns));
        let y = Integer::from_fe(*coords.y(), Rc::clone(&rns));
        Point { x, y }
    }

    /// Returns $x$ and $y$ coordinates limbs as native field elements
    pub(crate) fn public(&self) -> Vec<N> {
        let mut public_data = Vec::new();
        public_data.extend(self.x.limbs());
        public_data.extend(self.y.limbs());
        public_data
    }

    /// Returns $x$ coordinate
    pub fn x(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.x.clone()
    }

    /// Returns $y$ coordinate
    pub fn y(&self) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.y.clone()
    }
}

#[derive(Clone)]
/// point that is assumed to be on curve and not infinity
pub struct AssignedPoint<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub(crate) x: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub(crate) y: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> fmt::Debug
    for AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AssignedPoint")
            .field("xn", &self.x.native().value())
            .field("yn", &self.y.native().value())
            .finish()?;
        Ok(())
    }
}

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Returns a new `AssignedPoint` given its coordinates as `AssignedInteger`
    /// Does not check for validity (the point is in a specific curve)
    pub fn new(
        x: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        y: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        AssignedPoint { x, y }
    }

    /// Returns $x$ coordinate
    pub fn x(&self) -> AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.x.clone()
    }

    /// Returns $y$ coordinate
    pub fn y(&self) -> AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.y.clone()
    }
}

/// Config for Ecc Chip
#[derive(Clone, Debug)]
pub struct EccConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

impl EccConfig {
    /// Returns new `EccConfig` given `RangeConfig` and `MainGateConfig`
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        Self {
            range_config,
            main_gate_config,
        }
    }

    /// Returns new `IntegerConfig` with matching `RangeConfig` and
    /// `MainGateConfig`
    pub(crate) fn integer_chip_config(&self) -> IntegerConfig {
        IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    /// Returns new `MainGateConfig`
    pub(crate) fn main_gate_config(&self) -> MainGateConfig {
        self.main_gate_config.clone()
    }
}

/// Finds a point we need to subtract from the end result in the efficient batch
/// multiplication algorithm.
///
/// Computes AuxFin from AuxInit for batch multiplication
/// see https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg?view
pub(crate) fn make_mul_aux<C: CurveAffine>(
    aux_to_add: C,
    window_size: usize,
    number_of_pairs: usize,
) -> C {
    assert!(window_size > 0);
    assert!(number_of_pairs > 0);
    use group::ff::PrimeField;

    let n = C::Scalar::NUM_BITS as usize;
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
    // k = k0* 2^n_pairs
    let k = k0 * k1;
    (-aux_to_add * big_to_fe::<C::Scalar>(k)).to_affine()
}

/// Vector of `AssignedCondition` which is the binary representation of a
/// scalar.
///
/// Allows to select values of precomputed table in efficient multiplication
/// algorithm
#[derive(Default)]
pub(crate) struct Selector<F: PrimeField>(Vec<AssignedCondition<F>>);

impl<F: PrimeField> fmt::Debug for Selector<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Selector");
        for (i, bit) in self.0.iter().enumerate() {
            debug.field("window_index", &i).field("bit", bit);
        }
        debug.finish()?;
        Ok(())
    }
}

/// Vector of `Selectors` which represent the binary representation of a scalar
/// split in window sized selectors.
pub(crate) struct Windowed<F: PrimeField>(Vec<Selector<F>>);

impl<F: PrimeField> fmt::Debug for Windowed<F> {
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

/// Table of precomputed values for efficient multiplication algorithm.
pub(crate) struct Table<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(pub(crate) Vec<AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>);

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> fmt::Debug
    for Table<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
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

/// Auxiliary points for efficient multiplication algorithm
/// See: https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg
pub(super) struct MulAux<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    to_add: AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    to_sub: AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

/// Constructs `MulAux`
impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    MulAux<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn new(
        to_add: AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        to_sub: AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Self {
        // TODO Should we ensure that these 2 point are coherent:
        // to_sub = (to_add * (1 << ec_order ) -1)
        MulAux { to_add, to_sub }
    }
}
