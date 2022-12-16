use crate::{
    integer::{ConstantInteger, Integer, Limb},
    utils::big_to_fe,
    Composable, Witness,
};
use group::Curve;
use halo2::halo2curves::{CurveAffine, FieldExt};
use num_bigint::BigUint as Big;
use num_traits::One;
pub mod base_field_ecc;
#[cfg(test)]
mod tests;
#[derive(Clone, Debug)]
pub struct Point<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
{
    x: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    y: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(
        x: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        y: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        Point {
            x: x.clone(),
            y: y.clone(),
        }
    }
    pub fn public(&self) -> Vec<Limb<N>> {
        self.x
            .limbs()
            .iter()
            .chain(self.y.limbs().iter())
            .cloned()
            .collect()
    }
    pub fn x(&self) -> &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.x
    }

    pub fn y(&self) -> &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.y
    }
}
#[derive(Clone)]
pub struct ConstantPoint<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    x: ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    y: ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    ConstantPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(
        x: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        y: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> ConstantPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        ConstantPoint {
            x: x.clone(),
            y: y.clone(),
        }
    }
    pub fn x(&self) -> &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.x
    }
    pub fn y(&self) -> &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.y
    }
}
fn make_mul_aux<C: CurveAffine>(aux_to_add: C, window_size: usize, number_of_pairs: usize) -> C {
    assert!(window_size > 0);
    assert!(number_of_pairs > 0);
    use group::ff::PrimeField;
    let n = C::Scalar::NUM_BITS as usize;
    let mut number_of_selectors = n / window_size;
    if n % window_size != 0 {
        number_of_selectors += 1;
    }
    let mut k0 = Big::one();
    let one = Big::one();
    for i in 0..number_of_selectors {
        k0 |= &one << (i * window_size);
    }
    let k1 = (one << number_of_pairs) - 1usize;
    // k = k0* 2^n_pairs
    let k = k0 * k1;
    (-aux_to_add * big_to_fe::<C::Scalar>(k)).to_affine()
}
#[derive(Default)]
pub(crate) struct Selector<F: FieldExt>(Vec<Witness<F>>);

impl<F: FieldExt> std::fmt::Debug for Selector<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut debug = f.debug_struct("Selector");
        for (i, bit) in self.0.iter().enumerate() {
            debug.field("window_index", &i).field("bit", bit);
        }
        debug.finish()?;
        Ok(())
    }
}
pub(crate) struct Windowed<F: FieldExt>(Vec<Selector<F>>);

impl<F: FieldExt> std::fmt::Debug for Windowed<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
pub(crate) struct Table<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(pub(crate) Vec<Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>);

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    std::fmt::Debug for Table<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
#[derive(Debug, Clone)]
pub(crate) struct MulAux<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    to_add: Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    to_sub: Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    MulAux<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn new(
        to_add: Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        to_sub: Point<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Self {
        // TODO Should we ensure that these 2 point are coherent:
        // to_sub = (to_add * (1 << ec_order ) -1)
        MulAux { to_add, to_sub }
    }
}
