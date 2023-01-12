use crate::integer::{ConstantInteger, Integer, Limb};
use halo2::{
    circuit::Value,
    halo2curves::{CurveAffine, FieldExt},
};
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
    pub fn value<C>(&self) -> Value<C>
    where
        C: CurveAffine<Base = W, ScalarExt = N>,
    {
        let x = self.x.value();
        let y = self.y.value();
        x.zip(y).map(|(x, y)| C::from_xy(x, y).unwrap())
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
