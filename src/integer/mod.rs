use crate::{
    utils::{compose, compose_big, decompose_big, fe_to_big, modulus},
    Composable, Witness,
};
use halo2::{circuit::Value, halo2curves::FieldExt};
use num_bigint::BigUint as Big;
use std::marker::PhantomData;
pub mod chip;
mod operations;
pub mod rns;
#[cfg(test)]
pub mod tests;

#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt> {
    witness: Witness<F>,
    max: Big,
}
impl<F: FieldExt> Limb<F> {
    pub(crate) fn new(limb: &Witness<F>, max: Big) -> Self {
        #[cfg(feature = "sanity-check")]
        {
            limb.value().map(|e| assert!(fe_to_big(e).le(&max)));
        }
        Self {
            witness: *limb,
            max,
        }
    }
    pub(crate) fn value(&self) -> Value<F> {
        self.witness.value()
    }
    pub(crate) fn witness(&self) -> Witness<F> {
        self.witness
    }
    pub(crate) fn max(&self) -> Big {
        self.max.clone()
    }
    pub(crate) fn big(&self) -> Value<Big> {
        self.value().map(|e| fe_to_big(e))
    }
}
impl<F: FieldExt> AsRef<Witness<F>> for Limb<F> {
    fn as_ref(&self) -> &Witness<F> {
        &self.witness
    }
}
#[derive(Clone)]
pub struct Integer<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub(crate) limbs: [Limb<N>; NUMBER_OF_LIMBS],
    native: Witness<N>,
    _marker: PhantomData<W>,
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(limbs: &[Limb<N>; NUMBER_OF_LIMBS], native: Witness<N>) -> Self {
        Self {
            limbs: limbs.clone(),
            native,
            _marker: PhantomData,
        }
    }
    pub fn limbs(&self) -> &[Limb<N>; NUMBER_OF_LIMBS] {
        &self.limbs
    }
    pub fn limb(&self, idx: usize) -> &Witness<N> {
        self.limbs[idx].as_ref()
    }
    pub fn limbs_as_value(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        let limbs: Vec<Value<N>> = self
            .limbs()
            .iter()
            .map(|limb| limb.witness().value())
            .collect();
        let limbs: Value<Vec<N>> = Value::from_iter(limbs);
        limbs.map(|limbs| limbs.try_into().unwrap())
    }
    pub fn limbs_as_array(&self) -> [Value<N>; NUMBER_OF_LIMBS] {
        self.limbs_as_value().transpose_array()
    }
    pub fn value(&self) -> Value<W> {
        let limbs: Vec<Value<N>> = self.limbs.iter().map(|limb| limb.value()).collect();
        Value::from_iter(limbs).map(|limbs| compose(limbs, BIT_LEN_LIMB))
    }
    pub fn native(&self) -> &Witness<N> {
        &self.native
    }
    pub fn big(&self) -> Value<Big> {
        let limbs: Value<Vec<Big>> = Value::from_iter(self.limbs.iter().map(|limb| limb.big()));
        limbs.map(|limbs| compose_big(limbs, BIT_LEN_LIMB))
    }
    fn max(&self) -> Big {
        compose_big(self.max_vals().to_vec(), BIT_LEN_LIMB)
    }
    fn max_vals(&self) -> [Big; NUMBER_OF_LIMBS] {
        self.limbs
            .iter()
            .map(|limb| limb.max())
            .collect::<Vec<Big>>()
            .try_into()
            .unwrap()
    }
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    std::fmt::Debug for Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let big = self.big();
        let mut debug = f.debug_struct("Integer");
        self.native()
            .value()
            .map(|native| debug.field("nat", &native));
        big.map(|big| {
            debug.field("val", &big.to_str_radix(16));
            let reduced = &big % modulus::<W>();
            debug.field("red", &reduced.to_str_radix(16));
        });
        for (_, limb) in self.limbs().iter().enumerate() {
            limb.value().map(|limb| debug.field("limb", &limb));
        }
        for (_, limb) in self.limbs().iter().enumerate() {
            debug.field("max", &limb.max().to_str_radix(16));
        }
        debug.finish()?;
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct ConstantInteger<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    limbs: [N; NUMBER_OF_LIMBS],
    native: N,
    _marker: PhantomData<W>,
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> From<W>
    for ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn from(e: W) -> Self {
        let e = fe_to_big(e);
        let limbs: [N; NUMBER_OF_LIMBS] = decompose_big(e, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
            .try_into()
            .unwrap();
        Self::new(&limbs)
    }
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> From<&W>
    for ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn from(e: &W) -> Self {
        (*e).into()
    }
}
impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(limbs: &[N; NUMBER_OF_LIMBS]) -> Self {
        let native = compose(limbs.to_vec(), BIT_LEN_LIMB);
        Self {
            limbs: *limbs,
            native,
            _marker: PhantomData,
        }
    }
    pub fn limbs(&self) -> &[N; NUMBER_OF_LIMBS] {
        &self.limbs
    }
    pub fn value(&self) -> W {
        compose(self.limbs.to_vec(), BIT_LEN_LIMB)
    }
    pub fn native(&self) -> N {
        self.native
    }
    pub fn big(&self) -> Big {
        compose_big(
            self.limbs.iter().map(|e| fe_to_big(*e)).collect(),
            BIT_LEN_LIMB,
        )
    }
}
