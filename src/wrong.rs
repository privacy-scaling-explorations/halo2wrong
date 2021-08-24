use halo2::arithmetic::FieldExt;
use halo2::circuit::Cell;
use num_bigint::BigUint as big_uint;
use num_integer::Integer as _;
use num_traits::{Num, Zero};
use std::convert::TryInto;
use std::marker::PhantomData;
use std::ops::Shl;

mod int;
mod range;

pub(crate) const NUMBER_OF_LIMBS: usize = 4;
pub(crate) const LIMB_SIZE: usize = 64;

pub(crate) const NUMBER_OF_LOOKUP_LIMBS: usize = 4;
pub(crate) const LOOKUP_LIMB_SIZE: usize = 16;

pub trait Common {
    fn value(&self) -> big_uint;

    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

impl<W: FieldExt, N: FieldExt> Common for Integer<W, N> {
    fn value(&self) -> big_uint {
        self.decomposed.value()
    }
}

impl<F: FieldExt> Common for Limb<F> {
    fn value(&self) -> big_uint {
        fe_to_big(self._value)
    }
}

impl<F: FieldExt> Common for Decomposed<F> {
    fn value(&self) -> big_uint {
        let mut e = big_uint::zero();
        for (i, limb) in self.limbs.iter().enumerate() {
            e += limb.value() << (self.bit_len * i)
        }
        e
    }
}

fn fe_to_big<F: FieldExt>(fe: F) -> big_uint {
    big_uint::from_bytes_le(&fe.to_bytes()[..])
}

fn field_modulus<F: FieldExt>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

fn big_to_fe<F: FieldExt>(e: big_uint) -> F {
    F::from_str(&e.to_str_radix(10)[..]).unwrap()
}

#[derive(Debug, Clone)]
struct Rns {
    bit_len: usize,
    number_of_limbs: usize,
}

impl Default for Rns {
    fn default() -> Self {
        Self {
            bit_len: LIMB_SIZE,
            number_of_limbs: NUMBER_OF_LIMBS,
        }
    }
}

impl Rns {
    pub(crate) fn new<Wrong: FieldExt, Native: FieldExt>(
        &self,
        fe: Wrong,
    ) -> Integer<Wrong, Native> {
        self.new_from_big(fe_to_big(fe))
    }

    pub(crate) fn rand<Wrong: FieldExt, Native: FieldExt>(&self) -> Integer<Wrong, Native> {
        self.new(Wrong::rand())
    }

    pub(crate) fn char<Wrong: FieldExt, Native: FieldExt>(&self) -> Integer<Wrong, Native> {
        self.new_from_big(field_modulus::<Wrong>())
    }

    pub(crate) fn new_from_big<Wrong: FieldExt, Native: FieldExt>(
        &self,
        e: big_uint,
    ) -> Integer<Wrong, Native> {
        Integer {
            decomposed: Decomposed::new(e, self.bit_len, self.number_of_limbs),
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Integer<Wrong: FieldExt, Native: FieldExt> {
    pub decomposed: Decomposed<Native>,
    _marker: PhantomData<Wrong>,
}

#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt> {
    pub cell: Option<Cell>,
    _value: F,
}

#[derive(Debug, Clone, Default)]
pub struct Decomposed<F: FieldExt> {
    pub limbs: Vec<Limb<F>>,
    bit_len: usize,
}

impl<F: FieldExt> Default for Limb<F> {
    fn default() -> Self {
        Limb {
            _value: F::zero(),
            cell: None,
        }
    }
}

impl<W: FieldExt, N: FieldExt> From<Integer<W, N>> for big_uint {
    fn from(el: Integer<W, N>) -> Self {
        el.value()
    }
}

impl<F: FieldExt> From<Decomposed<F>> for big_uint {
    fn from(decomposed: Decomposed<F>) -> Self {
        decomposed.value()
    }
}

impl<F: FieldExt> From<Limb<F>> for big_uint {
    fn from(limb: Limb<F>) -> Self {
        limb.value()
    }
}

impl<F: FieldExt> From<big_uint> for Limb<F> {
    fn from(e: big_uint) -> Self {
        Self {
            _value: big_to_fe(e),
            cell: None,
        }
    }
}

impl<F: FieldExt> From<Decomposed<F>> for Limb<F> {
    fn from(decomposed: Decomposed<F>) -> Self {
        let e: big_uint = decomposed.into();
        Limb::from(e)
    }
}

impl<W: FieldExt, N: FieldExt> Integer<W, N> {
    pub fn fe(&self) -> W {
        big_to_fe(self.value())
    }

    pub fn mul(&self, other: &Self) -> (Self, Self) {
        let (q, r) = (self.value() * other.value()).div_rem(&Self::modulus());
        (self.new_from_big(q), self.new_from_big(r))
    }

    fn modulus() -> big_uint {
        big_uint::from_str_radix(&W::MODULUS[2..], 16).unwrap()
    }

    fn number_of_limbs(&self) -> usize {
        self.decomposed.limbs.len()
    }

    fn new_from_big(&self, e: big_uint) -> Self {
        let decomposed = Decomposed::new(e, self.decomposed.bit_len, self.number_of_limbs());
        Self {
            decomposed,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt> Decomposed<F> {
    pub fn new(e: big_uint, bit_len: usize, number_of_limbs: usize) -> Self {
        let mut e = e;
        let mask = big_uint::from(1usize).shl(bit_len) - 1usize;
        let limbs: Vec<Limb<F>> = (0..number_of_limbs)
            .map(|_| {
                let limb = mask.clone() & e.clone();
                e = e.clone() >> bit_len;
                limb.into()
            })
            .collect();

        Decomposed {
            limbs: limbs.try_into().expect("must fit in"),
            bit_len,
        }
    }
}

impl<F: FieldExt> Limb<F> {
    pub fn from_fe(fe: F) -> Limb<F> {
        big_uint::from_bytes_le(&fe.to_bytes()[..]).into()
    }

    pub fn fe(&self) -> F {
        self._value
    }
}

#[cfg(test)]
mod tests {

    use super::{field_modulus, Decomposed, Rns};

    use super::{Common, Limb};
    use num_bigint::BigUint as big_uint;
    use num_traits::Zero;
    use pasta_curves::{arithmetic::FieldExt, Fp, Fq};

    #[test]
    fn test_big_int() {
        const NUMBER_OF_LIMBS_LEVEL_1: usize = 4;
        const LIMB_SIZE_LEVEL_1: usize = 64;

        const NUMBER_OF_LIMBS_LEVEL_2: usize = 4;
        const LIMB_SIZE_LEVEL_2: usize = 16;

        let spec = Rns {
            bit_len: LIMB_SIZE_LEVEL_1,
            number_of_limbs: NUMBER_OF_LIMBS_LEVEL_1,
        };

        let a0_fe = Fp::rand();
        let a0 = spec.new::<_, Fq>(a0_fe);
        assert_eq!(a0.fe(), a0_fe);

        let a1_fe = Fp::rand();
        let a1 = spec.new::<_, Fq>(a1_fe);

        let (q, r) = a0.mul(&a1);
        assert_eq!(
            big_uint::zero(),
            a0.value() * a1.value() - q.value() * field_modulus::<Fp>() - r.value()
        );

        let decomposed = a0.decomposed;

        for limb in decomposed.limbs.iter() {
            let decomposed_limb =
                Decomposed::<Fq>::new(limb.value(), LIMB_SIZE_LEVEL_2, NUMBER_OF_LIMBS_LEVEL_2);
            assert!(limb.eq(&Limb::from(decomposed_limb)));
        }
    }
}
