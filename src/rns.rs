use halo2::arithmetic::{Field, FieldExt};
use halo2::circuit::Cell;
use num_bigint::BigUint as big_uint;
use num_integer::Integer as _;
use num_traits::{Num, One, Zero};
use std::convert::TryInto;
use std::marker::PhantomData;
use std::ops::Shl;

pub(crate) const CRT_MODULUS_BIT_LEN: usize = 256;
pub(crate) const NUMBER_OF_LIMBS: usize = 4;
pub(crate) const BIT_LEN_LIMB: usize = 64;

pub(crate) const NUMBER_OF_LOOKUP_LIMBS: usize = 4;
pub(crate) const BIT_LEN_LOOKUP_LIMB: usize = 16;

pub trait Common {
    fn value(&self) -> big_uint;

    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

fn fe_to_big<F: FieldExt>(fe: F) -> big_uint {
    big_uint::from_bytes_le(&fe.to_bytes()[..])
}

fn modulus<F: FieldExt>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

fn big_to_fe<F: FieldExt>(e: big_uint) -> F {
    F::from_str(&e.to_str_radix(10)[..]).unwrap()
}

impl<N: FieldExt> From<Integer<N>> for big_uint {
    fn from(el: Integer<N>) -> Self {
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

#[derive(Debug, Clone)]
pub enum Quotient<F: FieldExt> {
    Short(Limb<F>),
    Long(Decomposed<F>),
}

#[derive(Debug, Clone)]
pub struct ReductionContext<N: FieldExt> {
    pub result: Integer<N>,
    pub quotient: Quotient<N>,
    pub t: Vec<Limb<N>>,
    pub negative_modulus: Vec<Limb<N>>,
    pub u_0: Limb<N>,
    pub u_1: Limb<N>,
    pub v_0: Limb<N>,
    pub v_1: Limb<N>,
}

#[derive(Debug, Clone)]
pub struct Rns<Wrong: FieldExt, Native: FieldExt> {
    pub bit_len: usize,
    pub number_of_limbs: usize,
    pub right_shifter_r: Native,
    pub right_shifter_2r: Native,
    pub left_shifter_r: Native,
    pub left_shifter_2r: Native,
    pub aux: Decomposed<Native>,
    crt_modulus_bit_len: usize,
    wrong_modulus: big_uint,
    negative_wrong_modulus: Decomposed<Native>,
    s: Native,
    two_limb_mask: big_uint,
    _marker_wrong: PhantomData<Wrong>,
}

impl<W: FieldExt, N: FieldExt> Rns<W, N> {
    pub(crate) fn construct(bit_len: usize, number_of_limbs: usize, crt_modulus_bit_len: usize) -> Self {
        let two = N::from_u64(2);
        let two_inv = two.invert().unwrap();
        let right_shifter_r = two_inv.pow(&[bit_len as u64, 0, 0, 0]);
        let right_shifter_2r = two_inv.pow(&[2 * bit_len as u64, 0, 0, 0]);
        let left_shifter_r = two.pow(&[bit_len as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[2 * bit_len as u64, 0, 0, 0]);
        let wrong_modulus = big_uint::from_str_radix(&W::MODULUS[2..], 16).unwrap();

        let t = big_uint::one() << crt_modulus_bit_len;
        let negative_wrong_modulus = Decomposed::<N>::from_big(t - wrong_modulus.clone(), number_of_limbs, bit_len);
        let s = big_to_fe(big_uint::one() << bit_len);
        let two_limb_mask = (big_uint::one() << (bit_len * 2)) - 1usize;

        let range_correct_factor = s - N::one();

        let aux = &mut Decomposed::<N>::from_big(wrong_modulus.clone(), number_of_limbs, bit_len);
        aux.scale(range_correct_factor);
        let aux = aux.clone();

        Rns {
            bit_len,
            number_of_limbs,
            crt_modulus_bit_len,
            right_shifter_r,
            right_shifter_2r,
            left_shifter_r,
            left_shifter_2r,
            wrong_modulus,
            negative_wrong_modulus,
            s,
            aux,
            two_limb_mask,
            _marker_wrong: PhantomData,
        }
    }

    pub(crate) fn new(&self, fe: W) -> Integer<N> {
        self.new_from_big(fe_to_big(fe))
    }

    pub(crate) fn rand(&self) -> Integer<N> {
        self.new(W::rand())
    }

    pub(crate) fn modulus(&self) -> Integer<N> {
        self.new_from_big(modulus::<W>())
    }

    pub(crate) fn new_from_big(&self, e: big_uint) -> Integer<N> {
        Integer {
            decomposed: Decomposed::from_big(e, self.number_of_limbs, self.bit_len),
        }
    }

    pub(crate) fn new_from_limbs(&self, limbs: Vec<Limb<N>>) -> Integer<N> {
        assert_eq!(self.number_of_limbs, limbs.len());
        let decomposed = Decomposed { limbs, bit_len: self.bit_len };
        Integer { decomposed }
    }

    pub(crate) fn add(&self, integer_0: &Integer<N>, integer_1: &Integer<N>) -> Integer<N> {
        let limbs: Vec<Limb<N>> = integer_0
            .decomposed
            .limbs
            .iter()
            .zip(integer_1.decomposed.limbs.iter())
            .map(|(self_limb, other_limb)| (self_limb.value() + other_limb.value()).into())
            .collect();

        let decomposed = Decomposed { limbs, bit_len: self.bit_len };

        assert_eq!(decomposed.value(), integer_1.value() + integer_0.value());

        Integer { decomposed }
    }

    pub(crate) fn sub(&self, integer_0: &Integer<N>, integer_1: &Integer<N>) -> Integer<N> {
        let aux = self.aux.clone();

        let limbs: Vec<Limb<N>> = integer_0
            .decomposed
            .limbs
            .iter()
            .zip(integer_1.decomposed.limbs.iter())
            .zip(aux.limbs.iter())
            .map(|((integer_0_limb, integer_1_limb), aux)| (integer_0_limb.value() - integer_1_limb.value() + aux.value()).into())
            .collect();

        let decomposed = Decomposed { limbs, bit_len: self.bit_len };

        assert_eq!(
            decomposed.value(),
            (integer_0.value() - integer_1.value() + aux.value()) % self.modulus().value()
        );

        Integer { decomposed }
    }

    pub(crate) fn mul(&self, integer_0: &Integer<N>, integer_1: &Integer<N>) -> ReductionContext<N> {
        let modulus = self.wrong_modulus.clone();
        let negative_modulus = self.negative_wrong_modulus.clone();

        // compute quotient and the result
        let (quotient, result) = (integer_0.value() * integer_1.value()).div_rem(&modulus);

        let quotient = Decomposed::<N>::from_big(quotient, self.number_of_limbs, self.bit_len);
        let result = self.new_from_big(result);

        let l = self.number_of_limbs;
        let mut t: Vec<N> = vec![N::zero(); l];
        for i in 0..l {
            for j in 0..l {
                if i + j < l {
                    t[i + j] = t[i + j]
                        + integer_1.decomposed.limbs[i].fe() * integer_1.decomposed.limbs[j].fe()
                        + negative_modulus.limbs[i].fe() * quotient.limbs[j].fe();
                }
            }
        }

        let t: Vec<Limb<N>> = t.iter().map(|e| Limb::from_fe(*e)).collect();

        let (u_0, u_1, v_0, v_1) = self.residues(t.clone(), result.clone());
        let negative_modulus = negative_modulus.limbs;
        let quotient = Quotient::Long(quotient);
        ReductionContext {
            result,
            quotient,
            t,
            negative_modulus,
            u_0,
            u_1,
            v_0,
            v_1,
        }
    }

    fn residues(&self, t: Vec<Limb<N>>, r: Integer<N>) -> (Limb<N>, Limb<N>, Limb<N>, Limb<N>) {
        // for now works only for this case
        assert_eq!(self.number_of_limbs, 4);
        let s = self.s;

        let u_0 = t[0].fe() + s * t[1].fe() - r.decomposed.limbs[0].fe() - s * r.decomposed.limbs[1].fe();
        let u_1 = t[2].fe() + s * t[3].fe() - r.decomposed.limbs[2].fe() - s * r.decomposed.limbs[3].fe();

        // sanity check
        {
            let mask = self.two_limb_mask.clone();
            let u_0: big_uint = fe_to_big(u_0);
            let u_1: big_uint = fe_to_big(u_1);
            assert_eq!(u_0 & mask.clone(), big_uint::zero());
            assert_eq!(u_1 & mask, big_uint::zero());
        }

        let v_0 = u_0 * self.right_shifter_2r;
        let v_1 = (u_1 + v_0) * self.right_shifter_2r;

        (Limb::from_fe(u_0), Limb::from_fe(u_1), Limb::from_fe(v_0), Limb::from_fe(v_1))
    }

    pub(crate) fn reduce(&self, integer: &Integer<N>) -> ReductionContext<N> {
        let modulus = self.wrong_modulus.clone();
        let negative_modulus = self.negative_wrong_modulus.clone();

        // compute quotient and the result
        let (quotient, result) = integer.value().div_rem(&modulus);

        // keep quotient value under the size of a dense limb
        assert!(quotient < big_uint::one() << self.bit_len);
        let quotient: Limb<N> = quotient.into();

        // q must stay in single limb

        // compute temp values
        let t: Vec<Limb<N>> = integer
            .limbs()
            .iter()
            .zip(negative_modulus.limbs.iter())
            .map(|(a, p)| {
                let t = a.fe() + p.fe() * quotient.fe();
                Limb::from_fe(t)
            })
            .collect();

        let result = self.new_from_big(result);

        let (u_0, u_1, v_0, v_1) = self.residues(t.clone(), result.clone());
        let negative_modulus = negative_modulus.limbs;
        let quotient = Quotient::Short(quotient);

        ReductionContext {
            result,
            quotient,
            t,
            negative_modulus,
            u_0,
            u_1,
            v_0,
            v_1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Integer<Native: FieldExt> {
    pub decomposed: Decomposed<Native>,
}

impl<N: FieldExt> Common for Integer<N> {
    fn value(&self) -> big_uint {
        self.decomposed.value()
    }
}

impl<N: FieldExt> Integer<N> {
    pub(crate) fn fe<W: FieldExt>(&self) -> W {
        big_to_fe(self.value())
    }

    pub fn limbs(&self) -> Vec<Limb<N>> {
        self.decomposed.limbs.clone()
    }
}

#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt> {
    pub cell: Option<Cell>,
    _value: F,
}

impl<F: FieldExt> Common for Limb<F> {
    fn value(&self) -> big_uint {
        fe_to_big(self._value)
    }
}

impl<F: FieldExt> Default for Limb<F> {
    fn default() -> Self {
        Limb { _value: F::zero(), cell: None }
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

impl<F: FieldExt> Limb<F> {
    pub fn from_fe(fe: F) -> Limb<F> {
        big_uint::from_bytes_le(&fe.to_bytes()[..]).into()
    }

    pub fn fe(&self) -> F {
        self._value
    }
}

#[derive(Debug, Clone, Default)]
pub struct Decomposed<F: FieldExt> {
    pub limbs: Vec<Limb<F>>,
    bit_len: usize,
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

impl<F: FieldExt> Decomposed<F> {
    pub fn from_limb(limb: &Limb<F>, number_of_limbs: usize, bit_len: usize) -> Self {
        Decomposed::from_big(limb.value(), number_of_limbs, bit_len)
    }

    pub fn from_big(e: big_uint, number_of_limbs: usize, bit_len: usize) -> Self {
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

    pub fn scale(&mut self, k: F) {
        for limb in self.limbs.iter_mut() {
            limb._value = limb._value * k;
        }
    }
}
