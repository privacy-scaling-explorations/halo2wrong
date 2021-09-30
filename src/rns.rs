use crate::{BIT_LEN_CRT_MODULUS, BIT_LEN_LIMB, NUMBER_OF_LIMBS};
use halo2::arithmetic::{Field, FieldExt};
use num_bigint::BigUint as big_uint;
use num_integer::Integer as _;
use num_traits::{Num, One, Zero};
use rand::thread_rng;
use std::convert::TryInto;
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Div, Shl};

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
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
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

#[derive(Debug, Clone, Default)]
pub struct Rns<Wrong: FieldExt, Native: FieldExt> {
    pub right_shifter_r: Native,
    pub right_shifter_2r: Native,
    pub left_shifter_r: Native,
    pub left_shifter_2r: Native,
    pub aux: Decomposed<Native>,
    pub negative_wrong_modulus: Decomposed<Native>,
    wrong_modulus: big_uint,
    two_limb_mask: big_uint,
    _marker_wrong: PhantomData<Wrong>,
}

impl<W: FieldExt, N: FieldExt> Rns<W, N> {
    fn aux() -> Decomposed<N> {
        let two = N::from_u64(2);
        let R = &fe_to_big(two.pow(&[BIT_LEN_LIMB as u64, 0, 0, 0]));
        let wrong_modulus = modulus::<W>();
        let wrong_modulus_decomposed = Decomposed::<N>::from_big(wrong_modulus.clone(), NUMBER_OF_LIMBS, BIT_LEN_LIMB);
        let wrong_modulus_decomposed: Vec<big_uint> = wrong_modulus_decomposed.limbs.iter().map(|limb| limb.value()).collect();
        let wrong_modulus_top = wrong_modulus_decomposed[NUMBER_OF_LIMBS - 1].clone();
        let range_correct_factor = R.div(wrong_modulus_top) + 1usize;
        let mut aux: Vec<big_uint> = wrong_modulus_decomposed.iter().map(|limb| limb * range_correct_factor.clone()).collect();

        if aux[1] < R.clone() - 1usize {
            if aux[2] == big_uint::zero() {
                aux[1] += R.clone();
                aux[2] = R.clone() - 1usize;
                aux[3] -= 1usize;
            } else {
                aux[1] += R.clone();
                aux[2] -= 1usize;
            }
        }

        if aux[2] < R.clone() - 1usize {
            aux[2] += R.clone();
            aux[3] -= 1usize;
        }

        let aux = Decomposed {
            limbs: aux.iter().map(|aux| aux.clone().into()).collect(),
            bit_len: BIT_LEN_LIMB,
        };

        aux
    }

    pub(crate) fn construct() -> Self {
        let two = N::from_u64(2);
        let two_inv = two.invert().unwrap();
        let right_shifter_r = two_inv.pow(&[BIT_LEN_LIMB as u64, 0, 0, 0]);
        let right_shifter_2r = two_inv.pow(&[2 * BIT_LEN_LIMB as u64, 0, 0, 0]);
        let left_shifter_r = two.pow(&[BIT_LEN_LIMB as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[2 * BIT_LEN_LIMB as u64, 0, 0, 0]);
        let wrong_modulus = modulus::<W>();
        let t = big_uint::one() << BIT_LEN_CRT_MODULUS;
        let negative_wrong_modulus = Decomposed::<N>::from_big(t - wrong_modulus.clone(), NUMBER_OF_LIMBS, BIT_LEN_LIMB);
        let two_limb_mask = (big_uint::one() << (BIT_LEN_LIMB * 2)) - 1usize;
        let aux = Self::aux();

        Rns {
            right_shifter_r,
            right_shifter_2r,
            left_shifter_r,
            left_shifter_2r,
            wrong_modulus,
            negative_wrong_modulus,
            aux,
            two_limb_mask,
            _marker_wrong: PhantomData,
        }
    }

    pub(crate) fn new(&self, fe: W) -> Integer<N> {
        self.new_from_big(fe_to_big(fe))
    }

    pub(crate) fn new_from_big(&self, e: big_uint) -> Integer<N> {
        Integer {
            decomposed: Decomposed::from_big(e, NUMBER_OF_LIMBS, BIT_LEN_LIMB),
        }
    }

    pub(crate) fn new_from_limbs(&self, limbs: Vec<Limb<N>>) -> Integer<N> {
        assert_eq!(NUMBER_OF_LIMBS, limbs.len());
        let decomposed = Decomposed { limbs, bit_len: BIT_LEN_LIMB };
        Integer { decomposed }
    }

    pub(crate) fn new_from_str_limbs(&self, e: Vec<&str>) -> Integer<N> {
        let limbs = e.iter().map(|e| Limb::from(*e)).collect();
        self.new_from_limbs(limbs)
    }

    pub(crate) fn rand(&self) -> Integer<N> {
        self.new(W::rand())
    }

    pub(crate) fn rand_in_max(&self) -> Integer<N> {
        use num_bigint::RandBigInt;
        let mut rng = thread_rng();
        let el = rng.gen_biguint(BIT_LEN_CRT_MODULUS as u64);
        self.new_from_big(el)
    }

    pub(crate) fn rand_with_limb_bit_size(&self, bit_len: usize) -> Integer<N> {
        use num_bigint::RandBigInt;
        let limbs: Vec<Limb<N>> = (0..NUMBER_OF_LIMBS)
            .map(|_| {
                let mut rng = thread_rng();
                let el = rng.gen_biguint(bit_len as u64);
                let limb: Limb<N> = el.into();
                limb
            })
            .collect();

        self.new_from_limbs(limbs)
    }

    pub(crate) fn max(&self, bit_len: Option<usize>) -> Integer<N> {
        let limbs = (0..NUMBER_OF_LIMBS).map(|_| self.max_limb(bit_len)).collect();
        self.new_from_limbs(limbs)
    }

    pub(crate) fn max_limb(&self, bit_len: Option<usize>) -> Limb<N> {
        let bit_len = match bit_len {
            Some(bit_len) => bit_len,
            _ => BIT_LEN_LIMB,
        };

        let el = (big_uint::one() << bit_len) - 1usize;
        el.into()
    }

    pub(crate) fn modulus(&self) -> Integer<N> {
        self.new_from_big(modulus::<W>())
    }

    pub(crate) fn add(&self, integer_0: &Integer<N>, integer_1: &Integer<N>) -> Integer<N> {
        let limbs: Vec<Limb<N>> = integer_0
            .decomposed
            .limbs
            .iter()
            .zip(integer_1.decomposed.limbs.iter())
            .map(|(self_limb, other_limb)| (self_limb.value() + other_limb.value()).into())
            .collect();

        let decomposed = Decomposed { limbs, bit_len: BIT_LEN_LIMB };

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
            .map(|((integer_0_limb, integer_1_limb), aux)| ((integer_0_limb.value() + aux.value()) - integer_1_limb.value()).into())
            .collect();

        let decomposed = Decomposed { limbs, bit_len: BIT_LEN_LIMB };

        Integer { decomposed }
    }

    pub(crate) fn mul(&self, integer_0: &Integer<N>, integer_1: &Integer<N>) -> ReductionContext<N> {
        let modulus = self.wrong_modulus.clone();
        let negative_modulus = self.negative_wrong_modulus.clone();

        // compute quotient and the result
        let (quotient, result) = (integer_0.value() * integer_1.value()).div_rem(&modulus);

        let quotient = Decomposed::<N>::from_big(quotient, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
        let result = self.new_from_big(result);

        let l = NUMBER_OF_LIMBS;
        let mut t: Vec<N> = vec![N::zero(); l];
        for k in 0..l {
            for i in 0..=k {
                let j = k - i;
                t[i + j] = t[i + j]
                    + integer_0.decomposed.limbs[i].fe() * integer_1.decomposed.limbs[j].fe()
                    + negative_modulus.limbs[i].fe() * quotient.limbs[j].fe();
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

    pub(crate) fn reduce(&self, integer: &Integer<N>) -> ReductionContext<N> {
        let modulus = self.wrong_modulus.clone();
        let negative_modulus = self.negative_wrong_modulus.clone();

        // compute quotient and the result
        let (quotient, result) = integer.value().div_rem(&modulus);

        // FIX: q must stay in single limb
        // apply modulus shifted values

        // keep quotient value under the size of a dense limb
        assert!(quotient < big_uint::one() << BIT_LEN_LIMB);

        let quotient: Limb<N> = quotient.into();

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

    fn residues(&self, t: Vec<Limb<N>>, r: Integer<N>) -> (Limb<N>, Limb<N>, Limb<N>, Limb<N>) {
        let s = self.left_shifter_r;

        let u_0 = t[0].fe() + s * t[1].fe() - r.decomposed.limbs[0].fe() - s * r.decomposed.limbs[1].fe();
        let u_1 = t[2].fe() + s * t[3].fe() - r.decomposed.limbs[2].fe() - s * r.decomposed.limbs[3].fe();

        // sanity check
        {
            let mask = self.two_limb_mask.clone();
            let u_1 = u_0 * self.right_shifter_2r + u_1;
            let u_0: big_uint = fe_to_big(u_0);
            let u_1: big_uint = fe_to_big(u_1);
            assert_eq!(u_0 & mask.clone(), big_uint::zero());
            assert_eq!(u_1 & mask, big_uint::zero());
        }

        let v_0 = u_0 * self.right_shifter_2r;
        let v_1 = (u_1 + v_0) * self.right_shifter_2r;

        (Limb::from_fe(u_0), Limb::from_fe(u_1), Limb::from_fe(v_0), Limb::from_fe(v_1))
    }
}

#[derive(Clone)]
pub struct Integer<F: FieldExt> {
    pub decomposed: Decomposed<F>,
}

impl<N: FieldExt> Common for Integer<N> {
    fn value(&self) -> big_uint {
        self.decomposed.value()
    }
}

impl<F: FieldExt> fmt::Debug for Integer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = self.value();
        let value = value.to_str_radix(16);
        write!(f, "{}\n", value)?;
        for limb in self.limbs().iter() {
            let value = limb.value();
            let value = value.to_str_radix(16);
            write!(f, "{}\n", value)?;
        }
        Ok(())
    }
}

// impl<F: FieldExt> From<Vec<&str>> for Integer<F> {
//     fn from(e: Vec<&str>) -> Self {
//         let limbs = e.iter().map(|e| Limb::from(*e)).collect();
//         Self {
//             decomposed: Decomposed { limbs, bit_len: BIT_LEN_LIMB },
//         }
//     }
// }

impl<N: FieldExt> Integer<N> {
    pub(crate) fn fe<W: FieldExt>(&self) -> W {
        big_to_fe(self.value())
    }

    pub fn limbs(&self) -> Vec<Limb<N>> {
        self.decomposed.limbs.clone()
    }

    pub fn get_limb(&self, idx: usize) -> N {
        self.decomposed.limbs[idx].fe()
    }
}

#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt> {
    _value: F,
}

impl<F: FieldExt> Common for Limb<F> {
    fn value(&self) -> big_uint {
        fe_to_big(self._value)
    }
}

impl<F: FieldExt> Default for Limb<F> {
    fn default() -> Self {
        Limb { _value: F::zero() }
    }
}

impl<F: FieldExt> From<big_uint> for Limb<F> {
    fn from(e: big_uint) -> Self {
        Self { _value: big_to_fe(e) }
    }
}

impl<F: FieldExt> From<&str> for Limb<F> {
    fn from(e: &str) -> Self {
        Self {
            _value: big_to_fe(big_uint::from_str_radix(e, 16).unwrap()),
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

    pub fn limb(&self, idx: usize) -> Limb<F> {
        self.limbs[idx].clone()
    }

    pub fn scale(&mut self, k: F) {
        for limb in self.limbs.iter_mut() {
            limb._value = limb._value * k;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{big_to_fe, fe_to_big, modulus, Decomposed, Limb, Rns, BIT_LEN_CRT_MODULUS, BIT_LEN_LIMB};
    use crate::rns::Common;
    use crate::rns::Integer;
    use halo2::arithmetic::FieldExt;
    use halo2::pasta::Fp;
    use halo2::pasta::Fq;
    use num_bigint::{BigUint as big_uint, RandBigInt};
    use num_traits::{One, Zero};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_decomposing() {
        let mut rng = XorShiftRng::from_seed([0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5]);
        let number_of_limbs = 4usize;
        let bit_len_limb = 64usize;
        let bit_len_int = 256;
        let el = &rng.gen_biguint(bit_len_int);
        let decomposed = Decomposed::<Fp>::from_big(el.clone(), number_of_limbs, bit_len_limb);
        assert_eq!(decomposed.value(), el.clone());
    }

    #[test]
    fn test_rns_constants() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;

        let rns = Rns::<Wrong, Native>::construct();

        let wrong_modulus = rns.wrong_modulus.clone();
        let native_modulus = modulus::<Native>();

        // shifters

        let el_0 = Native::rand();
        let shifted_0 = el_0 * rns.left_shifter_r;
        let left_shifter_r = big_uint::one() << BIT_LEN_LIMB;
        let el = fe_to_big(el_0);
        let shifted_1 = (el * left_shifter_r) % native_modulus.clone();
        let shifted_0 = fe_to_big(shifted_0);
        assert_eq!(shifted_0, shifted_1);
        let shifted: Fq = big_to_fe(shifted_0);
        let el_1 = shifted * rns.right_shifter_r;
        assert_eq!(el_0, el_1);

        let el_0 = Native::rand();
        let shifted_0 = el_0 * rns.left_shifter_2r;
        let left_shifter_2r = big_uint::one() << (2 * BIT_LEN_LIMB);
        let el = fe_to_big(el_0);
        let shifted_1 = (el * left_shifter_2r) % native_modulus.clone();
        let shifted_0 = fe_to_big(shifted_0);
        assert_eq!(shifted_0, shifted_1);
        let shifted: Fq = big_to_fe(shifted_0);
        let el_1 = shifted * rns.right_shifter_2r;
        assert_eq!(el_0, el_1);

        // negated modulus

        let t = big_uint::one() << BIT_LEN_CRT_MODULUS;
        let negated_wrong_modulus = t - wrong_modulus.clone();
        assert_eq!(negated_wrong_modulus, rns.negative_wrong_modulus.value());

        // range correction aux
        let el_0 = Wrong::rand();
        let el = fe_to_big(el_0);
        let aux = rns.aux.value();
        let el = (aux + el) % wrong_modulus.clone();
        let el_1: Fp = big_to_fe(el);
        assert_eq!(el_0, el_1)
    }

    #[test]
    fn test_integer() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;
        let mut rng = XorShiftRng::from_seed([0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5]);

        let rns = Rns::<Wrong, Native>::construct();

        let wrong_modulus = rns.wrong_modulus.clone();

        // conversion
        let el_0 = rng.gen_biguint(BIT_LEN_CRT_MODULUS as u64);
        let el = rns.new_from_big(el_0.clone());
        let el_1 = el.value();
        assert_eq!(el_0, el_1);

        // add
        let el_0 = &rns.rand_in_max();
        let el_1 = &rns.rand_in_max();

        let r_0 = rns.add(el_0, el_1);
        let r_0: Wrong = r_0.fe();
        let r_1: Wrong = el_0.fe::<Wrong>() + el_1.fe::<Wrong>();
        assert_eq!(r_0, r_1);

        // sub
        let el_0 = &rns.rand_in_max();
        let el_1 = &rns.rand_in_max();

        let r_0 = rns.sub(el_0, el_1);
        let r_0: Wrong = r_0.fe();
        let r_1: Wrong = el_0.fe::<Wrong>() - el_1.fe::<Wrong>();
        assert_eq!(r_0, r_1);

        // reduce
        let overflow = BIT_LEN_LIMB + 10;
        let el = rns.rand_with_limb_bit_size(overflow);
        let result_0 = el.value() % wrong_modulus.clone();
        let reduction_context = rns.reduce(&el);
        let result_1 = reduction_context.result;
        assert_eq!(result_1.value(), result_0);

        // aux

        assert_eq!(rns.aux.value() % &wrong_modulus, big_uint::zero());

        let aux = Integer { decomposed: rns.aux.clone() };
        let el_0 = &rns.rand_in_max();
        let el_1 = rns.add(&aux, &el_0);
        let reduction_context = rns.reduce(&el_1);
        assert_eq!(el_0.value() % wrong_modulus.clone(), reduction_context.result.value());

        // mul
        for _ in 0..10000 {
            let el_0 = &rns.rand_in_max();
            let el_1 = &rns.rand_in_max();
            let result_0 = (el_0.value() * el_1.value()) % wrong_modulus.clone();
            let reduction_context = rns.mul(&el_0, &el_1);
            let result_1 = reduction_context.result;
            assert_eq!(result_1.value(), result_0);
        }
    }
}
