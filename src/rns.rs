use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use num_bigint::BigUint as big_uint;
use num_integer::Integer as _;
use num_traits::{Num, One, Zero};
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Div, Shl};

pub fn decompose_fe<F: FieldExt>(e: F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    decompose(fe_to_big(e), number_of_limbs, bit_len)
}

pub fn decompose<F: FieldExt>(e: big_uint, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    let mut e = e;
    let mask = big_uint::from(1usize).shl(bit_len) - 1usize;
    let limbs: Vec<F> = (0..number_of_limbs)
        .map(|_| {
            let limb = mask.clone() & e.clone();
            e = e.clone() >> bit_len;
            big_to_fe(limb)
        })
        .collect();

    limbs
}

fn compose(input: Vec<big_uint>, bit_len: usize) -> big_uint {
    let mut e = big_uint::zero();
    for (i, limb) in input.iter().enumerate() {
        e += limb << (bit_len * i)
    }
    e
}

fn compose_fe<F: FieldExt>(input: Vec<F>, bit_len: usize) -> big_uint {
    let mut e = big_uint::zero();
    for (i, limb) in input.iter().enumerate() {
        e += fe_to_big(*limb) << (bit_len * i)
    }
    e
}

pub trait Common<F: FieldExt> {
    fn value(&self) -> big_uint;

    fn native(&self) -> F {
        let native_value = self.value() % modulus::<F>();
        big_to_fe(native_value)
    }

    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

pub fn fe_to_big<F: FieldExt>(fe: F) -> big_uint {
    big_uint::from_bytes_le(&fe.to_bytes()[..])
}

fn modulus<F: FieldExt>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

pub fn big_to_fe<F: FieldExt>(e: big_uint) -> F {
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

impl<N: FieldExt> From<Integer<N>> for big_uint {
    fn from(el: Integer<N>) -> Self {
        el.value()
    }
}

fn bool_to_big(truth: bool) -> big_uint {
    if truth {
        big_uint::one()
    } else {
        big_uint::zero()
    }
}

impl<F: FieldExt> From<Limb<F>> for big_uint {
    fn from(limb: Limb<F>) -> Self {
        limb.value()
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Quotient<F: FieldExt> {
    Short(F),
    Long(Integer<F>),
}

#[derive(Debug, Clone)]
pub(crate) struct ReductionContext<N: FieldExt> {
    pub result: Integer<N>,
    pub quotient: Quotient<N>,
    pub t: Vec<N>,
    pub negative_modulus: Vec<N>,
    pub u_0: N,
    pub u_1: N,
    pub v_0: N,
    pub v_1: N,
}

pub(crate) struct ComparisionResult<N: FieldExt> {
    pub result: Integer<N>,
    pub borrow: [bool; NUMBER_OF_LIMBS],
}

#[derive(Debug, Clone, Default)]
pub struct Rns<Wrong: FieldExt, Native: FieldExt> {
    pub right_shifter_r: Native,
    pub right_shifter_2r: Native,
    pub left_shifter_r: Native,
    pub left_shifter_2r: Native,
    pub left_shifter_3r: Native,
    pub aux: Integer<Native>,
    pub negative_wrong_modulus: Vec<Native>,
    pub wrong_modulus_decomposed: Vec<Native>,
    pub wrong_modulus_minus_one: Integer<Native>,
    pub wrong_modulus_in_native_modulus: Native,
    pub bit_len_prenormalized: usize,
    pub bit_len_limb: usize,
    pub bit_len_lookup: usize,
    pub wrong_modulus: big_uint,
    pub limb_max_val: big_uint,
    pub most_significant_limb_max_val: big_uint,
    pub native_modulus: big_uint,
    two_limb_mask: big_uint,
    _marker_wrong: PhantomData<Wrong>,
}

impl<W: FieldExt, N: FieldExt> Rns<W, N> {
    fn aux(bit_len_limb: usize) -> Integer<N> {
        let two = N::from_u64(2);
        let r = &fe_to_big(two.pow(&[bit_len_limb as u64, 0, 0, 0]));
        let wrong_modulus = modulus::<W>();
        let wrong_modulus_decomposed = Integer::<N>::from_big(wrong_modulus.clone(), NUMBER_OF_LIMBS, bit_len_limb);
        let wrong_modulus_top = wrong_modulus_decomposed.limb(NUMBER_OF_LIMBS - 1).value();
        let range_correct_factor: big_uint = r.div(wrong_modulus_top) + 1usize;

        let mut aux: Vec<big_uint> = wrong_modulus_decomposed
            .limbs()
            .iter()
            .map(|limb| fe_to_big(*limb) * range_correct_factor.clone())
            .collect();

        if aux[1] < r.clone() - 1usize {
            if aux[2] == big_uint::zero() {
                aux[1] += r.clone();
                aux[2] = r.clone() - 1usize;
                aux[3] -= 1usize;
            } else {
                aux[1] += r.clone();
                aux[2] -= 1usize;
            }
        }

        if aux[2] < r.clone() - 1usize {
            aux[2] += r.clone();
            aux[3] -= 1usize;
        }

        let aux = Integer {
            limbs: aux.iter().map(|aux_limb| Limb::from_big(aux_limb.clone())).collect(),
        };

        aux
    }

    pub(crate) fn construct(bit_len_limb: usize) -> Self {
        let bit_len_crt_modulus = bit_len_limb * NUMBER_OF_LIMBS;
        let bit_len_lookup = bit_len_limb / NUMBER_OF_LOOKUP_LIMBS;
        let two = N::from_u64(2);
        let two_inv = two.invert().unwrap();
        let right_shifter_r = two_inv.pow(&[bit_len_limb as u64, 0, 0, 0]);
        let right_shifter_2r = two_inv.pow(&[2 * bit_len_limb as u64, 0, 0, 0]);
        let left_shifter_r = two.pow(&[bit_len_limb as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[2 * bit_len_limb as u64, 0, 0, 0]);
        let left_shifter_3r = two.pow(&[3 * bit_len_limb as u64, 0, 0, 0]);
        let wrong_modulus = modulus::<W>();
        let native_modulus = modulus::<N>();
        let wrong_modulus_in_native_modulus: N = big_to_fe(wrong_modulus.clone() % native_modulus.clone());
        let t = big_uint::one() << bit_len_crt_modulus;
        let negative_wrong_modulus = decompose(t - wrong_modulus.clone(), NUMBER_OF_LIMBS, bit_len_limb);
        let wrong_modulus_decomposed = decompose(wrong_modulus.clone(), NUMBER_OF_LIMBS, bit_len_limb);

        let wrong_modulus_minus_one = Integer::<N>::from_big(wrong_modulus.clone() - 1usize, NUMBER_OF_LIMBS, bit_len_limb);

        let two_limb_mask = (big_uint::one() << (bit_len_limb * 2)) - 1usize;
        let aux = Self::aux(bit_len_limb);

        let limb_max_val = (big_uint::one() << bit_len_limb) - 1usize;
        let bit_len_prenormalized = wrong_modulus.bits() as usize;
        let most_significant_limb_bit_len = bit_len_prenormalized - (bit_len_limb * (NUMBER_OF_LIMBS - 1));
        let most_significant_limb_max_val = (big_uint::one() << most_significant_limb_bit_len) - 1usize;

        Rns {
            right_shifter_r,
            right_shifter_2r,
            left_shifter_r,
            left_shifter_2r,
            left_shifter_3r,
            wrong_modulus,
            native_modulus,
            negative_wrong_modulus,
            wrong_modulus_decomposed,
            wrong_modulus_minus_one,
            wrong_modulus_in_native_modulus,
            aux,
            two_limb_mask,
            bit_len_limb,
            bit_len_lookup,
            bit_len_prenormalized,
            limb_max_val,
            most_significant_limb_max_val,
            _marker_wrong: PhantomData,
        }
    }

    pub(crate) fn new_in_crt(&self, fe: W) -> Integer<N> {
        Integer::from_big(fe_to_big(fe), NUMBER_OF_LIMBS, self.bit_len_limb)
    }

    pub(crate) fn new_from_limbs(&self, limbs: Vec<N>) -> Integer<N> {
        let limbs = limbs.iter().map(|limb| Limb::<N>::new(*limb)).collect();
        Integer { limbs }
    }

    pub(crate) fn new_from_big(&self, e: big_uint) -> Integer<N> {
        let limbs = decompose::<N>(e, NUMBER_OF_LIMBS, self.bit_len_limb);
        self.new_from_limbs(limbs)
    }

    #[cfg(test)]
    pub(crate) fn rand_normalized(&self) -> Integer<N> {
        self.new_from_big(fe_to_big(W::rand()))
    }

    #[cfg(test)]
    pub(crate) fn rand_prenormalized(&self) -> Integer<N> {
        use num_bigint::RandBigInt;
        use rand::thread_rng;
        let mut rng = thread_rng();
        let el = rng.gen_biguint(self.bit_len_prenormalized as u64);
        self.new_from_big(el)
    }

    #[cfg(test)]
    pub(crate) fn rand_with_limb_bit_size(&self, bit_len: usize) -> Integer<N> {
        use num_bigint::RandBigInt;
        use rand::thread_rng;
        let limbs: Vec<Limb<N>> = (0..NUMBER_OF_LIMBS)
            .map(|_| {
                let mut rng = thread_rng();
                let el = rng.gen_biguint(bit_len as u64);
                let limb: Limb<N> = el.into();
                limb
            })
            .collect();

        Integer { limbs }
    }

    pub(crate) fn value(&self, a: &Integer<N>) -> big_uint {
        compose_fe(a.limbs(), self.bit_len_limb)
    }

    pub(crate) fn compare_to_modulus(&self, integer: &Integer<N>) -> ComparisionResult<N> {
        let mut borrow = [false; NUMBER_OF_LIMBS];
        let modulus_minus_one = self.wrong_modulus_minus_one.clone();

        let mut prev_borrow = big_uint::zero();
        let limbs: Vec<N> = integer
            .limbs
            .iter()
            .zip(modulus_minus_one.limbs.iter())
            .zip(borrow.iter_mut())
            .map(|((limb, modulus_limb), borrow)| {
                let limb = &limb.value();
                let modulus_limb = &modulus_limb.value();
                let cur_borrow = *modulus_limb < limb + prev_borrow.clone();
                *borrow = cur_borrow;
                let cur_borrow = bool_to_big(cur_borrow) << self.bit_len_limb;
                let res_limb = ((modulus_limb + cur_borrow) - prev_borrow.clone()) - limb;
                prev_borrow = bool_to_big(*borrow);

                big_to_fe(res_limb)
            })
            .collect();

        let result = self.new_from_limbs(limbs);

        ComparisionResult { result, borrow }
    }

    pub(crate) fn mul(&self, integer_0: &Integer<N>, integer_1: &Integer<N>) -> ReductionContext<N> {
        let modulus = self.wrong_modulus.clone();
        let negative_modulus = self.negative_wrong_modulus.clone();

        let (quotient, result) = (self.value(integer_0) * self.value(integer_1)).div_rem(&modulus);

        let quotient = self.new_from_big(quotient);
        let result = self.new_from_big(result);

        let l = NUMBER_OF_LIMBS;
        let mut t: Vec<N> = vec![N::zero(); l];
        for k in 0..l {
            for i in 0..=k {
                let j = k - i;
                t[i + j] = t[i + j] + integer_0.limb_value(i) * integer_1.limb_value(j) + negative_modulus[i] * quotient.limb_value(j);
            }
        }

        let (u_0, u_1, v_0, v_1) = self.residues(t.clone(), result.clone());
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

        let (quotient, result) = self.value(integer).div_rem(&modulus);
        assert!(quotient < big_uint::one() << self.bit_len_limb);

        let quotient: N = big_to_fe(quotient);

        // compute intermediate values
        let t: Vec<N> = integer
            .limbs()
            .iter()
            .zip(negative_modulus.iter())
            .map(|(a, p)| {
                let t = *a + *p * quotient;
                t
            })
            .collect();

        let result = self.new_from_big(result);

        let (u_0, u_1, v_0, v_1) = self.residues(t.clone(), result.clone());
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

    fn residues(&self, t: Vec<N>, r: Integer<N>) -> (N, N, N, N) {
        let s = self.left_shifter_r;

        let u_0 = t[0] + s * t[1] - r.limb_value(0) - s * r.limb_value(1);
        let u_1 = t[2] + s * t[3] - r.limb_value(2) - s * r.limb_value(3);

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

        (u_0, u_1, v_0, v_1)
    }

    pub(crate) fn invert(&self, a: &Integer<N>) -> Option<Integer<N>> {
        let a_biguint = a.value();
        let a_w = big_to_fe::<W>(a_biguint);
        let inv_w = a_w.invert();

        inv_w.map(|inv| {
            self.new_from_big(fe_to_big(inv))
        }).into()
    }

    pub(crate) fn div(&self, a: &Integer<N>, b: &Integer<N>) -> Option<Integer<N>> {
        let modulus = self.wrong_modulus.clone();
        self.invert(b).map(|b_inv| {
            let a_mul_b = (a.value() * b_inv.value()) % modulus;
            self.new_from_big(a_mul_b)
        })
    }
}

#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt> {
    _value: F,
}

impl<F: FieldExt> Common<F> for Limb<F> {
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

impl<F: FieldExt> Limb<F> {
    pub(crate) fn new(value: F) -> Self {
        Limb { _value: value }
    }

    pub(crate) fn from_big(e: big_uint) -> Self {
        Self::new(big_to_fe(e))
    }

    pub(crate) fn fe(&self) -> F {
        self._value
    }
}

#[derive(Clone, Default)]
pub struct Integer<F: FieldExt> {
    limbs: Vec<Limb<F>>,
}

impl<F: FieldExt> fmt::Debug for Integer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = self.value();
        let value = value.to_str_radix(16);
        write!(f, "value: {}\n", value)?;
        for limb in self.limbs().iter() {
            let value = fe_to_big(*limb);
            let value = value.to_str_radix(16);
            write!(f, "limb: {}\n", value)?;
        }
        Ok(())
    }
}

impl<N: FieldExt> Common<N> for Integer<N> {
    fn value(&self) -> big_uint {
        let limb_values = self.limbs.iter().map(|limb| limb.value()).collect();
        compose(limb_values, BIT_LEN_LIMB)
    }
}

impl<F: FieldExt> Integer<F> {
    pub fn new(limbs: Vec<Limb<F>>) -> Self {
        assert!(limbs.len() == NUMBER_OF_LIMBS);
        Self { limbs }
    }

    pub fn from_big(e: big_uint, number_of_limbs: usize, bit_len: usize) -> Self {
        let limbs = decompose::<F>(e, number_of_limbs, bit_len);
        let limbs = limbs.iter().map(|e| Limb::<F>::new(*e)).collect();
        Self { limbs }
    }

    pub fn from_bytes_le(e: &[u8], number_of_limbs: usize, bit_len: usize) -> Self {
        let x = num_bigint::BigUint::from_bytes_le(e);
        Self::from_big(x, number_of_limbs, bit_len)
    }


    pub fn limbs(&self) -> Vec<F> {
        self.limbs.iter().map(|limb| limb.fe()).collect()
    }

    pub fn limb_value(&self, idx: usize) -> F {
        self.limb(idx).fe()
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

    use super::{big_to_fe, fe_to_big, modulus, Rns};
    use crate::rns::Common;
    use crate::rns::Integer;
    use crate::NUMBER_OF_LIMBS;
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
        let decomposed = Integer::<Fp>::from_big(el.clone(), number_of_limbs, bit_len_limb);
        assert_eq!(decomposed.value(), el.clone());
    }

    #[test]
    fn test_rns_constants() {
        use halo2::pasta::Fp as Wrong;
        use halo2::pasta::Fq as Native;

        let bit_len_limb = 64;

        let rns = Rns::<Wrong, Native>::construct(bit_len_limb);

        let wrong_modulus = rns.wrong_modulus.clone();
        let native_modulus = modulus::<Native>();

        // shifters

        let el_0 = Native::rand();
        let shifted_0 = el_0 * rns.left_shifter_r;
        let left_shifter_r = big_uint::one() << rns.bit_len_limb;
        let el = fe_to_big(el_0);
        let shifted_1 = (el * left_shifter_r) % native_modulus.clone();
        let shifted_0 = fe_to_big(shifted_0);
        assert_eq!(shifted_0, shifted_1);
        let shifted: Fq = big_to_fe(shifted_0);
        let el_1 = shifted * rns.right_shifter_r;
        assert_eq!(el_0, el_1);

        let el_0 = Native::rand();
        let shifted_0 = el_0 * rns.left_shifter_2r;
        let left_shifter_2r = big_uint::one() << (2 * rns.bit_len_limb);
        let el = fe_to_big(el_0);
        let shifted_1 = (el * left_shifter_2r) % native_modulus.clone();
        let shifted_0 = fe_to_big(shifted_0);
        assert_eq!(shifted_0, shifted_1);
        let shifted: Fq = big_to_fe(shifted_0);
        let el_1 = shifted * rns.right_shifter_2r;
        assert_eq!(el_0, el_1);

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
        let bit_len_limb = 64;

        let rns = Rns::<Wrong, Native>::construct(bit_len_limb);

        let wrong_modulus = rns.wrong_modulus.clone();

        // conversion
        let el_0 = rng.gen_biguint((bit_len_limb * NUMBER_OF_LIMBS) as u64);
        let el = rns.new_from_big(el_0.clone());
        let el_1 = el.value();
        assert_eq!(el_0, el_1);

        // reduce
        let overflow = rns.bit_len_limb + 10;
        let el = rns.rand_with_limb_bit_size(overflow);
        let result_0 = el.value() % wrong_modulus.clone();
        let reduction_context = rns.reduce(&el);
        let result_1 = reduction_context.result;
        assert_eq!(result_1.value(), result_0);

        // aux

        assert_eq!(rns.aux.value() % &wrong_modulus, big_uint::zero());

        // mul
        for _ in 0..10000 {
            let el_0 = &rns.rand_prenormalized();
            let el_1 = &rns.rand_prenormalized();
            let result_0 = (el_0.value() * el_1.value()) % wrong_modulus.clone();
            let reduction_context = rns.mul(&el_0, &el_1);
            let result_1 = reduction_context.result;
            assert_eq!(result_1.value(), result_0);
        }

        // inv
        for _ in 0..10000 {
            let el = &rns.rand_prenormalized();
            let result = rns.invert(&el);
            let result = result.map(|inv| {
                (inv.value() * el.value()) % wrong_modulus.clone()
            });

            match result {
                Some(result) => assert_eq!(result, 1u32.into()),
                None => assert_eq!(el.value(), 0u32.into())
            }
        }

        // inv of 0
        {
            let el = rns.new_from_big(0u32.into());
            let result = rns.invert(&el);
            assert_eq!(result.map(|_| {}), None);
        }

        // div
        for _ in 0..10000 {
            let el_0 = &rns.rand_prenormalized();
            let el_1 = &rns.rand_prenormalized();
            let result_0 = rns.div(el_0, el_1);
            let result = result_0.map(|result_0| {
                (result_0.value() * el_1.value() - el_0.value()) % wrong_modulus.clone()
            });

            match result {
                Some(result) => assert_eq!(result, 0u32.into()),
                None => assert_eq!(el_1.value(), 0u32.into())
            }
        }

        // div 0
        {
            let el_0 = &rns.rand_prenormalized();
            let el_1 = &rns.new_from_big(0u32.into());
            let result = rns.div(el_0, el_1);
            assert_eq!(result.map(|_| {}), None);
        }
    }

    // #[test]
    // fn test_comparison() {
    //     use halo2::pasta::Fp as Wrong;
    //     use halo2::pasta::Fq as Native;
    //     let bit_len_limb = 64;

    //     let rns = &Rns::<Wrong, Native>::construct(bit_len_limb);

    //     let wrong_modulus = rns.wrong_modulus_decomposed.clone();

    //     let a_0 = wrong_modulus[0];
    //     let a_1 = wrong_modulus[1];
    //     let a_2 = wrong_modulus[2];
    //     let a_3 = wrong_modulus[3];

    //     let a = &rns.new_from_limbs(vec![a_0, a_1, a_2, a_3]);

    //     let comparison_result = rns.compare_to_modulus(a);
    //     println!("{:?}", comparison_result.borrow);
    //     println!("{:?}", comparison_result.result);
    // }
}
