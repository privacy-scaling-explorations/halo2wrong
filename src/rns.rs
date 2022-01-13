use crate::circuit::AssignedInteger;
use crate::{WrongExt, NUMBER_OF_LIMBS, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2arith::halo2;
use halo2arith::utils::{big_to_fe, compose, decompose_big, fe_to_big};
use num_bigint::BigUint as big_uint;
use num_integer::Integer as _;
use num_traits::{Num, One, Zero};
use std::fmt;
use std::marker::PhantomData;

#[cfg(feature = "kzg")]
use crate::halo2::arithmetic::BaseExt;

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

#[cfg(feature = "zcash")]
fn modulus<F: FieldExt>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

#[cfg(feature = "kzg")]
fn modulus<F: BaseExt>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

impl<'a, W: WrongExt, N: FieldExt> From<Integer<'a, W, N>> for big_uint {
    fn from(el: Integer<'a, W, N>) -> Self {
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

#[derive(Clone)]
pub struct ReductionWitness<'a, W: WrongExt, N: FieldExt> {
    pub result: Integer<'a, W, N>,
    pub quotient: Quotient<'a, W, N>,
    pub t: Vec<N>,
    pub u_0: N,
    pub u_1: N,
    pub v_0: N,
    pub v_1: N,
}

pub(crate) struct MaybeReduced<'a, W: WrongExt, N: FieldExt>(Option<ReductionWitness<'a, W, N>>);

impl<'a, W: WrongExt, N: FieldExt> From<Option<ReductionWitness<'a, W, N>>> for MaybeReduced<'a, W, N> {
    fn from(integer: Option<ReductionWitness<'a, W, N>>) -> Self {
        MaybeReduced(integer)
    }
}

impl<'a, W: WrongExt, N: FieldExt> MaybeReduced<'a, W, N> {
    pub(crate) fn long(&self) -> Option<Integer<'a, W, N>> {
        self.0.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Long(quotient) => quotient,
                _ => panic!("long quotient expected"),
            };
            quotient
        })
    }

    pub(crate) fn short(&self) -> Option<N> {
        self.0.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Short(quotient) => quotient,
                _ => panic!("short quotient expected"),
            };
            quotient
        })
    }

    pub(crate) fn result(&self) -> Option<Integer<'a, W, N>> {
        self.0.as_ref().map(|u| u.result.clone()).into()
    }

    pub(crate) fn residues(&self) -> (Option<N>, Option<N>, Option<N>, Option<N>) {
        (self.u_0(), self.u_1(), self.v_0(), self.v_1())
    }

    fn u_0(&self) -> Option<N> {
        self.0.as_ref().map(|u| u.u_0)
    }

    fn u_1(&self) -> Option<N> {
        self.0.as_ref().map(|u| u.u_1)
    }

    fn v_0(&self) -> Option<N> {
        self.0.as_ref().map(|u| u.v_0)
    }

    fn v_1(&self) -> Option<N> {
        self.0.as_ref().map(|u| u.v_1)
    }

    pub(crate) fn intermediate_values(&self) -> (Option<N>, Option<N>, Option<N>, Option<N>) {
        let t = self.0.as_ref().map(|u| u.t.clone());
        let t_0 = t.as_ref().map(|t| t[0]);
        let t_1 = t.as_ref().map(|t| t[1]);
        let t_2 = t.as_ref().map(|t| t[2]);
        let t_3 = t.as_ref().map(|t| t[3]);
        (t_0, t_1, t_2, t_3)
    }
}

#[derive(Clone)]
pub enum Quotient<'a, W: WrongExt, N: FieldExt> {
    Short(N),
    Long(Integer<'a, W, N>),
}

#[derive(Clone)]
pub(crate) struct ComparisionResult<'a, W: WrongExt, N: FieldExt> {
    pub result: Integer<'a, W, N>,
    pub borrow: [bool; NUMBER_OF_LIMBS],
}

#[derive(Debug, Clone, Default)]
pub struct Rns<W: WrongExt, N: FieldExt> {
    pub bit_len_limb: usize,
    pub bit_len_lookup: usize,

    pub wrong_modulus: big_uint,
    pub native_modulus: big_uint,
    pub binary_modulus: big_uint,
    pub crt_modulus: big_uint,

    pub right_shifter_r: N,
    pub right_shifter_2r: N,
    pub left_shifter_r: N,
    pub left_shifter_2r: N,
    pub left_shifter_3r: N,

    pub base_aux: Vec<big_uint>,

    pub negative_wrong_modulus_decomposed: Vec<N>,
    pub wrong_modulus_decomposed: Vec<N>,
    pub wrong_modulus_minus_one: Vec<N>,
    pub wrong_modulus_in_native_modulus: N,

    pub max_reduced_limb: big_uint,
    pub max_unreduced_limb: big_uint,
    pub max_remainder: big_uint,
    pub max_operand: big_uint,
    pub max_mul_quotient: big_uint,
    pub max_reducible_value: big_uint,
    pub max_with_max_unreduced_limbs: big_uint,
    pub max_dense_value: big_uint,

    pub max_most_significant_reduced_limb: big_uint,
    pub max_most_significant_operand_limb: big_uint,
    pub max_most_significant_unreduced_limb: big_uint,
    pub max_most_significant_mul_quotient_limb: big_uint,

    pub mul_v0_overflow: usize,
    pub mul_v1_overflow: usize,

    pub red_v0_overflow: usize,
    pub red_v1_overflow: usize,

    two_limb_mask: big_uint,

    _marker_wrong: PhantomData<W>,
}

impl<W: WrongExt, N: FieldExt> Rns<W, N> {
    fn calculate_base_aux(bit_len_limb: usize) -> Vec<big_uint> {
        let two = N::from(2);
        let r = &fe_to_big(two.pow(&[bit_len_limb as u64, 0, 0, 0]));
        let wrong_modulus = modulus::<W>();

        // base aux = 2 * w
        let wrong_modulus: Vec<N> = decompose_big(wrong_modulus, NUMBER_OF_LIMBS, bit_len_limb);
        let mut base_aux: Vec<big_uint> = wrong_modulus.into_iter().map(|limb| fe_to_big(limb) << 1usize).collect();

        for i in 0..NUMBER_OF_LIMBS - 1 {
            let hidx = NUMBER_OF_LIMBS - i - 1;
            let lidx = hidx - 1;

            if (base_aux[lidx].bits() as usize) < (bit_len_limb + 1) {
                base_aux[hidx] = base_aux[hidx].clone() - 1usize;
                base_aux[lidx] = base_aux[lidx].clone() + r;
            }
        }

        base_aux
    }

    pub(crate) fn construct(bit_len_limb: usize) -> Self {
        let one = &big_uint::one();

        let binary_modulus_bit_len = bit_len_limb * NUMBER_OF_LIMBS;
        let binary_modulus = &(one << binary_modulus_bit_len);
        let wrong_modulus = &modulus::<W>();
        let native_modulus = &modulus::<N>();

        assert!(binary_modulus > wrong_modulus);
        assert!(binary_modulus > native_modulus);
        assert!(binary_modulus * native_modulus > wrong_modulus * wrong_modulus);

        let two = N::from(2);
        let two_inv = two.invert().unwrap();
        let right_shifter_r = two_inv.pow(&[bit_len_limb as u64, 0, 0, 0]);
        let right_shifter_2r = two_inv.pow(&[2 * bit_len_limb as u64, 0, 0, 0]);
        let left_shifter_r = two.pow(&[bit_len_limb as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[2 * bit_len_limb as u64, 0, 0, 0]);
        let left_shifter_3r = two.pow(&[3 * bit_len_limb as u64, 0, 0, 0]);

        let wrong_modulus_in_native_modulus: N = big_to_fe(wrong_modulus.clone() % native_modulus.clone());

        let negative_wrong_modulus_decomposed: Vec<N> = decompose_big(binary_modulus - wrong_modulus.clone(), NUMBER_OF_LIMBS, bit_len_limb);
        let wrong_modulus_decomposed: Vec<N> = decompose_big(wrong_modulus.clone(), NUMBER_OF_LIMBS, bit_len_limb);
        let wrong_modulus_minus_one = decompose_big(wrong_modulus.clone() - 1usize, NUMBER_OF_LIMBS, bit_len_limb);

        let two_limb_mask = (one << (bit_len_limb * 2)) - 1usize;

        let crt_modulus = &(binary_modulus * native_modulus);
        let crt_modulus_bit_len = crt_modulus.bits();

        // n * T > a' * a'
        let pre_max_operand_bit_len = (crt_modulus_bit_len / 2) - 1;
        let pre_max_operand = &((one << pre_max_operand_bit_len) - one);

        // n * T > q * w + r
        let wrong_modulus_len = wrong_modulus.bits();
        let max_remainder = &((one << wrong_modulus_len) - one);

        let pre_max_mul_quotient: &big_uint = &((crt_modulus - max_remainder) / wrong_modulus);
        let max_mul_quotient = &((one << (pre_max_mul_quotient.bits() - 1)) - big_uint::one());

        let max_operand_bit_len = (max_mul_quotient * wrong_modulus + max_remainder).bits() / 2 - 1;
        let max_operand = &((one << max_operand_bit_len) - one);

        let max_reduced_limb = &(one << bit_len_limb) - one;
        // TODO: this is for now just much lower than actual
        let max_unreduced_limb = &(one << (bit_len_limb + bit_len_limb / 2)) - one;

        assert!(*crt_modulus > pre_max_operand * pre_max_operand);
        assert!(pre_max_operand > wrong_modulus);
        assert!(*crt_modulus > (max_mul_quotient * wrong_modulus) + max_remainder);
        assert!(max_mul_quotient > wrong_modulus);
        assert!(max_operand <= pre_max_operand);
        assert!(max_operand > wrong_modulus);
        assert!(*crt_modulus > max_operand * max_operand);
        assert!(max_mul_quotient * wrong_modulus + max_remainder > max_operand * max_operand);

        let max_most_significant_reduced_limb = &(max_remainder >> ((NUMBER_OF_LIMBS - 1) * bit_len_limb));
        let max_most_significant_operand_limb = &(max_operand >> ((NUMBER_OF_LIMBS - 1) * bit_len_limb));
        // TODO: this is for now just much lower than actual
        let max_most_significant_unreduced_limb = &(max_unreduced_limb.clone());
        let max_most_significant_mul_quotient_limb = &(max_mul_quotient >> ((NUMBER_OF_LIMBS - 1) * bit_len_limb));

        assert!((max_most_significant_reduced_limb.bits() as usize) < bit_len_limb);
        assert!((max_most_significant_operand_limb.bits() as usize) < bit_len_limb);
        assert!((max_most_significant_mul_quotient_limb.bits() as usize) <= bit_len_limb);

        // limit reduction quotient by single limb
        let max_reduction_quotient = &max_reduced_limb.clone();
        let max_reducible_value = max_reduction_quotient * wrong_modulus.clone() + max_remainder;
        let max_with_max_unreduced_limbs = compose(vec![max_unreduced_limb.clone(); 4], bit_len_limb);
        assert!(max_reducible_value > max_with_max_unreduced_limbs);
        let max_dense_value = compose(vec![max_reduced_limb.clone(); 4], bit_len_limb);

        // emulate multiplication to find out max residue overflows
        let (mul_v0_max, mul_v1_max) = {
            let a = vec![
                max_reduced_limb.clone(),
                max_reduced_limb.clone(),
                max_reduced_limb.clone(),
                max_most_significant_operand_limb.clone(),
            ];
            let p: Vec<big_uint> = negative_wrong_modulus_decomposed.iter().map(|e| fe_to_big(*e)).collect();
            let q = vec![
                max_reduced_limb.clone(),
                max_reduced_limb.clone(),
                max_reduced_limb.clone(),
                max_most_significant_mul_quotient_limb.clone(),
            ];

            let mut t = vec![big_uint::zero(); 2 * NUMBER_OF_LIMBS - 1];
            for i in 0..NUMBER_OF_LIMBS {
                for j in 0..NUMBER_OF_LIMBS {
                    t[i + j] = &t[i + j] + &a[i] * &a[j] + &p[i] * &q[j];
                }
            }

            let u0 = &t[0] + (&t[1] << bit_len_limb);
            let u1 = &t[2] + (&t[3] << bit_len_limb);
            let u1 = u1 + (u0.clone() >> (2 * bit_len_limb));

            let v0 = u0.clone() >> (2 * bit_len_limb);
            let v1 = u1.clone() >> (2 * bit_len_limb);

            (v0, v1)
        };
        let mul_v0_overflow = mul_v0_max.bits() as usize - bit_len_limb;
        let mul_v1_overflow = mul_v1_max.bits() as usize - bit_len_limb;

        // emulate reduction to find out max residue overflows
        let (red_v0_max, red_v1_max) = {
            let a = vec![
                max_unreduced_limb.clone(),
                max_unreduced_limb.clone(),
                max_unreduced_limb.clone(),
                max_unreduced_limb.clone(),
            ];
            let a_value = compose(a.clone(), bit_len_limb);
            let q_max = a_value / wrong_modulus;
            assert!(q_max < (one << bit_len_limb));

            let p: Vec<big_uint> = negative_wrong_modulus_decomposed.iter().map(|e| fe_to_big(*e)).collect();
            let q = &max_reduced_limb.clone();
            let t: Vec<big_uint> = a.iter().zip(p.iter()).map(|(a, p)| a + q * p).collect();

            let u0 = &t[0] + (&t[1] << bit_len_limb);
            let u1 = &t[2] + (&t[3] << bit_len_limb);
            let u1 = u1 + (u0.clone() >> (2 * bit_len_limb));

            let v0 = u0.clone() >> (2 * bit_len_limb);
            let v1 = u1.clone() >> (2 * bit_len_limb);

            (v0, v1)
        };
        let red_v0_overflow = red_v0_max.bits() as usize - bit_len_limb;
        let red_v1_overflow = red_v1_max.bits() as usize - bit_len_limb;

        let bit_len_lookup = bit_len_limb / NUMBER_OF_LOOKUP_LIMBS;
        assert!(bit_len_lookup * NUMBER_OF_LOOKUP_LIMBS == bit_len_limb);

        let base_aux = Self::calculate_base_aux(bit_len_limb);
        let base_aux_value = compose(base_aux.clone(), bit_len_limb);
        assert!(base_aux_value.clone() % wrong_modulus == big_uint::zero());
        assert!(base_aux_value > *max_remainder);

        for i in 0..NUMBER_OF_LIMBS {
            let is_last_limb = i == NUMBER_OF_LIMBS - 1;
            let target = if is_last_limb {
                max_most_significant_reduced_limb.clone()
            } else {
                max_reduced_limb.clone()
            };
            assert!(base_aux[i] >= target);
        }

        let rns = Rns {
            bit_len_limb,
            bit_len_lookup,

            right_shifter_r,
            right_shifter_2r,
            left_shifter_r,
            left_shifter_2r,
            left_shifter_3r,

            wrong_modulus: wrong_modulus.clone(),
            native_modulus: native_modulus.clone(),
            binary_modulus: binary_modulus.clone(),
            crt_modulus: crt_modulus.clone(),

            base_aux,

            negative_wrong_modulus_decomposed,
            wrong_modulus_decomposed,
            wrong_modulus_minus_one,
            wrong_modulus_in_native_modulus,

            max_reduced_limb: max_reduced_limb.clone(),
            max_unreduced_limb: max_unreduced_limb.clone(),
            max_remainder: max_remainder.clone(),
            max_operand: max_operand.clone(),
            max_mul_quotient: max_mul_quotient.clone(),
            max_reducible_value,
            max_with_max_unreduced_limbs,
            max_dense_value,

            max_most_significant_reduced_limb: max_most_significant_reduced_limb.clone(),
            max_most_significant_operand_limb: max_most_significant_operand_limb.clone(),
            max_most_significant_unreduced_limb: max_most_significant_unreduced_limb.clone(),
            max_most_significant_mul_quotient_limb: max_most_significant_mul_quotient_limb.clone(),

            mul_v0_overflow,
            mul_v1_overflow,
            red_v0_overflow,
            red_v1_overflow,

            two_limb_mask,
            _marker_wrong: PhantomData,
        };

        let max_with_max_unreduced_limbs = vec![big_to_fe(max_unreduced_limb.clone()); 4];
        let max_with_max_unreduced = rns.new_from_limbs(max_with_max_unreduced_limbs);
        let reduction_result = max_with_max_unreduced.reduce();
        let quotient = match reduction_result.quotient.clone() {
            Quotient::Short(quotient) => quotient,
            _ => panic!("short quotient is expected"),
        };
        let quotient = fe_to_big(quotient);
        assert!(quotient < max_reduced_limb);

        rns
    }

    pub(crate) fn new(&self, fe: W) -> Integer<W, N> {
        Integer::from_big(fe_to_big(fe), self)
    }

    pub(crate) fn zero(&self) -> Integer<W, N> {
        Integer::from_big(big_uint::zero(), self)
    }

    pub(crate) fn new_from_limbs(&self, limbs: Vec<N>) -> Integer<W, N> {
        let limbs = limbs.iter().map(|limb| Limb::<N>::new(*limb)).collect();
        Integer { limbs, rns: self }
    }

    pub(crate) fn new_from_big(&self, e: big_uint) -> Integer<W, N> {
        assert!(e <= self.max_dense_value);
        let limbs = decompose_big::<N>(e, NUMBER_OF_LIMBS, self.bit_len_limb);
        self.new_from_limbs(limbs)
    }

    pub(crate) fn make_aux(&self, max_vals: Vec<big_uint>) -> Integer<W, N> {
        let mut max_shift = 0usize;

        for i in 0..NUMBER_OF_LIMBS {
            let (max_val, mut aux) = (max_vals[i].clone(), self.base_aux[i].clone());
            let mut shift = 1;
            while max_val > aux {
                aux = aux << 1usize;
                max_shift = std::cmp::max(shift, max_shift);
                shift += 1;
            }
        }
        let aux_limbs = self.base_aux.iter().map(|aux_limb| big_to_fe(aux_limb << max_shift)).collect();
        self.new_from_limbs(aux_limbs)
    }

    pub(crate) fn overflow_lengths(&self) -> Vec<usize> {
        let max_most_significant_mul_quotient_limb_size = self.max_most_significant_mul_quotient_limb.bits() as usize % self.bit_len_lookup;
        let max_most_significant_operand_limb_size = self.max_most_significant_operand_limb.bits() as usize % self.bit_len_lookup;
        let max_most_significant_reduced_limb_size = self.max_most_significant_reduced_limb.bits() as usize % self.bit_len_lookup;
        vec![
            self.mul_v0_overflow,
            self.mul_v1_overflow,
            self.red_v0_overflow,
            self.red_v1_overflow,
            max_most_significant_mul_quotient_limb_size,
            max_most_significant_operand_limb_size,
            max_most_significant_reduced_limb_size,
        ]
    }

    pub(crate) fn to_integer(&self, a: &AssignedInteger<N>) -> Option<Integer<W, N>> {
        a.limbs().map(|limbs| Integer::new(limbs, self))
    }
}

#[derive(Debug, Clone)]
pub struct Limb<F: FieldExt>(F);

impl<F: FieldExt> Common<F> for Limb<F> {
    fn value(&self) -> big_uint {
        fe_to_big(self.0)
    }
}

impl<F: FieldExt> Default for Limb<F> {
    fn default() -> Self {
        Limb(F::zero())
    }
}

impl<F: FieldExt> From<big_uint> for Limb<F> {
    fn from(e: big_uint) -> Self {
        Self(big_to_fe(e))
    }
}

impl<F: FieldExt> From<&str> for Limb<F> {
    fn from(e: &str) -> Self {
        Self(big_to_fe(big_uint::from_str_radix(e, 16).unwrap()))
    }
}

impl<F: FieldExt> Limb<F> {
    pub(crate) fn new(value: F) -> Self {
        Limb(value)
    }

    pub(crate) fn from_big(e: big_uint) -> Self {
        Self::new(big_to_fe(e))
    }

    pub(crate) fn fe(&self) -> F {
        self.0
    }
}

#[derive(Clone)]
pub struct Integer<'a, W: WrongExt, N: FieldExt> {
    limbs: Vec<Limb<N>>,
    rns: &'a Rns<W, N>,
}

impl<'a, W: WrongExt, N: FieldExt> fmt::Debug for Integer<'a, W, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = self.value();
        let value = value.to_str_radix(16);
        writeln!(f, "value: {}", value)?;
        for limb in self.limbs().iter() {
            let value = fe_to_big(*limb);
            let value = value.to_str_radix(16);
            writeln!(f, "limb: {}", value)?;
        }
        Ok(())
    }
}

impl<'a, W: WrongExt, N: FieldExt> Common<N> for Integer<'a, W, N> {
    fn value(&self) -> big_uint {
        let limb_values = self.limbs.iter().map(|limb| limb.value()).collect();
        compose(limb_values, self.rns.bit_len_limb)
    }
}

impl<'a, W: WrongExt, N: FieldExt> Integer<'a, W, N> {
    pub fn new(limbs: Vec<Limb<N>>, rns: &'a Rns<W, N>) -> Self {
        assert!(limbs.len() == NUMBER_OF_LIMBS);
        Self { limbs, rns }
    }

    pub fn from_big(e: big_uint, rns: &'a Rns<W, N>) -> Self {
        let limbs = decompose_big::<N>(e, NUMBER_OF_LIMBS, rns.bit_len_limb);
        let limbs = limbs.iter().map(|e| Limb::<N>::new(*e)).collect();
        Self { limbs, rns }
    }

    pub fn from_bytes_le(e: &[u8], rns: &'a Rns<W, N>) -> Self {
        let x = num_bigint::BigUint::from_bytes_le(e);
        Self::from_big(x, rns)
    }

    pub fn limbs(&self) -> Vec<N> {
        self.limbs.iter().map(|limb| limb.fe()).collect()
    }

    pub fn limb_value(&self, idx: usize) -> N {
        self.limb(idx).fe()
    }

    pub fn limb(&self, idx: usize) -> Limb<N> {
        self.limbs[idx].clone()
    }

    pub fn scale(&mut self, k: N) {
        for limb in self.limbs.iter_mut() {
            limb.0 = limb.0 * k;
        }
    }

    pub(crate) fn invert(&self) -> Option<Integer<W, N>> {
        let a_biguint = self.value();
        let a_w = big_to_fe::<W>(a_biguint);
        let inv_w = a_w.invert();

        inv_w.map(|inv| self.rns.new_from_big(fe_to_big(inv))).into()
    }

    pub(crate) fn div(&self, denom: &Integer<'a, W, N>) -> Option<Integer<W, N>> {
        denom.invert().map(|b_inv| {
            let a_mul_b = (self.value() * b_inv.value()) % self.rns.wrong_modulus.clone();
            self.rns.new_from_big(a_mul_b)
        })
    }

    pub(crate) fn square(&self) -> ReductionWitness<'a, W, N> {
        self.mul(self)
    }

    pub(crate) fn mul(&self, other: &Integer<'a, W, N>) -> ReductionWitness<'a, W, N> {
        let modulus = self.rns.wrong_modulus.clone();
        let negative_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let (quotient, result) = (self.value() * other.value()).div_rem(&modulus);

        let quotient = self.rns.new_from_big(quotient);
        let result = self.rns.new_from_big(result);

        let l = NUMBER_OF_LIMBS;
        let mut t: Vec<N> = vec![N::zero(); l];
        for k in 0..l {
            for i in 0..=k {
                let j = k - i;
                t[i + j] = t[i + j] + self.limb_value(i) * other.limb_value(j) + negative_modulus[i] * quotient.limb_value(j);
            }
        }

        let (u_0, u_1, v_0, v_1) = result.residues(t.clone());
        let quotient = Quotient::Long(quotient);

        ReductionWitness {
            result,
            quotient,
            t,
            u_0,
            u_1,
            v_0,
            v_1,
        }
    }

    pub(crate) fn reduce(&self) -> ReductionWitness<W, N> {
        let modulus = self.rns.wrong_modulus.clone();
        let negative_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let (quotient, result) = self.value().div_rem(&modulus);
        assert!(quotient < big_uint::one() << self.rns.bit_len_limb);

        let quotient: N = big_to_fe(quotient);

        // compute intermediate values
        let t: Vec<N> = self
            .limbs()
            .iter()
            .zip(negative_modulus.iter())
            .map(|(a, p)| {
                let t = *a + *p * quotient;
                t
            })
            .collect();

        let result = self.rns.new_from_big(result);

        let (u_0, u_1, v_0, v_1) = result.residues(t.clone());
        let quotient = Quotient::Short(quotient);

        ReductionWitness {
            result,
            quotient,
            t,
            u_0,
            u_1,
            v_0,
            v_1,
        }
    }

    fn residues(&self, t: Vec<N>) -> (N, N, N, N) {
        let s = self.rns.left_shifter_r;

        let u_0 = t[0] + s * t[1] - self.limb_value(0) - s * self.limb_value(1);
        let u_1 = t[2] + s * t[3] - self.limb_value(2) - s * self.limb_value(3);

        // sanity check
        {
            let mask = self.rns.two_limb_mask.clone();
            let u_1 = u_0 * self.rns.right_shifter_2r + u_1;
            let u_0: big_uint = fe_to_big(u_0);
            let u_1: big_uint = fe_to_big(u_1);
            assert_eq!(u_0 & mask.clone(), big_uint::zero());
            assert_eq!(u_1 & mask, big_uint::zero());
        }

        let v_0 = u_0 * self.rns.right_shifter_2r;
        let v_1 = (u_1 + v_0) * self.rns.right_shifter_2r;

        (u_0, u_1, v_0, v_1)
    }

    pub(crate) fn compare_to_modulus(&self) -> ComparisionResult<W, N> {
        let mut borrow = [false; NUMBER_OF_LIMBS];
        let modulus_minus_one = self.rns.wrong_modulus_minus_one.clone();

        let mut prev_borrow = big_uint::zero();
        let limbs: Vec<N> = self
            .limbs
            .iter()
            .zip(modulus_minus_one.iter())
            .zip(borrow.iter_mut())
            .map(|((limb, modulus_limb), borrow)| {
                let limb = &limb.value();
                let modulus_limb = fe_to_big(*modulus_limb);
                let cur_borrow = modulus_limb < limb + prev_borrow.clone();
                *borrow = cur_borrow;
                let cur_borrow = bool_to_big(cur_borrow) << self.rns.bit_len_limb;
                let res_limb = ((modulus_limb + cur_borrow) - prev_borrow.clone()) - limb;
                prev_borrow = bool_to_big(*borrow);

                big_to_fe(res_limb)
            })
            .collect();

        let result = self.rns.new_from_limbs(limbs);

        ComparisionResult { result, borrow }
    }
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]

    impl<W: WrongExt, N: FieldExt> Rns<W, N> {
        pub(crate) fn rand_in_field(&self) -> Integer<W, N> {
            use rand::thread_rng;
            let mut rng = thread_rng();
            self.new_from_big(fe_to_big(W::random(&mut rng)))
        }

        pub(crate) fn rand_in_remainder_range(&self) -> Integer<W, N> {
            use rand::thread_rng;
            let mut rng = thread_rng();
            let el = rng.gen_biguint(self.max_remainder.bits() as u64);
            self.new_from_big(el)
        }

        pub(crate) fn rand_in_operand_range(&self) -> Integer<W, N> {
            use rand::thread_rng;
            let mut rng = thread_rng();
            let el = rng.gen_biguint(self.max_operand.bits() as u64);
            self.new_from_big(el)
        }

        pub(crate) fn rand_in_unreduced_range(&self) -> Integer<W, N> {
            self.rand_with_limb_bit_size(self.max_unreduced_limb.bits() as usize)
        }

        pub(crate) fn rand_with_limb_bit_size(&self, bit_len: usize) -> Integer<W, N> {
            use rand::thread_rng;
            let limbs: Vec<N> = (0..NUMBER_OF_LIMBS)
                .map(|_| {
                    let mut rng = thread_rng();
                    let el = rng.gen_biguint(bit_len as u64);
                    big_to_fe(el)
                })
                .collect();

            self.new_from_limbs(limbs)
        }

        pub(crate) fn max_in_remainder_range(&self) -> Integer<W, N> {
            self.new_from_big(self.max_remainder.clone())
        }

        pub(crate) fn max_in_operand_range(&self) -> Integer<W, N> {
            self.new_from_big(self.max_operand.clone())
        }

        pub(crate) fn max_in_unreduced_range(&self) -> Integer<W, N> {
            self.new_from_limbs(vec![big_to_fe(self.max_unreduced_limb.clone()); 4])
        }
    }

    use super::{big_to_fe, fe_to_big, modulus, Rns};
    use crate::rns::Common;
    use crate::rns::Integer;
    use crate::WrongExt;
    use crate::NUMBER_OF_LIMBS;
    use halo2::arithmetic::FieldExt;

    use halo2arith::compose;
    use halo2arith::halo2;
    use num_bigint::{BigUint as big_uint, RandBigInt};
    use num_traits::{One, Zero};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[cfg(feature = "kzg")]
    use halo2::pairing::bn256::Fq as Wrong;
    #[cfg(feature = "kzg")]
    use halo2::pairing::bn256::Fr as Native;

    #[cfg(feature = "zcash")]
    use halo2::pasta::Fp as Wrong;
    #[cfg(feature = "zcash")]
    use halo2::pasta::Fq as Native;

    fn rns() -> Rns<Wrong, Native> {
        let bit_len_limb = 68;
        Rns::<Wrong, Native>::construct(bit_len_limb)
    }

    // #[test]
    // fn test_decomposing() {
    //     let mut rng = XorShiftRng::from_seed([0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5]);
    //     let number_of_limbs = 4usize;
    //     let bit_len_limb = 64usize;
    //     let bit_len_int = 256;
    //     let el = &rng.gen_biguint(bit_len_int);
    //     let decomposed = Integer::<Fp>::from_big(el.clone(), number_of_limbs, bit_len_limb);
    //     assert_eq!(decomposed.value(), el.clone());
    // }

    #[test]
    fn test_rns_constants() {
        let mut rng = XorShiftRng::from_seed([0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5]);

        let rns = rns();

        let wrong_modulus = rns.wrong_modulus.clone();
        let native_modulus = modulus::<Native>();

        // shifters

        let el_0 = Native::random(&mut rng);
        let shifted_0 = el_0 * rns.left_shifter_r;
        let left_shifter_r = big_uint::one() << rns.bit_len_limb;
        let el = fe_to_big(el_0);
        let shifted_1 = (el * left_shifter_r) % native_modulus.clone();
        let shifted_0 = fe_to_big(shifted_0);
        assert_eq!(shifted_0, shifted_1);
        let shifted: Native = big_to_fe(shifted_0);
        let el_1 = shifted * rns.right_shifter_r;
        assert_eq!(el_0, el_1);

        let el_0 = Native::random(&mut rng);
        let shifted_0 = el_0 * rns.left_shifter_2r;
        let left_shifter_2r = big_uint::one() << (2 * rns.bit_len_limb);
        let el = fe_to_big(el_0);
        let shifted_1 = (el * left_shifter_2r) % native_modulus.clone();
        let shifted_0 = fe_to_big(shifted_0);
        assert_eq!(shifted_0, shifted_1);
        let shifted: Native = big_to_fe(shifted_0);
        let el_1 = shifted * rns.right_shifter_2r;
        assert_eq!(el_0, el_1);

        let el_0 = Wrong::random(&mut rng);
        let el = fe_to_big(el_0);
        let aux = compose(rns.base_aux, rns.bit_len_limb);
        let el = (aux + el) % wrong_modulus.clone();
        let el_1: Wrong = big_to_fe(el);
        assert_eq!(el_0, el_1)
    }

    #[test]
    fn test_integer() {
        let rns = rns();

        let mut rng = XorShiftRng::from_seed([0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5]);

        let wrong_modulus = rns.wrong_modulus.clone();

        // conversion
        let el_0 = rng.gen_biguint((rns.bit_len_limb * NUMBER_OF_LIMBS) as u64);
        let el = rns.new_from_big(el_0.clone());
        let el_1 = el.value();
        assert_eq!(el_0, el_1);

        // reduce
        let overflow = rns.bit_len_limb + 10;
        let el = rns.rand_with_limb_bit_size(overflow);
        let result_0 = el.value() % wrong_modulus.clone();
        let reduction_context = el.reduce();
        let result_1 = reduction_context.result;
        assert_eq!(result_1.value(), result_0);

        // aux
        let aux = compose(rns.base_aux.clone(), rns.bit_len_limb);
        assert_eq!(aux % &wrong_modulus, big_uint::zero());

        // mul
        for _ in 0..10000 {
            let el_0 = &rns.rand_in_remainder_range();
            let el_1 = &rns.rand_in_remainder_range();
            let result_0 = (el_0.value() * el_1.value()) % wrong_modulus.clone();
            let reduction_context = el_0.mul(el_1);
            let result_1 = reduction_context.result;
            assert_eq!(result_1.value(), result_0);
        }

        // inv
        for _ in 0..10000 {
            let el = &rns.rand_in_remainder_range();
            let result = el.invert();
            let result = result.map(|inv| (inv.value() * el.value()) % wrong_modulus.clone());

            match result {
                Some(result) => assert_eq!(result, 1u32.into()),
                None => assert_eq!(el.value(), 0u32.into()),
            }
        }

        // inv of 0
        {
            let el = rns.new_from_big(0u32.into());
            let result = el.invert();
            assert_eq!(result.map(|_| {}), None);
        }

        // div
        for _ in 0..10000 {
            let el_0 = &rns.rand_in_remainder_range();
            let el_1 = &rns.rand_in_remainder_range();
            let result_0 = el_0.div(el_1);
            let result = result_0.map(|result_0| (result_0.value() * el_1.value() - el_0.value()) % wrong_modulus.clone());

            match result {
                Some(result) => assert_eq!(result, 0u32.into()),
                None => assert_eq!(el_1.value(), 0u32.into()),
            }
        }

        // div 0
        {
            let el_0 = &rns.rand_in_remainder_range();
            let el_1 = &rns.new_from_big(0u32.into());
            let result = el_0.div(el_1);
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
