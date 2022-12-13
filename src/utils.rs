use halo2::halo2curves::FieldExt;
use num_bigint::BigUint as Big;
use num_traits::{Num, One, Zero};
use std::ops::Shl;

pub fn modulus<F: FieldExt>() -> Big {
    Big::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}
pub fn power_of_two<F: FieldExt>(n: usize) -> F {
    big_to_fe(Big::one() << n)
}
pub fn big_to_fe<F: FieldExt>(e: Big) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}
pub fn fe_to_big<F: FieldExt>(fe: F) -> Big {
    Big::from_bytes_le(fe.to_repr().as_ref())
}
pub fn decompose<W: FieldExt, N: FieldExt>(e: W, number_of_limbs: usize, bit_len: usize) -> Vec<N> {
    decompose_big(fe_to_big(e), number_of_limbs, bit_len)
}
pub fn bool_to_big(truth: bool) -> Big {
    if truth {
        Big::one()
    } else {
        Big::zero()
    }
}
pub fn decompose_big<F: FieldExt>(e: Big, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    let mut e = e;
    let mask = Big::from(1usize).shl(bit_len) - 1usize;
    let limbs: Vec<F> = (0..number_of_limbs)
        .map(|_| {
            let limb = mask.clone() & e.clone();
            e = e.clone() >> bit_len;
            big_to_fe(limb)
        })
        .collect();

    limbs
}
pub fn compose<W: FieldExt, N: FieldExt>(input: Vec<N>, bit_len: usize) -> W {
    big_to_fe(compose_big(
        input.into_iter().map(|e| fe_to_big(e)).collect(),
        bit_len,
    ))
}
pub fn compose_big(input: Vec<Big>, bit_len: usize) -> Big {
    input
        .iter()
        .rev()
        .fold(Big::zero(), |acc, val| (acc << bit_len) + val)
}
