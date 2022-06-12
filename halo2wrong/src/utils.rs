use crate::halo2::arithmetic::FieldExt;
use num_bigint::BigUint as big_uint;
use num_traits::{Num, One, Zero};
use std::ops::Shl;

pub fn modulus<F: FieldExt>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

pub fn power_of_two<F: FieldExt>(n: usize) -> F {
    big_to_fe(big_uint::one() << n)
}

pub fn big_to_fe<F: FieldExt>(e: big_uint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

pub fn fe_to_big<F: FieldExt>(fe: F) -> big_uint {
    big_uint::from_bytes_le(fe.to_repr().as_ref())
}

pub fn decompose<F: FieldExt>(e: F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    decompose_big(fe_to_big(e), number_of_limbs, bit_len)
}

pub fn decompose_big<F: FieldExt>(e: big_uint, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
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

/// Compute the represented value by a vector of values and a bit length.
///
/// This function is used to compute the value of an integer
/// passing as input its limb values and the bit length used.
/// Returns the sum of all limbs scaled by 2^(bit_len * i)
pub fn compose(input: Vec<big_uint>, bit_len: usize) -> big_uint {
    input
        .iter()
        .rev()
        .fold(big_uint::zero(), |acc, val| (acc << bit_len) + val)
}

#[test]
fn test_round_trip() {
    use crate::curves::pasta::Fp;
    use group::ff::Field as _;
    use num_bigint::RandomBits;
    use rand::Rng;
    use rand_core::OsRng;

    for _ in 0..1000 {
        let a: big_uint = OsRng.sample(RandomBits::new(256));
        let modulus = modulus::<Fp>();
        let a_0 = a % modulus;
        let t: Fp = big_to_fe(a_0.clone());
        let a_1 = fe_to_big(t);
        assert_eq!(a_0, a_1);
    }

    for _ in 0..1000 {
        let a_0 = Fp::random(OsRng);
        let t = fe_to_big(a_0);
        let a_1 = big_to_fe(t);
        assert_eq!(a_0, a_1);
    }
}

#[test]
fn test_bit_decomposition() {
    use crate::curves::pasta::Fp;
    use num_bigint::RandomBits;
    use rand::Rng;
    use rand_core::OsRng;

    let bit_size = 256usize;
    let e_0: big_uint = OsRng.sample(RandomBits::new(bit_size as u64));

    let decomposed = decompose_big::<Fp>(e_0.clone(), bit_size, 1);
    let e_1 = compose(decomposed.into_iter().map(fe_to_big).collect(), 1);

    assert_eq!(e_0, e_1);
}
