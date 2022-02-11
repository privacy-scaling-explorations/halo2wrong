use num_bigint::BigUint as big_uint;
use num_traits::{Num, Zero};
use std::ops::Shl;

cfg_if::cfg_if! {
    if #[cfg(feature = "kzg")] {
        use crate::halo2::arithmetic::BaseExt as Field;
    } else {
        // default feature
        use crate::halo2::arithmetic::FieldExt as Field;
    }
}

fn modulus<F: Field>() -> big_uint {
    big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

pub fn big_to_fe<F: Field>(e: big_uint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;

    cfg_if::cfg_if! {
        if #[cfg(feature = "kzg")] {
            let mut bytes = e.to_bytes_le();
            bytes.resize(32, 0);
            let mut bytes = &bytes[..];
            F::read(&mut bytes).unwrap()
        } else {
            // default feature
            F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
        }
    }
}

pub fn fe_to_big<F: Field>(fe: F) -> big_uint {
    cfg_if::cfg_if! {
        if #[cfg(feature = "kzg")] {
            let mut bytes: Vec<u8> = Vec::new();
            fe.write(&mut bytes).unwrap();
            big_uint::from_bytes_le(&bytes[..])
        } else {
            // default feature
            big_uint::from_bytes_le(fe.to_repr().as_ref())
        }
    }
}

pub fn decompose<F: Field>(e: F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    decompose_big(fe_to_big(e), number_of_limbs, bit_len)
}

pub fn decompose_big<F: Field>(e: big_uint, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
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

pub fn compose(input: Vec<big_uint>, bit_len: usize) -> big_uint {
    let mut e = big_uint::zero();
    for (i, limb) in input.iter().enumerate() {
        e += limb << (bit_len * i)
    }
    e
}

#[test]
fn test_round_trip() {
    use group::ff::Field as _;
    use num_bigint::RandomBits;
    use rand::Rng;

    cfg_if::cfg_if! {
        if #[cfg(feature = "kzg")] {
            use crate::halo2::pairing::bn256::Fr as Fp;
        } else {
            // default feature
            use crate::halo2::pasta::Fp;
        }
    }

    for _ in 0..1000 {
        let mut rng = rand::thread_rng();
        let a: big_uint = rng.sample(RandomBits::new(256));
        let modulus = modulus::<Fp>();
        let a_0 = a % modulus;
        let t: Fp = big_to_fe(a_0.clone());
        let a_1 = fe_to_big(t);
        assert_eq!(a_0, a_1);
    }

    for _ in 0..1000 {
        let mut rng = rand::thread_rng();
        let a_0 = Fp::random(&mut rng);
        let t = fe_to_big(a_0);
        let a_1 = big_to_fe(t);
        assert_eq!(a_0, a_1);
    }
}

#[test]
fn test_bit_decomposition() {
    use num_bigint::RandomBits;
    use rand::Rng;

    cfg_if::cfg_if! {
        if #[cfg(feature = "kzg")] {
            use crate::halo2::pairing::bn256::Fr as Fp;
        } else {
            // default feature
            use crate::halo2::pasta::Fp;
        }
    }

    let mut rng = rand::thread_rng();
    let bit_size = 256usize;
    let e_0: big_uint = rng.sample(RandomBits::new(bit_size as u64));

    let decomposed = decompose_big::<Fp>(e_0.clone(), bit_size, 1);
    let e_1 = compose(decomposed.into_iter().map(fe_to_big).collect(), 1);

    assert_eq!(e_0, e_1);
}
