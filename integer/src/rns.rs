use crate::{WrongExt, NUMBER_OF_LOOKUP_LIMBS};
use halo2::arithmetic::FieldExt;
use maingate::{big_to_fe, compose, decompose_big, fe_to_big, halo2};
use num_bigint::BigUint as big_uint;
use num_integer::Integer as _;
use num_traits::{Num, One, Zero};
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;

#[cfg(feature = "kzg")]
use crate::halo2::arithmetic::BaseExt;

/// Common interface for [`Limb`] and [`Integer`]
pub trait Common<F: FieldExt> {
    /// Returns the represented value
    fn value(&self) -> big_uint;

    /// Return the value modulus the Native field size.
    fn native(&self) -> F {
        let native_value = self.value() % modulus::<F>();
        big_to_fe(native_value)
    }

    /// Returns true if the represented values, false otherwise.
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "kzg")] {
        fn modulus<F: BaseExt>() -> big_uint {
            big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
        }

    } else {
        // default feature
        fn modulus<F: FieldExt>() -> big_uint {
            big_uint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
        }
    }
}

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    From<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> for big_uint
{
    fn from(el: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) -> Self {
        el.value()
    }
}

/// Returns `1` if `true`, `0` otherwise.
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

/// Witness values for the reduction circuit
/// see <https://hackmd.io/LoEG5nRHQe-PvstVaD51Yw>.
///
/// Operations that will need later reduction return this struct
/// that holds the result and intermediate vals for the reduction
/// circuit.
#[derive(Clone)]
pub struct ReductionWitness<
    W: WrongExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub result: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub quotient: Quotient<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub t: Vec<N>,
    pub u_0: N,
    pub u_1: N,
    pub v_0: N,
    pub v_1: N,
}

pub(crate) struct MaybeReduced<
    W: WrongExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(Option<ReductionWitness<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>);

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    From<Option<ReductionWitness<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>
    for MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn from(integer: Option<ReductionWitness<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        MaybeReduced(integer)
    }
}

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Returns the quotient value as [`Integer`].
    /// The quotient must be [`Long`] otherwise the function panics
    pub(crate) fn long(&self) -> Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        self.0
            .as_ref()
            .map(|reduction_result| match reduction_result.quotient.clone() {
                Quotient::Long(quotient) => quotient,
                _ => panic!("long quotient expected"),
            })
    }

    /// Returns the quotient value as an element of the native field.
    /// The quotient must be [`Short`] otherwise the function panics
    pub(crate) fn short(&self) -> Option<N> {
        self.0
            .as_ref()
            .map(|reduction_result| match reduction_result.quotient.clone() {
                Quotient::Short(quotient) => quotient,
                _ => panic!("short quotient expected"),
            })
    }

    /// Returns a copy of the result value as an [`Integer`]
    pub(crate) fn result(&self) -> Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        self.0.as_ref().map(|u| u.result.clone())
    }

    /// Returns the residue values `u0`, `u1`, `v0`, `v1`,
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

    /// Return the intermediate values of the reduction algorithm
    // In the algorithm `t_0, t_1, t_2, t_3`
    pub(crate) fn intermediate_values(&self) -> (Option<N>, Option<N>, Option<N>, Option<N>) {
        let t = self.0.as_ref().map(|u| u.t.clone());
        let t_0 = t.as_ref().map(|t| t[0]);
        let t_1 = t.as_ref().map(|t| t[1]);
        let t_2 = t.as_ref().map(|t| t[2]);
        let t_3 = t.as_ref().map(|t| t[3]);
        (t_0, t_1, t_2, t_3)
    }
}

/// Quotient term in [`ReductionWitness`].
///
/// There are two possible representations:
/// Short: as an element of the native field.
/// Long : as an [`Integer`].
#[derive(Clone)]
pub enum Quotient<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
{
    Short(N),
    Long(Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>),
}

/// Result of the substraction of a wrong field element as an [`Integer`]
/// from the wrong field modulus -1.
#[derive(Clone)]
pub(crate) struct ComparisionResult<
    W: WrongExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    /// Result of the subtraction.
    pub result: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    /// Array of indicating if a borrow from the next limb was necessary for
    /// subtraction.
    pub borrow: [bool; NUMBER_OF_LIMBS],
}

/// Residue Numeral System
/// Representation of an integer holding its values modulo several coprime
/// integers.
///
/// Contains all the necessary values to carry out operations such as
/// multiplication and reduction in this representation.
#[derive(Debug, Clone)]
pub struct Rns<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> {
    /// Bit length of the last limb
    pub bit_len_last_limb: usize,
    /// Length of each lookup range check.
    pub bit_len_lookup: usize,
    /// TODO
    pub bit_len_wrong_modulus: usize,

    /// Order of the wrong field W. (In the article `p`).
    pub wrong_modulus: big_uint,
    /// Order of the native field N. (In the article `n`).
    pub native_modulus: big_uint,
    /// Order of the binary field (In the article: 2^t).
    pub binary_modulus: big_uint,
    /// Order of the ring result of the direct product of the native field and
    /// binary field (In the article notation: M = n * p).
    pub crt_modulus: big_uint,

    /// Native field element representing 2^-r with r = `bit_len_limb`.
    pub right_shifter_r: N,
    /// Native field element representing 2^-2r with r = `bit_len_limb`.
    pub right_shifter_2r: N,
    /// Native field element representing 2^r with r = `bit_len_limb`.
    pub left_shifter_r: N,
    /// Native field element representing 2^2r with r = `bit_len_limb`.
    pub left_shifter_2r: N,
    /// Native field element representing 2^3r with r = `bit_len_limb`.
    pub left_shifter_3r: N,

    /// The value `base_aux` is a vector of auxiliary limbs representing the
    /// value `2p` with `p` the size of the wrong modulus.
    pub base_aux: [big_uint; NUMBER_OF_LIMBS],

    /// Negative wrong modulus: `-p mod 2^t` as vector of limbs.
    pub negative_wrong_modulus_decomposed: [N; NUMBER_OF_LIMBS],
    /// Wrong modulus `p` as vector of limbs.
    pub wrong_modulus_decomposed: [N; NUMBER_OF_LIMBS],
    /// Wrong modulus -1  `p - 1` as vector of limbs.
    pub wrong_modulus_minus_one: [N; NUMBER_OF_LIMBS],
    /// Wrong modulus as native field element: `p mod n`.
    pub wrong_modulus_in_native_modulus: N,

    // Check out the `construct()` method to see how these values are obtained.
    /// Maximum value for a reduced limb.
    pub max_reduced_limb: big_uint,
    /// Maximum value for an unreduced limb.
    pub max_unreduced_limb: big_uint,
    /// Maximum value of the remainder.
    pub max_remainder: big_uint, // `r` in the algorithm
    /// Maximum value that can be safely multiplied (guaranteeing the result
    /// will be reducible).
    pub max_operand: big_uint,
    /// Maximum value of the quotient `q` in a reduction.
    pub max_mul_quotient: big_uint,
    /// Maximum reducible value.
    pub max_reducible_value: big_uint,
    /// Maximum value with max unreduced limbs.
    pub max_with_max_unreduced_limbs: big_uint,
    /// Maximum value with max reduced limbs.
    pub max_dense_value: big_uint,

    /// Maximum value of most significant limb for `max_reduced_limb`.
    pub max_most_significant_reduced_limb: big_uint,
    /// Maximum value of most significant limb for `max_operand_limb`.
    pub max_most_significant_operand_limb: big_uint,
    /// Maximum value of most significant limb for `max_unreduced_limb`.
    pub max_most_significant_unreduced_limb: big_uint,
    /// Maximum value of most significant limb for `max_mul_quotient`.
    pub max_most_significant_mul_quotient_limb: big_uint,

    /// Bit length of the maximum value allowed for v0 in multiplication
    /// circuit.
    pub mul_v0_bit_len: usize,
    /// Bit length of the maximum value allowed for v1 in multiplication
    /// circuit.
    pub mul_v1_bit_len: usize,

    /// Bit length of the maximum value allowed for v0 in reduction circuit.
    pub red_v0_bit_len: usize,
    /// Bit length of the maximum value allowed for v1 in reduction circuit
    pub red_v1_bit_len: usize,

    /// Binary mask used to keep/eliminate 2 limbs using logic bitwise
    /// operation.
    two_limb_mask: big_uint,

    _marker_wrong: PhantomData<W>,
}

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Calculates [`Rns`] `base_aux`.
    ///
    /// The value `base_aux` is a vector of auxiliary limbs representing the
    /// value `2p` with `p` the size of the wrong modulus. This value is
    /// used in operations like subtractions in order to avoid negative when
    /// values when working with `big_uint`.
    fn calculate_base_aux() -> [big_uint; NUMBER_OF_LIMBS] {
        let two = N::from(2);
        let r = &fe_to_big(two.pow(&[BIT_LEN_LIMB as u64, 0, 0, 0]));
        let wrong_modulus = modulus::<W>();

        // base aux = 2 * w
        let wrong_modulus: Vec<N> = decompose_big(wrong_modulus, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
        let mut base_aux: Vec<big_uint> = wrong_modulus
            .into_iter()
            .map(|limb| fe_to_big(limb) << 1usize)
            .collect();

        for i in 1..=NUMBER_OF_LIMBS - 1 {
            let hidx = NUMBER_OF_LIMBS - i;
            let lidx = hidx - 1;

            if (base_aux[lidx].bits() as usize) < (BIT_LEN_LIMB + 1) {
                base_aux[hidx] = base_aux[hidx].clone() - 1usize;
                base_aux[lidx] = base_aux[lidx].clone() + r;
            }
        }

        base_aux.try_into().unwrap()
    }

    /// Calculates and builds a [`Rns`] with all its necessary values given
    /// the bit length used for its limbs.
    pub fn construct() -> Self {
        let one = &big_uint::one();

        let binary_modulus_bit_len = BIT_LEN_LIMB * NUMBER_OF_LIMBS;
        let binary_modulus = &(one << binary_modulus_bit_len);
        let wrong_modulus = &modulus::<W>();
        let native_modulus = &modulus::<N>();

        assert!(binary_modulus > wrong_modulus);
        assert!(binary_modulus > native_modulus);
        assert!(binary_modulus * native_modulus > wrong_modulus * wrong_modulus);

        let two = N::from(2);
        let two_inv = two.invert().unwrap();
        let right_shifter_r = two_inv.pow(&[BIT_LEN_LIMB as u64, 0, 0, 0]);
        let right_shifter_2r = two_inv.pow(&[2 * BIT_LEN_LIMB as u64, 0, 0, 0]);
        let left_shifter_r = two.pow(&[BIT_LEN_LIMB as u64, 0, 0, 0]);
        let left_shifter_2r = two.pow(&[2 * BIT_LEN_LIMB as u64, 0, 0, 0]);
        let left_shifter_3r = two.pow(&[3 * BIT_LEN_LIMB as u64, 0, 0, 0]);

        let wrong_modulus_in_native_modulus: N =
            big_to_fe(wrong_modulus.clone() % native_modulus.clone());

        let negative_wrong_modulus_decomposed: [N; NUMBER_OF_LIMBS] = decompose_big(
            binary_modulus - wrong_modulus.clone(),
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
        )
        .try_into()
        .unwrap();
        let wrong_modulus_decomposed =
            decompose_big(wrong_modulus.clone(), NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                .try_into()
                .unwrap();
        let wrong_modulus_minus_one = decompose_big(
            wrong_modulus.clone() - 1usize,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
        )
        .try_into()
        .unwrap();

        let two_limb_mask = (one << (BIT_LEN_LIMB * 2)) - 1usize;

        let crt_modulus = &(binary_modulus * native_modulus);
        let crt_modulus_bit_len = crt_modulus.bits();

        // n * T > a' * a'
        let pre_max_operand_bit_len = (crt_modulus_bit_len / 2) - 1;
        let pre_max_operand = &((one << pre_max_operand_bit_len) - one);

        // n * T > q * w + r
        let bit_len_wrong_modulus = wrong_modulus.bits() as usize;
        let max_remainder = &((one << bit_len_wrong_modulus) - one);

        let pre_max_mul_quotient: &big_uint = &((crt_modulus - max_remainder) / wrong_modulus);
        let max_mul_quotient = &((one << (pre_max_mul_quotient.bits() - 1)) - big_uint::one());

        let max_operand_bit_len = (max_mul_quotient * wrong_modulus + max_remainder).bits() / 2 - 1;
        let max_operand = &((one << max_operand_bit_len) - one);

        let max_reduced_limb = &(one << BIT_LEN_LIMB) - one;
        // TODO: this is for now just much lower than actual
        let max_unreduced_limb = &(one << (BIT_LEN_LIMB + BIT_LEN_LIMB / 2)) - one;

        assert!(*crt_modulus > pre_max_operand * pre_max_operand);
        assert!(pre_max_operand > wrong_modulus);
        assert!(*crt_modulus > (max_mul_quotient * wrong_modulus) + max_remainder);
        assert!(max_mul_quotient > wrong_modulus);
        assert!(max_operand <= pre_max_operand);
        assert!(max_operand > wrong_modulus);
        assert!(*crt_modulus > max_operand * max_operand);
        assert!(max_mul_quotient * wrong_modulus + max_remainder > max_operand * max_operand);

        let max_most_significant_reduced_limb =
            &(max_remainder >> ((NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB));
        let max_most_significant_operand_limb =
            &(max_operand >> ((NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB));
        // TODO: this is for now just much lower than actual
        let max_most_significant_unreduced_limb = &max_unreduced_limb;
        let max_most_significant_mul_quotient_limb =
            &(max_mul_quotient >> ((NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB));

        assert!((max_most_significant_reduced_limb.bits() as usize) < BIT_LEN_LIMB);
        assert!((max_most_significant_operand_limb.bits() as usize) < BIT_LEN_LIMB);
        assert!((max_most_significant_mul_quotient_limb.bits() as usize) <= BIT_LEN_LIMB);

        // limit reduction quotient by single limb
        let max_reduction_quotient = &max_reduced_limb;
        let max_reducible_value = max_reduction_quotient * wrong_modulus.clone() + max_remainder;
        let max_with_max_unreduced_limbs =
            compose(vec![max_unreduced_limb.clone(); 4], BIT_LEN_LIMB);
        assert!(max_reducible_value > max_with_max_unreduced_limbs);
        let max_dense_value = compose(vec![max_reduced_limb.clone(); 4], BIT_LEN_LIMB);

        // emulate multiplication to find out max residue overflows
        let (mul_v0_max, mul_v1_max) = {
            let a = vec![
                max_reduced_limb.clone(),
                max_reduced_limb.clone(),
                max_reduced_limb.clone(),
                max_most_significant_operand_limb.clone(),
            ];
            let p: Vec<big_uint> = negative_wrong_modulus_decomposed
                .iter()
                .map(|e| fe_to_big(*e))
                .collect();
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

            let u0 = &t[0] + (&t[1] << BIT_LEN_LIMB);
            let u1 = &t[2] + (&t[3] << BIT_LEN_LIMB);
            let u1 = u1 + (u0.clone() >> (2 * BIT_LEN_LIMB));

            let v0 = u0 >> (2 * BIT_LEN_LIMB);
            let v1 = u1 >> (2 * BIT_LEN_LIMB);

            (v0, v1)
        };
        let mul_v0_bit_len = std::cmp::max(mul_v0_max.bits() as usize, BIT_LEN_LIMB);
        let mul_v1_bit_len = std::cmp::max(mul_v1_max.bits() as usize, BIT_LEN_LIMB);

        // emulate reduction to find out max residue overflows
        let (red_v0_max, red_v1_max) = {
            let a = vec![
                max_unreduced_limb.clone(),
                max_unreduced_limb.clone(),
                max_unreduced_limb.clone(),
                max_unreduced_limb.clone(),
            ];
            let a_value = compose(a.clone(), BIT_LEN_LIMB);
            let q_max = a_value / wrong_modulus;
            assert!(q_max < (one << BIT_LEN_LIMB));

            let p: Vec<big_uint> = negative_wrong_modulus_decomposed
                .iter()
                .map(|e| fe_to_big(*e))
                .collect();
            let q = &max_reduced_limb;
            let t: Vec<big_uint> = a.iter().zip(p.iter()).map(|(a, p)| a + q * p).collect();

            let u0 = &t[0] + (&t[1] << BIT_LEN_LIMB);
            let u1 = &t[2] + (&t[3] << BIT_LEN_LIMB);
            let u1 = u1 + (u0.clone() >> (2 * BIT_LEN_LIMB));

            let v0 = u0 >> (2 * BIT_LEN_LIMB);
            let v1 = u1 >> (2 * BIT_LEN_LIMB);

            (v0, v1)
        };
        let red_v0_bit_len = std::cmp::max(red_v0_max.bits() as usize, BIT_LEN_LIMB);
        let red_v1_bit_len = std::cmp::max(red_v1_max.bits() as usize, BIT_LEN_LIMB);

        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        assert!(bit_len_lookup * NUMBER_OF_LOOKUP_LIMBS == BIT_LEN_LIMB);

        let base_aux = Self::calculate_base_aux();
        let base_aux_value = compose(base_aux.to_vec(), BIT_LEN_LIMB);
        assert!(base_aux_value.clone() % wrong_modulus == big_uint::zero());
        assert!(base_aux_value > *max_remainder);

        for (i, aux) in base_aux.iter().enumerate() {
            let is_last_limb = i == NUMBER_OF_LIMBS - 1;
            let target = if is_last_limb {
                max_most_significant_reduced_limb.clone()
            } else {
                max_reduced_limb.clone()
            };
            assert!(*aux >= target);
        }

        let bit_len_last_limb = bit_len_wrong_modulus as usize % BIT_LEN_LIMB;

        let rns = Rns {
            bit_len_last_limb,
            bit_len_lookup,
            bit_len_wrong_modulus,

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

            mul_v0_bit_len,
            mul_v1_bit_len,
            red_v0_bit_len,
            red_v1_bit_len,

            two_limb_mask,
            _marker_wrong: PhantomData,
        };

        let max_with_max_unreduced_limbs = &[big_to_fe(max_unreduced_limb); NUMBER_OF_LIMBS];
        let max_with_max_unreduced =
            Integer::from_limbs(max_with_max_unreduced_limbs, Rc::new(rns.clone()));
        let reduction_result = max_with_max_unreduced.reduce();
        let quotient = match reduction_result.quotient {
            Quotient::Short(quotient) => quotient,
            _ => panic!("short quotient is expected"),
        };
        let quotient = fe_to_big(quotient);
        assert!(quotient < max_reduced_limb);

        rns
    }

    /// Computes the overflow that each component of the [`Rns`] must support.
    pub fn overflow_lengths(&self) -> Vec<usize> {
        let max_most_significant_mul_quotient_limb_size =
            self.max_most_significant_mul_quotient_limb.bits() as usize % self.bit_len_lookup;
        let max_most_significant_operand_limb_size =
            self.max_most_significant_operand_limb.bits() as usize % self.bit_len_lookup;
        let max_most_significant_reduced_limb_size =
            self.max_most_significant_reduced_limb.bits() as usize % self.bit_len_lookup;
        vec![
            self.mul_v0_bit_len % self.bit_len_lookup,
            self.mul_v1_bit_len % self.bit_len_lookup,
            self.red_v0_bit_len % self.bit_len_lookup,
            self.red_v1_bit_len % self.bit_len_lookup,
            max_most_significant_mul_quotient_limb_size,
            max_most_significant_operand_limb_size,
            max_most_significant_reduced_limb_size,
        ]
    }
}

/// Limb of an [`Integer`].
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
    /// Creates a [`Limb`] from a field element.
    pub(crate) fn new(value: F) -> Self {
        Limb(value)
    }

    /// Creates a [`Limb`] from an unsigned integer.
    pub(crate) fn from_big(e: big_uint) -> Self {
        Self::new(big_to_fe(e))
    }

    /// Returns the value of the [`Limb`]
    pub(crate) fn fe(&self) -> F {
        self.0
    }
}
/// Representation of an integer.
///
/// The integer is represented as a vector of [`Limb`]s with values in the
/// native field plus a reference to the [`Rns`] used.
#[derive(Clone)]
pub struct Integer<
    W: WrongExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    limbs: Vec<Limb<N>>,
    rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
}

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> fmt::Debug
    for Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = self.value();
        let mut debug = f.debug_struct("Integer");
        debug.field("value", &value.to_str_radix(16));
        for (i, limb) in self.limbs().iter().enumerate() {
            let value = fe_to_big(*limb);
            debug.field(&format!("limb {}", i), &value.to_str_radix(16));
        }
        debug.finish()?;
        Ok(())
    }
}

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> Common<N>
    for Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Returns the represented value.
    fn value(&self) -> big_uint {
        let limb_values = self.limbs.iter().map(|limb| limb.value()).collect();
        compose(limb_values, BIT_LEN_LIMB)
    }
}

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Creates a new integer from a vector of limbs and reference to the used
    /// [`Rns`].
    pub fn new(limbs: Vec<Limb<N>>, rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        assert!(limbs.len() == NUMBER_OF_LIMBS);
        Self { limbs, rns }
    }

    /// Creates a new [`Integer`] from a wrong field element and reference to
    /// the used [`Rns`].
    pub fn from_fe(e: W, rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        Integer::from_big(fe_to_big(e), rns)
    }

    /// Creates a new [`Integer`] from an unsigned integer and reference to the
    /// used [`Rns`].
    pub fn from_big(e: big_uint, rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        let limbs = decompose_big::<N>(e, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
        let limbs = limbs.iter().map(|e| Limb::<N>::new(*e)).collect();
        Self { limbs, rns }
    }

    /// Creates a new [`Integer`] from a vector of native field elements and
    /// reference to the used [`Rns`].
    pub fn from_limbs(
        limbs: &[N; NUMBER_OF_LIMBS],
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    ) -> Self {
        let limbs = limbs.iter().map(|limb| Limb::<N>::new(*limb)).collect();
        Integer { limbs, rns }
    }

    /// Creates a new [`Integer`] from byte representation and reference to the
    /// used [`Rns`].
    pub fn from_bytes_le(e: &[u8], rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>) -> Self {
        let x = num_bigint::BigUint::from_bytes_le(e);
        Self::from_big(x, rns)
    }

    /// Returns the [`Limb`] as a vector of native field elements.
    pub fn limbs(&self) -> Vec<N> {
        self.limbs.iter().map(|limb| limb.fe()).collect()
    }

    /// Returns the [`Limb`] at the `id` position.
    pub fn limb(&self, idx: usize) -> Limb<N> {
        self.limbs[idx].clone()
    }

    /// Scales each [`Limb`] by `k`.
    pub fn scale(&mut self, k: N) {
        for limb in self.limbs.iter_mut() {
            limb.0 *= k;
        }
    }

    /// Computes the inverse of the [`Integer`] as an element of the Wrong
    /// field. Returns `None` if the value cannot be inverted.
    pub(crate) fn invert(&self) -> Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        let a_biguint = self.value();
        let a_w = big_to_fe::<W>(a_biguint);
        let inv_w = a_w.invert();
        inv_w
            .map(|inv| Self::from_big(fe_to_big(inv), Rc::clone(&self.rns)))
            .into()
    }

    /// Compute division, multiplying by the inverse of the denominator, in the
    /// Wrong field.
    pub(crate) fn div(
        &self,
        denom: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Option<Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        denom.invert().map(|b_inv| {
            let a_mul_b = (self.value() * b_inv.value()) % self.rns.wrong_modulus.clone();
            Self::from_big(a_mul_b, Rc::clone(&self.rns))
        })
    }

    /// Computes the square.
    ///
    /// The result of this operation needs to be reduced therefore function
    /// returns [`ReductionWitness`] for the reduction circuit.
    pub(crate) fn square(&self) -> ReductionWitness<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.mul(self)
    }

    /// Computes multiplication in the Wrong field.
    ///
    /// The result of this operation needs to be reduced therefore function
    /// returns [`ReductionWitness`] for the reduction circuit.
    pub(crate) fn mul(
        &self,
        other: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> ReductionWitness<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let modulus = self.rns.wrong_modulus.clone();
        let negative_modulus = self.rns.negative_wrong_modulus_decomposed;
        let (quotient, result) = (self.value() * other.value()).div_rem(&modulus);
        let quotient = Self::from_big(quotient, Rc::clone(&self.rns));
        let result = Self::from_big(result, Rc::clone(&self.rns));

        let l = NUMBER_OF_LIMBS;
        let mut t: Vec<N> = vec![N::zero(); l];
        for k in 0..l {
            for i in 0..=k {
                let j = k - i;
                t[i + j] = t[i + j]
                    + self.limb(i).0 * other.limb(j).0
                    + negative_modulus[i] * quotient.limb(j).0;
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

    /// Reduce an integer in the WrongField
    ///
    /// The result of this operation needs to be reduced therefore function
    /// returns [`ReductionWitness`] for the reduction circuit.
    pub(crate) fn reduce(&self) -> ReductionWitness<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let modulus = self.rns.wrong_modulus.clone();
        let negative_modulus = self.rns.negative_wrong_modulus_decomposed;

        let (quotient, result) = self.value().div_rem(&modulus);
        assert!(quotient < big_uint::one() << BIT_LEN_LIMB);

        let quotient: N = big_to_fe(quotient);

        // compute intermediate values
        let t: Vec<N> = self
            .limbs()
            .iter()
            .zip(negative_modulus.iter())
            .map(|(a, p)| *a + *p * quotient)
            .collect();

        let result = Integer::from_big(result, Rc::clone(&self.rns));

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

    /// Compute residues `u0`, `u1`, `v0`, `v1`.
    ///
    /// See steps 4 to 7 in <https://hackmd.io/LoEG5nRHQe-PvstVaD51Yw>.
    fn residues(&self, t: Vec<N>) -> (N, N, N, N) {
        let s = self.rns.left_shifter_r;

        let u_0 = t[0] + s * t[1] - self.limb(0).0 - s * self.limb(1).0;
        let u_1 = t[2] + s * t[3] - self.limb(2).0 - s * self.limb(3).0;

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

    /// Compares value to the Wrong field modulus.
    ///
    /// Subtracts the provided value from the wrong field modulus -1
    /// The result is given in [`ComparisonResult`] which holds the
    /// result of the subtraction and if a borrow was needed in each
    /// limb.
    /// This function is used in [`IntegerChip::_assert_in_field`] which
    /// needs to reject the case where the value equals the wrong field
    /// modulus. This is the reason for using modulus - 1.
    pub(crate) fn compare_to_modulus(
        &self,
    ) -> ComparisionResult<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        // value = [v0, v1, v2, v3]
        // p-1 = [p0, p1, p2, p3]

        // If a values limb is greater than its corresponding modulus limb
        // we 'borrow' 1 from the next the modulus limb. Keeping track of
        // these borrows is necessary in the circuit.
        let mut borrow = [false; NUMBER_OF_LIMBS];
        let modulus_minus_one = self.rns.wrong_modulus_minus_one;

        let mut prev_borrow = big_uint::zero();
        let limbs = self
            .limbs
            .iter()
            .zip(modulus_minus_one.iter())
            .zip(borrow.iter_mut())
            .map(|((limb, modulus_limb), borrow)| {
                let limb = &limb.value();
                let modulus_limb = fe_to_big(*modulus_limb);
                let cur_borrow = modulus_limb < limb + prev_borrow.clone();
                *borrow = cur_borrow;
                let cur_borrow = bool_to_big(cur_borrow) << BIT_LEN_LIMB;
                let res_limb = ((modulus_limb + cur_borrow) - prev_borrow.clone()) - limb;
                prev_borrow = bool_to_big(*borrow);

                big_to_fe(res_limb)
            })
            .collect::<Vec<N>>()
            .try_into()
            .unwrap();

        let result = Integer::from_limbs(&limbs, Rc::clone(&self.rns));
        ComparisionResult { result, borrow }
    }

    /// Computes the auxiliary value needed for subtraction.
    ///
    /// The valued will be added before subtracting the value represented by
    /// `max_vals` in order to ensure every [`Limb`] value remains positive.
    /// This auxiliary value is always a multiple of `p` therefore it
    /// ensures the correct result is preserved in the Wrong field.
    pub fn subtracion_aux(
        max_vals: Vec<big_uint>,
        rns: Rc<Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
    ) -> Self {
        let mut max_shift = 0usize;
        for (max_val, aux) in max_vals.iter().zip(rns.base_aux.iter()) {
            let mut shift = 1;
            let mut aux = aux.clone();
            while *max_val > aux {
                aux <<= 1usize;
                max_shift = std::cmp::max(shift, max_shift);
                shift += 1;
            }
        }
        let limbs = rns
            .base_aux
            .iter()
            .map(|aux_limb| big_to_fe(aux_limb << max_shift))
            .collect::<Vec<N>>()
            .try_into()
            .unwrap();
        Self::from_limbs(&limbs, rns)
    }
}
