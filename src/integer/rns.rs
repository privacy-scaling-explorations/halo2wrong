use super::{chip::Range, ConstantInteger};
use crate::utils::{big_to_fe, compose_big, decompose, decompose_big, fe_to_big, modulus};
use halo2::{circuit::Value, halo2curves::FieldExt};
use num_bigint::BigUint as Big;
use num_traits::{One, Zero};
use std::marker::PhantomData;

/// Common interface for [`Limb`] and [`Integer`]
pub trait Common<F: FieldExt> {
    /// Returns the represented value
    fn big(&self) -> Big;

    /// Return the value modulus the Native field size.
    fn native(&self) -> F {
        let native_value = self.big() % modulus::<F>();
        big_to_fe(native_value)
    }

    /// Returns true if the represented values, false otherwise.
    fn eq(&self, other: &Self) -> bool {
        self.big() == other.big()
    }
}

/// Residue Numeral System
/// Representation of an integer holding its values modulo several coprime
/// integers.
///
/// Contains all the necessary values to carry out operations such as
/// multiplication and reduction in this representation.
#[derive(Debug, Clone)]
pub struct Rns<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
> {
    /// Order of the wrong field W. (In the article `p`).
    pub(crate) wrong_modulus: Big,
    /// Order of the native field N. (In the article `n`).
    pub(crate) native_modulus: Big,
    /// Native field elements representing `2^(i*r)` with `r = BIT_LEN_LIMB`.
    pub(super) left_shifters: [N; NUMBER_OF_LIMBS],
    /// The value `base_aux` is a vector of auxiliary limbs representing the
    /// value `2p` with `p` the size of the wrong modulus.
    base_aux: [Big; NUMBER_OF_LIMBS],
    // TODO: consider `ConstantInteger` to replace `[N;NUMBER_OF_LIMBS]`
    /// Negative wrong modulus: `-p mod 2^t` as vector of limbs.
    pub(super) negative_wrong_modulus_decomposed: [N; NUMBER_OF_LIMBS],
    /// Wrong modulus `p` as vector of limbs.
    pub(super) wrong_modulus_decomposed: [N; NUMBER_OF_LIMBS],
    /// Wrong modulus as native field element: `p mod n`.
    pub(super) wrong_modulus_in_native_modulus: N,

    /// Maximum value for a reduced limb.
    pub(super) max_reduced_limb: Big,
    /// Maximum value for an unreduced limb.
    pub(super) max_unreduced_limb: Big,
    /// Maximum value of the remainder.
    pub(super) max_remainder: Big,
    /// Maximum value that can be safely multiplied (guaranteeing the result
    /// will be reducible).
    pub(super) max_operand: Big,
    /// Maximum value of the quotient `q` in a reduction.
    // pub(super) max_mul_quotient: Big,

    /// Maximum value of most significant limb for `max_reduced_limb`.
    pub(super) max_most_significant_reduced_limb: Big,
    /// Maximum value of most significant limb for `max_operand_limb`.
    pub(super) max_most_significant_operand_limb: Big,
    /// Maximum value of most significant limb for `max_mul_quotient`.
    pub(super) max_most_significant_mul_quotient_limb: Big,

    /// Bit length of the maximum value allowed for residues in multiplication
    pub(super) mul_v_bit_len: usize,
    /// Bit length of the maximum value allowed for residues in reduction
    /// circuit.
    pub(super) red_v_bit_len: usize,

    _marker_wrong: PhantomData<W>,
}

impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    /// Calculates [`Rns`] `base_aux`.
    /// Calculates base auxillary value wich must be equal to `wrong_modulus`
    /// and all limbs of it must be higher than dense limb value. This value
    /// is used in operations like subtractions in order to avoid negative
    /// when values when working with `Big`.
    fn calculate_base_aux() -> [Big; NUMBER_OF_LIMBS] {
        let two = N::from(2);
        let r = &fe_to_big(two.pow(&[BIT_LEN_LIMB as u64, 0, 0, 0]));
        let wrong_modulus = modulus::<W>();
        let wrong_modulus: Vec<N> = decompose_big(wrong_modulus, NUMBER_OF_LIMBS, BIT_LEN_LIMB);

        // `base_aux = 2 * wrong_modulus`
        let mut base_aux: Vec<Big> = wrong_modulus
            .into_iter()
            .map(|limb| fe_to_big(limb) << 1usize)
            .collect();

        // If value of a limb is not above dense limb borrow from the next one
        for i in 0..NUMBER_OF_LIMBS - 1 {
            let hidx = NUMBER_OF_LIMBS - i - 1;
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
        assert!(NUMBER_OF_LIMBS > 2);
        let one = &Big::one();
        // previous power of two
        macro_rules! log_floor {
            ($u:expr) => {
                &(one << ($u.bits() as usize - 1))
            };
        }
        // next power of two
        macro_rules! log_ceil {
            ($u:expr) => {
                &(one << $u.bits() as usize)
            };
        }
        // `t = BIT_LEN_LIMB * NUMBER_OF_LIMBS`
        // `T = 2 ^ t` which we also name as `binary_modulus`
        let binary_modulus_bit_len = BIT_LEN_LIMB * NUMBER_OF_LIMBS;
        let binary_modulus = &(one << binary_modulus_bit_len);
        // wrong field modulus: `w`
        let wrong_modulus = &modulus::<W>();
        // native field modulus: `n`
        let native_modulus = &modulus::<N>();

        // Multiplication is constrained as:
        //
        // `a * b = w * quotient + remainder`
        //
        // where `quotient` and `remainder` is witnesses, `a` and `b` are assigned
        // operands. Both sides of the equation must not wrap `crt_modulus`.
        let crt_modulus = &(binary_modulus * native_modulus);

        // Witness remainder might overflow the wrong modulus but it is limited
        // to the next power of two of the wrong modulus.
        let max_remainder = &(log_ceil!(wrong_modulus) - one);

        // Find maxium quotient that won't wrap `quotient * wrong + remainder` side of
        // the equation under `crt_modulus`.
        let pre_max_quotient = &((crt_modulus - max_remainder) / wrong_modulus);
        // Lower this value to make this value suitable for bit range checks.
        let max_quotient = &(log_floor!(pre_max_quotient) - one);

        // Find the maximum operand: in order to meet completeness maximum allowed
        // operand value is saturated as below:
        //
        // `max_operand ^ 2 < max_quotient * wrong + max_remainder`
        //
        // So that prover can find `quotient` and `remainder` witnesses for any
        // allowed input operands. And it also automativally ensures that:
        //
        // `max_operand^2 < crt_modulus`
        //
        // must hold.
        let max_operand_bit_len = ((max_quotient * wrong_modulus + max_remainder).bits() - 1) / 2;
        let max_operand = &((one << max_operand_bit_len) - one);
        // Sanity check
        {
            let lhs = &(max_operand * max_operand);
            let rhs = &(max_quotient * wrong_modulus + max_remainder);
            assert!(binary_modulus > wrong_modulus);
            assert!(binary_modulus > native_modulus);
            assert!(max_remainder > wrong_modulus);
            assert!(max_operand > wrong_modulus);
            assert!(max_quotient > wrong_modulus);
            assert!(max_remainder < binary_modulus);
            assert!(max_operand < binary_modulus);
            assert!(max_quotient < binary_modulus);
            assert!(rhs < crt_modulus);
            assert!(lhs < rhs);
        }
        // negative wrong field modulus moduli binary modulus `w'`
        // `w' = (T - w)`
        // `w' = [w'_0, w'_1, ... ]`
        let negative_wrong_modulus_decomposed: [N; NUMBER_OF_LIMBS] = decompose_big(
            binary_modulus - wrong_modulus.clone(),
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
        )
        .try_into()
        .unwrap();
        // `w = [w_0, w_1, ... ]`
        let wrong_modulus_decomposed =
            decompose_big(wrong_modulus.clone(), NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                .try_into()
                .unwrap();
        // Full dense limb without overflow
        let max_reduced_limb = &(one << BIT_LEN_LIMB) - one;
        // Keep this much lower than what we can reduce with single limb quotient to
        // take extra measure for overflow issues
        let max_unreduced_limb = &(one << (BIT_LEN_LIMB + BIT_LEN_LIMB / 2)) - one;

        // Most significant limbs are subjected to different range checks which will be
        // probably less than full sized limbs.
        let max_most_significant_reduced_limb =
            &(max_remainder >> ((NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB));
        let max_most_significant_operand_limb =
            &(max_operand >> ((NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB));
        let max_most_significant_mul_quotient_limb =
            &(max_quotient >> ((NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB));

        // Emulate a multiplication to find out max residue overflows:
        let mut mul_v_bit_len: usize = BIT_LEN_LIMB;
        {
            // Maximum operand
            let a = (0..NUMBER_OF_LIMBS)
                .map(|i| {
                    if i != NUMBER_OF_LIMBS - 1 {
                        max_reduced_limb.clone()
                    } else {
                        max_most_significant_operand_limb.clone()
                    }
                })
                .collect::<Vec<Big>>();

            let p: Vec<Big> = negative_wrong_modulus_decomposed
                .iter()
                .map(|e| fe_to_big(*e))
                .collect();

            // Maximum quotient
            let q = (0..NUMBER_OF_LIMBS)
                .map(|i| {
                    if i != NUMBER_OF_LIMBS - 1 {
                        max_reduced_limb.clone()
                    } else {
                        max_most_significant_mul_quotient_limb.clone()
                    }
                })
                .collect::<Vec<Big>>();

            // Find intermediate maximums
            let mut t = vec![Big::zero(); 2 * NUMBER_OF_LIMBS - 1];
            for i in 0..NUMBER_OF_LIMBS {
                for j in 0..NUMBER_OF_LIMBS {
                    t[i + j] = &t[i + j] + &a[i] * &a[j] + &p[i] * &q[j];
                }
            }
            let is_odd = NUMBER_OF_LIMBS & 1 == 1;
            let u_len = (NUMBER_OF_LIMBS + 1) / 2;

            let mut carry = Big::zero();
            for i in 0..u_len {
                let v = if (i == u_len - 1) && is_odd {
                    // odd and last iter
                    let u = &t[i] + &carry;
                    u >> BIT_LEN_LIMB
                } else {
                    let u = &t[i] + (&t[i + 1] << BIT_LEN_LIMB) + &carry;
                    u >> (2 * BIT_LEN_LIMB)
                };
                carry = v.clone();
                mul_v_bit_len = std::cmp::max(v.bits() as usize, mul_v_bit_len)
            }
        };
        // Emulate a multiplication to find out max residue overflows:
        let mut red_v_bit_len: usize = BIT_LEN_LIMB;
        {
            // Maximum operand
            let a = (0..NUMBER_OF_LIMBS)
                .map(|i| {
                    if i != NUMBER_OF_LIMBS - 1 {
                        max_reduced_limb.clone()
                    } else {
                        max_most_significant_operand_limb.clone()
                    }
                })
                .collect::<Vec<Big>>();

            let p: Vec<Big> = negative_wrong_modulus_decomposed
                .iter()
                .map(|e| fe_to_big(*e))
                .collect();

            // Maximum quorient
            let q = (0..NUMBER_OF_LIMBS)
                .map(|i| {
                    if i != NUMBER_OF_LIMBS - 1 {
                        max_reduced_limb.clone()
                    } else {
                        max_most_significant_mul_quotient_limb.clone()
                    }
                })
                .collect::<Vec<Big>>();

            // Find intermediate maximums
            let mut t = vec![Big::zero(); 2 * NUMBER_OF_LIMBS - 1];
            for i in 0..NUMBER_OF_LIMBS {
                for j in 0..NUMBER_OF_LIMBS {
                    t[i + j] = &t[i + j] + &a[i] + &p[i] * &q[j];
                }
            }

            let is_odd = NUMBER_OF_LIMBS & 1 == 1;
            let u_len = (NUMBER_OF_LIMBS + 1) / 2;

            let mut carry = Big::zero();
            for i in 0..u_len {
                let v = if (i == u_len - 1) && is_odd {
                    // odd and last iter
                    let u = &t[i] + &carry;
                    u >> BIT_LEN_LIMB
                } else {
                    let u = &t[i] + (&t[i + 1] << BIT_LEN_LIMB) + &carry;
                    u >> (2 * BIT_LEN_LIMB)
                };
                carry = v.clone();
                red_v_bit_len = std::cmp::max(v.bits() as usize, red_v_bit_len)
            }
        };
        // Calculate auxillary value for subtraction
        let base_aux = Self::calculate_base_aux();
        // Sanity check for auxillary value
        {
            let base_aux_value = compose_big(base_aux.to_vec(), BIT_LEN_LIMB);
            // Must be equal to wrong modulus
            assert!(base_aux_value.clone() % wrong_modulus == Big::zero());
            // Expected to be above next power of two
            assert!(base_aux_value > *max_remainder);
            // Assert limbs are above max values
            for (i, aux) in base_aux.iter().enumerate() {
                let is_last_limb = i == NUMBER_OF_LIMBS - 1;
                let target = if is_last_limb {
                    max_most_significant_reduced_limb.clone()
                } else {
                    max_reduced_limb.clone()
                };
                assert!(*aux >= target);
            }
        }
        let wrong_modulus_in_native_modulus: N =
            big_to_fe(wrong_modulus.clone() % native_modulus.clone());

        // Calculate shifter elements
        let two = N::from(2);
        // Left shifts field element by `u * BIT_LEN_LIMB` bits
        let left_shifters = (0..NUMBER_OF_LIMBS)
            .map(|i| two.pow(&[(i * BIT_LEN_LIMB) as u64, 0, 0, 0]))
            .collect::<Vec<N>>()
            .try_into()
            .unwrap();

        // let rns = Rns {
        Self {
            left_shifters,
            wrong_modulus: wrong_modulus.clone(),
            native_modulus: native_modulus.clone(),
            base_aux,
            negative_wrong_modulus_decomposed,
            wrong_modulus_decomposed,
            wrong_modulus_in_native_modulus,
            max_reduced_limb,
            max_unreduced_limb,
            max_remainder: max_remainder.clone(),
            max_operand: max_operand.clone(),
            max_most_significant_reduced_limb: max_most_significant_reduced_limb.clone(),
            max_most_significant_operand_limb: max_most_significant_operand_limb.clone(),
            max_most_significant_mul_quotient_limb: max_most_significant_mul_quotient_limb.clone(),
            mul_v_bit_len,
            red_v_bit_len,
            _marker_wrong: PhantomData,
        }
        // Another sanity check for maximum reducible value:
        // TODO: uncomment
        // {
        //     let max_with_max_unreduced_limbs = &[big_to_fe(max_unreduced_limb); NUMBER_OF_LIMBS];
        //     let max_with_max_unreduced =
        //         Integer::from_limbs(max_with_max_unreduced_limbs, Rc::new(rns.clone()));
        //     let reduction_result = max_with_max_unreduced.reduction_witness();
        //     let quotient = match reduction_result.quotient {
        //         Quotient::Short(quotient) => quotient,
        //         _ => panic!("short quotient is expected"),
        //     };
        //     let quotient = fe_to_big(quotient);
        //     assert!(quotient < max_reduced_limb);
        // }

        // rns
    }
    /// Left shifters by limb size
    pub(crate) fn left_shifter(&self, i: usize) -> N {
        self.left_shifters[i]
    }
    /// Computes the overflow that each component of the [`Rns`] must support.
    // TODO: consider soundness of only single overflow length
    pub fn overflow_lengths(&self) -> Vec<usize> {
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_SUBLIMBS;
        // Assert that bit length of limbs is divisible by sub limbs for lookup
        assert!(bit_len_lookup * NUMBER_OF_SUBLIMBS == BIT_LEN_LIMB);
        let max_most_significant_mul_quotient_limb_size =
            self.max_most_significant_mul_quotient_limb.bits() as usize % bit_len_lookup;
        let max_most_significant_operand_limb_size =
            self.max_most_significant_operand_limb.bits() as usize % bit_len_lookup;
        let max_most_significant_reduced_limb_size =
            self.max_most_significant_reduced_limb.bits() as usize % bit_len_lookup;
        vec![
            self.mul_v_bit_len % bit_len_lookup,
            self.red_v_bit_len % bit_len_lookup,
            max_most_significant_mul_quotient_limb_size,
            max_most_significant_operand_limb_size,
            max_most_significant_reduced_limb_size,
        ]
    }
    pub(crate) fn max_values(
        &self,
        range: Range,
    ) -> ([Big; NUMBER_OF_LIMBS], [usize; NUMBER_OF_LIMBS]) {
        let mut bit_lenghts = match range {
            Range::Unreduced => vec![self.max_unreduced_limb.bits() as usize; NUMBER_OF_LIMBS - 1],
            _ => vec![BIT_LEN_LIMB; NUMBER_OF_LIMBS - 1],
        };
        bit_lenghts.push(
            (match range {
                Range::Remainder => self.max_most_significant_reduced_limb.bits(),
                Range::Operand => self.max_most_significant_operand_limb.bits(),
                Range::MulQuotient => self.max_most_significant_mul_quotient_limb.bits(),
                Range::Unreduced => self.max_unreduced_limb.bits(),
            }) as usize,
        );
        let max_values = bit_lenghts
            .iter()
            .map(|b| (Big::one() << b) - 1usize)
            .collect::<Vec<Big>>()
            .try_into()
            .unwrap();
        (max_values, bit_lenghts.try_into().unwrap())
    }
    pub(crate) fn subtracion_aux(
        &self,
        max_vals: &[Big; NUMBER_OF_LIMBS],
    ) -> ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut max_shift = 0usize;
        for (max_val, aux) in max_vals.iter().zip(self.base_aux.iter()) {
            let mut shift = 1;
            let mut aux = aux.clone();
            while *max_val > aux {
                aux <<= 1usize;
                max_shift = std::cmp::max(shift, max_shift);
                shift += 1;
            }
        }
        let aux: Vec<N> = self
            .base_aux
            .iter()
            .map(|aux_limb| big_to_fe(aux_limb << max_shift))
            .collect::<Vec<N>>();
        ConstantInteger::new(&aux.try_into().unwrap())
    }
    pub fn from_big(&self, e: Value<Big>) -> Value<[N; NUMBER_OF_LIMBS]> {
        // let (max_values, _) = self.max_values(range);
        let limbs: Value<[N; NUMBER_OF_LIMBS]> = e.map(|e| {
            decompose_big::<N>(e, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                .try_into()
                .unwrap()
        });
        limbs
    }
    pub fn constant(&self, e: W) -> ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let limbs = decompose(e, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
            .try_into()
            .unwrap();
        ConstantInteger::new(&limbs)
    }
    pub fn from_fe(&self, e: Value<W>) -> Value<[N; NUMBER_OF_LIMBS]> {
        self.from_big(e.map(|e| fe_to_big(e)))
    }
}
