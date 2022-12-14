use super::{chip::IntegerChip, ConstantInteger, Integer};
use crate::utils::{big_to_fe, decompose_big, fe_to_big};
use halo2::{circuit::Value, halo2curves::FieldExt};
use num_bigint::BigUint as Big;
use num_integer::Integer as _;
use num_traits::{One, Zero};

mod add;
mod assert_not_zero;
mod assign;
mod mul;
mod reduce;

impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn reduce_if_limbs_gt_unreduced(
        &mut self,

        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let exceeds_max_limb_value = a
            .limbs
            .iter()
            .any(|limb| limb.max() > self.rns.max_unreduced_limb);
        #[cfg(feature = "sanity-check")]
        {
            // Sanity check for completeness

            // Reduction quotient is limited upto a dense single limb. It is quite possible
            // to make it more than a single limb. However even single limb will
            // support quite amount of lazy additions and make reduction process
            // much easier.
            let max_reduction_quotient = self.rns.max_reduced_limb.clone();
            let max_reducible_value =
                max_reduction_quotient * &self.rns.wrong_modulus + &self.rns.max_remainder;
            assert!(a.max() < max_reducible_value);
        }
        if exceeds_max_limb_value {
            #[cfg(test)]
            {
                self.report.n_reduce_limbs_gt_unreduced += 1;
            }
            self._reduce(a)
        } else {
            a.clone()
        }
    }
    pub(crate) fn reduce_if_limbs_gt_reduced(
        &mut self,

        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let exceeds_max_limb_value = a
            .limbs
            .iter()
            .any(|limb| limb.max() > self.rns.max_reduced_limb);
        if exceeds_max_limb_value {
            #[cfg(test)]
            {
                self.report.n_reduce_limbs_gt_reduced += 1;
            }
            self._reduce(a)
        } else {
            a.clone()
        }
    }
    pub(crate) fn reduce_if_gt_max_operand(
        &mut self,

        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        if a.max() > self.rns.max_operand {
            #[cfg(test)]
            {
                self.report.n_reduce_value_gt_operand += 1;
            }
            self._reduce(a)
        } else {
            a.clone()
        }
    }
    pub(crate) fn reduction_witness(
        &self,
        w: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> (Value<[N; NUMBER_OF_LIMBS]>, Value<N>) {
        w.big()
            .map(|w| {
                let (quotient, result) = w.div_rem(&self.rns.wrong_modulus);
                assert!(quotient < Big::one() << BIT_LEN_LIMB);
                let quotient: N = big_to_fe(quotient);
                let result: [N; NUMBER_OF_LIMBS] =
                    decompose_big(result, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                        .try_into()
                        .unwrap();
                (result, quotient)
            })
            .unzip()
    }
    pub(crate) fn multiplication_witness(
        &self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> (Value<[N; NUMBER_OF_LIMBS]>, Value<[N; NUMBER_OF_LIMBS]>) {
        w0.big()
            .zip(w1.big())
            .map(|(w0, w1)| {
                let (quotient, result) = (w0 * w1).div_rem(&self.rns.wrong_modulus);
                let result: [N; NUMBER_OF_LIMBS] =
                    decompose_big(result, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                        .try_into()
                        .unwrap();
                let quotient: [N; NUMBER_OF_LIMBS] =
                    decompose_big(quotient, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                        .try_into()
                        .unwrap();
                (result, quotient)
            })
            .unzip()
    }
    pub(crate) fn division_witness(
        &self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> (Value<[N; NUMBER_OF_LIMBS]>, Value<[N; NUMBER_OF_LIMBS]>) {
        let modulus = &self.rns.wrong_modulus.clone();
        w0.big()
            .zip(w1.big())
            .map(|(w0, w1)| {
                let w1_inv = big_to_fe::<W>(w1.clone()).invert().unwrap();
                let w1_inv = fe_to_big(w1_inv);
                let result = (w1_inv * &w0) % modulus;
                let (quotient, reduced_w0) = (&w1 * &result).div_rem(modulus);
                let (k, must_be_zero) = (&w0 - &reduced_w0).div_rem(modulus);
                assert_eq!(must_be_zero, Big::zero());
                let result: [N; NUMBER_OF_LIMBS] =
                    decompose_big(result, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                        .try_into()
                        .unwrap();
                let quotient: [N; NUMBER_OF_LIMBS] =
                    decompose_big(quotient - k, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                        .try_into()
                        .unwrap();
                (result, quotient)
            })
            .unzip()
    }
    pub(crate) fn constant_multiplication_witness(
        &self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> (Value<[N; NUMBER_OF_LIMBS]>, Value<[N; NUMBER_OF_LIMBS]>) {
        w0.big()
            .map(|w0| {
                let (quotient, result) = (w0 * w1.big()).div_rem(&self.rns.wrong_modulus);
                let result: [N; NUMBER_OF_LIMBS] =
                    decompose_big(result, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                        .try_into()
                        .unwrap();
                let quotient: [N; NUMBER_OF_LIMBS] =
                    decompose_big(quotient, NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                        .try_into()
                        .unwrap();
                (result, quotient)
            })
            .unzip()
    }
}
