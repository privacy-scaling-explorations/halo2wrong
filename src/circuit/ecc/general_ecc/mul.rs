use super::AssignedPoint;
use crate::circuit::ecc::general_ecc::{GeneralEccChip, GeneralEccInstruction};
use crate::circuit::AssignedInteger;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::{
    halo2,
    utils::{big_to_fe, fe_to_big},
    Assigned, AssignedCondition, CombinationOptionCommon, MainGateInstructions, Term,
};
use num_bigint::BigUint as big_uint;
use num_integer::Integer;

struct ScalarTuple<F: FieldExt> {
    h: AssignedCondition<F>,
    l: AssignedCondition<F>,
}

impl<Emulated: CurveAffine, F: FieldExt> GeneralEccChip<Emulated, F> {
    fn decompose(
        &self,
        region: &mut Region<'_, F>,
        input: AssignedInteger<F>,
        offset: &mut usize,
    ) -> Result<(AssignedCondition<F>, Vec<ScalarTuple<F>>), Error> {
        // Algorithm's limitation.
        assert!(input.bit_len_limb % 2 == 0);

        let zero = F::zero();
        let one = F::one();
        let two = F::from(2u64);
        let four = F::from(4u64);
        let main_gate = self.main_gate();

        let mut res = Vec::with_capacity(NUMBER_OF_LIMBS * input.bit_len_limb / 2);
        let mut limb_carry_bits: Vec<AssignedCondition<F>> = vec![];

        // For each two bits,
        // b00: 0
        // b01: 1
        // b10: 2
        // b11: -1
        //
        // d_next * 4 + lb + lh * 2 - lb * lh * 4 = d_curr
        //
        // Witness layout:
        // | A   | B   | C     | D  |
        // | --- | --- | ----- | -- |
        // | lb0 | hb0 | limb0 | 0  |
        // | lb1 | hb1 | 0     | d1 |
        // | lb2 | hb2 | 0     | d2 |
        // ...
        //
        // On next limb
        // | lb0' | hb0' | limb1 | d0' |
        // | lb1' | hb1' | 0     | d1' |
        // | lb2' | hb2' | 0     | d2' |
        // ...
        //
        // At last
        // | lbn | hbn | 0 | dn |
        // | 0   | 0   | 0 | d  |

        let mut rem = big_uint::from(0u64);

        for idx in 0..NUMBER_OF_LIMBS {
            let last_limb_rem = rem.clone();
            rem = match input.limb(idx).value() {
                Some(v) => rem + fe_to_big(v),
                _ => rem,
            };

            for i in 0..(input.bit_len_limb / 2) {
                let shift = |rem: big_uint, carry| {
                    if rem.is_odd() {
                        (rem >> 1, one.clone(), carry)
                    } else {
                        (rem >> 1, zero.clone(), 0u64)
                    }
                };

                let d = if i == 0 { big_to_fe(last_limb_rem.clone()) } else { big_to_fe(rem.clone()) };
                let carry = 1u64;
                let (rem_shifted, a, carry) = shift(rem, carry);
                let (rem_shifted, b, carry) = shift(rem_shifted, carry);
                rem = rem_shifted + carry;

                let (l, h, _, _, limb_carry_bit) = main_gate.combine(
                    region,
                    [
                        Term::Unassigned(Some(a), one),
                        Term::Unassigned(Some(b), two),
                        if i == 0 { Term::Assigned(&input.limbs[idx], -one) } else { Term::Zero },
                        Term::Zero,
                        Term::Unassigned(Some(d), -one),
                    ],
                    zero,
                    offset,
                    CombinationOptionCommon::CombineToNextScaleMul(four, -four).into(),
                )?;

                res.push(ScalarTuple { h: h.into(), l: l.into() });

                if idx != 0 && i == 0 {
                    limb_carry_bits.push(limb_carry_bit.into());
                };
            }
        }

        let rem = big_to_fe(rem);
        let rem: AssignedCondition<F> = main_gate.assign_to_acc(region, &Some(rem).into(), offset)?.into();
        limb_carry_bits.push(rem.clone());

        for limb_carry_bit in limb_carry_bits.iter() {
            main_gate.assert_bit(region, limb_carry_bit.clone(), offset)?;
        }

        for x in res.iter() {
            main_gate.assert_bit(region, x.h.clone(), offset)?;
            main_gate.assert_bit(region, x.l.clone(), offset)?;
        }

        Ok((rem, res))
    }

    pub(crate) fn _mul_var(
        &self,
        region: &mut Region<'_, F>,
        p: AssignedPoint<F>,
        e: AssignedInteger<F>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<F>, Error> {
        let p_neg = self.neg(region, &p, offset)?;
        let p_double = self.double(region, &p, offset)?;
        let (rem, selector) = self.decompose(region, e, offset)?;
        let mut acc = self.select_or_assign(region, &rem, &p, Emulated::identity(), offset)?;

        for di in selector.iter().rev() {
            // 0b01 - p, 0b00 - identity
            let b0 = self.select_or_assign(region, &di.l, &p, Emulated::identity(), offset)?;
            // 0b11 - p_neg, 0b10 - p_double
            let b1 = self.select(region, &di.l, &p_neg, &p_double, offset)?;
            let a = self.select(region, &di.h, &b1, &b0, offset)?;

            acc = self.double(region, &acc, offset)?;
            acc = self.double(region, &acc, offset)?;
            acc = self.add(region, &acc, &a, offset)?;
        }

        Ok(acc)
    }
}
