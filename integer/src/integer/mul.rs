use super::{IntegerChip, IntegerInstructions, Range};
use crate::rns::{Common, Integer, MaybeReduced};
use crate::{AssignedInteger, WrongExt, NUMBER_OF_LIMBS};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::Assigned;
use maingate::{halo2, AssignedValue, CombinationOptionCommon, MainGateInstructions, RangeInstructions, RegionCtx, Term};

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _mul(&self, ctx: &mut RegionCtx<'_, '_, N>, a: &AssignedInteger<W, N>, b: &AssignedInteger<W, N>) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let reduction_witness: MaybeReduced<W, N> = match (a.integer(), b.integer()) {
            (Some(a_int), Some(b_int)) => Some(a_int.mul(&b_int)),
            _ => None,
        }
        .into();

        let quotient = reduction_witness.long();
        let result = reduction_witness.result();
        let (t_0, t_1, t_2, t_3) = reduction_witness.intermediate_values();
        let intermediate_values = vec![t_0, t_1, t_2, t_3];
        let (u_0, u_1, v_0, v_1) = reduction_witness.residues();

        // Apply ranges
        let range_chip = self.range_chip();
        let quotient = &self.range_assign_integer(ctx, quotient.into(), Range::MulQuotient)?;
        let result = &self.range_assign_integer(ctx, result.into(), Range::Remainder)?;
        let v_0 = &range_chip.range_value(ctx, &v_0.into(), self.rns.mul_v0_bit_len)?;
        let v_1 = &range_chip.range_value(ctx, &v_1.into(), self.rns.mul_v1_bit_len)?;

        // Constaints:

        // t_0 = a_0 * b_0 + q_0 * p_0

        // t_1 =    a_0 * b_1 + a_1 * b_0 + q_0 * p_1 + q_1 * p_0
        // constained as:
        // t_1 =    a_0 * b_1 + q_0 * p_1 + tmp
        // tmp =    a_1 * b_0 + q_1 * p_0

        // t_2   =    a_0 * b_2 + a_1 * b_1 + a_2 * b_0 + q_0 * p_2 + q_1 * p_1 + q_2 * p_0
        // constained as:
        // t_2   =    a_0 * b_2 + q_0 * p_2 + tmp_a
        // tmp_a =    a_1 * b_1 + q_1 * p_1 + tmp_b
        // tmp_b =    a_2 * b_0 + q_2 * p_0

        // t_3   =    a_0 * b_3 + a_1 * b_2 + a_1 * b_2 + a_3 * b_0 + q_0 * p_3 + q_1 * p_2 + q_2 * p_1 + q_3 * p_0
        // constained as:
        // t_3   =    a_0 * b_3 + q_0 * p_3 + tmp_a
        // tmp_a =    a_1 * b_2 + q_1 * p_2 + tmp_b
        // tmp_b =    a_2 * b_1 + q_2 * p_1 + tmp_c
        // tmp_c =    a_3 * b_0 + q_3 * p_0

        // Witness layout:
        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | b_0 | q_0 | t_0   |

        // | a_0 | b_1 | q_1 | t_1   |
        // | a_1 | b_0 | q_0 | tmp   |

        // | a_0 | b_2 | q_2 | t_2   |
        // | a_1 | b_1 | q_1 | tmp_a |
        // | a_2 | b_0 | q_0 | tmp_b |

        // | a_0 | b_3 | q_3 | t_3   |
        // | a_1 | b_2 | q_2 | tmp_b |
        // | a_2 | b_1 | q_1 | tmp_a |
        // | a_3 | b_0 | q_0 | tmp_c |

        let mut intermediate_values_cycling: Vec<AssignedValue<N>> = vec![];

        for i in 0..NUMBER_OF_LIMBS {
            let mut intermediate_value = intermediate_values[i];

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOptionCommon::OneLinerMul
                } else {
                    CombinationOptionCommon::CombineToNextMul(one)
                }
                .into();

                let (_, _, _, _, t) = main_gate.combine(
                    ctx,
                    [
                        Term::Assigned(&a.limb(j), zero),
                        Term::Assigned(&b.limb(k), zero),
                        Term::Assigned(&quotient.limb(k), negative_wrong_modulus[j]),
                        Term::Zero,
                        Term::Unassigned(intermediate_value, -one),
                    ],
                    zero,
                    combination_option,
                )?;

                if j == 0 {
                    // first time we see t_j assignment
                    intermediate_values_cycling.push(t);
                }

                // update running temp value
                intermediate_value = intermediate_value.map(|t| {
                    let a = a.limb(j).value().unwrap();
                    let b = b.limb(k).value().unwrap();
                    let q = quotient.limb(k).value().unwrap();
                    let p = negative_wrong_modulus[j];
                    t - (a * b + q * p)
                });
            }
        }

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&intermediate_values_cycling[0].clone(), one),
                Term::Assigned(&intermediate_values_cycling[1].clone(), left_shifter_r),
                Term::Assigned(&result.limbs[0].clone(), -one),
                Term::Zero,
                Term::Assigned(&result.limbs[1].clone(), -left_shifter_r),
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            ctx,
            [
                Term::Zero,
                Term::Zero,
                Term::Assigned(v_0, left_shifter_2r),
                Term::Zero,
                Term::Unassigned(u_0, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&intermediate_values_cycling[2].clone(), one),
                Term::Assigned(&intermediate_values_cycling[3].clone(), left_shifter_r),
                Term::Assigned(&result.limbs[2].clone(), -one),
                Term::Zero,
                Term::Assigned(&result.limbs[3].clone(), -left_shifter_r),
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            ctx,
            [
                Term::Zero,
                Term::Assigned(v_1, left_shifter_2r),
                Term::Assigned(v_0, -one),
                Term::Zero,
                Term::Unassigned(u_1, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // update native value

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.native(), zero),
                Term::Assigned(&b.native(), zero),
                Term::Assigned(&quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Zero,
                Term::Assigned(&result.native(), -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(result.clone())
    }

    pub(crate) fn _mul_constant(&self, ctx: &mut RegionCtx<'_, '_, N>, a: &AssignedInteger<W, N>, b: &Integer<W, N>) -> Result<AssignedInteger<W, N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let a_int = a.integer();
        let reduction_witness: MaybeReduced<W, N> = a_int.map(|a_int| a_int.mul(b)).into();
        let quotient = reduction_witness.long();
        let result = reduction_witness.result();
        let (t_0, t_1, t_2, t_3) = reduction_witness.intermediate_values();
        let (u_0, u_1, v_0, v_1) = reduction_witness.residues();

        // Apply ranges
        let range_chip = self.range_chip();
        let quotient = &self.range_assign_integer(ctx, quotient.into(), Range::MulQuotient)?;
        let result = &self.range_assign_integer(ctx, result.into(), Range::Remainder)?;
        let v_0 = &range_chip.range_value(ctx, &v_0.into(), self.rns.mul_v0_bit_len)?;
        let v_1 = &range_chip.range_value(ctx, &v_1.into(), self.rns.mul_v1_bit_len)?;

        // Witness layout:
        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | q_0 | -   | t_0   |

        // | a_0 | a_1 | q_0 | q_1   |
        // | -   | -   | -   | t_1   |

        // | a_0 | a_1 | a_2 | t_2   |
        // | q_0 | q_1 | q_2 | tmp   |

        // | a_0 | a_1 | a_2 | t_3   |
        // | a_3 | q_0 | q_1 | tmp_a |
        // | q_2 | q_3 | -   | tmp_b |

        let b_native = b.native();
        let b = b.limbs();

        // t0

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | a_0 | q_0 | -   | t_0 |

        let (_, _, _, _, t_0) = main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.limb(0), b[0]),
                Term::Assigned(&quotient.limb(0), negative_wrong_modulus[0]),
                Term::Zero,
                Term::Zero,
                Term::Unassigned(t_0, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // t1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | a_0 | a_1 | q_0 | q_1 |
        // | -   | -   | -   | t_1 |

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.limb(0), b[1]),
                Term::Assigned(&a.limb(1), b[0]),
                Term::Assigned(&quotient.limb(0), negative_wrong_modulus[1]),
                Term::Assigned(&quotient.limb(1), negative_wrong_modulus[0]),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        let t_1 = main_gate.assign_to_acc(ctx, &t_1.into())?;

        // t2

        // | A   | B   | C   | D    |
        // | --- | --- | --- | ---- |
        // | a_0 | a_1 | a_2 | t_2  |
        // | q_0 | q_1 | q_2 | tmp  |

        let tmp = t_2.map(|_| {
            let p = negative_wrong_modulus.clone();
            let q_0 = quotient.limb(0).value().unwrap();
            let q_1 = quotient.limb(1).value().unwrap();
            let q_2 = quotient.limb(2).value().unwrap();

            q_0 * p[2] + q_1 * p[1] + q_2 * p[0]
        });

        let (_, _, _, _, t_2) = main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.limb(0), b[2]),
                Term::Assigned(&a.limb(1), b[1]),
                Term::Assigned(&a.limb(2), b[0]),
                Term::Zero,
                Term::Unassigned(t_2, -one),
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(one).into(),
        )?;

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&quotient.limb(0), negative_wrong_modulus[2]),
                Term::Assigned(&quotient.limb(1), negative_wrong_modulus[1]),
                Term::Assigned(&quotient.limb(2), negative_wrong_modulus[0]),
                Term::Zero,
                Term::Unassigned(tmp, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | a_1 | a_2 | t_3   |
        // | a_3 | q_0 | q_1 | tmp_a |
        // | q_2 | q_3 | -   | tmp_b |

        let (tmp_a, tmp_b) = match t_3 {
            Some(t_3) => {
                let p = negative_wrong_modulus.clone();
                let a = a.integer().unwrap().limbs();
                let q = quotient.integer().unwrap().limbs();
                let tmp_a = t_3 - a[0] * b[3] - a[1] * b[2] - a[2] * b[1];
                let tmp_b = tmp_a - a[3] * b[0] - q[0] * p[3] - q[1] * p[2];

                (Some(tmp_a), Some(tmp_b))
            }
            None => (None, None),
        };
        let (_, _, _, t_3, _) = main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.limb(0), b[3]),
                Term::Assigned(&a.limb(1), b[2]),
                Term::Assigned(&a.limb(2), b[1]),
                Term::Unassigned(t_3, -one),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(one).into(),
        )?;

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.limb(3), b[0]),
                Term::Assigned(&quotient.limb(0), negative_wrong_modulus[3]),
                Term::Assigned(&quotient.limb(1), negative_wrong_modulus[2]),
                Term::Zero,
                Term::Unassigned(tmp_a, -one),
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(one).into(),
        )?;

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&quotient.limb(2), negative_wrong_modulus[1]),
                Term::Assigned(&quotient.limb(3), negative_wrong_modulus[0]),
                Term::Zero,
                Term::Zero,
                Term::Unassigned(tmp_b, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&t_0, one),
                Term::Assigned(&t_1, left_shifter_r),
                Term::Assigned(&result.limbs[0].clone(), -one),
                Term::Assigned(&result.limbs[1].clone(), -left_shifter_r),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            ctx,
            [
                Term::Zero,
                Term::Zero,
                Term::Assigned(v_0, left_shifter_2r),
                Term::Zero,
                Term::Unassigned(u_0, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&t_2, one),
                Term::Assigned(&t_3, left_shifter_r),
                Term::Assigned(&result.limbs[2].clone(), -one),
                Term::Assigned(&result.limbs[3].clone(), -left_shifter_r),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::CombineToNextAdd(-one).into(),
        )?;

        main_gate.combine(
            ctx,
            [
                Term::Zero,
                Term::Assigned(v_1, left_shifter_2r),
                Term::Assigned(v_0, -one),
                Term::Zero,
                Term::Unassigned(u_1, -one),
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // update native value

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.native(), b_native),
                Term::Zero,
                Term::Assigned(&quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Assigned(&result.native(), -one),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(result.clone())
    }

    pub(crate) fn _mul_into_one(&self, ctx: &mut RegionCtx<'_, '_, N>, a: &AssignedInteger<W, N>, b: &AssignedInteger<W, N>) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let reduction_witness: MaybeReduced<W, N> = match (a.integer(), b.integer()) {
            (Some(a_int), Some(b_int)) => Some(a_int.mul(&b_int)),
            _ => None,
        }
        .into();

        let quotient = reduction_witness.long();
        let (t_0, t_1, t_2, t_3) = reduction_witness.intermediate_values();
        let intermediate_values = vec![t_0, t_1, t_2, t_3];
        let (_, _, v_0, v_1) = reduction_witness.residues();

        // Apply ranges
        let range_chip = self.range_chip();
        let quotient = &self.range_assign_integer(ctx, quotient.into(), Range::MulQuotient)?;
        let v_0 = &range_chip.range_value(ctx, &v_0.into(), self.rns.mul_v0_bit_len)?;
        let v_1 = &range_chip.range_value(ctx, &v_1.into(), self.rns.mul_v1_bit_len)?;

        // Constaints:

        // t_0 = a_0 * b_0 + q_0 * p_0

        // t_1 =    a_0 * b_1 + a_1 * b_0 + q_0 * p_1 + q_1 * p_0
        // constained as:
        // t_1 =    a_0 * b_1 + q_0 * p_1 + tmp
        // tmp =    a_1 * b_0 + q_1 * p_0

        // t_2   =    a_0 * b_2 + a_1 * b_1 + a_2 * b_0 + q_0 * p_2 + q_1 * p_1 + q_2 * p_0
        // constained as:
        // t_2   =    a_0 * b_2 + q_0 * p_2 + tmp_a
        // tmp_a =    a_1 * b_1 + q_1 * p_1 + tmp_b
        // tmp_b =    a_2 * b_0 + q_2 * p_0

        // t_3   =    a_0 * b_3 + a_1 * b_2 + a_1 * b_2 + a_3 * b_0 + q_0 * p_3 + q_1 * p_2 + q_2 * p_1 + q_3 * p_0
        // constained as:
        // t_3   =    a_0 * b_3 + q_0 * p_3 + tmp_a
        // tmp_a =    a_1 * b_2 + q_1 * p_2 + tmp_b
        // tmp_b =    a_2 * b_1 + q_2 * p_1 + tmp_c
        // tmp_c =    a_3 * b_0 + q_3 * p_0

        // Witness layout:
        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | b_0 | q_0 | t_0   |

        // | a_0 | b_1 | q_1 | t_1   |
        // | a_1 | b_0 | q_0 | tmp   |

        // | a_0 | b_2 | q_2 | t_2   |
        // | a_1 | b_1 | q_1 | tmp_a |
        // | a_2 | b_0 | q_0 | tmp_b |

        // | a_0 | b_3 | q_3 | t_3   |
        // | a_1 | b_2 | q_2 | tmp_b |
        // | a_2 | b_1 | q_1 | tmp_a |
        // | a_3 | b_0 | q_0 | tmp_c |

        let mut intermediate_values_cycling: Vec<AssignedValue<N>> = vec![];

        for i in 0..NUMBER_OF_LIMBS {
            let mut t = intermediate_values[i];

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOptionCommon::OneLinerMul
                } else {
                    CombinationOptionCommon::CombineToNextMul(one)
                }
                .into();

                let (_, _, _, _, t_i) = main_gate.combine(
                    ctx,
                    [
                        Term::Assigned(&a.limb(j), zero),
                        Term::Assigned(&b.limb(k), zero),
                        Term::Assigned(&quotient.limb(k), negative_wrong_modulus[j]),
                        Term::Zero,
                        Term::Unassigned(t, -one),
                    ],
                    zero,
                    combination_option,
                )?;

                if j == 0 {
                    // first time we see t_j assignment
                    intermediate_values_cycling.push(t_i);
                }

                // update running temp value
                t = t.map(|t| {
                    let a = a.limb(j).value().unwrap();
                    let b = b.limb(k).value().unwrap();
                    let q = quotient.limb(k).value().unwrap();
                    let p = negative_wrong_modulus[j];
                    t - (a * b + q * p)
                });
            }
        }

        // t_0 + (t_1 * R) - 1 - v_0 * R^2 = 0

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&intermediate_values_cycling[0].clone(), one),
                Term::Assigned(&intermediate_values_cycling[1].clone(), left_shifter_r),
                Term::Assigned(v_0, -left_shifter_2r),
                Term::Zero,
                Term::Zero,
            ],
            -one,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&intermediate_values_cycling[2].clone(), one),
                Term::Assigned(&intermediate_values_cycling[3].clone(), left_shifter_r),
                Term::Assigned(v_0, one),
                Term::Assigned(v_1, -left_shifter_2r),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // update native value

        main_gate.combine(
            ctx,
            [
                Term::Assigned(&a.native(), zero),
                Term::Assigned(&b.native(), zero),
                Term::Assigned(&quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Zero,
                Term::Zero,
            ],
            -one,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(())
    }
}
