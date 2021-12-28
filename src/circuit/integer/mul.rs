use super::{IntegerChip, IntegerInstructions, Range};
use crate::circuit::main_gate::{CombinationOption, MainGateColumn, MainGateInstructions, Term};
use crate::circuit::range::RangeInstructions;
use crate::circuit::{AssignedInteger, AssignedValue};
use crate::rns::{Common, Integer, Quotient};
use crate::NUMBER_OF_LIMBS;

use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn mul_v0_range_tune(&self) -> usize {
        self.rns.bit_len_limb + self.rns.mul_v0_overflow
    }

    pub(super) fn mul_v1_range_tune(&self) -> usize {
        self.rns.bit_len_limb + self.rns.mul_v1_overflow
    }

    pub(super) fn _mul(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let reduction_result = a.integer().map(|integer_a| {
            let b_integer = b.integer().unwrap();
            self.rns.mul(&integer_a, &b_integer)
        });

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Long(quotient) => quotient,
                _ => panic!("long quotient expected"),
            };
            quotient
        });

        let result = reduction_result.as_ref().map(|u| u.result.clone());
        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.clone());
        let u_0 = reduction_result.as_ref().map(|u| u.u_0);
        let v_0 = reduction_result.as_ref().map(|u| u.v_0);
        let u_1 = reduction_result.as_ref().map(|u| u.u_1);
        let v_1 = reduction_result.as_ref().map(|u| u.v_1);

        // Apply ranges

        let range_chip = self.range_chip();
        let quotient = &self.range_assign_integer(region, quotient.into(), Range::MulQuotient, offset)?;
        let result = &self.range_assign_integer(region, result.into(), Range::Remainder, offset)?;
        let v_0 = &range_chip.range_value(region, &v_0.into(), self.mul_v0_range_tune(), offset)?;
        let v_1 = &range_chip.range_value(region, &v_1.into(), self.mul_v1_range_tune(), offset)?;

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
            let mut t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[i]);

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOption::SingleLinerMul
                } else {
                    CombinationOption::CombineToNextMul(one)
                };

                let (_, _, _, t_i_cell) = main_gate.combine(
                    region,
                    Term::Assigned(&a.limb(j), zero),
                    Term::Assigned(&b.limb(k), zero),
                    Term::Assigned(&quotient.limb(k), negative_wrong_modulus[j]),
                    Term::Unassigned(t, -one),
                    zero,
                    offset,
                    combination_option,
                )?;

                if j == 0 {
                    // first time we see t_j assignment
                    intermediate_values_cycling.push(AssignedValue::<N>::new(t_i_cell, t));
                }

                // update running temp value
                t = t.map(|t| {
                    let a = a.limb_value(j).unwrap();
                    let b = b.limb_value(k).unwrap();
                    let q = quotient.limb_value(k).unwrap();
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

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(&intermediate_values_cycling[0].clone(), one),
            Term::Assigned(&intermediate_values_cycling[1].clone(), left_shifter_r),
            Term::Assigned(&result.limbs[0].clone(), -one),
            Term::Assigned(&result.limbs[1].clone(), -left_shifter_r),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        main_gate.combine(
            region,
            Term::Zero,
            Term::Zero,
            Term::Assigned(v_0, left_shifter_2r),
            Term::Unassigned(u_0, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            region,
            Term::Assigned(&intermediate_values_cycling[2].clone(), one),
            Term::Assigned(&intermediate_values_cycling[3].clone(), left_shifter_r),
            Term::Assigned(&result.limbs[2].clone(), -one),
            Term::Assigned(&result.limbs[3].clone(), -left_shifter_r),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        main_gate.combine(
            region,
            Term::Zero,
            Term::Assigned(v_1, left_shifter_2r),
            Term::Assigned(v_0, -one),
            Term::Unassigned(u_1, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // update native value

        main_gate.combine(
            region,
            Term::Assigned(&a.native(), zero),
            Term::Assigned(&b.native(), zero),
            Term::Assigned(&quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
            Term::Assigned(&result.native(), -one),
            zero,
            offset,
            CombinationOption::SingleLinerMul,
        )?;

        Ok(result.clone())
    }

    pub(crate) fn _mul_constant(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        b: &Integer<N>,
        offset: &mut usize,
    ) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let reduction_result = a.integer().map(|integer_a| self.rns.mul(&integer_a, &b));

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Long(quotient) => quotient,
                _ => panic!("long quotient expected"),
            };
            quotient
        });

        let result = reduction_result.as_ref().map(|u| u.result.clone());
        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.clone());
        let u_0 = reduction_result.as_ref().map(|u| u.u_0);
        let v_0 = reduction_result.as_ref().map(|u| u.v_0);
        let u_1 = reduction_result.as_ref().map(|u| u.u_1);
        let v_1 = reduction_result.as_ref().map(|u| u.v_1);

        // Apply ranges

        let range_chip = self.range_chip();
        let quotient = &self.range_assign_integer(region, quotient.into(), Range::MulQuotient, offset)?;
        let result = &self.range_assign_integer(region, result.into(), Range::Remainder, offset)?;
        let v_0 = &range_chip.range_value(region, &v_0.into(), self.mul_v0_range_tune(), offset)?;
        let v_1 = &range_chip.range_value(region, &v_1.into(), self.mul_v1_range_tune(), offset)?;

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

        assert!(NUMBER_OF_LIMBS == 4);
        let b_native = b.native();
        let b = b.limbs();

        // t0

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | a_0 | q_0 | -   | t_0 |

        let t_0 = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[0]);

        let (_, _, _, t_0_cell) = main_gate.combine(
            region,
            Term::Assigned(&a.limb(0), b[0]),
            Term::Assigned(&quotient.limb(0), negative_wrong_modulus[0]),
            Term::Zero,
            Term::Unassigned(t_0, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        let t_0 = AssignedValue::new(t_0_cell, t_0);

        // t1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | a_0 | a_1 | q_0 | q_1 |
        // | -   | -   | -   | t_1 |

        let t_1 = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[1]);

        main_gate.combine(
            region,
            Term::Assigned(&a.limb(0), b[1]),
            Term::Assigned(&a.limb(1), b[0]),
            Term::Assigned(&quotient.limb(0), negative_wrong_modulus[1]),
            Term::Assigned(&quotient.limb(1), negative_wrong_modulus[0]),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        let t_1 = main_gate.assign_value(region, &t_1.into(), MainGateColumn::D, offset)?;

        // t2

        // | A   | B   | C   | D    |
        // | --- | --- | --- | ---- |
        // | a_0 | a_1 | a_2 | t_2  |
        // | q_0 | q_1 | q_2 | tmp  |

        let t_2 = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[2]);

        let tmp = t_2.map(|_| {
            let p = negative_wrong_modulus.clone();
            let q_0 = quotient.limb_value(0).unwrap();
            let q_1 = quotient.limb_value(1).unwrap();
            let q_2 = quotient.limb_value(2).unwrap();

            q_0 * p[2] + q_1 * p[1] + q_2 * p[0]
        });

        let (_, _, _, t_2_cell) = main_gate.combine(
            region,
            Term::Assigned(&a.limb(0), b[2]),
            Term::Assigned(&a.limb(1), b[1]),
            Term::Assigned(&a.limb(2), b[0]),
            Term::Unassigned(t_2, -one),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(one),
        )?;

        main_gate.combine(
            region,
            Term::Assigned(&quotient.limb(0), negative_wrong_modulus[2]),
            Term::Assigned(&quotient.limb(1), negative_wrong_modulus[1]),
            Term::Assigned(&quotient.limb(2), negative_wrong_modulus[0]),
            Term::Unassigned(tmp, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        let t_2 = AssignedValue::new(t_2_cell, t_2);

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | a_1 | a_2 | t_3   |
        // | a_3 | q_0 | q_1 | tmp_a |
        // | q_2 | q_3 | -   | tmp_b |

        let t_3 = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[3]);

        let (tmp_a, tmp_b) = match t_3 {
            Some(t_3) => {
                let p = negative_wrong_modulus.clone();
                let a_0 = a.limb_value(0).unwrap();
                let a_1 = a.limb_value(1).unwrap();
                let a_2 = a.limb_value(2).unwrap();
                let a_3 = a.limb_value(3).unwrap();
                let q_0 = quotient.limb_value(0).unwrap();
                let q_1 = quotient.limb_value(1).unwrap();
                let q_2 = quotient.limb_value(2).unwrap();
                let q_3 = quotient.limb_value(3).unwrap();

                let tmp_a = t_3 - a_0 * b[3] - a_1 * b[2] - a_2 * b[1];
                let tmp_b = tmp_a - a_3 * b[0] - q_0 * p[3] - q_1 * p[2];

                (Some(tmp_a), Some(tmp_b))
            }
            None => (None, None),
        };

        let (_, _, _, t_3_cell) = main_gate.combine(
            region,
            Term::Assigned(&a.limb(0), b[3]),
            Term::Assigned(&a.limb(1), b[2]),
            Term::Assigned(&a.limb(2), b[1]),
            Term::Unassigned(t_3, -one),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(one),
        )?;

        main_gate.combine(
            region,
            Term::Assigned(&a.limb(3), b[0]),
            Term::Assigned(&quotient.limb(0), negative_wrong_modulus[3]),
            Term::Assigned(&quotient.limb(1), negative_wrong_modulus[2]),
            Term::Unassigned(tmp_a, -one),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(one),
        )?;

        main_gate.combine(
            region,
            Term::Assigned(&quotient.limb(2), negative_wrong_modulus[1]),
            Term::Assigned(&quotient.limb(3), negative_wrong_modulus[0]),
            Term::Zero,
            Term::Unassigned(tmp_b, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        let t_3 = AssignedValue::new(t_3_cell, t_3);

        // u_0 = t_0 + (t_1 * R) - r_0 - (r_1 * R)
        // u_0 = v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | r_0 | r_1   |
        // | -   | -   | v_0 | u_0   |

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(&t_0, one),
            Term::Assigned(&t_1, left_shifter_r),
            Term::Assigned(&result.limbs[0].clone(), -one),
            Term::Assigned(&result.limbs[1].clone(), -left_shifter_r),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        main_gate.combine(
            region,
            Term::Zero,
            Term::Zero,
            Term::Assigned(v_0, left_shifter_2r),
            Term::Unassigned(u_0, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            region,
            Term::Assigned(&t_2, one),
            Term::Assigned(&t_3, left_shifter_r),
            Term::Assigned(&result.limbs[2].clone(), -one),
            Term::Assigned(&result.limbs[3].clone(), -left_shifter_r),
            zero,
            offset,
            CombinationOption::CombineToNextAdd(-one),
        )?;

        main_gate.combine(
            region,
            Term::Zero,
            Term::Assigned(v_1, left_shifter_2r),
            Term::Assigned(v_0, -one),
            Term::Unassigned(u_1, -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // update native value

        main_gate.combine(
            region,
            Term::Assigned(&a.native(), b_native),
            Term::Zero,
            Term::Assigned(&quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
            Term::Assigned(&result.native(), -one),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        Ok(result.clone())
    }

    pub(crate) fn _mul_into_one(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, b: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed.clone();

        let reduction_result = a.integer().map(|integer_a| {
            let b_integer = b.integer().unwrap();
            self.rns.mul(&integer_a, &b_integer)
        });

        let quotient = reduction_result.as_ref().map(|reduction_result| {
            let quotient = match reduction_result.quotient.clone() {
                Quotient::Long(quotient) => quotient,
                _ => panic!("long quotient expected"),
            };
            quotient
        });

        let intermediate_values: Option<Vec<N>> = reduction_result.as_ref().map(|u| u.t.clone());
        let v_0 = reduction_result.as_ref().map(|u| u.v_0);
        let v_1 = reduction_result.as_ref().map(|u| u.v_1);

        // Apply ranges

        let range_chip = self.range_chip();
        let quotient = &self.range_assign_integer(region, quotient.into(), Range::MulQuotient, offset)?;
        // let result = &self.range_assign_integer(region, result.into(), Range::Remainder, offset)?;
        let v_0 = &range_chip.range_value(region, &v_0.into(), self.mul_v0_range_tune(), offset)?;
        let v_1 = &range_chip.range_value(region, &v_1.into(), self.mul_v1_range_tune(), offset)?;

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
            let mut t = intermediate_values.as_ref().map(|intermediate_values| intermediate_values[i]);

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOption::SingleLinerMul
                } else {
                    CombinationOption::CombineToNextMul(one)
                };

                let (_, _, _, t_i_cell) = main_gate.combine(
                    region,
                    Term::Assigned(&a.limb(j), zero),
                    Term::Assigned(&b.limb(k), zero),
                    Term::Assigned(&quotient.limb(k), negative_wrong_modulus[j]),
                    Term::Unassigned(t, -one),
                    zero,
                    offset,
                    combination_option,
                )?;

                if j == 0 {
                    // first time we see t_j assignment
                    intermediate_values_cycling.push(AssignedValue::<N>::new(t_i_cell, t));
                }

                // update running temp value
                t = t.map(|t| {
                    let a = a.limb_value(j).unwrap();
                    let b = b.limb_value(k).unwrap();
                    let q = quotient.limb_value(k).unwrap();
                    let p = negative_wrong_modulus[j];
                    t - (a * b + q * p)
                });
            }
        }

        // t_0 + (t_1 * R) - 1 - v_0 * R^2 = 0

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        let (_, _, _, _) = main_gate.combine(
            region,
            Term::Assigned(&intermediate_values_cycling[0].clone(), one),
            Term::Assigned(&intermediate_values_cycling[1].clone(), left_shifter_r),
            Term::Zero,
            Term::Assigned(v_0, -left_shifter_2r),
            -one,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // u_1 = t_2 + (t_3 * R) - r_2 - (r_3 * R)
        // v_1 * 2R = u_1 + v_0

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | r_2 | r_3   |
        // | -   | v_1 | v_0 | u_1   |

        main_gate.combine(
            region,
            Term::Assigned(&intermediate_values_cycling[2].clone(), one),
            Term::Assigned(&intermediate_values_cycling[3].clone(), left_shifter_r),
            Term::Assigned(v_0, one),
            Term::Assigned(v_1, -left_shifter_2r),
            zero,
            offset,
            CombinationOption::SingleLinerAdd,
        )?;

        // update native value

        main_gate.combine(
            region,
            Term::Assigned(&a.native(), zero),
            Term::Assigned(&b.native(), zero),
            Term::Assigned(&quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
            Term::Zero,
            -one,
            offset,
            CombinationOption::SingleLinerMul,
        )?;

        Ok(())
    }
}
