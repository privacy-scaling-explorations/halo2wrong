use super::{IntegerChip, IntegerInstructions, Range};
use crate::{rns::MaybeReduced, AssignedInteger, PrimeField};
use halo2::{arithmetic::Field, plonk::Error};
use maingate::{
    halo2, AssignedValue, CombinationOptionCommon, MainGateInstructions, RangeInstructions,
    RegionCtx, Term,
};

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    #[allow(clippy::needless_range_loop)]
    pub(super) fn square_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::ZERO, N::ONE);

        let negative_wrong_modulus = self.rns.negative_wrong_modulus_decomposed;

        let a_int = a.integer();

        let witness: MaybeReduced<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
            a_int.map(|a_int| a_int.square()).into();
        let result = witness.result();
        let quotient = witness.long();

        // Apply ranges
        let range_chip = self.range_chip();
        let result = self.assign_integer(ctx, result.into(), Range::Remainder)?;
        let quotient = &self.assign_integer(ctx, quotient.into(), Range::MulQuotient)?;
        let residues = witness
            .residues()
            .iter()
            .map(|v| range_chip.assign(ctx, *v, Self::sublimb_bit_len(), self.rns.mul_v_bit_len))
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        // Follow same witness layout with mul:
        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | a_0 | a_0 | q_0 | t_0   |

        // | a_0 | a_1 | q_1 | t_1   |
        // | a_1 | a_0 | q_0 | tmp   |

        // | a_0 | a_2 | q_2 | t_2   |
        // | a_1 | a_1 | q_1 | tmp_a |
        // | a_2 | a_0 | q_0 | tmp_b |

        // | a_0 | a_3 | q_3 | t_3   |
        // | a_1 | a_2 | q_2 | tmp_b |
        // | a_2 | a_1 | q_1 | tmp_a |
        // | a_3 | a_0 | q_0 | tmp_c |

        let mut t: Vec<AssignedValue<N>> = vec![];

        // Assign intermediate values
        for (i, intermediate_value) in witness.intermediates().into_iter().enumerate() {
            let mut intermediate_value = intermediate_value;

            for j in 0..=i {
                let k = i - j;

                let combination_option = if k == 0 {
                    CombinationOptionCommon::OneLinerMul
                } else {
                    CombinationOptionCommon::CombineToNextMul(one)
                }
                .into();

                let t_i = main_gate
                    .apply(
                        ctx,
                        [
                            Term::Assigned(a.limb(j), zero),
                            Term::Assigned(a.limb(k), zero),
                            Term::Assigned(quotient.limb(k), negative_wrong_modulus[j]),
                            Term::Zero,
                            Term::Unassigned(intermediate_value, -one),
                        ],
                        zero,
                        combination_option,
                    )?
                    .swap_remove(4);

                if j == 0 {
                    // first time we see t_j assignment
                    t.push(t_i);
                }

                // update running temp value
                intermediate_value = intermediate_value
                    .zip(a.limb(j).value())
                    .zip(a.limb(k).value())
                    .zip(quotient.limb(k).value())
                    .map(|(((t, a_j), a_k), q)| {
                        let p = negative_wrong_modulus[j];
                        t - (*a_j * *a_k + *q * p)
                    });

                // Sanity check for the last running subtraction value
                {
                    if j == i {
                        intermediate_value.assert_if_known(Field::is_zero_vartime);
                    }
                }
            }
        }

        // Constrain binary part of crt
        self.constrain_binary_crt(ctx, &t.try_into().unwrap(), &result, residues)?;

        // Constrain native part of crt
        let native = a.native();
        main_gate.apply(
            ctx,
            [
                Term::Assigned(native, zero),
                Term::Assigned(native, zero),
                Term::Assigned(quotient.native(), -self.rns.wrong_modulus_in_native_modulus),
                Term::Assigned(result.native(), -one),
                Term::Zero,
            ],
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(result)
    }
}

// A bit more optimized witness layout that we didn't apply yet is below:
// | A   | B   | C   | D     |
// | --- | --- | --- | ----- |
// | a_0 | a_0 | q_0 | t_0   | t_0 = a_0 * a_0 + q_0 * p_0
// | a_0 | a_1 | q_0 | q_1   | t_1 = 2 * a_0 * a_1 + q_0 * p_1 + q_1 * p_0
// | a_0 | a_2 | q_0 | t_1   | tmp_a = 2 * a_0 * a_2 + q_0 * p_2
// | a_1 | a_1 | q_0 | tmp_a | tmp_b = a_1 * a_1 + q_1 * p_1 + tmp_a
// | t_2 | -   | q_2 | tmp_b | t_2 = tmp_b + q_2 * p_0
// | a_0 | a_3 | q_0 | q_1   | tmp_a = 2 * a_0 * a_3 + q_0 * p_3 + q_1 * p_2
// | a_1 | a_2 | q_2 | tmp_a | tmp_b = 2 * a_0 * a_2 + q_2 * p_1 + q_3 * p_0
// | t_3 | -   | q_3 | tmp_b | t_3 = tmp_b + q_3 * p_0
