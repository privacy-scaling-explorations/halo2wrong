use super::{IntegerChip, Range};
use crate::rns::{Common, Integer};
use crate::{AssignedInteger, AssignedLimb, UnassignedInteger};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::halo2::circuit::Layouter;
use maingate::{fe_to_big, halo2, MainGateInstructions, RangeInstructions, RegionCtx, Term};
use num_bigint::BigUint as big_uint;
use num_traits::One;
use std::rc::Rc;
use std::vec;

impl<W: FieldExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn assign_integer_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        integer: UnassignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        range: Range,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let range_chip = self.range_chip();
        let main_gate = self.main_gate();

        let bit_len_limb_msb = match range {
            Range::Operand => self.rns.max_most_significant_operand_limb.bits(),
            Range::Remainder => self.rns.max_most_significant_reduced_limb.bits(),
            Range::MulQuotient => self.rns.max_most_significant_mul_quotient_limb.bits(),
            Range::Unreduced => 0,
        } as usize;

        let max_val_msb = (big_uint::one() << bit_len_limb_msb) - 1usize;
        let max_val = (big_uint::one() << BIT_LEN_LIMB) - 1usize;

        let limbs = integer
            .0
            .map(|integer| integer.limbs())
            .transpose_vec(NUMBER_OF_LIMBS);
        let limbs = match range {
            Range::Unreduced => limbs
                .into_iter()
                .map(|limb| {
                    Ok(AssignedLimb::from(
                        main_gate.assign_value(ctx, limb)?,
                        self.rns.max_unreduced_limb.clone(),
                    ))
                })
                .collect::<Result<Vec<AssignedLimb<N>>, Error>>(),
            _ => {
                limbs
                    .into_iter()
                    .enumerate()
                    .map(|(i, limb)| {
                        Ok(
                            // Most significant limb
                            if i == NUMBER_OF_LIMBS - 1 {
                                AssignedLimb::from(
                                    range_chip.assign(
                                        ctx,
                                        limb,
                                        Self::sublimb_bit_len(),
                                        bit_len_limb_msb,
                                    )?,
                                    max_val_msb.clone(),
                                )

                            // Rest
                            } else {
                                AssignedLimb::from(
                                    range_chip.assign(
                                        ctx,
                                        limb,
                                        Self::sublimb_bit_len(),
                                        BIT_LEN_LIMB,
                                    )?,
                                    max_val.clone(),
                                )
                            },
                        )
                    })
                    .collect::<Result<Vec<AssignedLimb<N>>, Error>>()
            }
        }?;

        let limbs_to_compose: Vec<Term<N>> = limbs
            .iter()
            .zip(self.rns.left_shifters.iter())
            .map(|(limb, sh)| Term::Assigned(limb.as_ref(), *sh))
            .collect();
        let native = main_gate.compose(ctx, &limbs_to_compose, N::zero())?;

        Ok(self.new_assigned_integer(&limbs.try_into().unwrap(), native))
    }

    pub(super) fn register_constants_generic(
        &mut self,
        layouter: &mut impl Layouter<N>,
        integers: Vec<W>,
    ) -> Result<(), Error> {
        let mut constants = vec![];
        for integer in integers {
            let unassigned = Integer::from_fe(integer, Rc::clone(&self.rns));
            for limb in unassigned.limbs() {
                constants.push(limb)
            }
            constants.push(unassigned.native());
        }
        self.main_gate.register_constants(layouter, constants)?;
        Ok(())
    }

    pub(super) fn get_constant_generic(
        &self,
        constant: W,
    ) -> Result<AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let constant = Integer::from_fe(constant, Rc::clone(&self.rns));

        let assigned_limbs = constant
            .limbs()
            .iter()
            .map(|limb| {
                Ok(AssignedLimb::from(
                    self.main_gate.get_constant(*limb)?,
                    fe_to_big(*limb),
                ))
            })
            .collect::<Result<Vec<AssignedLimb<N>>, Error>>()?;

        let native = self.main_gate.get_constant(constant.native())?;

        Ok(self.new_assigned_integer(&assigned_limbs.try_into().unwrap(), native))
    }
}
