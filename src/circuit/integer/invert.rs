use super::{AssignedCondition, IntegerChip, IntegerInstructions, MainGateInstructions};
use crate::NUMBER_OF_LIMBS;
use crate::circuit::{Assigned, AssignedInteger};
use crate::circuit::main_gate::{CombinationOption, Term};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    fn inert_inv_range_tune(&self) -> usize {
        self.rns.bit_len_prenormalized - (self.rns.bit_len_limb * (NUMBER_OF_LIMBS - 1)) + 1
    }

    pub(crate) fn _invert(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        let main_gate = self.main_gate();

        let (zero, one) = (N::zero(), N::one());
        let integer_one = self.rns.new_from_big(1u32.into());
        // TODO: Shall we just use SynthesisError here?
        // Passing None to mul is undefined behavior for invert,
        // throwing an error or panic would be a better choice.
        let integer_a = a.integer().ok_or(Error::SynthesisError)?;
        let integer_inv = self.rns.invert(&integer_a).or(Some(integer_one));

        // TODO: For range constraints, we have these options:
        // 1. extend mul to support prenormalized value.
        // 2. call normalize here.
        // 3. add wrong field range check on inv.
        let inv = self.range_assign_integer(region, integer_inv.into(), self.inert_inv_range_tune(), offset)?;
        let a_mul_inv = self.mul(region, &a, &inv, offset)?;

        // We believe the mul result is strictly less than wrong modulus, so we add strict constraints here.
        // The limbs[1..NUMBER_OF_LIMBS] of a_mul_inv should be 0.
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.assert_zero(region, a_mul_inv.limbs[i].clone(), offset)?;
        }

        // The limbs[0] of a_mul_inv should be 0 or 1, i.e. limbs[0] * limbs[0] - limbs[0] = 0.
        main_gate.combine(
            region,
            Term::Assigned(&a_mul_inv.limbs[0], zero),
            Term::Assigned(&a_mul_inv.limbs[0], zero),
            Term::Assigned(&a_mul_inv.limbs[0], -one),
            Term::Zero,
            zero,
            offset,
            CombinationOption::SingleLinerMul,
        )?;

        // If a_mul_inv is 0 (i.e. not 1), then inv must be 1 (i.e. [1, 0, 0, 0]).
        // Here we short x.limbs[i] as x[i].
        // 1. (a_mul_inv[0] - 1) * inv[1..NUMBER_OF_LIMBS] = 0
        // 2. (a_mul_inv[0] - 1) * (inv[0] - 1) = 0
        for i in 1..NUMBER_OF_LIMBS {
            main_gate.combine(
                region,
                Term::Assigned(&a_mul_inv.limbs[0], zero),
                Term::Assigned(&inv.limbs[i], -one),
                Term::Zero,
                Term::Zero,
                zero,
                offset,
                CombinationOption::SingleLinerMul,
            )?;
        }

        println!("{}", offset);

        main_gate.combine(
            region,
            Term::Assigned(&a_mul_inv.limbs[0], -one),
            Term::Assigned(&inv.limbs[0], -one),
            Term::Zero,
            Term::Zero,
            one,
            offset,
            CombinationOption::SingleLinerMul,
        )?;

        // Align with main_gain.invert(), cond = 1 - a_mul_inv
        let cond = a_mul_inv.limbs[0].value().map(|a_mul_inv| { one - a_mul_inv });
        let (_, cond_cell, _, _) = main_gate.combine(
            region,
            Term::Assigned(&a_mul_inv.limbs[0], one),
            Term::Unassigned(cond, one),
            Term::Zero,
            Term::Zero,
            -one,
            offset,
            CombinationOption::SingleLinerMul,
        )?;

        Ok((inv, AssignedCondition::new(cond_cell, cond)))
    }
}
