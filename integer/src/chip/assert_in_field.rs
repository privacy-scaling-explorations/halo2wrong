use super::{IntegerChip, Range};
use crate::{AssignedInteger, PrimeField};
use halo2::plonk::Error;
use maingate::{
    halo2, AssignedValue, CombinationOptionCommon, MainGateInstructions, RegionCtx, Term,
};

impl<W: PrimeField, N: PrimeField, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn assert_in_field_generic(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        input: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        // Constraints for `NUMBER_OF_LIMBS = 4`
        // 0 = -c_0 + p_0 - a_0 + b_0 * R
        // 0 = -c_1 + p_1 - a_1 + b_1 * R - b_0
        // 0 = -c_2 + p_2 - a_2 + b_2 * R - b_1
        // 0 = -c_3 + p_3 - a_3           - b_2

        let main_gate = self.main_gate();

        // to make `a = p` case not passing compare with `p - 1`
        let modulus_minus_one = &self.rns.wrong_modulus_minus_one.clone();

        let integer = input.integer();
        // result containts borrows must be bits and subtraaction result must be in
        // range
        let comparision_witness = integer.as_ref().map(|integer| integer.compare_to_modulus());
        let result = comparision_witness.as_ref().map(|r| r.result.clone());
        let result = &self.assign_integer_generic(ctx, result.into(), Range::Remainder)?;

        // assert borrow values are bits
        let borrow = comparision_witness.as_ref().map(|r| r.borrow);
        let borrow = (0..NUMBER_OF_LIMBS - 1)
            .map(|i| {
                let b_i = borrow.map(|borrow| if borrow[i] { N::ONE } else { N::ZERO });
                main_gate.assign_bit(ctx, b_i)
            })
            .collect::<Result<Vec<AssignedValue<N>>, Error>>()?;

        let left_shifter = self.rns.left_shifter(1);
        let one = N::ONE;

        // Witness layout:
        // | A   | B   | C   | D       |
        // | --- | --- | --- | -----   |
        // | c_0 | a_0 | b_0 | -       |
        // | c_i | a_i | b_i | b_(i-1) |
        // | c_n | a_n | -   | b_n     |

        main_gate.apply(
            ctx,
            [
                Term::Assigned(result.limb(0), -one),
                Term::Assigned(input.limb(0), -one),
                Term::Assigned(&borrow[0], left_shifter),
                Term::Zero,
                Term::Zero,
            ],
            modulus_minus_one[0],
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        for i in 1..NUMBER_OF_LIMBS - 1 {
            main_gate.apply(
                ctx,
                [
                    Term::Assigned(result.limb(i), -one),
                    Term::Assigned(input.limb(i), -one),
                    Term::Assigned(&borrow[i], left_shifter),
                    Term::Assigned(&borrow[i - 1], -one),
                    Term::Zero,
                ],
                modulus_minus_one[i],
                CombinationOptionCommon::OneLinerAdd.into(),
            )?;
        }

        let last = NUMBER_OF_LIMBS - 1;
        main_gate.apply(
            ctx,
            [
                Term::Assigned(result.limb(last), -one),
                Term::Assigned(input.limb(last), -one),
                Term::Zero,
                Term::Assigned(&borrow[last - 1], -one),
                Term::Zero,
            ],
            modulus_minus_one[last],
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(())
    }
}
