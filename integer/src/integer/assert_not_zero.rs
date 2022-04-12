use super::IntegerChip;
use crate::{AssignedInteger, WrongExt};
use halo2::arithmetic::FieldExt;
use halo2::plonk::Error;
use maingate::Assigned;
use maingate::{halo2, CombinationOptionCommon, MainGateInstructions, RegionCtx, Term};
use num_bigint::BigUint as big_uint;
use std::convert::TryInto;

impl<W: WrongExt, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub(super) fn _assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        a: &AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let one = N::one();

        // Reduce result (r) is restricted to be less than 1 <<
        // wrong_modulus_bit_lenght, so we only need to assert r <> 0 and r <>
        // wrong modulus.
        let r = self._reduce(ctx, a)?;

        // Sanity check.
        // This algorithm requires that wrong modulus * 2 <= native modulus * 2 ^
        // bit_len_limb.
        let two_pow_limb_bits_minus_1 =
            big_uint::from(2u64).pow((BIT_LEN_LIMB - 1).try_into().unwrap());
        assert!(
            self.rns.wrong_modulus.clone()
                <= self.rns.native_modulus.clone() * two_pow_limb_bits_minus_1
        );

        // r = 0 <-> r % 2 ^ 64 = 0 /\ r % native_modulus = 0
        // r <> 0 <-> r % 2 ^ 64 <> 0 \/ r % native_modulus <> 0
        // r <> 0 <-> invert(r.limb(0)) \/ invert(r.native())
        let cond_zero_0 = main_gate.is_zero(ctx, &r.limb(0))?;
        let cond_zero_1 = main_gate.is_zero(ctx, &r.native())?;

        // one of them should be succeed (0), i.e. cond_zero_0 * cond_zero_1 = 0
        main_gate.nand(ctx, &cond_zero_0, &cond_zero_1)?;

        // Similar to 0,
        // r = wrong_modulus <-> r % 2 ^ 64 = wrong_modulus % 2 ^ 64 /\ r %
        // native_modulus = wrong_modulus % native_modulus r <> p <->
        // invert(r.limb(0) - wrong_modulus[0]) \/ invert(r.native() -
        // wrong_modulus.native())
        let wrong_modulus = self.rns.wrong_modulus_decomposed;
        let limb_diff = r.limbs[0].value().map(|value| value - wrong_modulus[0]);
        let limb_diff = main_gate.combine(
            ctx,
            &[
                Term::Assigned(r.limb(0), one),
                Term::Unassigned(limb_diff, -one),
                Term::Zero,
                Term::Zero,
                Term::Zero,
            ],
            -wrong_modulus[0],
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1];

        let native_diff = r
            .native()
            .value()
            .map(|value| value - self.rns.wrong_modulus_in_native_modulus);
        let native_diff = main_gate.combine(
            ctx,
            &[
                Term::Assigned(r.native(), one),
                Term::Unassigned(native_diff, -one),
                Term::Zero,
                Term::Zero,
                Term::Zero,
            ],
            -self.rns.wrong_modulus_in_native_modulus,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1];

        let cond_wrong_0 = main_gate.is_zero(ctx, &limb_diff)?;
        let cond_wrong_1 = main_gate.is_zero(ctx, &native_diff)?;

        main_gate.nand(ctx, &cond_wrong_0, &cond_wrong_1)?;

        Ok(())
    }
}
