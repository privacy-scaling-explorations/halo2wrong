use crate::integer::{chip::IntegerChip, Integer};
use halo2::halo2curves::FieldExt;
use num_bigint::BigUint as Big;

impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn _assert_not_zero(&mut self, w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) {
        #[cfg(test)]
        {
            self.report.n_assert_not_zero += 1;
        }
        let w0 = self.reduce(w0);
        // Sanity check.
        // This algorithm requires that wrong modulus * 2 <= native modulus * 2 ^
        // bit_len_limb.
        let two_pow_limb_bits_minus_1 = Big::from(2u64).pow((BIT_LEN_LIMB - 1).try_into().unwrap());
        assert!(
            self.rns.wrong_modulus.clone()
                <= self.rns.native_modulus.clone() * two_pow_limb_bits_minus_1
        );
        // r = 0 <-> r % 2 ^ 64 = 0 /\ r % native_modulus = 0
        // r <> 0 <-> r % 2 ^ 64 <> 0 \/ r % native_modulus <> 0
        // r <> 0 <-> invert(r.limb(0)) \/ invert(r.native())
        let cond_zero_0 = self.o.is_zero(w0.limb(0));
        let cond_zero_1 = self.o.is_zero(w0.native());
        // one of them might be succeeded, i.e. cond_zero_0 * cond_zero_1 = 0
        self.o.assert_nand(&cond_zero_0, &cond_zero_1);
        // Similar to 0,
        // r = wrong_modulus <-> r % 2 ^ 64 = wrong_modulus % 2 ^ 64 /\ r %
        // native_modulus = wrong_modulus % native_modulus r <> p <->
        // invert(r.limb(0) - wrong_modulus[0]) \/ invert(r.native() -
        // wrong_modulus.native())
        let limb_dif = self
            .o
            .add_constant(w0.limb(0), -self.rns.wrong_modulus_decomposed[0]);
        let native_dif = self
            .o
            .add_constant(w0.native(), -self.rns.wrong_modulus_in_native_modulus);
        let cond_wrong_0 = self.o.is_zero(&limb_dif);
        let cond_wrong_1 = self.o.is_zero(&native_dif);
        self.o.assert_nand(&cond_wrong_0, &cond_wrong_1);
    }
}
