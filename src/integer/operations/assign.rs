use crate::{
    integer::{
        chip::{IntegerChip, Range},
        Integer, Limb,
    },
    Scaled, Witness,
};
use halo2::{circuit::Value, halo2curves::FieldExt};

impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn assign_constant(&mut self, constant: W) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let constant = self.rns.constant(constant);
        #[cfg(test)]
        {
            self.report.n_assign += 1;
        }
        let (max_values, _) = self.rns.max_values(Range::Remainder);
        // create limbs and find native value
        let limbs = constant
            .limbs()
            .iter()
            .zip(max_values.into_iter())
            .map(|(limb, max)| Limb::new(&self.o.register_constant(*limb), max))
            .collect::<Vec<Limb<N>>>();
        let native = self.o.register_constant(constant.native());
        Integer::new(&limbs.try_into().unwrap(), native)
    }
    pub fn range(
        &mut self,
        limbs: Value<[N; NUMBER_OF_LIMBS]>,
        range: Range,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_range += 1;
        }
        // create limb witnesses and find native value
        let limbs: Vec<Witness<N>> = limbs
            .transpose_vec(NUMBER_OF_LIMBS)
            .iter()
            .map(|limb| self.o.new_witness(*limb))
            .collect();

        let terms: Vec<Scaled<N>> = limbs
            .iter()
            .zip(self.rns.left_shifters.iter())
            .map(|(limb, base)| Scaled::new(limb, *base))
            .collect::<Vec<Scaled<N>>>();
        let native = self.o.compose(&terms[..], N::zero(), N::one());
        // range limbs
        let (max_values, bit_lenghts) = self.rns.max_values(range);

        let limbs: Vec<Limb<N>> = limbs
            .iter()
            .zip(max_values.into_iter())
            .zip(bit_lenghts.into_iter())
            .map(|((limb, max), bit_len)| {
                self.range_limb(limb, bit_len);
                Limb::new(limb, max)
            })
            .collect::<Vec<Limb<N>>>();
        Integer::new(&limbs.try_into().unwrap(), native)
    }
    pub fn range_limb(&mut self, limb: &Witness<N>, limb_len: usize) {
        #[cfg(test)]
        {
            self.report.n_range_limb += 1;
        }
        self.o.decompose(limb, Self::sublimb_bit_len(), limb_len);
    }
}
