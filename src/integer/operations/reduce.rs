use crate::{
    integer::{
        chip::{IntegerChip, Range},
        Integer, Limb,
    },
    Scaled,
};
use halo2curves::ff::PrimeField;
impl<
        'a,
        W: PrimeField + Ord,
        N: PrimeField + Ord,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<'a, W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn _reduce(
        &mut self,
        integer: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_reduce += 1;
        }
        // find result and quotient witnesses
        let (result, quotient) = self.reduction_witness(integer);
        // range the result and small quotient
        let result = self.range(result, Range::Remainder);
        let quotient = self.o.new_witness(quotient);
        self.range_limb(&quotient, BIT_LEN_LIMB);
        // find and range residues
        let modulus = self.rns.negative_wrong_modulus_decomposed;
        let mut carry: Option<Scaled<N>> = None;
        for chunk in integer
            .limbs()
            .iter()
            .zip(result.limbs().iter())
            .zip(modulus.iter())
            .map(|((a, r), w)| (a.clone(), r.clone(), *w))
            .collect::<Vec<(Limb<N>, Limb<N>, N)>>()
            .chunks(2)
        {
            let single_chunk = chunk.len() == 1;
            let mut terms: Vec<Scaled<N>> = chunk
                .iter()
                .enumerate()
                .map(|(i, (a, r, w))| {
                    let lsh = self.rns.left_shifter(i);
                    let a = Scaled::new(&a.witness(), lsh);
                    let qw = Scaled::new(&quotient, lsh * w);
                    let r = Scaled::new(&r.witness(), -lsh);
                    vec![a, qw, r]
                })
                .collect::<Vec<Vec<Scaled<N>>>>()
                .into_iter()
                .flatten()
                .collect();
            if let Some(e) = carry.as_ref() {
                terms.push(*e)
            }
            let carry_base = if single_chunk {
                self.rns.left_shifter(1)
            } else {
                self.rns.left_shifter(2)
            };
            // find the round residue
            let residue = self.o.compose(&terms[..], N::ZERO, carry_base);
            // range residue
            self.range_limb(&residue, self.rns.red_v_bit_len);
            // update carry
            carry = Some(Scaled::new(&residue, N::ONE));
        }
        // constrain in native modulus
        let integer_native = self.o.add_scaled(
            &Scaled::new(result.native(), N::ONE),
            &Scaled::new(&quotient, self.rns.wrong_modulus_in_native_modulus),
        );
        self.o.equal(integer.native(), &integer_native);
        result
    }
    pub(crate) fn _assert_zero(&mut self, integer: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) {
        #[cfg(test)]
        {
            self.report.n_reduce += 1;
        }

        let (_, quotient) = self.reduction_witness(integer);
        #[cfg(feature = "sanity-check")]
        {
            // TODO: check if result is zero
        }
        let quotient = self.o.new_witness(quotient);
        // range the result and small quotient
        self.range_limb(&quotient, BIT_LEN_LIMB);
        // find and range residues
        let modulus = self.rns.negative_wrong_modulus_decomposed;
        let mut carry: Option<Scaled<N>> = None;
        for chunk in integer
            .limbs()
            .iter()
            .zip(modulus.iter())
            .map(|(a, w)| (a.clone(), *w))
            .collect::<Vec<(Limb<N>, N)>>()
            .chunks(2)
        {
            let single_chunk = chunk.len() == 1;
            let mut terms: Vec<Scaled<N>> = chunk
                .iter()
                .enumerate()
                .map(|(i, (a, w))| {
                    let lsh = self.rns.left_shifter(i);
                    let a = Scaled::new(&a.witness(), lsh);
                    let qw = Scaled::new(&quotient, lsh * w);
                    vec![a, qw]
                })
                .collect::<Vec<Vec<Scaled<N>>>>()
                .into_iter()
                .flatten()
                .collect();
            // carry.as_ref().map(|e| terms.push(e.clone()));
            if let Some(e) = carry.as_ref() {
                terms.push(*e)
            }
            let carry_base = if single_chunk {
                self.rns.left_shifter(1)
            } else {
                self.rns.left_shifter(2)
            };
            // find the round residue
            let residue = self.o.compose(&terms[..], N::ZERO, carry_base);
            // range residue
            self.range_limb(&residue, self.rns.red_v_bit_len);
            // update carry
            carry = Some(Scaled::new(&residue, N::ONE));
        }
        // TODO: consider twice if native check is required
    }
}
