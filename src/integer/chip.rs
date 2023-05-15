use crate::{
    integer::{rns::Rns, ConstantInteger, Integer, Limb},
    maingate::operations::Collector,
    Witness,
};
use halo2curves::ff::PrimeField;

#[cfg(test)]
use crate::integer::tests::Report;

#[derive(Debug)]
pub enum Range {
    Remainder,
    Operand,
    MulQuotient,
    Unreduced,
}
#[derive(Debug)]
pub struct IntegerChip<
    'a,
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
> {
    pub(crate) o: &'a mut Collector<N>,
    pub(crate) rns: &'a Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    #[cfg(test)]
    pub(crate) report: Report,
}
impl<
        'a,
        W: PrimeField + Ord,
        N: PrimeField + Ord,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<'a, W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub const fn sublimb_bit_len() -> usize {
        assert!(BIT_LEN_LIMB % NUMBER_OF_SUBLIMBS == 0);
        BIT_LEN_LIMB / NUMBER_OF_SUBLIMBS
    }
    pub fn new(
        o: &'a mut Collector<N>,
        rns: &'a Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    ) -> Self {
        o.get_constant(N::ONE);
        o.get_constant(N::ZERO);
        Self {
            o,
            rns,
            #[cfg(test)]
            report: Report::default(),
        }
    }
}
impl<
        'a,
        W: PrimeField + Ord,
        N: PrimeField + Ord,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<'a, W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    // pub fn to_bits_native(&mut self, e: &Witness<N>) -> Vec<Witness<N>> {
    //     self.o.to_bits(e, N::NUM_BITS as usize)
    // }
    // pub fn decompose_native(&mut self, e: &Witness<N>, radix: usize) -> Vec<Witness<N>> {
    //     self.o.decompose(e, radix, N::NUM_BITS as usize)
    // }
    pub fn to_bits(
        &mut self,
        integer: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Vec<Witness<N>> {
        let decomposed: Vec<Witness<N>> = (0..NUMBER_OF_LIMBS)
            .flat_map(|idx| {
                let number_of_bits = if idx == NUMBER_OF_LIMBS - 1 {
                    self.rns.wrong_modulus.bits() as usize % BIT_LEN_LIMB
                } else {
                    BIT_LEN_LIMB
                };
                self.o.to_bits(integer.limb(idx), number_of_bits)
            })
            .collect();
        assert_eq!(decomposed.len(), self.rns.wrong_modulus.bits() as usize);
        decomposed
    }
    pub fn get_constant(&mut self, e: N) -> Witness<N> {
        self.o.get_constant(e)
    }
    pub fn copy_equal(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        for idx in 0..NUMBER_OF_LIMBS {
            self.o.equal(w0.limb(idx), w1.limb(idx));
        }
    }
    pub fn assert_equal(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        let must_be_zero = &self.sub(w0, w1);
        self.assert_zero(must_be_zero)
    }
    pub fn assert_not_equal(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        let c = &self.sub(w0, w1);
        self.assert_not_zero(c)
    }
    pub fn assert_not_zero(&mut self, w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) {
        self._assert_not_zero(w0)
    }
    pub fn assert_zero(&mut self, w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) {
        self._assert_zero(w0)
    }
    pub fn reduce(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self._reduce(w0)
    }
    pub fn add(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let a = &self.reduce_if_limbs_gt_unreduced(w0);
        let b = &self.reduce_if_limbs_gt_unreduced(w1);
        self._add(a, b)
    }
    pub fn add_constant(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        constant: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let a = &self.reduce_if_limbs_gt_unreduced(w0);
        self._add_constant(a, constant)
    }
    pub fn mul2(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let a = &self.reduce_if_limbs_gt_unreduced(w0);
        self._mul2(a)
    }
    pub fn mul3(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let a = &self.reduce_if_limbs_gt_unreduced(w0);
        self._mul3(a)
    }
    pub fn sub(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let a = &self.reduce_if_limbs_gt_unreduced(w0);
        let b = &self.reduce_if_limbs_gt_unreduced(w1);
        self._sub(a, b)
    }
    pub fn mul(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let w0 = &self.reduce_if_limbs_gt_reduced(w0);
        let w0 = &self.reduce_if_gt_max_operand(w0);
        let w1 = &self.reduce_if_limbs_gt_reduced(w1);
        let w1 = &self.reduce_if_gt_max_operand(w1);
        self._mul(w0, w1)
    }
    pub fn mul_constant(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        constant: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let w0 = &self.reduce_if_limbs_gt_reduced(w0);
        let w0 = &self.reduce_if_gt_max_operand(w0);
        self._mul_constant(w0, constant)
    }
    pub fn square(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let w0 = &self.reduce_if_limbs_gt_reduced(w0);
        let w0 = &self.reduce_if_gt_max_operand(w0);
        self._square(w0)
    }
    pub fn div_incomplete(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let w0 = &self.reduce_if_limbs_gt_reduced(w0);
        let w0 = &self.reduce_if_gt_max_operand(w0);
        let w1 = &self.reduce_if_limbs_gt_reduced(w1);
        let w1 = &self.reduce_if_gt_max_operand(w1);
        self._div_incomplete(w0, w1)
    }
    pub fn select(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        w1: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &Witness<N>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let limbs = w0
            .limbs()
            .iter()
            .zip(w1.limbs().iter())
            .map(|(w0, w1)| {
                let val = self.o.select(cond, &w0.witness(), &w1.witness());
                let max = std::cmp::max(w0.max(), w1.max());
                Limb::new(&val, max)
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = self.o.select(cond, w0.native(), w1.native());
        Integer::new(&limbs, native)
    }
    pub fn select_or_assign(
        &mut self,
        w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        constant: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        cond: &Witness<N>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let limbs = w0
            .limbs()
            .iter()
            .zip(constant.limbs().iter())
            .map(|(w0, constant)| {
                let val = self.o.select_or_assign(cond, &w0.witness(), *constant);
                Limb::new(&val, w0.max())
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = self
            .o
            .select_or_assign(cond, w0.native(), constant.native());
        Integer::new(&limbs, native)
    }
    pub fn select_constant(
        &mut self,
        cond: &Witness<N>,
        c0: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        c1: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let (max_values, _) = self.rns.max_values(Range::Remainder);
        let limbs = c0
            .limbs()
            .iter()
            .zip(c1.limbs().iter())
            .zip(max_values.into_iter())
            .map(|((c0, c1), max_val)| {
                let selected = self.o.select_constant(cond, *c0, *c1);
                Limb::new(&selected, max_val)
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = self.o.select_constant(cond, c0.native(), c1.native());
        Integer::new(&limbs, native)
    }
    pub fn assert_bit(&mut self, w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) {
        for limb in w0.limbs().iter().skip(1) {
            self.o.assert_zero(&limb.witness());
        }
        self.o.assert_bit(&w0.limbs().first().unwrap().witness())
    }
}
