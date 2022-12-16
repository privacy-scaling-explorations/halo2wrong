#[cfg(test)]
use super::tests::Report;
use super::{rns::Rns, ConstantInteger, Integer, Limb};
use crate::{maingate::operations::Collector, Witness};
use halo2::halo2curves::FieldExt;

#[derive(Debug)]
pub enum Range {
    Remainder,
    Operand,
    MulQuotient,
    Unreduced,
}
#[derive(Clone, Debug)]
pub struct IntegerChip<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
> {
    pub(crate) o: Collector<N>,
    pub(crate) rns: Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    #[cfg(test)]
    pub(crate) report: Report,
}
impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub const fn sublimb_bit_len() -> usize {
        assert!(BIT_LEN_LIMB % NUMBER_OF_SUBLIMBS == 0);
        BIT_LEN_LIMB / NUMBER_OF_SUBLIMBS
    }
    pub fn new(
        mut o: Collector<N>,
        rns: Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    ) -> Self {
        o.get_constant(N::one());
        o.get_constant(N::zero());

        Self {
            o,
            rns,
            #[cfg(test)]
            report: Report::default(),
        }
    }
    pub fn operations(&self) -> &Collector<N> {
        &self.o
    }
    pub fn rns(&self) -> &Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS> {
        &self.rns
    }
}
impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn to_bits(&mut self, e: &Witness<N>) -> Vec<Witness<N>> {
        self.o.to_bits(e, N::NUM_BITS as usize)
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
    pub fn assert_bit(&mut self, w0: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) {
        for limb in w0.limbs().iter().skip(1) {
            self.o.assert_zero(&limb.witness());
        }
        self.o.assert_bit(&w0.limbs().first().unwrap().witness())
    }
}
