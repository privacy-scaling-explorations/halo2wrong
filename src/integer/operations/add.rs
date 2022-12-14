use crate::{
    integer::{chip::IntegerChip, ConstantInteger, Integer, Limb},
    utils::fe_to_big,
    Scaled,
};
use halo2::halo2curves::FieldExt;
use std::marker::PhantomData;

impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub(crate) fn _add(
        &mut self,
        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_add += 1;
        }
        let limbs = a
            .limbs()
            .iter()
            .zip(b.limbs().iter())
            .map(|(a_limb, b_limb)| {
                let max = a_limb.max() + b_limb.max();
                let value = self.o.add(&a_limb.witness(), &b_limb.witness());
                Limb::new(&value, max)
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = self.o.add(a.native(), b.native());
        Integer {
            limbs,
            native,
            _marker: PhantomData,
        }
    }
    pub(crate) fn _sub(
        &mut self,
        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_sub += 1;
        }
        let aux = self.rns.subtracion_aux(&b.max_vals());
        let limbs = a
            .limbs()
            .iter()
            .zip(b.limbs().iter())
            .zip(aux.limbs().iter())
            .map(|((a_limb, b_limb), aux)| {
                let max = a_limb.max() + fe_to_big(*aux);
                let value = self
                    .o
                    .sub_and_add_constant(&a_limb.witness(), &b_limb.witness(), *aux);
                Limb::new(&value, max)
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = self
            .o
            .sub_and_add_constant(a.native(), b.native(), aux.native());

        Integer {
            limbs,
            native,
            _marker: PhantomData,
        }
    }
    pub(crate) fn _add_constant(
        &mut self,
        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        constant: &ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_add_constant += 1;
        }
        let limbs = a
            .limbs()
            .iter()
            .zip(constant.limbs().iter())
            .map(|(a_limb, b_limb)| {
                let max = a_limb.max() + fe_to_big(*b_limb);
                let value = self.o.add_constant(&a_limb.witness(), *b_limb);
                Limb::new(&value, max)
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = self.o.add_constant(a.native(), constant.native());
        Integer {
            limbs,
            native,
            _marker: PhantomData,
        }
    }
    pub(crate) fn _mul2(
        &mut self,
        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_mul_2 += 1;
        }
        let limbs = a
            .limbs()
            .iter()
            .map(|limb| {
                let max = limb.max() * 2u32;
                let limb = Scaled::new(&limb.witness(), N::from(2));
                let limb = self.o.scale(limb);
                Limb::new(&limb, max)
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = Scaled::new(a.native(), N::from(2));
        let native = self.o.scale(native);
        Integer {
            limbs,
            native,
            _marker: PhantomData,
        }
    }
    pub(crate) fn _mul3(
        &mut self,
        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_mul_3 += 1;
        }
        let limbs = a
            .limbs()
            .iter()
            .map(|limb| {
                let max = limb.max() * 3u32;
                let limb = Scaled::new(&limb.witness(), N::from(3));
                let limb = self.o.scale(limb);
                Limb::new(&limb, max)
            })
            .collect::<Vec<Limb<N>>>()
            .try_into()
            .unwrap();
        let native = Scaled::new(a.native(), N::from(3));
        let native = self.o.scale(native);
        Integer {
            limbs,
            native,
            _marker: PhantomData,
        }
    }
}
