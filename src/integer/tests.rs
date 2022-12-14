use super::{
    chip::{IntegerChip, Range},
    rns::Rns,
    ConstantInteger, Integer,
};
use crate::{
    integer::Limb,
    maingate::{config::MainGate, operations::Collector},
    utils::{big_to_fe, modulus},
    Scaled, Witness,
};
use halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::{
        pasta::{Fp, Fq},
        FieldExt,
    },
    plonk::{Circuit, ConstraintSystem, Error},
};
use num_bigint::{BigUint as Big, RandBigInt};
use num_traits::{Num, One, Zero};
use rand_core::OsRng;
use std::marker::PhantomData;

#[derive(Clone, Debug, Default)]
pub(crate) struct Report {
    pub(crate) n_reduce_limbs_gt_reduced: usize,
    pub(crate) n_reduce_limbs_gt_unreduced: usize,
    pub(crate) n_reduce_value_gt_operand: usize,
    pub(crate) n_reduce: usize,
    pub(crate) n_range: usize,
    pub(crate) n_range_limb: usize,
    pub(crate) n_assign: usize,
    pub(crate) n_add: usize,
    pub(crate) n_add_constant: usize,
    pub(crate) n_sub: usize,
    pub(crate) n_mul: usize,
    pub(crate) n_div: usize,
    pub(crate) n_square: usize,
    pub(crate) n_mul_constant: usize,
    pub(crate) n_mul_2: usize,
    pub(crate) n_mul_3: usize,
    pub(crate) n_assert_not_zero: usize,
}
impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn info(&self) {
        self.o.info();
        println!("{:#?}", self.report);
    }
    pub fn assign(
        &mut self,

        limbs: Value<[N; NUMBER_OF_LIMBS]>,
        range: Range,
    ) -> Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        #[cfg(test)]
        {
            self.report.n_range += 1;
        }
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
        let (max_values, _) = self.rns.max_values(range);
        let limbs: Vec<Limb<N>> = limbs
            .iter()
            .zip(max_values.into_iter())
            .map(|(limb, max)| Limb::new(limb, max))
            .collect::<Vec<Limb<N>>>();
        Integer::new(&limbs.try_into().unwrap(), native)
    }
    pub fn assert_strict_equal(
        &mut self,
        a: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        b: &Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        for idx in 0..NUMBER_OF_LIMBS {
            self.o.assert_equal(a.limb(idx), b.limb(idx))
        }
    }
}
impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn modulus(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        self.from_big(Value::known(modulus::<W>()))
    }
    pub fn from_str(&self, e: &str) -> Value<[N; NUMBER_OF_LIMBS]> {
        let a: W = big_to_fe(Big::from_str_radix(e, 16).unwrap());
        self.from_fe(Value::known(a))
    }
    pub fn rand_in_field(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        let a = W::random(OsRng);
        self.from_fe(Value::known(a))
    }
    pub fn rand_in_remainder_range(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        self.from_big(Value::known(
            OsRng.gen_biguint(self.max_remainder.bits() as u64),
        ))
    }
    pub fn rand_in_operand_range(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        self.from_big(Value::known(
            OsRng.gen_biguint(self.max_operand.bits() as u64),
        ))
    }
    pub fn rand_in_unreduced_range(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        self.rand_with_limb_bit_size(self.max_unreduced_limb.bits() as usize)
    }
    pub fn rand_with_limb_bit_size(&self, bit_len: usize) -> Value<[N; NUMBER_OF_LIMBS]> {
        let limbs = (0..NUMBER_OF_LIMBS)
            .map(|_| {
                let e = OsRng.gen_biguint(bit_len as u64);
                big_to_fe(e)
            })
            .collect::<Vec<N>>();
        Value::known(limbs.try_into().unwrap())
    }
    pub fn rand_constant(&self) -> ConstantInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.constant(W::random(OsRng))
    }
    pub fn zero(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        self.from_big(Value::known(Big::zero()))
    }
    pub fn one(&self) -> Value<[N; NUMBER_OF_LIMBS]> {
        self.from_big(Value::known(Big::one()))
    }
}
#[derive(Clone)]
pub struct TestConfig<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
    const MAINGATE_LOOKUP_WIDTH: usize,
> {
    pub(crate) maingate: MainGate<N, MAINGATE_LOOKUP_WIDTH>,
    pub(crate) rns: Rns<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
}
impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
        const MAINGATE_LOOKUP_WIDTH: usize,
    > TestConfig<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS, MAINGATE_LOOKUP_WIDTH>
{
    pub fn integer_chip(
        &self,
        o: Collector<N>,
    ) -> IntegerChip<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS> {
        IntegerChip::new(o, self.rns.clone())
    }
}
#[derive(Default)]
struct MyCircuit<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
    const MAINGATE_LOOKUP_WIDTH: usize,
> {
    _marker: PhantomData<(W, N)>,
    #[allow(dead_code)]
    fail: Option<usize>,
}
impl<
        W: FieldExt,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
        const MAINGATE_LOOKUP_WIDTH: usize,
    > Circuit<N>
    for MyCircuit<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS, MAINGATE_LOOKUP_WIDTH>
{
    type Config =
        TestConfig<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS, MAINGATE_LOOKUP_WIDTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let rns = Rns::construct();
        let overflow_bit_lens = rns.overflow_lengths();
        let composition_bit_len = IntegerChip::<
            W,
            N,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
            NUMBER_OF_SUBLIMBS,
        >::sublimb_bit_len();
        let maingate = MainGate::<N, MAINGATE_LOOKUP_WIDTH>::configure(
            meta,
            vec![composition_bit_len],
            overflow_bit_lens,
        );
        TestConfig { maingate, rns }
    }
    fn synthesize(&self, config: Self::Config, mut ly: impl Layouter<N>) -> Result<(), Error> {
        let mut config = config;
        let o = Collector::default();
        let mut ch = config.integer_chip(o);
        {
            let zero = ch.rns.zero();
            let zero = ch.range(zero, Range::Remainder);
            ch.assert_zero(&zero);
            let zero = ch.rns.modulus();
            let zero = ch.range(zero, Range::Remainder);
            ch.assert_zero(&zero);
        }
        // assert
        {
            let a0 = ch.rns.rand_in_field();
            let a0 = ch.range(a0, Range::Remainder);
            ch.assert_not_zero(&a0);
            let a1 = ch.reduce(&a0);
            ch.assert_strict_equal(&a0, &a1);
            ch.copy_equal(&a0, &a1);
            ch.assert_equal(&a0, &a1);
            let a0 = ch.rns.rand_in_remainder_range();
            let a0 = ch.range(a0, Range::Remainder);
            ch.assert_not_zero(&a0);
            let a1 = ch.reduce(&a0);
            ch.assert_equal(&a0, &a1);
            let a0 = ch.rns.rand_in_operand_range();
            let a0 = ch.range(a0, Range::Operand);
            ch.assert_not_zero(&a0);
            let a1 = ch.reduce(&a0);
            ch.assert_equal(&a0, &a1);
            let a0 = ch.rns.rand_in_unreduced_range();
            let a0 = ch.assign(a0, Range::Unreduced);
            ch.assert_not_zero(&a0);
            let a1 = ch.reduce(&a0);
            ch.assert_equal(&a0, &a1);
            let a0 = ch.rns.rand_with_limb_bit_size(BIT_LEN_LIMB * 3 / 2);
            let a0 = ch.assign(a0, Range::Unreduced);
            ch.assert_not_zero(&a0);
            let a1 = ch.reduce(&a0);
            ch.assert_equal(&a0, &a1);
        }
        // add
        {
            // add
            let a0 = ch.rns.rand_in_remainder_range();
            let a1 = ch.rns.rand_in_remainder_range();
            let a0 = &ch.range(a0, Range::Remainder);
            let a1 = &ch.range(a1, Range::Remainder);
            let u0 = ch.add(a0, a1);
            let u1 = ch.add(a1, a0);
            ch.assert_equal(&u0, &u1);
            u0.value()
                .zip(a0.value())
                .zip(a1.value())
                .map(|((u0, a0), a1)| assert_eq!(u0, a0 + a1));
            // add constant
            let a0 = ch.rns.rand_in_remainder_range();
            let a0 = &ch.range(a0, Range::Remainder);
            let constant = &ch.rns.rand_constant();
            let u0 = ch.add_constant(a0, constant);
            u0.value()
                .zip(a0.value())
                .map(|(u0, a0)| assert_eq!(u0, a0 + constant.value()));
            // sub
            let u0 = ch.sub(a0, a1);
            u0.value()
                .zip(a0.value())
                .zip(a1.value())
                .map(|((u0, a0), a1)| assert_eq!(u0, a0 - a1));
            let u1 = ch.add(&u0, a1);
            ch.assert_equal(a0, &u1);
        }
        // mul
        {
            // mul
            let a0 = ch.rns.rand_in_field();
            let a1 = ch.rns.rand_in_field();
            let a0 = &ch.range(a0, Range::Remainder);
            let a1 = &ch.range(a1, Range::Remainder);
            let res = a0.value().zip(a1.value()).map(|(a0, a1)| a0 * a1);
            let u0 = ch.rns.from_fe(res);
            let u0 = ch.range(u0, Range::Remainder);
            let u1 = ch.mul(a0, a1);
            ch.assert_strict_equal(&u0, &u1);
            ch.copy_equal(&u0, &u1);
            ch.assert_equal(&u0, &u1);
            u1.value()
                .zip(a0.value())
                .zip(a1.value())
                .map(|((u0, a0), a1)| assert_eq!(u0, a0 * a1));
            // mul constant
            let a0 = ch.rns.rand_in_field();
            let constant = ch.rns.rand_constant();
            let a0 = &ch.range(a0, Range::Remainder);
            let res = a0.value().map(|a0| (a0 * constant.value()));
            let u0 = ch.rns.from_fe(res);
            let u0 = ch.range(u0, Range::Remainder);
            let u1 = ch.mul_constant(a0, &constant);
            ch.assert_strict_equal(&u0, &u1);
            ch.copy_equal(&u0, &u1);
            ch.assert_equal(&u0, &u1);
            u1.value()
                .zip(a0.value())
                .map(|(u0, a0)| assert_eq!(u0, a0 * constant.value()));
            // square
            let a0 = ch.rns.rand_in_field();
            let a0 = &ch.range(a0, Range::Remainder);
            let res = a0.value().map(|a0| (a0 * a0));
            let u0 = ch.rns.from_fe(res);
            let u0 = ch.range(u0, Range::Remainder);
            let u1 = ch.square(a0);
            ch.assert_strict_equal(&u0, &u1);
            ch.copy_equal(&u0, &u1);
            ch.assert_equal(&u0, &u1);
            u1.value()
                .zip(a0.value())
                .map(|(u0, a0)| assert_eq!(u0, a0 * a0));
            // div
            let a0 = ch.rns.rand_in_field();
            let a1 = ch.rns.rand_in_field();
            let a0 = &ch.range(a0, Range::Remainder);
            let a1 = &ch.range(a1, Range::Remainder);
            let res = a0
                .value()
                .zip(a1.value())
                .map(|(a0, a1)| a0 * a1.invert().unwrap());
            let u0 = ch.rns.from_fe(res);
            let u0 = ch.range(u0, Range::Remainder);
            let u1 = ch.div_incomplete(a0, a1);
            ch.assert_strict_equal(&u0, &u1);
            ch.copy_equal(&u0, &u1);
            ch.assert_equal(&u0, &u1);
        }

        config.maingate.layout(&mut ly, ch.o)
    }
}
#[test]
fn test_integer() {
    // const K: u32 = 23;
    // const LIMB_BIT_LEN: usize = 88;
    // const NUMBER_OF_LIMBS: usize = 3;
    // const LOOKUP_WIDTH: usize = 2;
    // const NUMBER_OF_SUBLIMBS: usize = 4;

    const K: u32 = 18;
    const LIMB_BIT_LEN: usize = 68;
    const NUMBER_OF_LIMBS: usize = 4;
    const LOOKUP_WIDTH: usize = 2;
    const NUMBER_OF_SUBLIMBS: usize = 4;

    type Native = Fp;
    type Wrong = Fq;

    let circuit = MyCircuit::<
        Wrong,
        Native,
        NUMBER_OF_LIMBS,
        LIMB_BIT_LEN,
        NUMBER_OF_SUBLIMBS,
        LOOKUP_WIDTH,
    > {
        _marker: PhantomData,
        fail: None,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#}", e),
    };
    prover.assert_satisfied();
}
