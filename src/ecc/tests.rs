use super::{base_field_ecc::BaseFieldEccChip, Point};
use crate::{
    integer::{chip::IntegerChip, rns::Rns},
    maingate::{config::MainGate, operations::Collector, Gate},
    Witness,
};
use group::Curve;
use group::Group;
use halo2::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::CurveAffine,
    plonk::{Circuit, ConstraintSystem, Error},
};

use rand_core::OsRng;
use std::marker::PhantomData;

#[derive(Clone)]
struct TestConfig<
    C: CurveAffine,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
    const MAINGATE_LOOKUP_WIDTH: usize,
> {
    maingate: MainGate<C::Scalar, MAINGATE_LOOKUP_WIDTH>,
    rns: Rns<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    aux_generator: C,
}
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    // fn from_str(&self, x: &str, y: &str) -> Value<C> {
    //     use crate::utils::big_to_fe;
    //     use num_bigint::BigUint as Big;
    //     use num_traits::Num;
    //     let x: C::Base = big_to_fe(Big::from_str_radix(x, 16).unwrap());
    //     let y: C::Base = big_to_fe(Big::from_str_radix(y, 16).unwrap());
    //     Value::known(C::from_xy(x, y).unwrap())
    // }
}
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
        const MAINGATE_LOOKUP_WIDTH: usize,
    > TestConfig<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS, MAINGATE_LOOKUP_WIDTH>
{
    pub fn ecc_chip(
        &mut self,
        o: Collector<C::Scalar>,
    ) -> BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS> {
        let integer_chip = IntegerChip::new(o, self.rns.clone());
        BaseFieldEccChip::new(integer_chip, self.aux_generator)
    }
}
#[derive(Default)]
struct MyCircuit<
    C: CurveAffine,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
    const MAINGATE_LOOKUP_WIDTH: usize,
> {
    _marker: PhantomData<C>,
}
impl<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
        const MAINGATE_LOOKUP_WIDTH: usize,
    > Circuit<C::Scalar>
    for MyCircuit<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS, MAINGATE_LOOKUP_WIDTH>
{
    type Config =
        TestConfig<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS, MAINGATE_LOOKUP_WIDTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
        let rns = Rns::construct();
        let overflow_bit_lens = rns.overflow_lengths();
        let composition_bit_len = IntegerChip::<
            C::Base,
            C::Scalar,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
            NUMBER_OF_SUBLIMBS,
        >::sublimb_bit_len();
        let maingate = MainGate::<C::Scalar, MAINGATE_LOOKUP_WIDTH>::configure(
            meta,
            vec![composition_bit_len, 1],
            overflow_bit_lens,
        );
        let aux_generator = <C as CurveAffine>::CurveExt::random(OsRng).to_affine();
        TestConfig {
            maingate,
            rns,
            aux_generator,
        }
    }
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut ly: impl Layouter<C::Scalar>,
    ) -> Result<(), Error> {
        let point = |point: C::CurveExt| -> Value<C> { Value::known(point.into()) };
        let scalar = |e: C::Scalar| -> Value<C::Scalar> { Value::known(e) };
        let rand_point = || point(C::CurveExt::random(OsRng));
        let rand_scalar = || scalar(C::Scalar::random(OsRng));
        let o = Collector::default();
        let mut ch = config.ecc_chip(o);
        // constant registry
        let p = C::CurveExt::random(OsRng);
        let p_val = Value::known(p.into());
        let p_assigned = ch.assign_point(p_val);
        ch.assert_is_on_curve(&p_assigned);
        let p_constant = ch.register_constant(p.into());
        ch.assert_is_on_curve(&p_constant);
        ch.assert_equal(&p_assigned, &p_constant);
        let p_constant = ch.get_constant(p.into());
        ch.assert_equal(&p_assigned, &p_constant);
        // add
        let a = rand_point();
        let b = rand_point();
        let c = (a + b).map(|p| p.to_affine());
        let a = ch.assign_point(a);
        let b = ch.assign_point(b);
        let c0 = ch.assign_point(c);
        let c1 = ch.add(&a, &b);
        ch.assert_equal(&c0, &c1);
        // double
        let a = rand_point();
        let c = (a + a).map(|p| p.to_affine());
        let a = ch.assign_point(a);
        let c0 = ch.assign_point(c);
        let c1 = ch.double(&a);
        ch.assert_equal(&c0, &c1);
        // ladder
        let a = rand_point();
        let b = rand_point();
        let c = a.zip(b).map(|(a, b)| (a + b + a).to_affine());
        let a = ch.assign_point(a);
        let b = ch.assign_point(b);
        let c0 = ch.assign_point(c);
        let c1 = ch.ladder(&a, &b);
        ch.assert_equal(&c0, &c1);
        // mul
        let a = rand_point();
        let e = rand_scalar();
        let c = a.zip(e).map(|(a, e)| (a * e).to_affine());
        let a = ch.assign_point(a);
        let e = ch.assign_scalar(e);
        let c0 = ch.assign_point(c);
        let c1 = ch.mul(&a, &e, 2);
        ch.assert_equal(&c0, &c1);
        // mul batch
        let number_of_pairs = 50;
        let window_size = 4;
        // ch.configure_for_batch_multiplication(ly, window_size, number_of_pairs)?;
        let pairs = (0..number_of_pairs)
            .map(|_| {
                let a = rand_point();
                let e = rand_scalar();
                let a = ch.assign_point(a);
                let e = ch.assign_scalar(e);
                (a, e)
            })
            .collect::<Vec<(
                Point<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                Witness<C::Scalar>,
            )>>();
        ch.mul_batch(pairs, window_size);
        let o = ch.operations();
        o.info();
        ch.integer_chip.info();
        config.maingate.layout(&mut ly, o)
    }
}

#[test]
fn test_ecc_base_field() {
    const K: u32 = 23;
    const LIMB_BIT_LEN: usize = 88;
    const NUMBER_OF_LIMBS: usize = 3;
    const LOOKUP_WIDTH: usize = 1;
    const NUMBER_OF_SUBLIMBS: usize = 4;

    // const K: u32 = 20;
    // const LIMB_BIT_LEN: usize = 68;
    // const NUMBER_OF_LIMBS: usize = 4;
    // const LOOKUP_WIDTH: usize = 2;
    // const NUMBER_OF_SUBLIMBS: usize = 4;
    use halo2::halo2curves::pasta::EpAffine;
    let circuit =
        MyCircuit::<EpAffine, NUMBER_OF_LIMBS, LIMB_BIT_LEN, NUMBER_OF_SUBLIMBS, LOOKUP_WIDTH> {
            _marker: PhantomData,
        };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}
