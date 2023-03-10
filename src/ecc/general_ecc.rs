use super::{ConstantPoint, Point};
use crate::{
    integer::{
        chip::{IntegerChip, Range},
        rns::Rns,
        ConstantInteger, Integer,
    },
    maingate::operations::Collector,
    Scaled, Witness,
};
use halo2::{
    circuit::Value,
    halo2curves::{CurveAffine, FieldExt},
};

mod add;
mod mul_fix;
#[allow(dead_code)]
mod mul_var_bucket;
mod mul_var_sliding;

#[derive(Debug)]
pub struct GeneralEccChip<
    'a,
    Emulated: CurveAffine,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
    const NUMBER_OF_SUBLIMBS: usize,
> {
    rns_base_field: &'a Rns<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    rns_scalar_field:
        &'a Rns<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
    operations: &'a mut Collector<N>,
    aux_generator: Emulated,
}
impl<
        'a,
        Emulated: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > GeneralEccChip<'a, Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn new(
        operations: &'a mut Collector<N>,
        rns_base_field: &'a Rns<
            Emulated::Base,
            N,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
            NUMBER_OF_SUBLIMBS,
        >,
        rns_scalar_field: &'a Rns<
            Emulated::Scalar,
            N,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
            NUMBER_OF_SUBLIMBS,
        >,
        aux_generator: Emulated,
    ) -> Self {
        Self {
            rns_base_field,
            rns_scalar_field,
            operations,
            aux_generator,
        }
    }
    pub fn rns_base_field(
        &self,
    ) -> &Rns<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS> {
        self.rns_base_field
    }
    pub fn rns_scalar_field(
        &self,
    ) -> &Rns<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS> {
        self.rns_scalar_field
    }
    // pub fn base_field_chip(
    //     &mut self,
    // ) -> &mut IntegerChip<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
    // {
    //     &mut IntegerChip::new(self.operations, self.rns_base_field)
    // }
    // pub fn scalar_field_chip(
    //     &mut self,
    // ) -> &mut IntegerChip<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
    // {
    //     &mut IntegerChip::new(self.operations, self.rns_scalar_field)
    // }
    fn parameter_b() -> ConstantInteger<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        Emulated::b().into()
    }
}
impl<
        'a,
        Emulated: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > GeneralEccChip<'a, Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn get_constant_point(
        &mut self,
        point: &Emulated,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.register_constant_point(point)
    }
    pub fn register_constant_point(
        &mut self,
        point: &Emulated,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        let coords = point.coordinates();
        // disallow point of infinity
        // it will not pass assing point enforcement
        let coords = coords.unwrap();
        let x = coords.x();
        let y = coords.y();
        let x = &ch.register_constant(*x);
        let y = &ch.register_constant(*y);
        Point::new(x, y)
    }
    pub fn get_constant_scalar(
        &mut self,
        scalar: &Emulated::Scalar,
    ) -> Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.register_constant_scalar(scalar)
    }
    pub fn register_constant_scalar(
        &mut self,
        scalar: &Emulated::Scalar,
    ) -> Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_scalar_field);
        ch.register_constant(*scalar)
    }
    pub fn assign_point(
        &mut self,
        point: Value<Emulated>,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        let rns = ch.rns;
        let (x, y) = point
            .map(|point| {
                let coords = point.coordinates();
                // disallow point of infinity
                // it will not pass assing point enforcement
                let coords = coords.unwrap();
                let x = coords.x();
                let y = coords.y();
                (*x, *y)
            })
            .unzip();
        let x = rns.from_fe(x);
        let y = rns.from_fe(y);
        let x = &ch.range(x, Range::Remainder);
        let y = &ch.range(y, Range::Remainder);
        let point = Point::new(x, y);
        self.assert_is_on_curve(&point);
        point
    }
    pub fn assign_scalar(
        &mut self,
        scalar: Value<Emulated::Scalar>,
    ) -> Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_scalar_field);
        let scalar = self.rns_scalar_field.from_fe(scalar);
        ch.range(scalar, Range::Remainder)
    }
}
impl<
        'a,
        Emulated: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
    > GeneralEccChip<'a, Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>
{
    pub fn assert_is_on_curve(
        &mut self,
        point: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        let y_square = &ch.square(point.y());
        let x_square = &ch.square(point.x());
        let x_cube = &ch.mul(point.x(), x_square);
        let x_cube_b = &ch.add_constant(x_cube, &Self::parameter_b());
        ch.assert_equal(x_cube_b, y_square);
    }
    pub fn assert_equal(
        &mut self,
        p0: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p1: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        ch.assert_equal(p0.x(), p1.x());
        ch.assert_equal(p0.y(), p1.y());
    }
    pub fn select(
        &mut self,
        c: &Witness<N>,
        p1: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        let x = &ch.select(p1.x(), p2.x(), c);
        let y = &ch.select(p1.y(), p2.y(), c);
        Point::new(x, y)
    }
    pub fn select_or_assign(
        &mut self,
        c: &Witness<N>,
        p1: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: Emulated,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        let p2 = ConstantPoint::<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(p2);
        let x = &ch.select_or_assign(p1.x(), p2.x(), c);
        let y = &ch.select_or_assign(p1.y(), p2.y(), c);
        Point::new(x, y)
    }
    pub fn select_multi(
        &mut self,
        selector: &[Witness<N>],
        table: &[Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let number_of_selectors = selector.len();
        let mut reducer = table.to_vec();
        for (i, selector) in selector.iter().enumerate() {
            let n = 1 << (number_of_selectors - 1 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(selector, &reducer[k + 1], &reducer[k]);
            }
        }
        reducer[0].clone()
    }
    pub fn select_constant(
        &mut self,
        c: &Witness<N>,
        p1: &ConstantPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: &ConstantPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        let x = &ch.select_constant(c, p1.x(), p2.x());
        let y = &ch.select_constant(c, p1.y(), p2.y());
        Point::new(x, y)
    }
    pub fn select_constant_multi(
        &mut self,
        selector: &[Witness<N>],
        table: &[ConstantPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let number_of_selectors = selector.len();
        let n = 1 << (number_of_selectors - 1);
        let mut reducer = (0..n)
            .map(|j| {
                let k = 2 * j;
                self.select_constant(&selector[0], &table[k + 1], &table[k])
            })
            .collect::<Vec<Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>>();
        for (i, selector) in selector.iter().skip(1).enumerate() {
            let n = 1 << (number_of_selectors - 2 - i);
            for j in 0..n {
                let k = 2 * j;
                reducer[j] = self.select(selector, &reducer[k + 1], &reducer[k]);
            }
        }
        reducer[0].clone()
    }
    fn update_table(
        &mut self,
        slice: &[Witness<N>],
        point: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        table: &mut [Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
    ) {
        let slice: Vec<Scaled<N>> = slice
            .iter()
            .enumerate()
            .map(|(i, bit)| Scaled::new(bit, N::from(1 << i)))
            .collect();
        let index = self.operations.compose(&slice[..], N::zero(), N::one());
        for (j, bucket) in table.iter_mut().take(1 << slice.len()).enumerate() {
            let j = self.operations.get_constant(N::from(j as u64));
            let cond = self.operations.is_equal(&index, &j);
            *bucket = self.select(&cond, point, bucket);
        }
    }
    pub fn normalize(
        &mut self,
        point: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        let x = &ch.reduce(point.x());
        let y = &ch.reduce(point.y());
        Point::new(x, y)
    }
    pub fn add(
        &mut self,
        p0: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p1: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        // guarantees that p0 != p1 or p0 != p1
        // so that we can use unsafe addition formula which assumes operands are not
        // equal addition to that we strictly disallow addition result to be
        // point of infinity
        let mut ch = IntegerChip::new(self.operations, self.rns_base_field);
        ch.assert_not_equal(p0.x(), p1.x());
        self._add_incomplete(p0, p1)
    }
    pub fn double(
        &mut self,
        p: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        // point must be asserted to be in curve and not infinity
        self._double_incomplete(p)
    }
    pub fn double_n(
        &mut self,
        p: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        logn: usize,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let mut acc = p.clone();
        for _ in 0..logn {
            acc = self._double_incomplete(&acc);
        }
        acc
    }
    pub fn ladder(
        &mut self,
        to_double: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        to_add: &Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self._ladder_incomplete(to_double, to_add)
    }
    pub fn msm(
        &mut self,
        points: &[Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
        scalars: &[Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>],
        window_size: usize,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.msm_1d_horizontal(points, scalars, window_size)
    }
}

#[cfg(test)]
mod tests {

    // fn from_str<C: CurveAffine>(x: &str, y: &str) -> C {
    //     let x = C::Base::from_str_vartime(x).unwrap();
    //     let y = C::Base::from_str_vartime(y).unwrap();
    //     C::from_xy(x, y).unwrap()
    // }

    use super::{GeneralEccChip, Point};
    use crate::ecc::multiexp_naive_var;
    use crate::integer::Integer;
    use crate::{
        integer::{chip::IntegerChip, rns::Rns},
        maingate::{config::MainGate, operations::Collector, Gate},
    };
    use group::Curve;
    use group::Group;
    use halo2::dev::MockProver;
    use halo2::halo2curves::FieldExt;
    use halo2::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        halo2curves::CurveAffine,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use rand_core::OsRng;
    use std::marker::PhantomData;

    #[derive(Clone)]
    struct TestConfig<
        Emulated: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
        const MAINGATE_LOOKUP_WIDTH: usize,
    > {
        maingate: MainGate<N, MAINGATE_LOOKUP_WIDTH>,
        rns_base: Rns<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
        rns_scalar: Rns<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB, NUMBER_OF_SUBLIMBS>,
        aux_generator: Emulated,
    }
    #[derive(Default)]
    struct MyCircuit<
        Emulated: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const NUMBER_OF_SUBLIMBS: usize,
        const MAINGATE_LOOKUP_WIDTH: usize,
    > {
        _marker: PhantomData<(Emulated, N)>,
    }
    impl<
            Emulated: CurveAffine,
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
            const NUMBER_OF_SUBLIMBS: usize,
            const MAINGATE_LOOKUP_WIDTH: usize,
        > Circuit<N>
        for MyCircuit<
            Emulated,
            N,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
            NUMBER_OF_SUBLIMBS,
            MAINGATE_LOOKUP_WIDTH,
        >
    {
        type Config = TestConfig<
            Emulated,
            N,
            NUMBER_OF_LIMBS,
            BIT_LEN_LIMB,
            NUMBER_OF_SUBLIMBS,
            MAINGATE_LOOKUP_WIDTH,
        >;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            let rns_base = Rns::construct();
            let rns_scalar = Rns::construct();
            let overflow_bit_lens = rns_base.overflow_lengths();
            let _ = rns_scalar.overflow_lengths();
            let composition_bit_len = IntegerChip::<
                Emulated::Base,
                N,
                NUMBER_OF_LIMBS,
                BIT_LEN_LIMB,
                NUMBER_OF_SUBLIMBS,
            >::sublimb_bit_len();
            let maingate = MainGate::<N, MAINGATE_LOOKUP_WIDTH>::configure(
                meta,
                vec![composition_bit_len, 1],
                overflow_bit_lens,
            );
            let aux_generator = <Emulated as CurveAffine>::CurveExt::random(OsRng).to_affine();
            TestConfig {
                maingate,
                rns_base,
                rns_scalar,
                aux_generator,
            }
        }
        fn synthesize(&self, config: Self::Config, mut ly: impl Layouter<N>) -> Result<(), Error> {
            fn value<T>(e: T) -> Value<T> {
                Value::known(e)
            }
            let rand_point = || Emulated::CurveExt::random(OsRng);
            let rand_scalar = || Emulated::Scalar::random(OsRng);

            let o = &mut Collector::default();
            let mut ch = GeneralEccChip::new(
                o,
                &config.rns_base,
                &config.rns_scalar,
                config.aux_generator,
            );
            // constant registry
            let p = Emulated::CurveExt::random(OsRng);
            let p_val = Value::known(p.into());
            let p_assigned = ch.assign_point(p_val);
            ch.assert_is_on_curve(&p_assigned);
            let p_constant = ch.register_constant_point(&p.into());
            ch.assert_is_on_curve(&p_constant);
            ch.assert_equal(&p_assigned, &p_constant);
            let p_constant = ch.get_constant_point(&p.into());
            ch.assert_equal(&p_assigned, &p_constant);
            // add
            let a: Value<Emulated> = value(rand_point().into());
            let b: Value<Emulated> = value(rand_point().into());
            let c: Value<Emulated> = (a + b).map(|p| p.to_affine());
            let a = ch.assign_point(a);
            let b = ch.assign_point(b);
            let c0 = ch.assign_point(c);
            let c1 = ch.add(&a, &b);
            ch.assert_equal(&c0, &c1);
            // double
            let a: Value<Emulated> = value(rand_point().into());
            let c = (a + a).map(|p| p.to_affine());
            let a = ch.assign_point(a);
            let c0 = ch.assign_point(c);
            let c1 = ch.double(&a);
            ch.assert_equal(&c0, &c1);
            // ladder
            let a: Value<Emulated> = value(rand_point().into());
            let b: Value<Emulated> = value(rand_point().into());
            let c = a.zip(b).map(|(a, b)| (a + b + a).to_affine());
            let a = ch.assign_point(a);
            let b = ch.assign_point(b);
            let c0 = ch.assign_point(c);
            let c1 = ch.ladder(&a, &b);
            ch.assert_equal(&c0, &c1);
            // mul var
            let a: Value<Emulated> = value(rand_point().into());
            let e = value(rand_scalar());
            let c = a.zip(e).map(|(a, e)| (a * e).to_affine());
            let a = ch.assign_point(a);
            let e = ch.assign_scalar(e);
            let c0 = ch.assign_point(c);
            let c1 = ch.mul(&a, &e, 2);
            ch.assert_equal(&c0, &c1);
            // msm
            let number_of_points = 100;
            let window_size = 4;
            let (points, scalars): (Vec<Emulated::CurveExt>, Vec<Emulated::Scalar>) = (0
                ..number_of_points)
                .map(|_| (rand_point(), rand_scalar()))
                .unzip();
            let res0 = multiexp_naive_var(&points[..], &scalars[..]);
            let res0 = ch.assign_point(value(res0.into()));
            #[allow(clippy::type_complexity)]
            let (points, scalars): (
                Vec<Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
                Vec<Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>>,
            ) = points
                .into_iter()
                .zip(scalars.into_iter())
                .map(|(point, scalar)| {
                    let point = ch.assign_point(value(point.into()));
                    let scalar = ch.assign_scalar(value(scalar));
                    (point, scalar)
                })
                .unzip();

            let res1 = ch.msm_1d_horizontal(&points[..], &scalars[..], window_size);
            let res2 = ch.msm_bucket(&points[..], &scalars[..], window_size);
            ch.assert_equal(&res0, &res1);
            ch.assert_equal(&res0, &res2);
            // mul fix
            let a: Emulated = rand_point().into();
            let e = value(rand_scalar());
            let c = e.map(|e| (a * e).to_affine());
            let e = ch.assign_scalar(e);
            let res0 = ch.assign_point(c);
            let res1 = ch.mul_fix(a, e, 3);
            ch.assert_equal(&res0, &res1);

            config.maingate.layout(&mut ly, o)
        }
    }
    #[test]
    fn test_ecc_general() {
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
        use halo2::halo2curves::bn256::G1Affine as Bn256;
        use halo2::halo2curves::pasta::EpAffine as Pallas;
        use halo2::halo2curves::pasta::EqAffine as Vesta;
        use halo2::halo2curves::secp256k1::Secp256k1Affine as Secp256k1;

        let circuit = MyCircuit::<
            Bn256,
            <Pallas as CurveAffine>::ScalarExt,
            NUMBER_OF_LIMBS,
            LIMB_BIT_LEN,
            NUMBER_OF_SUBLIMBS,
            LOOKUP_WIDTH,
        > {
            _marker: PhantomData,
        };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(K, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.assert_satisfied();

        let circuit = MyCircuit::<
            Secp256k1,
            <Vesta as CurveAffine>::ScalarExt,
            NUMBER_OF_LIMBS,
            LIMB_BIT_LEN,
            NUMBER_OF_SUBLIMBS,
            LOOKUP_WIDTH,
        > {
            _marker: PhantomData,
        };
        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(K, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.assert_satisfied();
    }
}
