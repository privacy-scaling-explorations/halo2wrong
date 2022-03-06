use super::{make_mul_aux, AssignedPoint, EccConfig, MulAux, Point};
use crate::halo2;
use crate::integer::rns::{Integer, Rns};
use crate::integer::{IntegerChip, IntegerInstructions, Range, UnassignedInteger};
use crate::maingate;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Layouter;
use halo2::plonk::Error;
use halo2::plonk::{Column, Instance};
use integer::maingate::RegionCtx;
use maingate::five::main_gate::MainGate;
use maingate::{Assigned, AssignedCondition};
use std::collections::BTreeMap;

mod add;
mod mul;

#[derive(Clone)]
pub struct GeneralEccChip<Emulated: CurveAffine, N: FieldExt> {
    config: EccConfig,
    rns_base_field: Rns<Emulated::Base, N>,
    rns_scalar_field: Rns<Emulated::Scalar, N>,
    aux_generator: Option<(AssignedPoint<N>, Option<Emulated>)>,
    aux_registry: BTreeMap<(usize, usize), AssignedPoint<N>>,
}

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
    pub fn rns(bit_len_limb: usize) -> (Rns<Emulated::Base, N>, Rns<Emulated::ScalarExt, N>) {
        (Rns::construct(bit_len_limb), Rns::construct(bit_len_limb))
    }

    pub fn rns_base(&self) -> Rns<Emulated::Base, N> {
        self.rns_base_field.clone()
    }

    pub fn rns_scalar(&self) -> Rns<Emulated::Scalar, N> {
        self.rns_scalar_field.clone()
    }

    pub fn new(config: EccConfig, bit_len_limb: usize) -> Self {
        let (rns_base_field, rns_scalar_field) = Self::rns(bit_len_limb);
        Self {
            config,
            rns_base_field,
            rns_scalar_field,
            aux_generator: None,
            aux_registry: BTreeMap::new(),
        }
    }

    fn instance_column(&self) -> Column<Instance> {
        self.config.main_gate_config.instance
    }

    pub fn base_field_chip(&self) -> IntegerChip<Emulated::Base, N> {
        IntegerChip::new(self.config.integer_chip_config(), self.rns_base_field.clone())
    }

    pub fn scalar_field_chip(&self) -> IntegerChip<Emulated::ScalarExt, N> {
        IntegerChip::new(self.config.integer_chip_config(), self.rns_scalar_field.clone())
    }

    pub fn main_gate(&self) -> MainGate<N> {
        MainGate::<N>::new(self.config.main_gate_config.clone())
    }

    pub fn to_rns_point(&self, point: Emulated) -> Point<Emulated::Base, N> {
        let coords = point.coordinates();
        // disallow point of infinity
        // it will not pass assing point enforcement
        let coords = coords.unwrap();

        let x = self.rns_base_field.new(*coords.x());
        let y = self.rns_base_field.new(*coords.y());
        Point { x, y }
    }

    fn parameter_b(&self) -> Integer<Emulated::Base, N> {
        self.rns_base_field.new(Emulated::b())
    }

    fn get_mul_aux(&self, window_size: usize, number_of_pairs: usize) -> Result<MulAux<N>, Error> {
        let to_add = match self.aux_generator.clone() {
            Some((assigned, _)) => Ok(assigned),
            None => {
                println!("x1 {} {}", window_size, number_of_pairs);
                Err(Error::Synthesis)
            }
        }?;
        let to_sub = match self.aux_registry.get(&(window_size, number_of_pairs)) {
            Some(aux) => Ok(aux.clone()),
            None => {
                println!("x0 {} {}", window_size, number_of_pairs);

                Err(Error::Synthesis)
            }
        }?;
        Ok(MulAux::new(to_add, to_sub))
    }
}

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
    pub fn expose_public(&self, mut layouter: impl Layouter<N>, point: AssignedPoint<N>, offset: usize) -> Result<(), Error> {
        let instance_column = self.instance_column();
        let mut offset = offset;
        for limb in point.x.limbs {
            layouter.constrain_instance(limb.cell(), instance_column, offset)?;
            offset += 1;
        }
        for limb in point.y.limbs {
            layouter.constrain_instance(limb.cell(), instance_column, offset)?;
            offset += 1;
        }
        Ok(())
    }

    pub fn assign_constant(&self, ctx: &mut RegionCtx<'_, '_, N>, point: Emulated) -> Result<AssignedPoint<N>, Error> {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();
        let base_field_chip = self.base_field_chip();
        let x = base_field_chip.assign_constant(ctx, *coords.x())?;
        let y = base_field_chip.assign_constant(ctx, *coords.y())?;
        Ok(AssignedPoint::new(x, y))
    }

    pub fn assign_point(&self, ctx: &mut RegionCtx<'_, '_, N>, point: Option<Emulated>) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();

        let point = point.map(|point| self.to_rns_point(point));
        let (x, y) = match point {
            Some(point) => (Some(point.x).into(), Some(point.y).into()),
            None => (UnassignedInteger::from(None), UnassignedInteger::from(None)),
        };

        let x = integer_chip.range_assign_integer(ctx, x, Range::Remainder)?;
        let y = integer_chip.range_assign_integer(ctx, y, Range::Remainder)?;

        let point = AssignedPoint::new(x, y);
        self.assert_is_on_curve(ctx, &point)?;
        Ok(point)
    }

    pub fn assign_aux_generator(&mut self, ctx: &mut RegionCtx<'_, '_, N>, aux_generator: Option<Emulated>) -> Result<(), Error> {
        let aux_generator_assigned = self.assign_point(ctx, aux_generator)?;
        self.aux_generator = Some((aux_generator_assigned, aux_generator));
        Ok(())
    }

    pub fn assign_aux(&mut self, ctx: &mut RegionCtx<'_, '_, N>, window_size: usize, number_of_pairs: usize) -> Result<(), Error> {
        match self.aux_generator {
            Some((_, point)) => {
                let aux = match point {
                    Some(point) => Some(make_mul_aux(point, window_size, number_of_pairs)),
                    None => None,
                };
                let aux = self.assign_point(ctx, aux)?;
                self.aux_registry.insert((window_size, number_of_pairs), aux);
                Ok(())
            }
            // aux generator is not assigned yet
            None => {
                println!("ee {} {}", window_size, number_of_pairs);

                Err(Error::Synthesis)
            }
        }
    }

    pub fn assert_is_on_curve(&self, ctx: &mut RegionCtx<'_, '_, N>, point: &AssignedPoint<N>) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();

        let y_square = &integer_chip.square(ctx, &point.y)?;
        let x_square = &integer_chip.square(ctx, &point.x)?;
        let x_cube = &integer_chip.mul(ctx, &point.x, x_square)?;
        let x_cube_b = &integer_chip.add_constant(ctx, x_cube, &self.parameter_b())?;
        integer_chip.assert_equal(ctx, x_cube_b, y_square)?;
        Ok(())
    }

    pub fn assert_equal(&self, ctx: &mut RegionCtx<'_, '_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();
        integer_chip.assert_equal(ctx, &p0.x, &p1.x)?;
        integer_chip.assert_equal(ctx, &p0.y, &p1.y)
    }

    pub fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: &AssignedPoint<N>,
    ) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.select(ctx, &p1.x, &p2.x, c)?;
        let y = integer_chip.select(ctx, &p1.y, &p2.y, c)?;
        Ok(AssignedPoint::new(x, y))
    }

    pub fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: Emulated,
    ) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let p2 = self.to_rns_point(p2);
        let x = integer_chip.select_or_assign(ctx, &p1.x, &p2.x, c)?;
        let y = integer_chip.select_or_assign(ctx, &p1.y, &p2.y, c)?;
        Ok(AssignedPoint::new(x, y))
    }

    pub fn normalize(&self, ctx: &mut RegionCtx<'_, '_, N>, point: &AssignedPoint<N>) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.reduce(ctx, &point.x)?;
        let y = integer_chip.reduce(ctx, &point.y)?;
        Ok(AssignedPoint::new(x, y))
    }

    pub fn add(&self, ctx: &mut RegionCtx<'_, '_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>) -> Result<AssignedPoint<N>, Error> {
        // guarantees that p0 != p1 or p0 != p1
        // so that we can use unsafe addition formula which assumes operands are not equal
        // addition to that we strictly disallow addition result to be point of infinity
        self.base_field_chip().assert_not_equal(ctx, &p0.x, &p1.x)?;

        self._add_incomplete_unsafe(ctx, p0, p1)
    }

    pub fn double(&self, ctx: &mut RegionCtx<'_, '_, N>, p: &AssignedPoint<N>) -> Result<AssignedPoint<N>, Error> {
        // point must be asserted to be in curve and not infinity
        self._double_incomplete(ctx, p)
    }

    pub fn double_n(&self, ctx: &mut RegionCtx<'_, '_, N>, p: &AssignedPoint<N>, logn: usize) -> Result<AssignedPoint<N>, Error> {
        let mut acc = p.clone();
        for _ in 0..logn {
            acc = self._double_incomplete(ctx, &acc)?;
        }
        Ok(acc)
    }

    pub fn ladder(&self, ctx: &mut RegionCtx<'_, '_, N>, to_double: &AssignedPoint<N>, to_add: &AssignedPoint<N>) -> Result<AssignedPoint<N>, Error> {
        self._ladder_incomplete(ctx, to_double, to_add)
    }

    pub fn neg(&self, ctx: &mut RegionCtx<'_, '_, N>, p: &AssignedPoint<N>) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let y_neg = integer_chip.neg(ctx, &p.y)?;
        Ok(AssignedPoint::new(p.x.clone(), y_neg))
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::{AssignedPoint, EccConfig, GeneralEccChip, Point};
    use crate::halo2;
    use crate::integer::rns::Rns;
    use crate::integer::NUMBER_OF_LOOKUP_LIMBS;
    use crate::integer::{AssignedInteger, IntegerConfig, IntegerInstructions};
    use crate::maingate;
    use group::{Curve as _, Group};
    use halo2::arithmetic::{CurveAffine, FieldExt};
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use integer::maingate::RegionCtx;
    use maingate::five::main_gate::{MainGate, MainGateConfig};
    use maingate::five::range::{RangeChip, RangeConfig, RangeInstructions};
    use rand::thread_rng;

    cfg_if::cfg_if! {
        if #[cfg(feature = "kzg")] {
            use halo2::pairing::bn256::Fq as Field;
            use halo2::pairing::bn256::G1Affine as Curve;
            use halo2::pairing::bn256::G1 as CurveProjective;
        } else {
            use halo2::pasta::EqAffine as Curve;
            use halo2::pasta::Eq as CurveProjective;
            use halo2::pasta::Fp as Field;
        }
    }

    const BIT_LEN_LIMB: usize = 68;

    fn setup<C: CurveAffine, N: FieldExt>(k_override: u32) -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>, u32) {
        let (rns_base, rns_scalar) = GeneralEccChip::<C, N>::rns(BIT_LEN_LIMB);
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        if k_override != 0 {
            k = k_override;
        }
        (rns_base, rns_scalar, k)
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    }

    impl TestCircuitConfig {
        fn ecc_chip_config(&self) -> EccConfig {
            EccConfig {
                range_config: self.range_config.clone(),
                main_gate_config: self.main_gate_config.clone(),
            }
        }
    }

    impl TestCircuitConfig {
        fn new<C: CurveAffine, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
            let (rns_base, rns_scalar) = GeneralEccChip::<C, N>::rns(BIT_LEN_LIMB);

            let main_gate_config = MainGate::<N>::configure(meta);
            let mut overflow_bit_lengths: Vec<usize> = vec![];
            overflow_bit_lengths.extend(rns_base.overflow_lengths());
            overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            TestCircuitConfig {
                main_gate_config,
                range_config,
            }
        }

        fn integer_chip_config(&self) -> IntegerConfig {
            IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
        }

        fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
            let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
            let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
            range_chip.load_limb_range_table(layouter)?;
            range_chip.load_overflow_range_tables(layouter)?;

            Ok(())
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccAddition<C: CurveAffine, N: FieldExt> {
        rns_base: Rns<C::Base, N>,
        rns_scalar: Rns<C::ScalarExt, N>,
    }

    impl<C: CurveAffine, N: FieldExt> Circuit<N> for TestEccAddition<C, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();

            let ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, BIT_LEN_LIMB);
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let mut rng = thread_rng();

                    let a = C::CurveExt::random(&mut rng);
                    let b = C::CurveExt::random(&mut rng);

                    let c = a + b;
                    let a = &ecc_chip.assign_point(ctx, Some(a.into()))?;
                    let b = &ecc_chip.assign_point(ctx, Some(b.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Some(c.into()))?;
                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test doubling

                    let a = C::CurveExt::random(&mut rng);
                    let c = a + a;

                    let a = &ecc_chip.assign_point(ctx, Some(a.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Some(c.into()))?;
                    let c_1 = &ecc_chip.double(ctx, a)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test ladder

                    let a = C::CurveExt::random(&mut rng);
                    let b = C::CurveExt::random(&mut rng);
                    let c = a + b + a;

                    let a = &ecc_chip.assign_point(ctx, Some(a.into()))?;
                    let b = &ecc_chip.assign_point(ctx, Some(b.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Some(c.into()))?;
                    let c_1 = &ecc_chip.ladder(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_addition_circuit() {
        let (rns_base, rns_scalar, k) = setup::<Curve, Field>(0);

        let circuit = TestEccAddition::<Curve, Field> { rns_base, rns_scalar };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccPublicInput<C: CurveAffine, N: FieldExt> {
        a: Option<C>,
        b: Option<C>,
        _marker: PhantomData<N>,
    }

    impl<C: CurveAffine, N: FieldExt> Circuit<N> for TestEccPublicInput<C, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, BIT_LEN_LIMB);

            let sum = layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let a = self.a;
                    let b = self.b;
                    let a = ecc_chip.assign_point(ctx, a)?;
                    let b = ecc_chip.assign_point(ctx, b)?;
                    let c = ecc_chip.add(ctx, &a, &b)?;
                    ecc_chip.normalize(ctx, &c)
                },
            )?;
            ecc_chip.expose_public(layouter.namespace(|| "sum"), sum, 0)?;

            let sum = layouter.assign_region(
                || "region 1",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let a = self.a;
                    let a = ecc_chip.assign_point(ctx, a)?;
                    let c = ecc_chip.double(ctx, &a)?;
                    ecc_chip.normalize(ctx, &c)
                },
            )?;
            ecc_chip.expose_public(layouter.namespace(|| "sum"), sum, 8)?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_public_input() {
        let (rns_base, _, k) = setup::<Curve, Field>(0);
        use rand::thread_rng;
        let mut rng = thread_rng();

        let a = CurveProjective::random(&mut rng).to_affine();
        let b = CurveProjective::random(&mut rng).to_affine();

        let c0: Curve = (a + b).into();
        let c0 = Point::from(&rns_base, c0);
        let mut public_data = c0.public();
        let c1: Curve = (a + a).into();
        let c1 = Point::from(&rns_base, c1);
        public_data.extend(c1.public());

        let circuit = TestEccPublicInput::<Curve, Field> {
            a: Some(a),
            b: Some(b),
            _marker: PhantomData,
        };

        let prover = match MockProver::run(k, &circuit, vec![public_data]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccMul<C: CurveAffine, N: FieldExt> {
        window_size: usize,
        aux_generator: C,
        _marker: PhantomData<N>,
    }

    impl<C: CurveAffine, N: FieldExt> Circuit<N> for TestEccMul<C, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let mut ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, BIT_LEN_LIMB);
            let scalar_chip = ecc_chip.scalar_field_chip();
            // let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            // main_gate.break_here(ctx)?;

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    ecc_chip.assign_aux_generator(ctx, Some(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                    ecc_chip.get_mul_aux(self.window_size, 1)?;
                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "region mul",
                |mut region| {
                    use group::ff::Field;
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let mut rng = thread_rng();

                    let base = C::CurveExt::random(&mut rng);
                    let s = C::ScalarExt::random(&mut rng);
                    let result = base * s;

                    let s = ecc_chip.rns_scalar_field.new(s);
                    let base = ecc_chip.assign_point(ctx, Some(base.into()))?;
                    let s = scalar_chip.assign_integer(ctx, Some(s).into())?;
                    let result_0 = ecc_chip.assign_point(ctx, Some(result.into()))?;

                    let result_1 = ecc_chip.mul(ctx, &base, &s, self.window_size)?;
                    ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_mul_circuit() {
        let (_, _, k) = setup::<Curve, Field>(20);
        for window_size in 1..5 {
            let mut rng = thread_rng();
            let aux_generator = CurveProjective::random(&mut rng).to_affine();

            let circuit = TestEccMul::<Curve, Field> {
                aux_generator,
                window_size,
                _marker: PhantomData,
            };

            let public_inputs = vec![vec![]];
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccBatchMul<C: CurveAffine, N: FieldExt> {
        window_size: usize,
        aux_generator: C,
        number_of_pairs: usize,
        _marker: PhantomData<N>,
    }

    impl<C: CurveAffine, N: FieldExt> Circuit<N> for TestEccBatchMul<C, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let mut ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, BIT_LEN_LIMB);
            let scalar_chip = ecc_chip.scalar_field_chip();
            // let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            // main_gate.break_here(ctx)?;

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    ecc_chip.assign_aux_generator(ctx, Some(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, self.number_of_pairs)?;
                    ecc_chip.get_mul_aux(self.window_size, self.number_of_pairs)?;
                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "region mul",
                |mut region| {
                    use group::ff::Field;
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);
                    let mut rng = thread_rng();

                    let mut acc = C::CurveExt::identity();
                    let pairs: Vec<(AssignedPoint<N>, AssignedInteger<N>)> = (0..self.number_of_pairs)
                        .map(|_| {
                            let base = C::CurveExt::random(&mut rng);
                            let s = C::ScalarExt::random(&mut rng);
                            acc = acc + (base * s);
                            let s = ecc_chip.rns_scalar_field.new(s);
                            let base = ecc_chip.assign_point(ctx, Some(base.into()))?;
                            let s = scalar_chip.assign_integer(ctx, Some(s).into())?;
                            Ok((base, s))
                        })
                        .collect::<Result<_, Error>>()?;

                    let result_0 = ecc_chip.assign_point(ctx, Some(acc.into()))?;
                    let result_1 = ecc_chip.mul_batch_1d_horizontal(ctx, pairs, self.window_size)?;
                    ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_mul_batch_circuit() {
        let (_, _, k) = setup::<Curve, Field>(20);
        for number_of_pairs in 4..5 {
            for window_size in 1..3 {
                let mut rng = thread_rng();
                let aux_generator = CurveProjective::random(&mut rng).to_affine();

                let circuit = TestEccBatchMul::<Curve, Field> {
                    aux_generator,
                    window_size,
                    number_of_pairs,
                    _marker: PhantomData,
                };

                let public_inputs = vec![vec![]];
                let prover = match MockProver::run(k, &circuit, public_inputs) {
                    Ok(prover) => prover,
                    Err(e) => panic!("{:#?}", e),
                };
                assert_eq!(prover.verify(), Ok(()));
            }
        }
    }
}
