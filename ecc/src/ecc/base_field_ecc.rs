use super::{make_mul_aux, AssignedPoint, EccConfig, MulAux, Point};
use crate::integer::rns::{Integer, Rns};
use crate::integer::{IntegerChip, IntegerInstructions, Range};
use crate::{halo2, maingate};
use halo2::arithmetic::CurveAffine;
use halo2::circuit::Layouter;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2::plonk::{Column, Instance};
use integer::UnassignedInteger;
use maingate::five::main_gate::MainGate;
use maingate::{Assigned, AssignedCondition};
use std::collections::BTreeMap;

mod add;
mod mul;

pub struct BaseFieldEccChip<C: CurveAffine> {
    config: EccConfig,
    pub(crate) rns: Rns<C::Base, C::ScalarExt>,
    aux_generator: Option<(AssignedPoint<C::ScalarExt>, Option<C>)>,
    aux_registry: BTreeMap<(usize, usize), AssignedPoint<C::ScalarExt>>,
}

impl<C: CurveAffine> BaseFieldEccChip<C> {
    pub fn rns(bit_len_limb: usize) -> Rns<C::Base, C::Scalar> {
        Rns::construct(bit_len_limb)
    }

    #[allow(unused_variables)]
    pub fn new(config: EccConfig, bit_len_limb: usize) -> Self {
        Self {
            config,
            rns: Self::rns(bit_len_limb),
            aux_generator: None,
            aux_registry: BTreeMap::new(),
        }
    }

    fn instance_column(&self) -> Column<Instance> {
        self.config.main_gate_config.instance
    }

    fn integer_chip(&self) -> IntegerChip<C::Base, C::ScalarExt> {
        let integer_chip_config = self.config.integer_chip_config();
        IntegerChip::<C::Base, C::ScalarExt>::new(integer_chip_config, self.rns.clone())
    }

    fn main_gate(&self) -> MainGate<C::ScalarExt> {
        MainGate::<_>::new(self.config.main_gate_config.clone())
    }

    fn to_rns_point(&self, point: C) -> Point<C::Base, C::ScalarExt> {
        let coords = point.coordinates();
        // disallow point of infinity
        // it will not pass assing point enforcement
        let coords = coords.unwrap();

        let x = self.rns.new(*coords.x());
        let y = self.rns.new(*coords.y());
        Point { x, y }
    }

    fn parameter_b(&self) -> Integer<C::Base, C::ScalarExt> {
        self.rns.new(C::b())
    }

    fn get_mul_aux(&self, window_size: usize, number_of_pairs: usize) -> Result<MulAux<C::ScalarExt>, Error> {
        let to_add = match self.aux_generator.clone() {
            Some((assigned, _)) => Ok(assigned),
            None => Err(Error::Synthesis),
        }?;
        let to_sub = match self.aux_registry.get(&(window_size, number_of_pairs)) {
            Some(aux) => Ok(aux.clone()),
            None => Err(Error::Synthesis),
        }?;
        Ok(MulAux::new(to_add, to_sub))
    }
}

impl<C: CurveAffine> BaseFieldEccChip<C> {
    fn expose_public(&self, mut layouter: impl Layouter<C::Scalar>, point: AssignedPoint<C::Scalar>, offset: usize) -> Result<(), Error> {
        let instance_column = self.instance_column();
        let mut offset = offset;
        for limb in point.x.limbs.iter() {
            layouter.constrain_instance(limb.cell(), instance_column, offset)?;
            offset += 1;
        }
        for limb in point.y.limbs.iter() {
            layouter.constrain_instance(limb.cell(), instance_column, offset)?;
            offset += 1;
        }
        Ok(())
    }

    fn assign_constant(&self, region: &mut Region<'_, C::Scalar>, point: C, offset: &mut usize) -> Result<AssignedPoint<C::Scalar>, Error> {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();
        let base_field_chip = self.integer_chip();
        let x = base_field_chip.assign_constant(region, *coords.x(), offset)?;
        let y = base_field_chip.assign_constant(region, *coords.y(), offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn assign_point(&self, region: &mut Region<'_, C::Scalar>, point: Option<C>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.integer_chip();

        let point = point.map(|point| self.to_rns_point(point));
        let (x, y) = match point {
            Some(point) => (Some(point.x).into(), Some(point.y).into()),
            None => (UnassignedInteger::from(None), UnassignedInteger::from(None)),
        };

        let x = integer_chip.range_assign_integer(region, x, Range::Remainder, offset)?;
        let y = integer_chip.range_assign_integer(region, y, Range::Remainder, offset)?;

        let point = AssignedPoint::new(x, y);
        self.assert_is_on_curve(region, &point, offset)?;
        Ok(point)
    }

    pub fn assign_aux_generator(&mut self, region: &mut Region<'_, C::ScalarExt>, aux_generator: Option<C>, offset: &mut usize) -> Result<(), Error> {
        let aux_generator_assigned = self.assign_point(region, aux_generator, offset)?;
        // let aux_to_sub = ecc_chip.assign_point(&mut region, Some(aux_to_sub), offset)?;
        self.aux_generator = Some((aux_generator_assigned, aux_generator));
        Ok(())
    }

    pub fn assign_aux(&mut self, region: &mut Region<'_, C::ScalarExt>, window_size: usize, number_of_pairs: usize, offset: &mut usize) -> Result<(), Error> {
        match self.aux_generator {
            Some((_, point)) => {
                let aux = match point {
                    Some(point) => Some(make_mul_aux(point, window_size, number_of_pairs)),
                    None => None,
                };
                let aux = self.assign_point(region, aux, offset)?;
                self.aux_registry.insert((window_size, number_of_pairs), aux);
                Ok(())
            }
            // aux generator is not assigned yet
            None => Err(Error::Synthesis),
        }
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: &AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<(), Error> {
        let integer_chip = self.integer_chip();

        let y_square = &integer_chip.square(region, &point.y, offset)?;
        let x_square = &integer_chip.square(region, &point.x, offset)?;
        let x_cube = &integer_chip.mul(region, &point.x, x_square, offset)?;
        let x_cube_b = &integer_chip.add_constant(region, x_cube, &self.parameter_b(), offset)?;
        integer_chip.assert_equal(region, x_cube_b, y_square, offset)?;
        Ok(())
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: &AssignedPoint<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let integer_chip = self.integer_chip();
        integer_chip.assert_equal(region, &p0.x, &p1.x, offset)?;
        integer_chip.assert_equal(region, &p0.y, &p1.y, offset)
    }

    fn select(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        p2: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.integer_chip();
        let x = integer_chip.select(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.select(region, &p1.y, &p2.y, c, offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn select_or_assign(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        p2: C,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.integer_chip();
        let p2 = self.to_rns_point(p2);
        let x = integer_chip.select_or_assign(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.select_or_assign(region, &p1.y, &p2.y, c, offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn normalize(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        point: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.integer_chip();
        let x = integer_chip.reduce(region, &point.x, offset)?;
        let y = integer_chip.reduce(region, &point.y, offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    #[allow(unused_variables)]
    fn add(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: &AssignedPoint<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        // guarantees that p0 != p1 or p0 != p1
        // so that we can use unsafe addition formula which assumes operands are not equal
        // addition to that we strictly disallow addition result to be point of infinity
        self.integer_chip().assert_not_equal(region, &p0.x, &p1.x, offset)?;

        self._add_incomplete_unsafe(region, p0, p1, offset)
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: &AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        // point must be asserted to be in curve and not infinity
        self._double_incomplete(region, p, offset)
    }

    fn double_n(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: &AssignedPoint<C::ScalarExt>,
        logn: usize,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let mut acc = p.clone();
        for _ in 0..logn {
            acc = self._double_incomplete(region, &acc, offset)?;
        }
        Ok(acc)
    }

    fn ladder(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        to_double: &AssignedPoint<C::ScalarExt>,
        to_add: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        self._ladder_incomplete(region, to_double, to_add, offset)
    }

    fn neg(&self, region: &mut Region<'_, C::ScalarExt>, p: &AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.integer_chip();
        let y_neg = integer_chip.neg(region, &p.y, offset)?;
        Ok(AssignedPoint::new(p.x.clone(), y_neg))
    }
}

#[cfg(test)]
mod tests {
    use super::BaseFieldEccChip;
    use crate::ecc::{AssignedPoint, EccConfig, Point};
    use crate::halo2;
    use crate::integer::rns::Rns;
    use crate::integer::{IntegerConfig, NUMBER_OF_LOOKUP_LIMBS};
    use crate::maingate;
    use group::{Curve as _, Group};
    use halo2::arithmetic::{CurveAffine, FieldExt};
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use maingate::five::main_gate::{MainGate, MainGateConfig};
    use maingate::five::range::{RangeChip, RangeConfig, RangeInstructions};
    use maingate::{AssignedValue, MainGateInstructions};
    use rand::thread_rng;

    cfg_if::cfg_if! {
        if #[cfg(feature = "kzg")] {
            use halo2::pairing::bn256::G1Affine as Curve;
            use halo2::pairing::bn256::G1 as CurveProjective;
        } else {
            use halo2::pasta::EqAffine as Curve;
            use halo2::pasta::Eq as CurveProjective;
        }
    }

    const BIT_LEN_LIMB: usize = 68;

    fn rns<C: CurveAffine>() -> Rns<C::Base, C::ScalarExt> {
        Rns::construct(BIT_LEN_LIMB)
    }

    fn setup<C: CurveAffine>(k_override: u32) -> (Rns<C::Base, C::ScalarExt>, u32) {
        let rns = rns::<C>();
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        if k_override != 0 {
            k = k_override;
        }
        (rns, k)
    }

    fn gen_table_aux<C: CurveAffine>() -> C {
        let rng = thread_rng();
        C::Curve::random(rng).to_affine()
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
        fn new<C: CurveAffine>(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self {
            let rns = BaseFieldEccChip::<C>::rns(BIT_LEN_LIMB);

            let main_gate_config = MainGate::<C::ScalarExt>::configure(meta);
            let mut overflow_bit_lengths: Vec<usize> = vec![];
            overflow_bit_lengths.extend(rns.overflow_lengths());
            let range_config = RangeChip::<C::ScalarExt>::configure(meta, &main_gate_config, overflow_bit_lengths);
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
    struct TestEccAddition<C: CurveAffine> {
        rns: Rns<C::Base, C::ScalarExt>,
    }

    impl<C: CurveAffine> Circuit<C::ScalarExt> for TestEccAddition<C> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<C::ScalarExt>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let ecc_chip = BaseFieldEccChip::<C>::new(ecc_chip_config, BIT_LEN_LIMB);
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let mut rng = thread_rng();

                    let a = C::CurveExt::random(&mut rng);
                    let b = C::CurveExt::random(&mut rng);

                    let c = a + b;
                    let a = &ecc_chip.assign_point(&mut region, Some(a.into()), offset)?;
                    let b = &ecc_chip.assign_point(&mut region, Some(b.into()), offset)?;
                    let c_0 = &ecc_chip.assign_point(&mut region, Some(c.into()), offset)?;
                    let c_1 = &ecc_chip.add(&mut region, a, b, offset)?;
                    ecc_chip.assert_equal(&mut region, c_0, c_1, offset)?;

                    let c_1 = &ecc_chip.add(&mut region, a, b, offset)?;
                    ecc_chip.assert_equal(&mut region, c_0, c_1, offset)?;

                    // test doubling

                    let a = C::CurveExt::random(&mut rng);
                    let c = a + a;

                    let a = &ecc_chip.assign_point(&mut region, Some(a.into()), offset)?;
                    let c_0 = &ecc_chip.assign_point(&mut region, Some(c.into()), offset)?;
                    let c_1 = &ecc_chip.double(&mut region, a, offset)?;
                    ecc_chip.assert_equal(&mut region, c_0, c_1, offset)?;

                    // test ladder

                    let a = C::CurveExt::random(&mut rng);
                    let b = C::CurveExt::random(&mut rng);
                    let c = a + b + a;

                    let a = &ecc_chip.assign_point(&mut region, Some(a.into()), offset)?;
                    let b = &ecc_chip.assign_point(&mut region, Some(b.into()), offset)?;
                    let c_0 = &ecc_chip.assign_point(&mut region, Some(c.into()), offset)?;
                    let c_1 = &ecc_chip.ladder(&mut region, a, b, offset)?;
                    ecc_chip.assert_equal(&mut region, c_0, c_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_base_field_ecc_addition_circuit() {
        let (rns, k) = setup::<Curve>(0);

        let circuit = TestEccAddition::<Curve> { rns };

        let public_inputs = vec![vec![]];
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccPublicInput<C: CurveAffine> {
        rns: Rns<C::Base, C::ScalarExt>,
        a: Option<C>,
        b: Option<C>,
    }

    impl<C: CurveAffine> Circuit<C::ScalarExt> for TestEccPublicInput<C> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<C::ScalarExt>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let ecc_chip = BaseFieldEccChip::<C>::new(ecc_chip_config, BIT_LEN_LIMB);

            let sum = layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let a = self.a;
                    let b = self.b;
                    let a = ecc_chip.assign_point(&mut region, a, offset)?;
                    let b = ecc_chip.assign_point(&mut region, b, offset)?;
                    let c = ecc_chip.add(&mut region, &a, &b, offset)?;
                    ecc_chip.normalize(&mut region, &c, offset)
                },
            )?;
            ecc_chip.expose_public(layouter.namespace(|| "sum"), sum, 0)?;

            let sum = layouter.assign_region(
                || "region 1",
                |mut region| {
                    let offset = &mut 0;

                    let a = self.a;
                    let a = ecc_chip.assign_point(&mut region, a, offset)?;
                    let c = ecc_chip.double(&mut region, &a, offset)?;
                    ecc_chip.normalize(&mut region, &c, offset)
                },
            )?;
            ecc_chip.expose_public(layouter.namespace(|| "sum"), sum, 8)?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_base_field_ecc_public_input() {
        let (rns, k) = setup::<Curve>(0);
        use rand::thread_rng;
        let mut rng = thread_rng();

        let a = CurveProjective::random(&mut rng).to_affine();
        let b = CurveProjective::random(&mut rng).to_affine();

        let c0: Curve = (a + b).into();
        let c0 = Point::from(&rns, c0);
        let mut public_data = c0.public();
        let c1: Curve = (a + a).into();
        let c1 = Point::from(&rns, c1);
        public_data.extend(c1.public());

        let circuit = TestEccPublicInput::<Curve> { rns, a: Some(a), b: Some(b) };

        let prover = match MockProver::run(k, &circuit, vec![public_data]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccMul<C: CurveAffine> {
        window_size: usize,
        aux_generator: C,
    }

    impl<C: CurveAffine> Circuit<C::ScalarExt> for TestEccMul<C> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<C::ScalarExt>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let mut ecc_chip = BaseFieldEccChip::<C>::new(ecc_chip_config, BIT_LEN_LIMB);
            let main_gate = MainGate::<C::ScalarExt>::new(config.main_gate_config.clone());
            // let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            // main_gate.break_here(&mut region, offset)?;

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    ecc_chip.assign_aux_generator(&mut region, Some(self.aux_generator), offset)?;
                    ecc_chip.assign_aux(&mut region, self.window_size, 1, offset)?;
                    ecc_chip.get_mul_aux(self.window_size, 1)?;
                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    use group::ff::Field;
                    let offset = &mut 0;
                    let mut rng = thread_rng();

                    let base = C::CurveExt::random(&mut rng);
                    let s = C::ScalarExt::random(&mut rng);
                    let result = base * s;

                    let base = ecc_chip.assign_point(&mut region, Some(base.into()), offset)?;
                    let s = main_gate.assign_value(&mut region, &Some(s).into(), offset)?;
                    let result_0 = ecc_chip.assign_point(&mut region, Some(result.into()), offset)?;

                    let result_1 = ecc_chip.mul(&mut region, &base, &s, self.window_size, offset)?;
                    ecc_chip.assert_equal(&mut region, &result_0, &result_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_base_field_ecc_mul_circuit() {
        let (_, k) = setup::<Curve>(20);
        for window_size in 1..5 {
            let mut rng = thread_rng();
            let aux_generator = CurveProjective::random(&mut rng).to_affine();

            let circuit = TestEccMul::<Curve> { aux_generator, window_size };

            let public_inputs = vec![vec![]];
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccBatchMul<C: CurveAffine> {
        window_size: usize,
        number_of_pairs: usize,
        aux_generator: C,
    }

    impl<C: CurveAffine> Circuit<C::ScalarExt> for TestEccBatchMul<C> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<C::ScalarExt>) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let mut ecc_chip = BaseFieldEccChip::<C>::new(ecc_chip_config, BIT_LEN_LIMB);
            let main_gate = MainGate::<C::ScalarExt>::new(config.main_gate_config.clone());

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    ecc_chip.assign_aux_generator(&mut region, Some(self.aux_generator), offset)?;
                    ecc_chip.assign_aux(&mut region, self.window_size, self.number_of_pairs, offset)?;
                    ecc_chip.get_mul_aux(self.window_size, self.number_of_pairs)?;
                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    use group::ff::Field;
                    let offset = &mut 0;
                    let mut rng = thread_rng();

                    let mut acc = C::CurveExt::identity();
                    let pairs: Vec<(AssignedPoint<C::ScalarExt>, AssignedValue<C::ScalarExt>)> = (0..self.number_of_pairs)
                        .map(|_| {
                            let base = C::CurveExt::random(&mut rng);
                            let s = C::ScalarExt::random(&mut rng);
                            acc = acc + (base * s);
                            let base = ecc_chip.assign_point(&mut region, Some(base.into()), offset)?;
                            let s = main_gate.assign_value(&mut region, &Some(s).into(), offset)?;
                            Ok((base, s))
                        })
                        .collect::<Result<_, Error>>()?;

                    let result_0 = ecc_chip.assign_point(&mut region, Some(acc.into()), offset)?;
                    let result_1 = ecc_chip.mul_batch_1d_horizontal(&mut region, pairs, self.window_size, offset)?;
                    ecc_chip.assert_equal(&mut region, &result_0, &result_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_base_field_ecc_mul_batch_circuit() {
        let (_, k) = setup::<Curve>(20);

        for number_of_pairs in 4..5 {
            for window_size in 1..3 {
                let mut rng = thread_rng();
                let aux_generator = CurveProjective::random(&mut rng).to_affine();

                let circuit = TestEccBatchMul::<Curve> {
                    aux_generator,
                    window_size,
                    number_of_pairs,
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
