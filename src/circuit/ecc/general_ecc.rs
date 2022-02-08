use super::{AssignedPoint, EccConfig, Point};
use crate::circuit::integer::{IntegerChip, IntegerInstructions, Range};
use crate::circuit::UnassignedInteger;
use crate::rns::{Integer, Rns};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::halo2::circuit::Layouter;
use halo2arith::halo2::plonk::{Column, Instance};
use halo2arith::main_gate::five::main_gate::MainGate;
use halo2arith::{big_to_fe, halo2, Assigned, AssignedCondition};

mod add;
mod mul;

fn make_mul_aux<C: CurveAffine>(aux_to_add: C, window_size: usize) -> C {
    use group::ff::PrimeField;
    use group::Curve;
    use num_bigint::BigUint as big_uint;
    use num_traits::One;

    let n = C::Scalar::NUM_BITS as usize;
    let mut number_of_selectors = n / window_size;
    if n % window_size != 0 {
        number_of_selectors += 1;
    }
    let mut k = big_uint::one();
    let one = big_uint::one();
    for i in 0..number_of_selectors {
        k |= &one << (i * window_size);
    }
    (-aux_to_add * big_to_fe::<C::Scalar>(k)).to_affine()
}

pub struct GeneralEccChip<Emulated: CurveAffine, N: FieldExt> {
    config: EccConfig,
    rns_base_field: Rns<Emulated::Base, N>,
    rns_scalar_field: Rns<Emulated::Scalar, N>,
}

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
    fn rns(bit_len_limb: usize) -> (Rns<Emulated::Base, N>, Rns<Emulated::ScalarExt, N>) {
        (Rns::construct(bit_len_limb), Rns::construct(bit_len_limb))
    }

    pub(super) fn new(config: EccConfig, bit_len_limb: usize) -> Result<Self, Error> {
        let (rns_base_field, rns_scalar_field) = Self::rns(bit_len_limb);
        Ok(Self {
            config,
            rns_base_field,
            rns_scalar_field,
        })
    }

    fn instance_column(&self) -> Column<Instance> {
        self.config.main_gate_config.instance
    }

    fn base_field_chip(&self) -> IntegerChip<Emulated::Base, N> {
        IntegerChip::new(self.config.integer_chip_config(), self.rns_base_field.clone())
    }

    fn scalar_field_chip(&self) -> IntegerChip<Emulated::ScalarExt, N> {
        IntegerChip::new(self.config.integer_chip_config(), self.rns_scalar_field.clone())
    }

    fn main_gate(&self) -> MainGate<N> {
        MainGate::<N>::new(self.config.main_gate_config.clone())
    }

    pub(super) fn to_rns_point(&self, point: Emulated) -> Point<Emulated::Base, N> {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();

        let x = self.rns_base_field.new(*coords.x());
        let y = self.rns_base_field.new(*coords.y());
        Point { x, y }
    }

    cfg_if::cfg_if! {
      if #[cfg(feature = "kzg")] {
        fn parameter_a(&self) -> Integer<Emulated::Base, N> {
            use group::ff::Field;
            self.rns_base_field.new(Emulated::Base::zero())
        }

        fn is_a_0(&self) -> bool {
            true
        }
      } else {
        fn parameter_a(&self) -> Integer<Emulated::Base, N> {
            self.rns_base_field.new(Emulated::a())
        }
        fn is_a_0(&self) -> bool {
            use group::ff::Field;
            Emulated::a() == Emulated::Base::zero()
        }
      }
    }

    fn parameter_b(&self) -> Integer<Emulated::Base, N> {
        self.rns_base_field.new(Emulated::b())
    }
}

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
    fn expose_public(&self, mut layouter: impl Layouter<N>, point: AssignedPoint<N>, offset: usize) -> Result<(), Error> {
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

    fn assign_constant(&self, region: &mut Region<'_, N>, point: Emulated, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();
        let base_field_chip = self.base_field_chip();
        let x = base_field_chip.assign_constant(region, *coords.x(), offset)?;
        let y = base_field_chip.assign_constant(region, *coords.y(), offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, N>, point: &AssignedPoint<N>, offset: &mut usize) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();

        let y_square = &integer_chip.square(region, &point.y, offset)?;
        let x_square = &integer_chip.square(region, &point.x, offset)?;
        let x_cube = &integer_chip.mul(region, &point.x, x_square, offset)?;
        let x_cube_b = &integer_chip.add_constant(region, x_cube, &self.parameter_b(), offset)?;
        if self.is_a_0() {
            integer_chip.assert_equal(region, x_cube_b, y_square, offset)?;
        } else {
            let a_x = &integer_chip.mul_constant(region, &point.x, &self.parameter_a(), offset)?;
            let must_be_y_square = &integer_chip.add(region, a_x, x_cube_b, offset)?;
            integer_chip.assert_equal(region, must_be_y_square, y_square, offset)?;
        }

        Ok(())
    }

    fn assign_point(&self, region: &mut Region<'_, N>, point: Option<Emulated>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();

        let point = point.map(|point| self.to_rns_point(point));
        let (x, y) = match point {
            Some(point) => (Some(point.x).into(), Some(point.y).into()),
            None => (UnassignedInteger::from(None), UnassignedInteger::from(None)),
        };

        let x = integer_chip.range_assign_integer(region, x, Range::Remainder, offset)?;
        let y = integer_chip.range_assign_integer(region, y, Range::Remainder, offset)?;

        let point = AssignedPoint { x, y };
        self.assert_is_on_curve(region, &point, offset)?;

        Ok(point)
    }

    fn assert_equal(&self, region: &mut Region<'_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>, offset: &mut usize) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();
        integer_chip.assert_equal(region, &p0.x, &p1.x, offset)?;
        integer_chip.assert_equal(region, &p0.y, &p1.y, offset)
    }

    fn select(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.select(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.select(region, &p1.y, &p2.y, c, offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let p2 = self.to_rns_point(p2);
        let x = integer_chip.select_or_assign(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.select_or_assign(region, &p1.y, &p2.y, c, offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn normalize(&self, region: &mut Region<'_, N>, point: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.reduce(region, &point.x, offset)?;
        let y = integer_chip.reduce(region, &point.y, offset)?;
        Ok(AssignedPoint::new(x, y))
    }

    fn add(&self, region: &mut Region<'_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        self._add_incomplete_unsafe(region, p0, p1, offset)
    }

    fn double(&self, region: &mut Region<'_, N>, p: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        self._double_incomplete(region, p, offset)
    }

    fn double_n(&self, region: &mut Region<'_, N>, p: &AssignedPoint<N>, logn: usize, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        let mut acc = p.clone();
        for _ in 0..logn {
            acc = self._double_incomplete(region, &acc, offset)?;
        }
        Ok(acc)
    }

    fn ladder(
        &self,
        region: &mut Region<'_, N>,
        to_double: &AssignedPoint<N>,
        to_add: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        self._ladder_incomplete(region, to_double, to_add, offset)
    }

    fn neg(&self, region: &mut Region<'_, N>, p: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let y_neg = integer_chip.neg(region, &p.y, offset)?;
        Ok(AssignedPoint::new(p.x.clone(), y_neg))
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::ecc::general_ecc::mul::MulAux;
    use crate::circuit::ecc::general_ecc::GeneralEccChip;
    use crate::circuit::ecc::{EccConfig, Point};
    use crate::circuit::integer::{IntegerConfig, IntegerInstructions};
    use crate::rns::Rns;
    use crate::NUMBER_OF_LOOKUP_LIMBS;
    use group::{Curve as _, Group};
    use halo2::arithmetic::{CurveAffine, FieldExt};
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use halo2arith::halo2;
    use halo2arith::main_gate::five::main_gate::{MainGate, MainGateConfig};
    use halo2arith::main_gate::five::range::{RangeChip, RangeConfig, RangeInstructions};
    use rand::thread_rng;

    use super::make_mul_aux;

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

    fn rns<C: CurveAffine, N: FieldExt>() -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>) {
        (Rns::construct(BIT_LEN_LIMB), Rns::construct(BIT_LEN_LIMB))
    }

    fn setup<C: CurveAffine, N: FieldExt>(k_override: u32) -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>, u32) {
        let (rns_base, rns_scalar) = rns::<C, N>();
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        if k_override != 0 {
            k = k_override;
        }
        (rns_base, rns_scalar, k)
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

            let ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, BIT_LEN_LIMB)?;
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    // this should fail
                    // let x = self.rns_base.rand_in_remainder_range();
                    // let y = self.rns_base.rand_in_remainder_range();
                    // let z = N::zero();
                    // let x = base_chip.assign_integer(&mut region, Some(x), offset)?;
                    // let y = base_chip.assign_integer(&mut region, Some(y), offset)?;
                    // let z = main_gate.assign_value(&mut region, &Some(z).into(), MainGateColumn::A, offset)?.into();
                    // let point = AssignedPoint { x, y, z };
                    // ecc_chip.assert_is_on_curve(&mut region, &point, offset)?;
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
        rns_base: Rns<C::Base, N>,
        rns_scalar: Rns<C::ScalarExt, N>,
        a: Option<C>,
        b: Option<C>,
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
            let ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, BIT_LEN_LIMB)?;

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
    fn test_general_ecc_public_input() {
        let (rns_base, rns_scalar, k) = setup::<Curve, Field>(0);
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
            rns_base: rns_base.clone(),
            rns_scalar,
            a: Some(a),
            b: Some(b),
        };

        let prover = match MockProver::run(k, &circuit, vec![public_data]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccScalarMul<C: CurveAffine, N: FieldExt> {
        rns_base: Rns<C::Base, N>,
        rns_scalar: Rns<C::ScalarExt, N>,
        window_size: usize,
        aux_to_add: C,
    }

    impl<C: CurveAffine, N: FieldExt> Circuit<N> for TestEccScalarMul<C, N> {
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
            let ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, BIT_LEN_LIMB)?;
            let scalar_chip = ecc_chip.scalar_field_chip();
            // let main_gate = MainGate::<N>::new(config.main_gate_config.clone());
            // main_gate.break_here(&mut region, offset)?;

            let aux_to_sub = make_mul_aux(self.aux_to_add, self.window_size);

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    use group::ff::Field;
                    let offset = &mut 0;
                    let mut rng = thread_rng();

                    let aux_to_add = ecc_chip.assign_point(&mut region, Some(self.aux_to_add), offset)?;
                    let aux_to_sub = ecc_chip.assign_point(&mut region, Some(aux_to_sub), offset)?;
                    let mul_aux = MulAux::new(aux_to_add, aux_to_sub);

                    let base = C::CurveExt::random(&mut rng);
                    let s = C::ScalarExt::random(&mut rng);
                    let result = base * s;

                    let s = self.rns_scalar.new(s);
                    let base = ecc_chip.assign_point(&mut region, Some(base.into()), offset)?;
                    let s = scalar_chip.assign_integer(&mut region, Some(s).into(), offset)?;
                    let result_0 = ecc_chip.assign_point(&mut region, Some(result.into()), offset)?;

                    let result_1 = ecc_chip.mul_var(&mut region, &base, &s, &mul_aux, self.window_size, offset)?;
                    ecc_chip.assert_equal(&mut region, &result_0, &result_1, offset)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_multiplication_circuit() {
        let (rns_base, rns_scalar, k) = setup::<Curve, Field>(20);
        for window_size in 1..5 {
            let mut rng = thread_rng();
            let aux_to_add = CurveProjective::random(&mut rng).to_affine();

            let circuit = TestEccScalarMul::<Curve, Field> {
                rns_base: rns_base.clone(),
                rns_scalar: rns_scalar.clone(),
                aux_to_add,
                window_size,
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
