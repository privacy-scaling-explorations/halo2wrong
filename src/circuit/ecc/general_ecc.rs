use super::{AssignedIncompletePoint, EccConfig};
use crate::circuit::integer::{IntegerChip, IntegerInstructions, Range};
use crate::circuit::{AssignedInteger, UnassignedInteger};
use crate::rns::{Integer, Rns};
use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::main_gate::five::main_gate::MainGate;
use halo2arith::{halo2, AssignedCondition, MainGateInstructions};

use crate::circuit::ecc::{AssignedPoint, Point};

pub trait GeneralEccInstruction<Emulated: CurveAffine, N: FieldExt> {
    fn assign_point(&self, region: &mut Region<'_, N>, point: Option<Emulated>, offset: &mut usize) -> Result<AssignedPoint<N>, Error>;

    fn assign_point_incomplete(&self, region: &mut Region<'_, N>, point: Option<Emulated>, offset: &mut usize) -> Result<AssignedIncompletePoint<N>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, N>, point: &AssignedPoint<N>, offset: &mut usize) -> Result<(), Error>;

    fn assert_is_on_curve_incomplete(&self, region: &mut Region<'_, N>, point: &AssignedIncompletePoint<N>, offset: &mut usize) -> Result<(), Error>;

    fn select(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;

    fn select_incomplete(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedIncompletePoint<N>,
        p2: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error>;

    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;

    fn select_or_assign_incomplete(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedIncompletePoint<N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error>;

    fn assert_equal(&self, region: &mut Region<'_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>, offset: &mut usize) -> Result<(), Error>;

    fn assert_equal_incomplete(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedIncompletePoint<N>,
        p1: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn add(&self, region: &mut Region<'_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error>;

    fn add_incomplete(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedIncompletePoint<N>,
        p1: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error>;

    fn double(&self, region: &mut Region<'_, N>, p: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error>;

    fn double_incomplete(&self, region: &mut Region<'_, N>, p: &AssignedIncompletePoint<N>, offset: &mut usize) -> Result<AssignedIncompletePoint<N>, Error>;

    fn ladder_incomplete(
        &self,
        region: &mut Region<'_, N>,
        to_double: &AssignedIncompletePoint<N>,
        to_add: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error>;

    fn neg(&self, region: &mut Region<'_, N>, p: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error>;

    fn neg_incomplete(&self, region: &mut Region<'_, N>, p: &AssignedIncompletePoint<N>, offset: &mut usize) -> Result<AssignedIncompletePoint<N>, Error>;

    fn mul_var(&self, region: &mut Region<'_, N>, p: AssignedPoint<N>, e: AssignedInteger<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error>;

    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<Emulated::Base, N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;
}

pub struct GeneralEccChip<Emulated: CurveAffine, N: FieldExt> {
    pub(super) config: EccConfig,
    pub(super) rns_base_field: Rns<Emulated::Base, N>,
    pub(super) rns_scalar_field: Rns<Emulated::Scalar, N>,
}

// Ecc operation mods
mod add;
mod double;
mod ladder;
mod mul;

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
    pub(super) fn new(config: EccConfig, rns_base_field: Rns<Emulated::Base, N>, rns_scalar_field: Rns<Emulated::ScalarExt, N>) -> Result<Self, Error> {
        Ok(Self {
            config,
            rns_base_field,
            rns_scalar_field,
        })
    }

    fn scalar_field_chip(&self) -> IntegerChip<Emulated::ScalarExt, N> {
        let integer_chip_config = self.config.integer_chip_config();
        IntegerChip::new(integer_chip_config, self.rns_scalar_field.clone())
    }

    fn base_field_chip(&self) -> IntegerChip<Emulated::Base, N> {
        let integer_chip_config = self.config.integer_chip_config();
        IntegerChip::new(integer_chip_config, self.rns_base_field.clone())
    }

    fn main_gate(&self) -> MainGate<N> {
        MainGate::<N>::new(self.config.main_gate_config.clone())
    }

    #[cfg(feature = "zcash")]
    fn parameter_a(&self) -> Integer<Emulated::Base, N> {
        self.rns_base_field.new(Emulated::a())
    }

    #[cfg(feature = "kzg")]
    fn parameter_a(&self) -> Integer<Emulated::Base, N> {
        self.rns_base_field.new(Emulated::Base::zero())
    }

    fn parameter_b(&self) -> Integer<Emulated::Base, N> {
        self.rns_base_field.new(Emulated::b())
    }

    #[cfg(feature = "zcash")]
    fn is_a_0(&self) -> bool {
        Emulated::a() == Emulated::Base::zero()
    }

    #[cfg(feature = "kzg")]
    fn is_a_0(&self) -> bool {
        true
    }

    fn into_rns_point(&self, point: Emulated) -> Point<Emulated::Base, N> {
        let coords = point.coordinates();
        if coords.is_some().into() {
            let coords = coords.unwrap();
            let x = self.rns_base_field.new(*coords.x());
            let y = self.rns_base_field.new(*coords.y());
            Point { x, y, is_identity: false }
        } else {
            Point {
                x: self.rns_base_field.zero(),
                y: self.rns_base_field.zero(),
                is_identity: true,
            }
        }
    }
}

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccInstruction<Emulated, N> for GeneralEccChip<Emulated, N> {
    fn assert_is_on_curve(&self, region: &mut Region<'_, N>, point: &AssignedPoint<N>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let is_infinity = point.z.clone();
        self.assert_is_on_curve_incomplete(region, &point.into(), offset)?;
        main_gate.assert_zero(region, is_infinity, offset)
    }

    fn assert_is_on_curve_incomplete(&self, region: &mut Region<'_, N>, point: &AssignedIncompletePoint<N>, offset: &mut usize) -> Result<(), Error> {
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
        let point = self.assign_point_incomplete(region, point, offset)?;
        let z = &self.main_gate().assign_bit(region, &Some(N::zero()).into(), offset)?;
        let point = AssignedPoint::from_impcomplete(&point, z);
        Ok(point)
    }

    fn assign_point_incomplete(&self, region: &mut Region<'_, N>, point: Option<Emulated>, offset: &mut usize) -> Result<AssignedIncompletePoint<N>, Error> {
        let integer_chip = self.base_field_chip();

        let point = point.map(|point| self.into_rns_point(point));
        let (x, y) = match point {
            Some(point) => (Some(point.x).into(), Some(point.y).into()),
            None => (UnassignedInteger::from(None), UnassignedInteger::from(None)),
        };

        let x = integer_chip.range_assign_integer(region, x, Range::Remainder, offset)?;
        let y = integer_chip.range_assign_integer(region, y, Range::Remainder, offset)?;

        let point = AssignedIncompletePoint { x, y };
        self.assert_is_on_curve_incomplete(region, &point, offset)?;

        Ok(point)
    }

    fn assert_equal(&self, region: &mut Region<'_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>, offset: &mut usize) -> Result<(), Error> {
        self.assert_equal_incomplete(region, &p0.into(), &p1.into(), offset)
    }

    fn assert_equal_incomplete(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedIncompletePoint<N>,
        p1: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<(), Error> {
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
        let point = &self.select_incomplete(region, c, &p1.into(), &p2.into(), offset)?;
        let c = self.main_gate().cond_select(region, p1.z.clone(), p2.z.clone(), c, offset)?.into();
        Ok(AssignedPoint::from_impcomplete(point, &c))
    }

    fn select_incomplete(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedIncompletePoint<N>,
        p2: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.cond_select(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.cond_select(region, &p1.y, &p2.y, c, offset)?;
        Ok(AssignedIncompletePoint::new(x, y))
    }

    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        let point = &self.select_or_assign_incomplete(region, c, &p1.into(), p2, offset)?;
        let c: AssignedCondition<N> = self
            .main_gate()
            .cond_select_or_assign(region, p1.z.clone(), if bool::from(p2.is_identity()) { N::one() } else { N::zero() }, c, offset)?
            .into();
        Ok(AssignedPoint::from_impcomplete(point, &c))
    }

    fn select_or_assign_incomplete(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedIncompletePoint<N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let p2 = self.into_rns_point(p2);
        let x = integer_chip.cond_select_or_assign(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.cond_select_or_assign(region, &p1.y, &p2.y, c, offset)?;
        Ok(AssignedIncompletePoint::new(x, y))
    }

    fn add(&self, region: &mut Region<'_, N>, p0: &AssignedPoint<N>, p1: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        self._add(region, p0, p1, offset)
    }

    fn add_incomplete(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedIncompletePoint<N>,
        p1: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error> {
        self._add_incomplete_unsafe(region, p0, p1, offset)
    }

    fn double(&self, region: &mut Region<'_, N>, p: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        self._double(region, p, offset)
    }

    fn double_incomplete(&self, region: &mut Region<'_, N>, p: &AssignedIncompletePoint<N>, offset: &mut usize) -> Result<AssignedIncompletePoint<N>, Error> {
        self._double_incomplete(region, p, offset)
    }

    fn ladder_incomplete(
        &self,
        region: &mut Region<'_, N>,
        to_double: &AssignedIncompletePoint<N>,
        to_add: &AssignedIncompletePoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedIncompletePoint<N>, Error> {
        self._ladder_incomplete(region, to_double, to_add, offset)
    }

    fn neg(&self, region: &mut Region<'_, N>, p: &AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        let incomplete = self.neg_incomplete(region, &p.into(), offset)?;
        Ok(AssignedPoint::from_impcomplete(&incomplete, &p.z.clone()))
    }

    fn neg_incomplete(&self, region: &mut Region<'_, N>, p: &AssignedIncompletePoint<N>, offset: &mut usize) -> Result<AssignedIncompletePoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let y_neg = integer_chip.neg(region, &p.y, offset)?;
        Ok(AssignedIncompletePoint::new(p.x.clone(), y_neg))
    }

    fn mul_var(&self, region: &mut Region<'_, N>, p: AssignedPoint<N>, e: AssignedInteger<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        self._mul_var(region, p, e, offset)
    }

    #[allow(unused_variables)]
    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<Emulated::Base, N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::ecc::general_ecc::{GeneralEccChip, GeneralEccInstruction};
    use crate::circuit::ecc::{AssignedPoint, EccConfig};
    use crate::circuit::integer::{IntegerChip, IntegerConfig, IntegerInstructions};
    use crate::rns::Rns;
    use crate::NUMBER_OF_LOOKUP_LIMBS;
    use group::ff::Field as _;
    use group::Group;
    use halo2::arithmetic::{CurveAffine, FieldExt};
    use halo2::circuit::{Layouter, Region, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use halo2arith::main_gate::five::main_gate::{MainGate, MainGateConfig};
    use halo2arith::main_gate::five::range::{RangeChip, RangeConfig, RangeInstructions};
    use halo2arith::{halo2, MainGateInstructions};

    #[cfg(feature = "kzg")]
    use halo2::pairing::bn256::Fq as Field;
    #[cfg(feature = "kzg")]
    use halo2::pairing::bn256::G1Affine as Curve;

    #[cfg(feature = "zcash")]
    use halo2::pasta::EqAffine as Curve;
    #[cfg(feature = "zcash")]
    use halo2::pasta::Fp as Field;

    const BIT_LEN_LIMB: usize = 68;

    impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
        fn assign_infinity(&self, region: &mut Region<'_, N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
            let integer_chip = self.base_field_chip();

            // TODO/FIX: prover can assign anything other than infinity
            let x = integer_chip.assign_integer(region, Some(self.rns_base_field.zero()).into(), offset)?;
            let y = integer_chip.assign_integer(region, Some(self.rns_base_field.zero()).into(), offset)?;
            let z = self.main_gate().assign_bit(region, &Some(N::one()).into(), offset)?;
            let point = AssignedPoint::new(x, y, z);

            Ok(point)
        }
    }

    fn rns<C: CurveAffine, N: FieldExt>() -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>) {
        let rns_base = Rns::construct(BIT_LEN_LIMB);
        let rns_scalar = Rns::construct(BIT_LEN_LIMB);
        (rns_base, rns_scalar)
    }

    fn setup<C: CurveAffine, N: FieldExt>(k_override: u32) -> (Rns<C::Base, N>, Rns<C::ScalarExt, N>, u32) {
        let (rns_base, rns_scalar) = rns::<C, N>();
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        #[cfg(not(feature = "no_lookup"))]
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let mut k: u32 = 8;
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
            let main_gate_config = MainGate::<N>::configure(meta);

            let (rns_base, rns_scalar) = rns::<C, N>();

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
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(layouter)?;
            #[cfg(not(feature = "no_lookup"))]
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
            let ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, self.rns_base.clone(), self.rns_scalar.clone())?;
            // let main_gate = MainGate::<N>::new(config.main_gate_config.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    use rand::thread_rng;
                    let mut rng = thread_rng();

                    // this should fail

                    // let x = self.rns_base.rand_in_remainder_range();
                    // let y = self.rns_base.rand_in_remainder_range();
                    // let z = N::zero();
                    // let x = base_chip.assign_integer(&mut region, Some(x), offset)?;
                    // let y = base_chip.assign_integer(&mut region, Some(y), offset)?;
                    // let z = main_gate.assign_value(&mut region, &Some(z).into(), MainGateColumn::A, offset)?.into();
                    // let point = AssignedPoint { x, y, z };
                    // ecc_chip.assert_is_on_curve(&mut region, &point, offset)?;

                    let a = C::CurveExt::random(&mut rng);
                    let b = C::CurveExt::random(&mut rng);

                    let c = a + b;
                    let a = &ecc_chip.assign_point(&mut region, Some(a.into()), offset)?;
                    let b = &ecc_chip.assign_point(&mut region, Some(b.into()), offset)?;
                    let c_0 = &ecc_chip.assign_point(&mut region, Some(c.into()), offset)?;
                    let c_1 = &ecc_chip.add(&mut region, a, b, offset)?;
                    ecc_chip.assert_equal(&mut region, c_0, c_1, offset)?;

                    let c_1 = &ecc_chip.add_incomplete(&mut region, &a.into(), &b.into(), offset)?;
                    ecc_chip.assert_equal_incomplete(&mut region, &c_0.into(), c_1, offset)?;

                    let inf = ecc_chip.assign_infinity(&mut region, offset)?;
                    let c = &ecc_chip.add(&mut region, a, &inf, offset)?;
                    ecc_chip.assert_equal(&mut region, c, a, offset)?;
                    let c = &ecc_chip.add(&mut region, &inf, b, offset)?;
                    ecc_chip.assert_equal(&mut region, c, b, offset)?;
                    let c = &ecc_chip.add(&mut region, &inf, &inf, offset)?;
                    ecc_chip.assert_equal(&mut region, c, &inf, offset)?;

                    // test doubling

                    let a = C::CurveExt::random(&mut rng);
                    let b = a.clone();
                    let c = a + b;

                    let a = &ecc_chip.assign_point(&mut region, Some(a.into()), offset)?;
                    let b = &ecc_chip.assign_point(&mut region, Some(b.into()), offset)?;
                    let c_0 = &ecc_chip.assign_point(&mut region, Some(c.into()), offset)?;
                    let c_1 = &ecc_chip.add(&mut region, a, b, offset)?;
                    ecc_chip.assert_equal(&mut region, c_0, c_1, offset)?;

                    let a = C::CurveExt::random(&mut rng);
                    let c = a + a;

                    let a = &ecc_chip.assign_point(&mut region, Some(a.into()), offset)?;
                    let c_0 = &ecc_chip.assign_point(&mut region, Some(c.into()), offset)?;
                    let c_1 = &ecc_chip.double(&mut region, a, offset)?;
                    ecc_chip.assert_equal(&mut region, c_0, c_1, offset)?;

                    let c_1 = &ecc_chip.double_incomplete(&mut region, &a.into(), offset)?;
                    ecc_chip.assert_equal_incomplete(&mut region, &c_0.into(), c_1, offset)?;

                    let c = &ecc_chip.double(&mut region, &inf, offset)?;
                    ecc_chip.assert_equal(&mut region, c, &inf, offset)?;

                    // test ladder

                    let a = C::CurveExt::random(&mut rng);
                    let b = C::CurveExt::random(&mut rng);
                    let c = a + b + a;

                    let a = &ecc_chip.assign_point(&mut region, Some(a.into()), offset)?;
                    let b = &ecc_chip.assign_point(&mut region, Some(b.into()), offset)?;
                    let c_0 = &ecc_chip.assign_point(&mut region, Some(c.into()), offset)?;
                    let c_1 = &ecc_chip.ladder_incomplete(&mut region, &a.into(), &b.into(), offset)?;

                    ecc_chip.assert_equal_incomplete(&mut region, &c_0.into(), c_1, offset)?;

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

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccScalarMul<C: CurveAffine, N: FieldExt> {
        rns_base: Rns<C::Base, N>,
        rns_scalar: Rns<C::ScalarExt, N>,
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
            let ecc_chip = GeneralEccChip::<C, N>::new(ecc_chip_config, self.rns_base.clone(), self.rns_scalar.clone())?;
            let scalar_chip = IntegerChip::<C::ScalarExt, N>::new(config.integer_chip_config(), self.rns_scalar.clone());
            // let main_gate = MainGate::<N>::new(config.main_gate_config.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    use rand::thread_rng;
                    let mut rng = thread_rng();

                    // s * G
                    let base = C::CurveExt::random(&mut rng);
                    let s = C::ScalarExt::random(&mut rng);
                    let result = base * s;
                    let s = self.rns_scalar.new(s);
                    let base = ecc_chip.assign_point(&mut region, Some(base.into()), offset)?;
                    let s = scalar_chip.assign_integer(&mut region, Some(s).into(), offset)?;
                    let result_0 = ecc_chip.assign_point(&mut region, Some(result.into()), offset)?;
                    // main_gate.break_here(&mut region, offset);
                    let result_1 = ecc_chip.mul_var(&mut region, base, s, offset)?;
                    ecc_chip.assert_equal(&mut region, &result_0, &result_1, offset)?;

                    // // 0 * G
                    // let infinity = ecc_chip.assign_infinity(&mut region, offset)?;
                    // let base = C::CurveExt::random(&mut rng);
                    // let s = self.rns_scalar.new(C::ScalarExt::zero());
                    // let base = ecc_chip.assign_point(&mut region, Some(base.into()), offset)?;
                    // let s = scalar_chip.assign_integer(&mut region, Some(s), offset)?;
                    // let result = ecc_chip.mul_var(&mut region, base, s, offset)?;
                    // ecc_chip.assert_equal(&mut region, &result, &infinity, offset)?;

                    // s * infinity
                    // let base = ecc_chip.assign_infinity(&mut region, offset)?;
                    // let s = self.rns_scalar.new(C::ScalarExt::rand());
                    // let s = scalar_chip.assign_integer(&mut region, Some(s), offset)?;
                    // let result = ecc_chip.mul_var(&mut region, base, s, offset)?;
                    // ecc_chip.assert_equal(&mut region, &result, &infinity, offset)?;

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
        let circuit = TestEccScalarMul::<Curve, Field> { rns_base, rns_scalar };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }
}
