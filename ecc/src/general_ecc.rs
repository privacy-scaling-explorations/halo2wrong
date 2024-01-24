use super::{AssignedPoint, EccConfig, MulAux, Point};
use crate::halo2;
use crate::halo2::arithmetic::Field;
use crate::integer::rns::{Integer, Rns};
use crate::integer::{IntegerChip, IntegerInstructions, Range, UnassignedInteger};
use crate::maingate;
use halo2::arithmetic::CurveAffine;
use halo2::circuit::{Layouter, Value};
use halo2::halo2curves::ff::PrimeField;
use halo2::plonk::Error;
use integer::maingate::RegionCtx;
use maingate::{AssignedCondition, MainGate};
use std::collections::BTreeMap;
use std::rc::Rc;

mod add;
mod mul;

/// Constaints elliptic curve operations such as assigment, addition and
/// multiplication
#[derive(Clone, Debug)]
#[allow(clippy::type_complexity)]
pub struct GeneralEccChip<
    Emulated: CurveAffine,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    /// `IntegerChip` for the base field of the EC
    base_field_chip: IntegerChip<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    /// `IntegerChip` for the scalar field of the EC
    scalar_field_chip: IntegerChip<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    /// Auxiliary point for optimized multiplication algorithm
    aux_generator: Option<(
        AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Value<Emulated>,
    )>,
    /// Auxiliary points for optimized multiplication for each (window_size,
    /// n_pairs) pairs
    aux_registry: BTreeMap<
        usize,
        (
            Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        ),
    >,
}

impl<
        Emulated: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > GeneralEccChip<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Residue numeral system
    /// Used to emulate the base field `Emulated::Base` and the scalar
    /// field `Emulated::Scalar` over the native field `N`
    pub fn rns() -> (
        Rns<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Rns<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        (Rns::construct(), Rns::construct())
    }

    /// Return `GeneralEccChip` from `EccConfig`
    pub fn new(config: EccConfig) -> Self {
        let (rns_base_field, rns_scalar_field) = Self::rns();
        let integer_config = config.integer_chip_config();
        Self {
            base_field_chip: IntegerChip::new(integer_config.clone(), Rc::new(rns_base_field)),
            scalar_field_chip: IntegerChip::new(integer_config, Rc::new(rns_scalar_field)),
            aux_generator: None,
            aux_registry: BTreeMap::new(),
        }
    }

    /// Residue numeral system for the base field of the curve
    /// Return new refence for chips' rns base field
    pub fn rns_base(&self) -> Rc<Rns<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        self.base_field_chip.rns()
    }

    /// Residue numeral system for the scalar field of the curve
    /// Return new refence for chips' rns scalar field
    pub fn rns_scalar(&self) -> Rc<Rns<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>> {
        self.scalar_field_chip.rns()
    }

    /// Assign Rns base for chip
    pub fn new_unassigned_base(
        &self,
        e: Value<Emulated::Base>,
    ) -> UnassignedInteger<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        e.map(|e| Integer::from_fe(e, self.rns_base())).into()
    }

    /// Assign Rns Scalar for chip
    pub fn new_unassigned_scalar(
        &self,
        e: Value<Emulated::Scalar>,
    ) -> UnassignedInteger<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        e.map(|e| Integer::from_fe(e, self.rns_scalar())).into()
    }

    /// Return `IntegerChip` for the base field of the EC
    pub fn base_field_chip(
        &self,
    ) -> &IntegerChip<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.base_field_chip
    }

    /// Return `IntegerChip` for the scalar field of the EC
    pub fn scalar_field_chip(
        &self,
    ) -> &IntegerChip<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        &self.scalar_field_chip
    }

    /// Return `Maingate` of the `GeneralEccChip`
    pub fn main_gate(&self) -> &MainGate<N> {
        self.base_field_chip.main_gate()
    }

    /// Returns a `Point` (Rns representation) from a point in the emulated EC
    pub fn to_rns_point(
        &self,
        point: Emulated,
    ) -> Point<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let coords = point.coordinates();
        // disallow point of infinity
        // it will not pass assing point enforcement
        let coords = coords.unwrap();

        let x = Integer::from_fe(*coords.x(), self.rns_base());
        let y = Integer::from_fe(*coords.y(), self.rns_base());
        Point { x, y }
    }

    /// Returns emulated EC constant $b$
    fn parameter_b(&self) -> Integer<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        Integer::from_fe(Emulated::b(), self.rns_base())
    }

    /// Auxilary point for optimized multiplication algorithm
    fn get_mul_correction(
        &self,
        window_size: usize,
    ) -> Result<
        (
            Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
            MulAux<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        ),
        Error,
    > {
        // Gets chips' aux generator
        let to_add = match self.aux_generator.clone() {
            Some((assigned, _)) => Ok(assigned),
            None => Err(Error::Synthesis),
        }?;
        let (scalar_correction, to_sub) = match self.aux_registry.get(&window_size) {
            Some(aux) => Ok(aux.clone()),
            None => Err(Error::Synthesis),
        }?;

        Ok((scalar_correction, MulAux::new(to_add, to_sub)))
    }
}

impl<
        Emulated: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > GeneralEccChip<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Expose `AssignedPoint` as Public Input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<N>,
        point: AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        offset: usize,
    ) -> Result<(), Error> {
        use integer::maingate::MainGateInstructions;
        let main_gate = self.main_gate();

        let mut offset = offset;
        for limb in point.x().limbs().iter() {
            main_gate.expose_public(layouter.namespace(|| "x coords"), limb.into(), offset)?;
            offset += 1;
        }
        for limb in point.y().limbs().iter() {
            main_gate.expose_public(layouter.namespace(|| "y coords"), limb.into(), offset)?;
            offset += 1;
        }
        Ok(())
    }

    /// Takes `Point` and assign its coordiantes as constant
    /// Returned as `AssignedPoint`
    pub fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: Emulated,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let coords = point.coordinates();
        // disallow point of infinity
        let coords = coords.unwrap();
        let base_field_chip = self.base_field_chip();
        let x = base_field_chip.assign_constant(ctx, *coords.x())?;
        let y = base_field_chip.assign_constant(ctx, *coords.y())?;

        Ok(AssignedPoint::new(x, y))
    }

    /// Takes `Point` of the EC and returns it as `AssignedPoint`
    pub fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: Value<Emulated>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let integer_chip = self.base_field_chip();

        let point = point.map(|point| self.to_rns_point(point));
        let (x, y) = point
            .map(|point| (point.x().clone(), point.y().clone()))
            .unzip();

        let x = integer_chip.assign_integer(ctx, x.into(), Range::Remainder)?;
        let y = integer_chip.assign_integer(ctx, y.into(), Range::Remainder)?;

        let point = AssignedPoint::new(x, y);
        self.assert_is_on_curve(ctx, &point)?;
        Ok(point)
    }

    /// Assigns the auxiliary generator point
    pub fn assign_aux_generator(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        aux_generator: Value<Emulated>,
    ) -> Result<(), Error> {
        let aux_generator_assigned = self.assign_point(ctx, aux_generator)?;
        self.aux_generator = Some((aux_generator_assigned, aux_generator));
        Ok(())
    }

    /// Assigns multiplication auxiliary point for window_size
    pub fn assign_correction(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        window_size: usize,
    ) -> Result<(), Error> {
        let scalar_correction = self.correct_scalar(window_size);

        match &self.aux_generator {
            Some((point, _)) => {
                // compute correction point -2^w aux
                let mut point_correction = self.double_n(ctx, point, window_size)?;
                point_correction = self.neg(ctx, &point_correction)?;

                self.aux_registry
                    .insert(window_size, (scalar_correction, point_correction));
                Ok(())
            }
            // aux generator is not assigned yet
            None => Err(Error::Synthesis),
        }
    }

    /// correct scalar before mul; correction value is -2(1 + 2^w + ... + 2^{w(n-1)})
    fn correct_scalar(
        &mut self,
        window_size: usize,
    ) -> Integer<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        let window: usize = 1 << window_size;
        let window_scalar = Emulated::Scalar::from(window as u64);

        let num_bits = Emulated::Scalar::NUM_BITS as usize;
        let number_of_windows = (num_bits + window_size - 1) / window_size;

        let mut correction = Emulated::Scalar::ONE;
        let mut power = window_scalar;
        for _ in 0..number_of_windows - 1 {
            correction += power;
            power *= window_scalar;
        }
        correction += correction;

        Integer::from_fe(-correction, self.rns_scalar())
    }

    /// Constraints to ensure `AssignedPoint` is on curve
    pub fn assert_is_on_curve(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();

        let y_square = &integer_chip.square(ctx, point.y())?;
        let x_square = &integer_chip.square(ctx, point.x())?;
        let x_cube = &integer_chip.mul(ctx, point.x(), x_square)?;
        let x_cube_b = &integer_chip.add_constant(ctx, x_cube, &self.parameter_b())?;
        integer_chip.assert_equal(ctx, x_cube_b, y_square)?;
        Ok(())
    }

    /// Constraints assert two `AssignedPoint`s are equal
    pub fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p0: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p1: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let integer_chip = self.base_field_chip();
        integer_chip.assert_equal(ctx, p0.x(), p1.x())?;
        integer_chip.assert_equal(ctx, p0.y(), p1.y())
    }

    /// Selects between 2 `AssignedPoint` determined by an `AssignedCondition`
    pub fn select(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.select(ctx, p1.x(), p2.x(), c)?;
        let y = integer_chip.select(ctx, p1.y(), p2.y(), c)?;
        Ok(AssignedPoint::new(x, y))
    }

    /// Selects between an `AssignedPoint` and a point on the EC `Emulated`
    /// determined by an `AssignedCondition`
    pub fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p2: Emulated,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let integer_chip = self.base_field_chip();
        let p2 = self.to_rns_point(p2);
        let x = integer_chip.select_or_assign(ctx, p1.x(), p2.x(), c)?;
        let y = integer_chip.select_or_assign(ctx, p1.y(), p2.y(), c)?;
        Ok(AssignedPoint::new(x, y))
    }

    /// Normalizes an `AssignedPoint` by reducing each of its coordinates
    pub fn normalize(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let integer_chip = self.base_field_chip();
        let x = integer_chip.reduce(ctx, point.x())?;
        let y = integer_chip.reduce(ctx, point.y())?;
        Ok(AssignedPoint::new(x, y))
    }

    /// Adds 2 distinct `AssignedPoints`
    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p0: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        p1: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        // guarantees that p0 != p1 or p0 != p1
        // so that we can use unsafe addition formula which assumes operands are not
        // equal addition to that we strictly disallow addition result to be
        // point of infinity
        self.base_field_chip()
            .assert_not_equal(ctx, p0.x(), p1.x())?;

        self._add_incomplete_unsafe(ctx, p0, p1)
    }

    /// Doubles an `AssignedPoint`
    pub fn double(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        // point must be asserted to be in curve and not infinity
        self._double_incomplete(ctx, p)
    }

    /// Given an `AssignedPoint` $P$ computes P * 2^logn
    pub fn double_n(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        logn: usize,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let mut acc = p.clone();
        for _ in 0..logn {
            acc = self._double_incomplete(ctx, &acc)?;
        }
        Ok(acc)
    }

    /// Wrapper for `_ladder_incomplete`
    /// Given 2 `AssignedPoint` $P$ and $Q$ efficiently computes $2*P + Q$
    pub fn ladder(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        to_double: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        to_add: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        self._ladder_incomplete(ctx, to_double, to_add)
    }

    /// Returns the negative or inverse of an `AssignedPoint`
    pub fn neg(
        &self,
        ctx: &mut RegionCtx<'_, N>,
        p: &AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let integer_chip = self.base_field_chip();
        let y_neg = integer_chip.neg(ctx, p.y())?;
        Ok(AssignedPoint::new(p.x().clone(), y_neg))
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use std::rc::Rc;

    use super::{AssignedPoint, EccConfig, GeneralEccChip, Point};
    use crate::halo2;
    use crate::halo2::halo2curves::{
        ff::{Field, FromUniformBytes, PrimeField},
        group::{prime::PrimeCurveAffine, Curve as _, Group},
    };
    use crate::integer::rns::Rns;
    use crate::integer::NUMBER_OF_LOOKUP_LIMBS;
    use crate::integer::{AssignedInteger, IntegerInstructions};
    use crate::maingate;
    use halo2::arithmetic::CurveAffine;
    use halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use integer::rns::Integer;
    use integer::Range;
    use maingate::mock_prover_verify;
    use maingate::{
        MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };
    use paste::paste;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    use crate::curves::bn256::{Fr as BnScalar, G1Affine as Bn256};
    use crate::curves::pasta::{
        EpAffine as Pallas, EqAffine as Vesta, Fp as PastaFp, Fq as PastaFq,
    };
    use crate::curves::secp256k1::Secp256k1Affine as Secp256k1;
    use crate::maingate::DimensionMeasurement;

    const NUMBER_OF_LIMBS: usize = 4;
    const BIT_LEN_LIMB: usize = 68;

    #[allow(clippy::type_complexity)]
    fn setup<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    >(
        k_override: u32,
    ) -> (
        Rns<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Rns<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        u32,
    ) {
        let (rns_base, rns_scalar) = GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
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
        fn new<
            C: CurveAffine,
            N: PrimeField,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >(
            meta: &mut ConstraintSystem<N>,
        ) -> Self {
            let (rns_base, rns_scalar) =
                GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();

            let main_gate_config = MainGate::<N>::configure(meta);
            let mut overflow_bit_lens: Vec<usize> = vec![];
            overflow_bit_lens.extend(rns_base.overflow_lengths());
            overflow_bit_lens.extend(rns_scalar.overflow_lengths());
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let range_config = RangeChip::<N>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );

            TestCircuitConfig {
                main_gate_config,
                range_config,
            }
        }

        fn config_range<N: PrimeField>(
            &self,
            layouter: &mut impl Layouter<N>,
        ) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_table(layouter)?;

            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestEccAddition<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        _marker: PhantomData<(C, N)>,
    }

    impl<
            C: CurveAffine,
            N: PrimeField,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        > Circuit<N> for TestEccAddition<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let ecc_chip =
                GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
            layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let a = C::Curve::random(OsRng);
                    let b = C::Curve::random(OsRng);

                    let c = a + b;
                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let b = &ecc_chip.assign_point(ctx, Value::known(b.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    let c_1 = &ecc_chip.add(ctx, a, b)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test doubling

                    let a = C::Curve::random(OsRng);
                    let c = a + a;

                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
                    let c_1 = &ecc_chip.double(ctx, a)?;
                    ecc_chip.assert_equal(ctx, c_0, c_1)?;

                    // test ladder

                    let a = C::Curve::random(OsRng);
                    let b = C::Curve::random(OsRng);
                    let c = a + b + a;

                    let a = &ecc_chip.assign_point(ctx, Value::known(a.into()))?;
                    let b = &ecc_chip.assign_point(ctx, Value::known(b.into()))?;
                    let c_0 = &ecc_chip.assign_point(ctx, Value::known(c.into()))?;
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
        fn run<
            C: CurveAffine,
            N: FromUniformBytes<64> + Ord,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            let circuit = TestEccAddition::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::default();
            let instance = vec![vec![]];
            mock_prover_verify(&circuit, instance);
        }

        run::<Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccPublicInput<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        a: Value<C>,
        b: Value<C>,
        _marker: PhantomData<N>,
    }

    impl<
            C: CurveAffine,
            N: PrimeField,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        > Circuit<N> for TestEccPublicInput<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let ecc_chip =
                GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

            let sum = layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

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
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

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
        fn run<
            C: CurveAffine,
            N: FromUniformBytes<64> + Ord,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            let (rns_base, _, _) = setup::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(0);
            let rns_base = Rc::new(rns_base);

            let a = C::Curve::random(OsRng).to_affine();
            let b = C::Curve::random(OsRng).to_affine();

            let c0: C = (a + b).into();
            let c0 = Point::new(Rc::clone(&rns_base), c0);
            let mut public_data = c0.public();
            let c1: C = (a + a).into();
            let c1 = Point::new(Rc::clone(&rns_base), c1);
            public_data.extend(c1.public());
            let circuit = TestEccPublicInput::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
                a: Value::known(a),
                b: Value::known(b),
                ..Default::default()
            };
            let instance = vec![public_data];
            mock_prover_verify(&circuit, instance);
        }

        run::<Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccMul<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        window_size: usize,
        aux_generator: C,
        _marker: PhantomData<N>,
    }

    impl<
            C: CurveAffine,
            N: PrimeField,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        > Circuit<N> for TestEccMul<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let mut ecc_chip =
                GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

            layouter.assign_region(
                || "assign aux values",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                    ecc_chip.assign_correction(ctx, self.window_size)?;
                    Ok(())
                },
            )?;

            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "region mul",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    // let mut rng = ChaCha20Rng::seed_from_u64(80);
                    let mut rng = OsRng;

                    let base = C::Curve::random(&mut rng);
                    let s = C::Scalar::random(&mut rng);
                    let result = base * s;

                    let s = Integer::from_fe(s, ecc_chip.rns_scalar());
                    let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                    let s = scalar_chip.assign_integer(
                        ctx,
                        Value::known(s).into(),
                        Range::Remainder,
                    )?;
                    let result_0 = ecc_chip.assign_point(ctx, Value::known(result.into()))?;

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
        fn run<
            C: CurveAffine,
            N: FromUniformBytes<64> + Ord,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            for window_size in 2..5 {
                //   let mut rng = ChaCha20Rng::seed_from_u64(42);
                let mut rng = OsRng;
                let aux_generator = C::Curve::random(&mut rng).to_affine();

                let circuit = TestEccMul::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
                    aux_generator,
                    window_size,
                    ..Default::default()
                };
                let instance = vec![vec![]];
                mock_prover_verify(&circuit, instance);
                let dimension = DimensionMeasurement::measure(&circuit).unwrap();
                println!(
                    "window_size = {:?}, dimention: {:?}",
                    window_size, dimension
                );
            }
        }

        run::<Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();

        run::<Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
        run::<Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccBatchMul<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        window_size: usize,
        aux_generator: C,
        number_of_pairs: usize,
        _marker: PhantomData<N>,
    }

    impl<
            C: CurveAffine,
            N: PrimeField,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        > Circuit<N> for TestEccBatchMul<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitConfig::new::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(meta)
        }

        #[allow(clippy::type_complexity)]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let ecc_chip_config = config.ecc_chip_config();
            let mut ecc_chip =
                GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

            layouter.assign_region(
                || "assign aux values",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                    ecc_chip.assign_correction(ctx, self.window_size)?;
                    Ok(())
                },
            )?;

            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "region mul",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut acc = C::Curve::identity();
                    let pairs: Vec<(
                        AssignedPoint<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                        AssignedInteger<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
                    )> = (0..self.number_of_pairs)
                        .map(|_| {
                            let base = C::Curve::random(OsRng);
                            let s = C::Scalar::random(OsRng);
                            acc += base * s;
                            let s = Integer::from_fe(s, ecc_chip.rns_scalar());
                            let base = ecc_chip.assign_point(ctx, Value::known(base.into()))?;
                            let s = scalar_chip.assign_integer(
                                ctx,
                                Value::known(s).into(),
                                Range::Remainder,
                            )?;
                            Ok((base, s))
                        })
                        .collect::<Result<_, Error>>()?;

                    let result_0 = ecc_chip.assign_point(ctx, Value::known(acc.into()))?;
                    let result_1 =
                        ecc_chip.mul_batch_1d_horizontal(ctx, pairs, self.window_size)?;
                    ecc_chip.assert_equal(ctx, &result_0, &result_1)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    macro_rules! test_general_ecc_mul_batch_circuit {
        ($C:ty, $N:ty, $NUMBER_OF_LIMBS:expr, $BIT_LEN_LIMB:expr) => {
            paste! {
                #[test]
                fn [<test_general_ecc_mul_batch_circuit_ $C:lower _ $N:lower>]() {
                    for number_of_pairs in 5..7 {
                        for window_size in 2..4 {
                            let aux_generator = <$C as PrimeCurveAffine>::Curve::random(OsRng).to_affine();

                            let circuit = TestEccBatchMul::<$C, $N, $NUMBER_OF_LIMBS, $BIT_LEN_LIMB> {
                                aux_generator,
                                window_size,
                                number_of_pairs,
                                ..Default::default()
                            };
                            let instance = vec![vec![]];
                            mock_prover_verify(&circuit, instance);
                        }
                    }
                }
            }
        }
    }

    test_general_ecc_mul_batch_circuit!(Pallas, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);

    test_general_ecc_mul_batch_circuit!(Vesta, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);

    test_general_ecc_mul_batch_circuit!(Bn256, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);

    test_general_ecc_mul_batch_circuit!(Secp256k1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFp, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFq, NUMBER_OF_LIMBS, BIT_LEN_LIMB);
}
