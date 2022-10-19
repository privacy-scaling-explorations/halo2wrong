use super::{make_mul_aux, AssignedPoint, MulAux, Point};
use crate::halo2;
use crate::integer::rns::{Integer, Rns};
use crate::integer::{IntegerChip, IntegerInstructions, Range, UnassignedInteger};
use crate::maingate;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::{Layouter, Value};
use halo2::plonk::Error;
use integer::maingate::MainGateInstructions;
use integer::maingate::RegionCtx;
use maingate::AssignedCondition;
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
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    /// `IntegerChip` for the base field of the EC
    base_field_chip: IntegerChip<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    /// `IntegerChip` for the scalar field of the EC
    scalar_field_chip: IntegerChip<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    /// Auxiliary point for optimized multiplication algorithm
    aux_generator: Emulated,
    /// Auxiliary points for optimized multiplication for each (window_size,
    /// n_pairs) pairs
    aux_registry: BTreeMap<(usize, usize), Emulated>,
}

impl<
        Emulated: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > GeneralEccChip<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    /// Used to emulate the base field `Emulated::Base` and the scalar
    /// field `Emulated::Scalar` over the native field `N`
    pub fn construct_rns() -> (
        Rns<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Rns<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) {
        (Rns::construct(), Rns::construct())
    }

    /// Creates new `GeneralEccChip`
    pub fn new(
        layouter: &mut impl Layouter<N>,
        base_field_chip: &mut IntegerChip<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        scalar_field_chip: &mut IntegerChip<Emulated::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        aux_generator: Emulated,
    ) -> Result<Self, Error> {
        scalar_field_chip
            .main_gate_mut()
            .register_constants(layouter, vec![N::from(0)])?;
        let mut ecc_chip = Self {
            base_field_chip: base_field_chip.clone(),
            scalar_field_chip: scalar_field_chip.clone(),
            aux_generator,
            aux_registry: BTreeMap::new(),
        };
        ecc_chip.register_constants(layouter, vec![aux_generator])?;
        Ok(ecc_chip)
    }

    /// Given multiplication specification assigns auxillary constants
    pub fn configure_multiplication(
        &mut self,
        layouter: &mut impl Layouter<N>,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<(), Error> {
        let aux = make_mul_aux(self.aux_generator, window_size, number_of_pairs);
        self.register_constants(layouter, vec![aux])?;
        self.aux_registry
            .insert((window_size, number_of_pairs), aux);
        Ok(())
    }

    fn get_mul_aux(
        &self,
        window_size: usize,
        number_of_pairs: usize,
    ) -> Result<MulAux<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let to_add = self.get_constant_point(self.aux_generator)?;
        let to_sub = match self.aux_registry.get(&(window_size, number_of_pairs)) {
            Some(aux) => Ok(self.get_constant_point(*aux)?),
            None => Err(Error::NotEnoughColumnsForConstants),
        }?;
        // to_add the equivalent of AuxInit and to_sub AuxFin
        // see https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg?view
        Ok(MulAux::new(to_add, to_sub))
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
}

impl<
        Emulated: CurveAffine,
        N: FieldExt,
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
        let main_gate = self.scalar_field_chip().main_gate();
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
    pub fn register_constants(
        &mut self,
        layouter: &mut impl Layouter<N>,
        points: Vec<Emulated>,
    ) -> Result<(), Error> {
        let mut integers = vec![];
        for point in points {
            // disallow point of infinity in synthesis time
            let coords = point.coordinates().unwrap();
            integers.push(*coords.x());
            integers.push(*coords.y());
        }
        self.base_field_chip.register_constants(layouter, integers)
    }

    /// Returns already assigned constant point
    pub fn get_constant_point(
        &self,
        point: Emulated,
    ) -> Result<AssignedPoint<Emulated::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
        let integer_chip = self.base_field_chip();
        let coords = point.coordinates().unwrap();
        let x = integer_chip.get_constant(*coords.x())?;
        let y = integer_chip.get_constant(*coords.y())?;
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

    use super::{AssignedPoint, GeneralEccChip, Point};
    use crate::halo2;
    use crate::integer::rns::Rns;
    use crate::integer::{AssignedInteger, IntegerInstructions};
    use crate::maingate;
    use group::ff::Field;
    use group::{prime::PrimeCurveAffine, Curve as _, Group};
    use halo2::arithmetic::{CurveAffine, FieldExt};
    use halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use integer::rns::Integer;
    use integer::{IntegerChip, Range};
    use maingate::mock_prover_verify;
    use maingate::{
        MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };
    use paste::paste;
    use rand_core::OsRng;

    use crate::curves::bn256::{Fr as BnScalar, G1Affine as Bn256};
    use crate::curves::pasta::{
        EpAffine as Pallas, EqAffine as Vesta, Fp as PastaFp, Fq as PastaFq,
    };
    use crate::curves::secp256k1::Secp256k1Affine as Secp256k1;

    const NUMBER_OF_SUBLIMBS: usize = 4;

    #[allow(clippy::type_complexity)]
    fn setup<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    >(
        k_override: u32,
    ) -> (
        Rns<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Rns<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        u32,
    ) {
        let (rns_base, rns_scalar) =
            GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct_rns();
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_SUBLIMBS;
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
        fn new<
            C: CurveAffine,
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >(
            meta: &mut ConstraintSystem<N>,
        ) -> Self {
            let (rns_base, rns_scalar) =
                GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct_rns();
            let main_gate_config = MainGate::<N>::configure(meta);
            let mut overflow_bit_lens: Vec<usize> = vec![];
            overflow_bit_lens.extend(rns_base.overflow_lengths());
            overflow_bit_lens.extend(rns_scalar.overflow_lengths());
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_SUBLIMBS];

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

        fn ecc_chip<
            Emulated: CurveAffine,
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >(
            &self,
            layouter: &mut impl Layouter<N>,
        ) -> Result<GeneralEccChip<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>, Error> {
            let (rns_base, rns_scalar) =
                GeneralEccChip::<Emulated, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct_rns();
            GeneralEccChip::new(
                layouter,
                &mut IntegerChip::new(
                    MainGate::new(self.main_gate_config.clone()),
                    RangeChip::new(self.range_config.clone()),
                    Rc::new(rns_base),
                ),
                &mut IntegerChip::new(
                    MainGate::new(self.main_gate_config.clone()),
                    RangeChip::new(self.range_config.clone()),
                    Rc::new(rns_scalar),
                ),
                <Emulated as PrimeCurveAffine>::Curve::random(OsRng).to_affine(),
            )
        }

        fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_table(layouter)?;

            Ok(())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestEccAddition<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        _marker: PhantomData<(C, N)>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccAddition<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

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
            let ecc_chip: GeneralEccChip<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
                config.ecc_chip(&mut layouter)?;

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
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            let circuit = TestEccAddition::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::default();
            let instance = vec![vec![]];
            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
        }

        run::<Pallas, BnScalar, 4, 68>();
        run::<Pallas, BnScalar, 3, 88>();
        run::<Pallas, PastaFp, 4, 68>();
        run::<Pallas, PastaFp, 3, 88>();
        run::<Pallas, PastaFq, 4, 68>();
        run::<Pallas, PastaFq, 3, 88>();

        run::<Vesta, BnScalar, 4, 68>();
        run::<Vesta, BnScalar, 3, 88>();
        run::<Vesta, PastaFp, 4, 68>();
        run::<Vesta, PastaFp, 3, 88>();
        run::<Vesta, PastaFq, 4, 68>();
        run::<Vesta, PastaFq, 3, 88>();

        run::<Bn256, BnScalar, 4, 68>();
        run::<Bn256, BnScalar, 3, 88>();
        run::<Bn256, PastaFp, 4, 68>();
        run::<Bn256, PastaFp, 3, 88>();
        run::<Bn256, PastaFq, 4, 68>();
        run::<Bn256, PastaFq, 3, 88>();

        run::<Secp256k1, BnScalar, 4, 68>();
        run::<Secp256k1, BnScalar, 3, 88>();
        run::<Secp256k1, PastaFp, 4, 68>();
        run::<Secp256k1, PastaFp, 3, 88>();
        run::<Secp256k1, PastaFq, 4, 68>();
        run::<Secp256k1, PastaFq, 3, 88>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccPublicInput<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        a: Value<C>,
        b: Value<C>,
        _marker: PhantomData<N>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccPublicInput<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

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
            let ecc_chip: GeneralEccChip<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
                config.ecc_chip(&mut layouter)?;

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
            ecc_chip.expose_public(layouter.namespace(|| "sum"), sum, NUMBER_OF_LIMBS * 2)?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_general_ecc_public_input() {
        fn run<
            C: CurveAffine,
            N: FieldExt,
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
            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
        }

        run::<Pallas, BnScalar, 4, 68>();
        run::<Pallas, BnScalar, 3, 88>();
        run::<Pallas, PastaFp, 4, 68>();
        run::<Pallas, PastaFp, 3, 88>();
        run::<Pallas, PastaFq, 4, 68>();
        run::<Pallas, PastaFq, 3, 88>();

        run::<Vesta, BnScalar, 4, 68>();
        run::<Vesta, BnScalar, 3, 88>();
        run::<Vesta, PastaFp, 4, 68>();
        run::<Vesta, PastaFp, 3, 88>();
        run::<Vesta, PastaFq, 4, 68>();
        run::<Vesta, PastaFq, 3, 88>();

        run::<Bn256, BnScalar, 4, 68>();
        run::<Bn256, BnScalar, 3, 88>();
        run::<Bn256, PastaFp, 4, 68>();
        run::<Bn256, PastaFp, 3, 88>();
        run::<Bn256, PastaFq, 4, 68>();
        run::<Bn256, PastaFq, 3, 88>();

        run::<Secp256k1, BnScalar, 4, 68>();
        run::<Secp256k1, BnScalar, 3, 88>();
        run::<Secp256k1, PastaFp, 4, 68>();
        run::<Secp256k1, PastaFp, 3, 88>();
        run::<Secp256k1, PastaFq, 4, 68>();
        run::<Secp256k1, PastaFq, 3, 88>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccMul<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        window_size: usize,
        _marker: PhantomData<(N, C)>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccMul<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

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
            let mut ecc_chip: GeneralEccChip<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
                config.ecc_chip(&mut layouter)?;
            ecc_chip.configure_multiplication(&mut layouter, self.window_size, 1)?;
            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "region mul",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let base = C::Curve::random(OsRng);
                    let s = C::Scalar::random(OsRng);
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
            N: FieldExt,
            const NUMBER_OF_LIMBS: usize,
            const BIT_LEN_LIMB: usize,
        >() {
            for window_size in 1..5 {
                let circuit = TestEccMul::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
                    window_size,
                    ..Default::default()
                };
                let instance = vec![vec![]];
                assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
            }
        }

        run::<Pallas, BnScalar, 4, 68>();
        run::<Pallas, BnScalar, 3, 88>();
        run::<Pallas, PastaFp, 4, 68>();
        run::<Pallas, PastaFp, 3, 88>();
        run::<Pallas, PastaFq, 4, 68>();
        run::<Pallas, PastaFq, 3, 88>();

        run::<Vesta, BnScalar, 4, 68>();
        run::<Vesta, BnScalar, 3, 88>();
        run::<Vesta, PastaFp, 4, 68>();
        run::<Vesta, PastaFp, 3, 88>();
        run::<Vesta, PastaFq, 4, 68>();
        run::<Vesta, PastaFq, 3, 88>();

        run::<Bn256, BnScalar, 4, 68>();
        run::<Bn256, BnScalar, 3, 88>();
        run::<Bn256, PastaFp, 4, 68>();
        run::<Bn256, PastaFp, 3, 88>();
        run::<Bn256, PastaFq, 4, 68>();
        run::<Bn256, PastaFq, 3, 88>();

        run::<Secp256k1, BnScalar, 4, 68>();
        run::<Secp256k1, BnScalar, 3, 88>();
        run::<Secp256k1, PastaFp, 4, 68>();
        run::<Secp256k1, PastaFp, 3, 88>();
        run::<Secp256k1, PastaFq, 4, 68>();
        run::<Secp256k1, PastaFq, 3, 88>();
    }

    #[derive(Default, Clone, Debug)]
    struct TestEccBatchMul<
        C: CurveAffine,
        N: FieldExt,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > {
        window_size: usize,
        number_of_pairs: usize,
        _marker: PhantomData<(C, N)>,
    }

    impl<C: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
        Circuit<N> for TestEccBatchMul<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

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
            let mut ecc_chip: GeneralEccChip<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> =
                config.ecc_chip(&mut layouter)?;
            ecc_chip.configure_multiplication(
                &mut layouter,
                self.window_size,
                self.number_of_pairs,
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
        ($C:ty, $N:ty, $number_of_limbs:expr, $bit_len:expr) => {
            paste! {
                #[test]
                fn [<test_general_ecc_mul_batch_circuit_ $C:lower _ $N:lower _ $number_of_limbs _ $bit_len>]() {
                    for number_of_pairs in 5..7 {
                        for window_size in 1..3 {


                            let circuit = TestEccBatchMul::<$C, $N, $number_of_limbs, $bit_len> {
                                window_size,
                                number_of_pairs,
                                ..Default::default()
                            };
                            let instance = vec![vec![]];
                            assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
                        }
                    }
                }
            }
        }
    }

    test_general_ecc_mul_batch_circuit!(Pallas, BnScalar, 4, 68);
    test_general_ecc_mul_batch_circuit!(Pallas, BnScalar, 3, 88);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFp, 4, 68);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFp, 3, 88);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFq, 4, 68);
    test_general_ecc_mul_batch_circuit!(Pallas, PastaFq, 3, 88);

    test_general_ecc_mul_batch_circuit!(Vesta, BnScalar, 4, 68);
    test_general_ecc_mul_batch_circuit!(Vesta, BnScalar, 3, 88);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFp, 4, 68);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFp, 3, 88);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFq, 4, 68);
    test_general_ecc_mul_batch_circuit!(Vesta, PastaFq, 3, 88);

    test_general_ecc_mul_batch_circuit!(Bn256, BnScalar, 4, 68);
    test_general_ecc_mul_batch_circuit!(Bn256, BnScalar, 3, 88);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFp, 4, 68);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFp, 3, 88);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFq, 4, 68);
    test_general_ecc_mul_batch_circuit!(Bn256, PastaFq, 3, 88);

    test_general_ecc_mul_batch_circuit!(Secp256k1, BnScalar, 4, 68);
    test_general_ecc_mul_batch_circuit!(Secp256k1, BnScalar, 3, 88);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFp, 4, 68);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFp, 3, 88);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFq, 4, 68);
    test_general_ecc_mul_batch_circuit!(Secp256k1, PastaFq, 3, 88);
}
