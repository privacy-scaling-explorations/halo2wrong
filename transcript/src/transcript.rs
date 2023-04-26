use crate::{
    halo2::{arithmetic::CurveAffine, halo2curves::ff::PrimeField, plonk::Error},
    hasher::HasherChip,
    maingate::{AssignedValue, RegionCtx},
};
use ecc::{
    halo2::circuit::Chip,
    maingate::{big_to_fe, decompose, fe_to_big},
    AssignedPoint, BaseFieldEccChip,
};
use poseidon::Spec;

/// `PointRepresentation` will encode point with an implemented strategy
pub trait PointRepresentation<
    C: CurveAffine<ScalarExt = N>,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>: Default
{
    fn encode_assigned(
        ctx: &mut RegionCtx<'_, N>,
        ecc_chip: &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedValue<N>>, Error>;

    /// Returns `None` if `point` is identity
    fn encode(point: C) -> Option<Vec<N>>;
}

/// `LimbRepresentation` encodes point as `[[limbs_of(x)],  sign_of(y)]`
#[derive(Default)]
pub struct LimbRepresentation;

impl<
        C: CurveAffine<ScalarExt = N>,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > PointRepresentation<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> for LimbRepresentation
{
    fn encode_assigned(
        ctx: &mut RegionCtx<'_, N>,
        ecc_chip: &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        let mut encoded: Vec<AssignedValue<N>> =
            point.x().limbs().iter().map(|limb| limb.into()).collect();
        encoded.push(ecc_chip.sign(ctx, point)?);
        Ok(encoded)
    }

    fn encode(point: C) -> Option<Vec<N>> {
        point
            .coordinates()
            .map(|coords| {
                decompose(*coords.x(), NUMBER_OF_LIMBS, BIT_LEN_LIMB)
                    .into_iter()
                    .map(|limb| big_to_fe(fe_to_big(limb)))
                    .chain(Some(N::from(bool::from(coords.y().is_odd()) as u64)))
                    .collect()
            })
            .into()
    }
}

/// `NativeRepresentation` encodes point as `[native(x),  native(y)]`
#[derive(Default)]
pub struct NativeRepresentation;

impl<
        C: CurveAffine<ScalarExt = N>,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    > PointRepresentation<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> for NativeRepresentation
{
    fn encode_assigned(
        _: &mut RegionCtx<'_, N>,
        _: &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        Ok(vec![point.x().native().clone(), point.y().native().clone()])
    }

    fn encode(point: C) -> Option<Vec<N>> {
        point
            .coordinates()
            .map(|coords| {
                [coords.x(), coords.y()]
                    .into_iter()
                    .map(|fe| big_to_fe(fe_to_big(*fe)))
                    .collect()
            })
            .into()
    }
}

#[derive(Clone, Debug)]
pub struct TranscriptChip<
    C: CurveAffine<ScalarExt = N>,
    N: PrimeField,
    E: PointRepresentation<C, N, NUMBER_OF_LIMBS, BIT_LEN>,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN: usize,
    const T: usize,
    const RATE: usize,
> {
    ecc_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN>,
    hasher_chip: HasherChip<N, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>,
    _point_repr: E,
}

impl<
        C: CurveAffine<ScalarExt = N>,
        N: PrimeField,
        E: PointRepresentation<C, N, NUMBER_OF_LIMBS, BIT_LEN>,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > TranscriptChip<C, N, E, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    /// Constructs the transcript chip
    pub fn new(
        ctx: &mut RegionCtx<'_, N>,
        spec: &Spec<N, T, RATE>,
        ecc_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN>,
        _point_repr: E,
    ) -> Result<Self, Error> {
        let main_gate = ecc_chip.main_gate();
        let main_gate_config = main_gate.config();
        let hasher_chip = HasherChip::new(ctx, spec, main_gate_config)?;
        Ok(Self {
            ecc_chip,
            hasher_chip,
            _point_repr,
        })
    }

    /// Write scalar to the transcript
    pub fn write_scalar(&mut self, scalar: &AssignedValue<N>) {
        self.hasher_chip.update(&[scalar.clone()]);
    }

    /// Write point to the transcript
    pub fn write_point(
        &mut self,
        ctx: &mut RegionCtx<'_, N>,
        point: &AssignedPoint<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN>,
    ) -> Result<(), Error> {
        let encoded = E::encode_assigned(ctx, &self.ecc_chip, point)?;
        self.hasher_chip.update(&encoded[..]);
        Ok(())
    }

    // Constrain squeezing new challenge
    pub fn squeeze(&mut self, ctx: &mut RegionCtx<'_, N>) -> Result<AssignedValue<N>, Error> {
        self.hasher_chip.hash(ctx)
    }
}

#[cfg(test)]
mod tests {
    use crate::halo2::circuit::Layouter;
    use crate::halo2::circuit::SimpleFloorPlanner;
    use crate::halo2::halo2curves::ff::{Field, PrimeField};
    use crate::halo2::plonk::Error;
    use crate::halo2::plonk::{Circuit, ConstraintSystem};
    use crate::maingate::mock_prover_verify;
    use crate::maingate::MainGate;
    use crate::maingate::MainGateConfig;
    use crate::maingate::{MainGateInstructions, RegionCtx};
    use crate::transcript::LimbRepresentation;
    use crate::TranscriptChip;
    use ecc::halo2::arithmetic::CurveAffine;
    use ecc::halo2::circuit::Value;
    use ecc::integer::rns::Rns;
    use ecc::maingate::RangeChip;
    use ecc::maingate::RangeConfig;
    use ecc::maingate::RangeInstructions;
    use ecc::BaseFieldEccChip;
    use ecc::EccConfig;
    use paste::paste;
    use poseidon::Poseidon;
    use poseidon::Spec;
    use rand_core::OsRng;

    const NUMBER_OF_LIMBS: usize = 4;
    const BIT_LEN_LIMB: usize = 68;

    #[derive(Clone)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    }

    impl TestCircuitConfig {
        fn ecc_chip_config(&self) -> EccConfig {
            EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
        }

        fn new<C: CurveAffine>(meta: &mut ConstraintSystem<C::Scalar>) -> Self {
            let rns = Rns::<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();

            let main_gate_config = MainGate::<C::Scalar>::configure(meta);
            let overflow_bit_lens = rns.overflow_lengths();
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let range_config = RangeChip::<C::Scalar>::configure(
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

    struct TestCircuit<C: CurveAffine, const T: usize, const RATE: usize> {
        spec: Spec<C::Scalar, T, RATE>,
        n: usize,
        inputs: Value<Vec<C::Scalar>>,
        expected: Value<C::Scalar>,
    }

    impl<C: CurveAffine, const T: usize, const RATE: usize> Circuit<C::Scalar>
        for TestCircuit<C, T, RATE>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
            TestCircuitConfig::new::<C>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<C::Scalar>::new(config.main_gate_config.clone());
            let ecc_chip_config = config.ecc_chip_config();
            let ecc_chip =
                BaseFieldEccChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

            // Run test against reference implementation and
            // compare results
            layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut transcript_chip =
                        TranscriptChip::<_, _, _, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>::new(
                            ctx,
                            &self.spec,
                            ecc_chip.clone(),
                            LimbRepresentation::default(),
                        )?;

                    for e in self.inputs.as_ref().transpose_vec(self.n) {
                        let e = main_gate.assign_value(ctx, e.map(|e| *e))?;
                        transcript_chip.write_scalar(&e);
                    }
                    let challenge = transcript_chip.squeeze(ctx)?;
                    let expected = main_gate.assign_value(ctx, self.expected)?;
                    main_gate.assert_equal(ctx, &challenge, &expected)?;

                    Ok(())
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    macro_rules! test {
        ($RF:expr, $RP:expr, $T:expr, $RATE:expr) => {
            paste! {
                #[test]
                fn [<test_permutation_ $RF _ $RP _ $T _ $RATE>]() {
                    use crate::curves::bn256::{Fr, G1Affine};
                    for number_of_inputs in 0..3*$T {

                        let mut ref_hasher = Poseidon::<Fr, $T, $RATE>::new($RF, $RP);
                        let spec = Spec::<Fr, $T, $RATE>::new($RF, $RP);

                        let inputs: Vec<Fr> = (0..number_of_inputs)
                            .map(|_| Fr::random(OsRng))
                            .collect::<Vec<Fr>>();

                        ref_hasher.update(&inputs[..]);
                        let expected = ref_hasher.squeeze();

                        let circuit: TestCircuit<G1Affine, $T, $RATE> = TestCircuit {
                            spec: spec.clone(),
                            n: number_of_inputs,
                            inputs: Value::known(inputs),
                            expected: Value::known(expected),
                        };
                        let instance = vec![vec![]];
                        mock_prover_verify(&circuit, instance);
                    }
                }
            }
        };
    }

    test!(8, 57, 3, 2);
    test!(8, 57, 4, 3);
    test!(8, 57, 5, 4);
    test!(8, 57, 6, 5);
    test!(8, 57, 7, 6);
    test!(8, 57, 8, 7);
    test!(8, 57, 9, 8);
    test!(8, 57, 10, 9);
}
