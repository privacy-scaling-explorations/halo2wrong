use crate::{
    halo2::{arithmetic::CurveAffine, plonk::Error},
    hasher::HasherChip,
    maingate::{AssignedValue, RegionCtx},
};
use ecc::{halo2::circuit::Chip, AssignedPoint, BaseFieldEccChip};
use poseidon::Spec;
use std::marker::PhantomData;

/// `PointRepresentation` will encode point with an implemented strategy
pub trait PointRepresentation<
    C: CurveAffine,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>
{
    fn encode(
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        ecc_chip: &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedValue<C::Scalar>>, Error>;
}

/// `LimbRepresentation` encodes point as `[[limbs_of(x)],  sign_of(y)]`
pub struct LimbRepresentation;

impl<C: CurveAffine, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    PointRepresentation<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB> for LimbRepresentation
{
    fn encode(
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        ecc_chip: &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedValue<C::Scalar>>, Error> {
        let mut encoded: Vec<AssignedValue<C::Scalar>> = point
            .get_x()
            .limbs()
            .iter()
            .map(|limb| limb.into())
            .collect();
        encoded.push(ecc_chip.sign(ctx, point)?);
        Ok(encoded)
    }
}

impl LimbRepresentation {
    // Construct new `TranscriptChip` with `LimbRepresentation` encoding strategy
    pub fn new<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const T: usize,
        const RATE: usize,
    >(
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        spec: &Spec<C::Scalar, T, RATE>,
        ecc_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<TranscriptChip<Self, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>, Error> {
        TranscriptChip::new(ctx, spec, ecc_chip)
    }
}

/// `NativeRepresentation` encodes point as `[native(x),  native(y)]`
pub struct NativeRepresentation;

impl<C: CurveAffine, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    PointRepresentation<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB> for NativeRepresentation
{
    fn encode(
        _: &mut RegionCtx<'_, '_, C::Scalar>,
        _: &BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<Vec<AssignedValue<C::Scalar>>, Error> {
        Ok(vec![point.get_x().native(), point.get_y().native()])
    }
}

impl NativeRepresentation {
    // Construct new `TranscriptChip` with `NativeRepresentation` encoding strategy
    pub fn new<
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
        const T: usize,
        const RATE: usize,
    >(
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        spec: &Spec<C::Scalar, T, RATE>,
        ecc_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<TranscriptChip<Self, C, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>, Error> {
        TranscriptChip::new(ctx, spec, ecc_chip)
    }
}

#[derive(Clone, Debug)]
pub struct TranscriptChip<
    E: PointRepresentation<C, NUMBER_OF_LIMBS, BIT_LEN>,
    C: CurveAffine,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN: usize,
    const T: usize,
    const RATE: usize,
> {
    ecc_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN>,
    hasher_chip: HasherChip<C::Scalar, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>,
    _marker: PhantomData<E>,
}

impl<
        E: PointRepresentation<C, NUMBER_OF_LIMBS, BIT_LEN>,
        C: CurveAffine,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > TranscriptChip<E, C, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    /// Constructs the transcript chip
    pub fn new(
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        spec: &Spec<C::Scalar, T, RATE>,
        ecc_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN>,
    ) -> Result<Self, Error> {
        let main_gate = ecc_chip.main_gate();
        let main_gate_config = main_gate.config();
        let hasher_chip = HasherChip::new(ctx, spec, main_gate_config)?;
        Ok(Self {
            ecc_chip,
            hasher_chip,
            _marker: PhantomData,
        })
    }

    /// Write scalar to the transcript
    pub fn write_scalar(&mut self, scalar: &AssignedValue<C::Scalar>) {
        self.hasher_chip.update(&[scalar.clone()]);
    }

    /// Write point to the transcript
    pub fn write_point(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
        point: &AssignedPoint<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN>,
    ) -> Result<(), Error> {
        let encoded = E::encode(ctx, &self.ecc_chip, point)?;
        self.hasher_chip.update(&encoded[..]);
        Ok(())
    }

    // Constrain squeezing new challenge
    pub fn squeeze(
        &mut self,
        ctx: &mut RegionCtx<'_, '_, C::Scalar>,
    ) -> Result<AssignedValue<C::Scalar>, Error> {
        self.hasher_chip.hash(ctx)
    }
}

#[cfg(test)]
mod tests {

    use crate::halo2::arithmetic::FieldExt;
    use crate::halo2::circuit::Layouter;
    use crate::halo2::circuit::SimpleFloorPlanner;
    use crate::halo2::dev::MockProver;
    use crate::halo2::plonk::Error;
    use crate::halo2::plonk::{Circuit, ConstraintSystem};
    use crate::maingate::MainGate;
    use crate::maingate::MainGateConfig;
    use crate::maingate::{MainGateInstructions, RegionCtx};
    use crate::transcript::LimbRepresentation;
    use ecc::halo2::arithmetic::CurveAffine;
    use ecc::halo2::circuit::Value;
    use ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
    use ecc::maingate::RangeChip;
    use ecc::maingate::RangeConfig;
    use ecc::maingate::RangeInstructions;
    use ecc::BaseFieldEccChip;
    use ecc::EccConfig;
    use group::ff::Field;
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
            let rns = BaseFieldEccChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();

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

        fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
            let range_chip = RangeChip::<N>::new(self.range_config.clone());
            range_chip.load_composition_tables(layouter)?;
            range_chip.load_overflow_tables(layouter)?;

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
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let mut transcript_chip =
                        LimbRepresentation::new::<_, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>(
                            ctx,
                            &self.spec,
                            ecc_chip.clone(),
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

    #[test]
    fn test_permutation() {
        use crate::curves::bn256::{Fr, G1Affine};
        const K: u32 = 20;

        macro_rules! run_test {
            (
                $([$RF:expr, $RP:expr, $T:expr, $RATE:expr]),*
            ) => {
                $(
                    {

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
                            let public_inputs = vec![vec![]];
                            let prover = match MockProver::run(K, &circuit, public_inputs) {
                                Ok(prover) => prover,
                                Err(e) => panic!("{:#?}", e),
                            };
                            assert_eq!(prover.verify(), Ok(()));
                        }
                    }
                )*
            };
        }

        run_test!([8, 57, 3, 2]);
        run_test!([8, 57, 4, 3]);
        run_test!([8, 57, 5, 4]);
        run_test!([8, 57, 6, 5]);
        run_test!([8, 57, 7, 6]);
        run_test!([8, 57, 8, 7]);
        run_test!([8, 57, 9, 8]);
        run_test!([8, 57, 10, 9]);
    }
}
