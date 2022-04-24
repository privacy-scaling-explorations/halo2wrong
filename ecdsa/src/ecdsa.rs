use super::integer::{IntegerChip, IntegerConfig};
use crate::halo2;
use crate::integer;
use crate::maingate;
use ecc::maingate::MainGateInstructions;
use ecc::maingate::RegionCtx;
use ecc::{AssignedPoint, EccConfig, GeneralEccChip};
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::plonk::Error;
use integer::rns::Integer;
use integer::{AssignedInteger, IntegerInstructions};
use maingate::{MainGateConfig, RangeConfig};

#[derive(Clone, Debug)]
pub struct EcdsaConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl EcdsaConfig {
    pub fn new(range_config: RangeConfig, main_gate_config: MainGateConfig) -> Self {
        Self {
            range_config,
            main_gate_config,
        }
    }

    pub fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    pub fn integer_chip_config(&self) -> IntegerConfig {
        IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }
}

#[derive(Clone, Debug)]
pub struct EcdsaSig<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub r: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub s: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

pub struct AssignedEcdsaSig<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub r: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub s: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

pub struct AssignedPublicKey<
    W: FieldExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub point: AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

pub struct AssignedEcdsaStarSig<
    WB: WrongExt,
    WS: WrongExt,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub point: AssignedPoint<WB, N, NUMBERO_OF_LIMBS, BIT_LEN_LIMB>,
    pub r: AssignedInteger<WS, N, NUMBERO_OF_LIMBS, BIT_LEN_LIMB>,
    pub s: AssignedInteger<WS, N, NUMBERO_OF_LIMBS, BIT_LEN_LIMB>,
}

pub struct EcdsaChip<
    E: CurveAffine,
    N: FieldExt,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
>(GeneralEccChip<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>);

impl<E: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    EcdsaChip<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn new(ecc_chip: GeneralEccChip<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>) -> Self {
        Self(ecc_chip)
    }

    pub fn scalar_field_chip(&self) -> IntegerChip<E::ScalarExt, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.0.scalar_field_chip()
    }

    fn ecc_chip(&self) -> GeneralEccChip<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB> {
        self.0.clone()
    }
}

impl<E: CurveAffine, N: FieldExt, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize>
    EcdsaChip<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>
{
    pub fn verify(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        sig: &AssignedEcdsaSig<E::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        pk: &AssignedPublicKey<E::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        msg_hash: &AssignedInteger<E::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        let ecc_chip = self.ecc_chip();
        let scalar_chip = ecc_chip.scalar_field_chip();
        let base_chip = ecc_chip.base_field_chip();

        // 1. check 0 < r, s < n

        // since `assert_not_zero` already includes a in-field check, we can just
        // call `assert_not_zero`
        scalar_chip.assert_not_zero(ctx, &sig.r)?;
        scalar_chip.assert_not_zero(ctx, &sig.s)?;

        // 2. w = s^(-1) (mod n)
        let (s_inv, _) = scalar_chip.invert(ctx, &sig.s)?;

        // 3. u1 = m' * w (mod n)
        let u1 = scalar_chip.mul(ctx, msg_hash, &s_inv)?;

        // 4. u2 = r * w (mod n)
        let u2 = scalar_chip.mul(ctx, &sig.r, &s_inv)?;

        // 5. compute Q = u1*G + u2*pk
        let e_gen = ecc_chip.assign_point(ctx, Some(E::generator()))?;
        let g1 = ecc_chip.mul(ctx, &e_gen, &u1, 2)?;
        let g2 = ecc_chip.mul(ctx, &pk.point, &u2, 2)?;
        let q = ecc_chip.add(ctx, &g1, &g2)?;

        // 6. reduce q_x in E::ScalarExt
        // assuming E::Base/E::ScalarExt have the same number of limbs
        let q_x = q.get_x();
        let q_x_reduced_in_q = base_chip.reduce(ctx, &q_x)?;
        let q_x_reduced_in_r = scalar_chip.reduce_external(ctx, &q_x_reduced_in_q)?;

        // 7. check if Q.x == r (mod n)
        scalar_chip.assert_strict_equal(ctx, &q_x_reduced_in_r, &sig.r)?;

        Ok(())
    }

    /// Verify batch of signatures
    pub fn batch_verify(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        triplets: Vec<(
            AssignedPublicKey<E::Base, N>,  // signer pk
            AssignedEcdsaSig<E::Scalar, N>, // signature
            AssignedInteger<E::Scalar, N>,  // msg_hash
        )>,
    ) -> Result<(), Error> {
        let ecc_chip = self.ecc_chip();
        let scalar_chip = ecc_chip.scalar_field_chip();
        let base_chip = ecc_chip.base_field_chip();
        let main_gate = scalar_chip.main_gate();

        let e_gen = ecc_chip.assign_point(ctx, Some(E::generator()))?;
        let batch_mul_input: Vec<(
            AssignedPoint<E::Base, N>,     // pk
            AssignedInteger<E::Scalar, N>, // u1
            AssignedInteger<E::Scalar, N>, // u2
        )> = triplets
            .iter()
            .map(|(pk, sig, msg_hash)| {
                // 1. check 0 < r, s < n
                // since `assert_not_zero` already includes a in-field check, we can just call
                // `assert_not_zero`
                scalar_chip.assert_not_zero(ctx, &sig.r)?;
                scalar_chip.assert_not_zero(ctx, &sig.s)?;
                // 2. w = s^(-1) (mod n)
                let (s_inv, _) = scalar_chip.invert(ctx, &sig.s)?;

                // 3. u1 = m' * w (mod n)
                let u1 = scalar_chip.mul(ctx, &msg_hash, &s_inv)?;

                // 4. u2 = r * w (mod n)
                let u2 = scalar_chip.mul(ctx, &sig.r, &s_inv)?;
                Ok((pk.point.clone(), u1, u2))
            })
            .collect::<Result<_, Error>>()?;

        // 5. compute vector of Q = u1*G + u2*pk for each signature
        let q_batch = ecc_chip.mul_batch_ecdsa(ctx, &e_gen, batch_mul_input, 4)?;

        for (q, (_, sig, _)) in q_batch.iter().zip(triplets.iter()) {
            // 6. reduce q_x in E::ScalarExt
            // assuming E::Base/E::ScalarExt have the same number of limbs
            let q_x = q.get_x();
            let q_x_reduced_in_q = base_chip.reduce(ctx, &q_x)?;
            let q_x_reduced_in_r = scalar_chip.reduce_external(ctx, &q_x_reduced_in_q)?;
            // 7. check if Q.x == r (mod n)
            scalar_chip.assert_strict_equal(ctx, &q_x_reduced_in_r, &sig.r)?;
        }

        main_gate.break_here(ctx)?;
        Ok(())
    }

    /// Verify batch of signatures
    /// The prover must provide the R point effectively following an ECDSA*
    /// scheme
    pub fn batch_verify_star(
        &self,
        ctx: &mut RegionCtx<'_, '_, N>,
        pk_sig_msg: Vec<(
            AssignedPublicKey<E::Base, N>,               // signer pk
            AssignedEcdsaStarSig<E::Base, E::Scalar, N>, // signature
            AssignedInteger<E::Scalar, N>,               // msg_hash
        )>,
    ) -> Result<(), Error> {
        let window_size = 4;
        let ecc_chip = self.ecc_chip();
        let scalar_chip = ecc_chip.scalar_field_chip();
        let base_chip = ecc_chip.base_field_chip();

        // 1. check 0 < r, s < n
        // since `assert_not_zero` already includes a in-field check, we can just call
        // `assert_not_zero`
        scalar_chip.assert_not_zero(ctx, &pk_sig_msg[0].1.r)?;
        scalar_chip.assert_not_zero(ctx, &pk_sig_msg[0].1.s)?;
        // 2. w = s^(-1) (mod n)
        let (s_inv, _) = scalar_chip.invert(ctx, &pk_sig_msg[0].1.s)?;

        // 3. u1 = m' * w (mod n)
        let mut u1_acc = scalar_chip.mul(ctx, &pk_sig_msg[0].2, &s_inv)?;

        // 4. u2 = r * w (mod n)
        let u2 = scalar_chip.mul(ctx, &pk_sig_msg[0].1.r, &s_inv)?;
        let mut batch_mul_input = vec![(pk_sig_msg[0].0.point.clone(), u2)];

        // 5. Initialize r_acc
        let mut r_acc = pk_sig_msg[0].1.point.clone();

        for (pk, sig, msg) in pk_sig_msg.into_iter().skip(1) {
            // 1. check 0 < r, s < n
            // since `assert_not_zero` already includes a in-field check, we can just call
            // `assert_not_zero`
            scalar_chip.assert_not_zero(ctx, &sig.r)?;
            scalar_chip.assert_not_zero(ctx, &sig.s)?;
            // 2. w = s^(-1) (mod n)
            let (s_inv, _) = scalar_chip.invert(ctx, &sig.s)?;

            // 3. u1 = m' * w (mod n)
            let u1 = scalar_chip.mul(ctx, &msg, &s_inv)?;
            u1_acc = scalar_chip.add(ctx, &u1_acc, &u1)?;

            // 4. u2 = r * w (mod n)
            let u2 = scalar_chip.mul(ctx, &sig.r, &s_inv)?;
            batch_mul_input.push((pk.point, u2));

            //5. r_acc += R
            r_acc = ecc_chip.add(ctx, &r_acc, &sig.point)?;
        }

        u1_acc = scalar_chip.reduce(ctx, &u1_acc)?;

        let e_gen = ecc_chip.assign_point(ctx, Some(E::generator()))?;
        batch_mul_input.push((e_gen, u1_acc));

        // 6. sum (u2_i * Q_i) + u1_acc * G
        let sum_point = ecc_chip.mul_batch_1d_horizontal(ctx, batch_mul_input, window_size)?;

        let sum_x = sum_point.get_x();
        let sum_x_reduced_in_q = base_chip.reduce(ctx, &sum_x)?;
        let sum_x_reduced_in_r = scalar_chip.reduce_external(ctx, &sum_x_reduced_in_q)?;
        let r_x = r_acc.get_x();
        let r_x_reduced_in_q = base_chip.reduce(ctx, &r_x)?;
        let r_x_reduced_in_r = scalar_chip.reduce_external(ctx, &r_x_reduced_in_q)?;
        scalar_chip.assert_equal(ctx, &r_x_reduced_in_r, &sum_x_reduced_in_r)?;
        let main_gate = scalar_chip.main_gate();
        main_gate.break_here(ctx)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AssignedEcdsaStarSig;
    use super::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
    use crate::halo2;
    use crate::integer;
    use crate::maingate;
    use ecc::integer::Range;
    use ecc::maingate::big_to_fe;
    use ecc::maingate::fe_to_big;
    use ecc::maingate::RegionCtx;
    use ecc::{EccConfig, GeneralEccChip};
    use group::ff::Field;
    use group::{Curve, Group};
    use halo2::arithmetic::CurveAffine;
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use integer::{IntegerInstructions, NUMBER_OF_LOOKUP_LIMBS};
    use maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions};
    use rand_core::OsRng;
    use std::marker::PhantomData;

    const BIT_LEN_LIMB: usize = 68;
    const NUMBER_OF_LIMBS: usize = 4;

    // Single verification test
    #[derive(Clone, Debug)]
    struct TestCircuitEcdsaVerifyConfig {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    }

    impl TestCircuitEcdsaVerifyConfig {
        pub fn new<C: CurveAffine, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
            let (rns_base, rns_scalar) =
                GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
            let main_gate_config = MainGate::<N>::configure(meta);
            let mut overflow_bit_lengths: Vec<usize> = vec![];
            overflow_bit_lengths.extend(rns_base.overflow_lengths());
            overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
            let range_config =
                RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            TestCircuitEcdsaVerifyConfig {
                main_gate_config,
                range_config,
            }
        }

        pub fn ecc_chip_config(&self) -> EccConfig {
            EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
        }

        pub fn config_range<N: FieldExt>(
            &self,
            layouter: &mut impl Layouter<N>,
        ) -> Result<(), Error> {
            let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
            let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
            range_chip.load_limb_range_table(layouter)?;
            range_chip.load_overflow_range_tables(layouter)?;

            Ok(())
        }
    }

    #[derive(Default, Clone)]
    struct TestCircuitEcdsaVerify<E: CurveAffine, N: FieldExt> {
        public_key: Option<E>,
        signature: Option<(E::Scalar, E::Scalar)>,
        msg_hash: Option<E::Scalar>,

        aux_generator: E,
        window_size: usize,
        _marker: PhantomData<N>,
    }

    impl<E: CurveAffine, N: FieldExt> Circuit<N> for TestCircuitEcdsaVerify<E, N> {
        type Config = TestCircuitEcdsaVerifyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitEcdsaVerifyConfig::new::<E, N>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let mut ecc_chip = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
                config.ecc_chip_config(),
            );
            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    ecc_chip.assign_aux_generator(ctx, Some(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                    Ok(())
                },
            )?;

            let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let r = self.signature.map(|signature| signature.0);
                    let s = self.signature.map(|signature| signature.1);
                    let integer_r = ecc_chip.new_unassigned_scalar(r);
                    let integer_s = ecc_chip.new_unassigned_scalar(s);
                    let msg_hash = ecc_chip.new_unassigned_scalar(self.msg_hash);

                    let r_assigned =
                        scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
                    let s_assigned =
                        scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
                    let sig = AssignedEcdsaSig {
                        r: r_assigned,
                        s: s_assigned,
                    };

                    let pk_in_circuit = ecc_chip.assign_point(ctx, self.public_key)?;
                    let pk_assigned = AssignedPublicKey {
                        point: pk_in_circuit,
                    };
                    let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;
                    ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
                },
            )?;

            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    // Batch verification test
    #[derive(Default, Clone)]
    struct BatchEcdsaVerifyInput<E: CurveAffine> {
        pk: Vec<E>,
        m_hash: Vec<E::ScalarExt>,
        sig_s: Vec<E::ScalarExt>,
        x_bytes_n: Vec<E::ScalarExt>,
    }

    impl<E: CurveAffine> BatchEcdsaVerifyInput<E> {
        fn new() -> Self {
            Self {
                pk: vec![],
                m_hash: vec![],
                sig_s: vec![],
                x_bytes_n: vec![],
            }
        }
    }

    #[derive(Default, Clone)]
    struct TestCircuitEcdsaBatchVerify<E: CurveAffine, N: FieldExt> {
        aux_generator: E,
        window_size: usize,
        batch_size: usize,
        _marker: PhantomData<N>,
    }

    impl<E: CurveAffine, N: FieldExt> Circuit<N> for TestCircuitEcdsaBatchVerify<E, N> {
        type Config = TestCircuitEcdsaVerifyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitEcdsaVerifyConfig::new::<E, N>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let mut ecc_chip = GeneralEccChip::<E, N>::new(config.ecc_chip_config());
            let scalar_chip = ecc_chip.scalar_field_chip();

            let mut rng = thread_rng();

            let mut bevi = BatchEcdsaVerifyInput::new();
            // generate a batch of valid signatures
            let generator = <E as PrimeCurveAffine>::generator();
            for _ in 0..self.batch_size {
                let sk = <E as CurveAffine>::ScalarExt::random(&mut rng);
                let pk = generator * sk;
                let pk = pk.to_affine();

                let m_hash = <E as CurveAffine>::ScalarExt::random(&mut rng);
                let randomness = <E as CurveAffine>::ScalarExt::random(&mut rng);
                let randomness_inv = randomness.invert().unwrap();
                let sig_point = generator * randomness;
                let x = sig_point.to_affine().coordinates().unwrap().x().clone();

                cfg_if::cfg_if! {
                    if #[cfg(feature = "kzg")] {
                        let x_repr = &mut Vec::with_capacity(32);
                        x.write(x_repr)?;
                    } else {
                        let mut x_repr = [0u8; 32];
                        x_repr.copy_from_slice(x.to_repr().as_ref());
                    }
                }

                let mut x_bytes = [0u8; 64];
                x_bytes[..32].copy_from_slice(&x_repr[..]);

                let x_bytes_on_n = <E as CurveAffine>::ScalarExt::from_bytes_wide(&x_bytes); // get x cordinate (E::Base) on E::Scalar
                let sig_s = randomness_inv * (m_hash + x_bytes_on_n * sk);
                bevi.pk.push(pk);
                bevi.m_hash.push(m_hash);
                bevi.x_bytes_n.push(x_bytes_on_n);
                bevi.sig_s.push(sig_s);
            }

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    ecc_chip.assign_aux_generator(ctx, Some(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, 2)?;
                    Ok(())
                },
            )?;

            let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());
            layouter
                .assign_region(
                    || "region 0",
                    |mut region| {
                        let mut assigned_bevi: Vec<(
                            AssignedPublicKey<E::Base, N>,
                            AssignedEcdsaSig<E::Scalar, N>,
                            AssignedInteger<E::Scalar, N>,
                        )> = Vec::with_capacity(self.batch_size);
                        let offset = &mut 0;
                        let ctx = &mut RegionCtx::new(&mut region, offset);

                        for i in 0..self.batch_size {
                            let integer_r = ecc_chip.new_unassigned_scalar(Some(bevi.x_bytes_n[i]));
                            let integer_s = ecc_chip.new_unassigned_scalar(Some(bevi.sig_s[i]));
                            let msg_hash = ecc_chip.new_unassigned_scalar(Some(bevi.m_hash[i]));

                            let r_assigned = scalar_chip.assign_integer(ctx, integer_r)?;
                            let s_assigned = scalar_chip.assign_integer(ctx, integer_s)?;
                            let sig = AssignedEcdsaSig {
                                r: r_assigned,
                                s: s_assigned,
                            };

                            let pk_in_circuit =
                                ecc_chip.assign_point(ctx, Some(bevi.pk[i].into()))?;
                            let pk_assigned = AssignedPublicKey {
                                point: pk_in_circuit,
                            };
                            let msg_hash = scalar_chip.assign_integer(ctx, msg_hash)?;
                            assigned_bevi.push((pk_assigned, sig, msg_hash));
                        }

                        ecdsa_chip.batch_verify(ctx, assigned_bevi).unwrap();
                        Ok(())
                    },
                )
                .unwrap();
            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    // Batch ecdsa_star verification test
    #[derive(Default, Clone)]
    struct BatchEcdsaStarVerifyInput<E: CurveAffine> {
        pk: Vec<E>,
        m_hash: Vec<E::ScalarExt>,
        sig_s: Vec<E::ScalarExt>,
        sig_point: Vec<E>,
        x_bytes_n: Vec<E::ScalarExt>,
    }

    impl<E: CurveAffine> BatchEcdsaStarVerifyInput<E> {
        fn new() -> Self {
            Self {
                pk: vec![],
                m_hash: vec![],
                sig_s: vec![],
                sig_point: vec![],
                x_bytes_n: vec![],
            }
        }
    }
    #[derive(Default, Clone)]
    struct TestCircuitEcdsaStarBatchVerify<E: CurveAffine, N: FieldExt> {
        aux_generator: E,
        window_size: usize,
        batch_size: usize,
        _marker: PhantomData<N>,
    }

    impl<E: CurveAffine, N: FieldExt> Circuit<N> for TestCircuitEcdsaStarBatchVerify<E, N> {
        type Config = TestCircuitEcdsaVerifyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            TestCircuitEcdsaVerifyConfig::new::<E, N>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<N>,
        ) -> Result<(), Error> {
            let mut ecc_chip = GeneralEccChip::<E, N>::new(config.ecc_chip_config(), BIT_LEN_LIMB);
            let scalar_chip = ecc_chip.scalar_field_chip();

            let mut rng = thread_rng();

            let mut bevi = BatchEcdsaStarVerifyInput::new();
            // generate a batch of valid signatures
            let generator = <E as PrimeCurveAffine>::generator();
            for _ in 0..self.batch_size {
                let sk = <E as CurveAffine>::ScalarExt::random(&mut rng);
                let pk = generator * sk;
                let pk = pk.to_affine();

                let m_hash = <E as CurveAffine>::ScalarExt::random(&mut rng);
                let randomness = <E as CurveAffine>::ScalarExt::random(&mut rng);
                let randomness_inv = randomness.invert().unwrap();
                let sig_point = generator * randomness;
                let sig_point = sig_point.to_affine();
                let x = sig_point.coordinates().unwrap().x().clone();

                cfg_if::cfg_if! {
                    if #[cfg(feature = "kzg")] {
                        let x_repr = &mut Vec::with_capacity(32);
                        x.write(x_repr)?;
                    } else {
                        let mut x_repr = [0u8; 32];
                        x_repr.copy_from_slice(x.to_repr().as_ref());
                    }
                }

                let mut x_bytes = [0u8; 64];
                x_bytes[..32].copy_from_slice(&x_repr[..]);

                let x_bytes_on_n = <E as CurveAffine>::ScalarExt::from_bytes_wide(&x_bytes); // get x cordinate (E::Base) on E::Scalar
                let sig_s = randomness_inv * (m_hash + x_bytes_on_n * sk);
                bevi.pk.push(pk);
                bevi.m_hash.push(m_hash);
                bevi.x_bytes_n.push(x_bytes_on_n);
                bevi.sig_s.push(sig_s);
                bevi.sig_point.push(sig_point);
            }

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    ecc_chip.assign_aux_generator(ctx, Some(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, self.batch_size + 1)?;
                    Ok(())
                },
            )?;

            let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());
            layouter
                .assign_region(
                    || "region 0",
                    |mut region| {
                        let mut assigned_bevi: Vec<(
                            AssignedPublicKey<E::Base, N>,
                            AssignedEcdsaStarSig<E::Base, E::Scalar, N>,
                            AssignedInteger<E::Scalar, N>,
                        )> = Vec::with_capacity(self.batch_size);
                        let offset = &mut 0;
                        let ctx = &mut RegionCtx::new(&mut region, offset);

                        for i in 0..self.batch_size {
                            let integer_r = ecc_chip.new_unassigned_scalar(Some(bevi.x_bytes_n[i]));
                            let integer_s = ecc_chip.new_unassigned_scalar(Some(bevi.sig_s[i]));
                            let msg_hash = ecc_chip.new_unassigned_scalar(Some(bevi.m_hash[i]));
                            let sig_point_assigned =
                                ecc_chip.assign_point(ctx, Some(bevi.sig_point[i].into()))?;

                            let r_assigned = scalar_chip.assign_integer(ctx, integer_r)?;
                            let s_assigned = scalar_chip.assign_integer(ctx, integer_s)?;
                            let sig = AssignedEcdsaStarSig {
                                point: sig_point_assigned,
                                r: r_assigned,
                                s: s_assigned,
                            };

                            let pk_in_circuit =
                                ecc_chip.assign_point(ctx, Some(bevi.pk[i].into()))?;
                            let pk_assigned = AssignedPublicKey {
                                point: pk_in_circuit,
                            };
                            let msg_hash = scalar_chip.assign_integer(ctx, msg_hash)?;
                            assigned_bevi.push((pk_assigned, sig, msg_hash));
                        }

                        ecdsa_chip.batch_verify_star(ctx, assigned_bevi).unwrap();
                        Ok(())
                    },
                )
                .unwrap();
            config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    // Run tests
    #[test]
    fn test_ecdsa_verifier() {
        fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
            let x_big = fe_to_big(x);
            big_to_fe(x_big)
        }

        fn run<C: CurveAffine, N: FieldExt>() {
            let g = C::generator();

            // Generate a key pair
            let sk = <C as CurveAffine>::ScalarExt::random(OsRng);
            let public_key = (g * sk).to_affine();

            // Generate a valid signature
            // Suppose `m_hash` is the message hash
            let msg_hash = <C as CurveAffine>::ScalarExt::random(OsRng);

            // Draw arandomness
            let k = <C as CurveAffine>::ScalarExt::random(OsRng);
            let k_inv = k.invert().unwrap();

            // Calculate `r`
            let r_point = (g * k).to_affine().coordinates().unwrap();
            let x = r_point.x();
            let r = mod_n::<C>(*x);

            // Calculate `s`
            let s = k_inv * (msg_hash + (r * sk));

            // Sanity check. Ensure we construct a valid signature. So lets verify it
            {
                let s_inv = s.invert().unwrap();
                let u_1 = msg_hash * s_inv;
                let u_2 = r * s_inv;
                let r_point = ((g * u_1) + (public_key * u_2))
                    .to_affine()
                    .coordinates()
                    .unwrap();
                let x_candidate = r_point.x();
                let r_candidate = mod_n::<C>(*x_candidate);
                assert_eq!(r, r_candidate);
            }

            let k = 20;
            let aux_generator = C::CurveExt::random(OsRng).to_affine();
            let circuit = TestCircuitEcdsaVerify::<C, N> {
                public_key: Some(public_key),
                signature: Some((r, s)),
                msg_hash: Some(msg_hash),

                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            };

            let public_inputs = vec![vec![]];
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            assert_eq!(prover.verify(), Ok(()));
        }

        use crate::curves::bn256::Fr as BnScalar;
        use crate::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
        use crate::curves::secp256k1::Secp256k1Affine as Secp256k1;
        run::<Secp256k1, BnScalar>();
        run::<Secp256k1, PastaFp>();
        run::<Secp256k1, PastaFq>();
    }

    #[test]
    fn test_ecdsa_batch_verifier() {
        fn run<C: CurveAffine, N: FieldExt>() {
            use group::Group;
            let k = 20;
            let mut rng = thread_rng();
            let aux_generator = C::CurveExt::random(&mut rng).to_affine();
            let circuit = TestCircuitEcdsaBatchVerify::<C, N> {
                aux_generator,
                window_size: 4,
                batch_size: 4,
                _marker: PhantomData,
            };

            let public_inputs = vec![vec![]];
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            assert_eq!(prover.verify(), Ok(()));
        }

        #[cfg(not(feature = "kzg"))]
        {}
        #[cfg(feature = "kzg")]
        {
            use halo2::pairing::bn256::Fr;
            use secp256k1::Secp256k1Affine as Secp256;
            run::<Secp256, Fr>();
        }
    }

    #[test]
    fn test_ecdsa_star_batch_verifier() {
        fn run<C: CurveAffine, N: FieldExt>() {
            use group::Group;
            let k = 20;
            let mut rng = thread_rng();
            let aux_generator = C::CurveExt::random(&mut rng).to_affine();
            let circuit = TestCircuitEcdsaStarBatchVerify::<C, N> {
                aux_generator,
                window_size: 4,
                batch_size: 8,
                _marker: PhantomData,
            };

            let public_inputs = vec![vec![]];
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            assert_eq!(prover.verify(), Ok(()));
        }

        #[cfg(not(feature = "kzg"))]
        {}
        #[cfg(feature = "kzg")]
        {
            use halo2::pairing::bn256::Fr;
            use secp256k1::Secp256k1Affine as Secp256;
            run::<Secp256, Fr>();
        }
    }
}
