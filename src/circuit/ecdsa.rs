use crate::circuit::ecc::{AssignedPoint, general_ecc::GeneralEccChip, EccConfig, general_ecc::GeneralEccInstruction};
use crate::circuit::integer::IntegerInstructions;
use crate::circuit::AssignedInteger;
use crate::rns::Integer;
use halo2arith::halo2;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::{ConstraintSystem, Error};
use crate::rns::Rns;
use crate::circuit::fe_to_big;

#[derive(Clone, Debug)]
pub struct EcdsaConfig {
    ecc_chip_config: EccConfig, 
}

impl EcdsaConfig {
    pub fn ecc_chip_config(&self) -> EccConfig {
        self.ecc_chip_config.clone()
    }
}

/// E is the emulated curve, C is the native curve
struct EcdsaChip<E: CurveAffine, C: CurveAffine> {
    pub config: EcdsaConfig,
    pub rns_base_field: Rns<E::Base, C::ScalarExt>,
    pub rns_scalar_field: Rns<E::Scalar, C::ScalarExt>,
}

impl<E: CurveAffine, C: CurveAffine> EcdsaChip<E, C> {
    pub fn new(config: EcdsaConfig, rns_base_field: Rns<E::Base, C::ScalarExt>, rns_scalar_field: Rns<E::ScalarExt, C::ScalarExt>) -> Result<Self, Error> {
        Ok(
            Self {
                config,
                rns_base_field,
                rns_scalar_field,
            }
        )
    }

    pub fn configure(_: &mut ConstraintSystem<C::ScalarExt>, ecc_chip_config: &EccConfig) -> EcdsaConfig {
        EcdsaConfig {
            ecc_chip_config: ecc_chip_config.clone(),
        }
    }

    pub fn ecc_chip(&self) -> Result<GeneralEccChip<E, C::ScalarExt>, Error> {
        let ecc_chip_config = self.config.ecc_chip_config();
        GeneralEccChip::new(ecc_chip_config, self.rns_base_field.clone(), self.rns_scalar_field.clone())
    }
}

#[derive(Clone, Debug)]
pub struct EcdsaSig<'a, W: FieldExt, N: FieldExt> {
    pub r: Integer<'a, W, N>,
    pub s: Integer<'a, W, N>,
}

pub struct AssignedEcdsaSig<N: FieldExt> {
    pub r: AssignedInteger<N>,
    pub s: AssignedInteger<N>,
}

pub struct AssignedPublicKey<N: FieldExt> {
    pub point: AssignedPoint<N>,
}

impl<E: CurveAffine, C: CurveAffine> EcdsaChip<E, C> {
    // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    fn verify(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        sig: &AssignedEcdsaSig<C::ScalarExt>,
        pk: &AssignedPublicKey<C::ScalarExt>,
        msg_hash: &AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let ecc_chip = self.ecc_chip()?;
        let scalar_chip = ecc_chip.scalar_field_chip();

        // 1. check 0 < r, s < n

        // // since `assert_not_zero` already includes a in-field check, we can just call `assert_not_zero`
        scalar_chip.assert_not_zero(region, &sig.r, offset)?;
        scalar_chip.assert_not_zero(region, &sig.s, offset)?;

        // 2. w = s^(-1) (mod n)
        let (s_inv, _) = scalar_chip.invert(region, &sig.s, offset)?;

        // 3. u1 = m' * w (mod n)
        let u1 = scalar_chip.mul(region, &msg_hash, &s_inv, offset)?;

        // 4. u2 = r * w (mod n)
        let u2 = scalar_chip.mul(region, &sig.r, &s_inv, offset)?;

        // 5. compute Q = u1*G + u2*pk
        let e_gen = ecc_chip.assign_point(region, Some(E::generator()), offset)?;
        let g1 = ecc_chip.mul_var(region, e_gen.clone(), u1, offset)?;
        let g2 = ecc_chip.mul_var(region, pk.point.clone(), u2, offset)?;
        let q = ecc_chip.add(region, &g1, &g2, offset)?;

        // 6. check if Q.x == r (mod n)
        let q_x = q.x.clone();
        // TODO: no equal constraint yet!
        let q_x_integer = self.rns_scalar_field.new_from_big(fe_to_big(q_x.native().value.ok_or_else(|| Error::Synthesis)?));   // get q_x assigned in our rns_scalar integer chip
        let q_x_integer_assigned = scalar_chip.assign_integer(region, q_x_integer.into(), offset)?;

        scalar_chip.assert_equal(region, &q_x_integer_assigned, &sig.r, offset)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::ecc::{EccConfig, general_ecc::GeneralEccInstruction};
    use crate::circuit::integer::IntegerInstructions;
    use crate::rns::Rns;
    use halo2arith::halo2;
    use halo2::arithmetic::{CurveAffine};
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use crate::circuit::ecdsa::{
        AssignedEcdsaSig, AssignedPublicKey, EcdsaChip, EcdsaConfig,
    };
    use halo2arith::main_gate::five::main_gate::MainGate; 
    use halo2arith::main_gate::five::range::RangeChip;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use group::{Curve, prime::PrimeCurveAffine};
    use halo2arith::fe_to_big;
    use group::ff::Field;
    use rand_xorshift::XorShiftRng;
    use rand::SeedableRng;
    use halo2arith::main_gate::five::range::RangeInstructions;
    use group::ff::PrimeField;
    use halo2arith::halo2::arithmetic::FieldExt;

    #[derive(Clone, Debug)]
    struct TestCircuitEcdsaVerifyConfig {
        ecdsa_verify_config: EcdsaConfig,
    }

    impl TestCircuitEcdsaVerifyConfig {}

    #[derive(Default, Clone)]
    struct TestCircuitEcdsaVerify<E: CurveAffine, C: CurveAffine> {
        rns_base: Rns<E::Base, C::ScalarExt>,
        rns_scalar: Rns<E::ScalarExt, C::ScalarExt>,
    }

    impl<E: CurveAffine, C: CurveAffine> Circuit<C::ScalarExt> for TestCircuitEcdsaVerify<E, C> {
        type Config = TestCircuitEcdsaVerifyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
            let mut overflow_bit_lengths: Vec<usize> = vec![];
            let bit_len_limb = 68;
            let rns_base = Rns::<<E as CurveAffine>::Base, <C as CurveAffine>::ScalarExt>::construct(bit_len_limb);
            let rns_scalar = Rns::<<E as CurveAffine>::ScalarExt, <C as CurveAffine>::ScalarExt>::construct(bit_len_limb);

            overflow_bit_lengths.extend(rns_base.overflow_lengths());
            overflow_bit_lengths.extend(rns_scalar.overflow_lengths());

            let main_gate_config = MainGate::<C::ScalarExt>::configure(meta);
            let range_config = RangeChip::<C::ScalarExt>::configure(meta, &main_gate_config, overflow_bit_lengths.clone());
            let ecc_chip_config = EccConfig {
                range_config: range_config.clone(),
                main_gate_config: main_gate_config.clone(),
            };

            let ecdsa_verify_config = EcdsaChip::<E, C>::configure(meta, &ecc_chip_config);

            TestCircuitEcdsaVerifyConfig { ecdsa_verify_config }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<<C as CurveAffine>::ScalarExt>) -> Result<(), Error> {
            let ecdsa_chip = EcdsaChip::<E, C>::new(config.ecdsa_verify_config.clone(), self.rns_base.clone(), self.rns_scalar.clone())?;
            let ecc_chip = ecdsa_chip.ecc_chip()?;
            let scalar_chip = ecc_chip.scalar_field_chip();

            let mut rng = XorShiftRng::from_seed([
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
            ]);

            // generate a valid signature
            let generator = <E as PrimeCurveAffine>::generator();
            let sk = <E as CurveAffine>::ScalarExt::random(&mut rng);
            let pk = generator * sk;
            let pk = pk.to_affine();

            let m_hash = <E as CurveAffine>::ScalarExt::random(&mut rng);
            let randomness = <E as CurveAffine>::ScalarExt::random(&mut rng);
            let randomness_inv = randomness.invert().unwrap();
            let sig_point = generator * randomness;
            let x = sig_point.to_affine().coordinates().unwrap().x().clone();
            println!("E char = {}", E::ScalarExt::MODULUS);
            println!("x coord = {:?}", x);

            let mut x_repr = [0u8;32];
            x_repr.copy_from_slice(x.to_repr().as_ref());
            let mut x_bytes = [0u8;64];
            x_bytes[..32].copy_from_slice(&x_repr[..]);
            let x_bytes_on_n = <E as CurveAffine>::ScalarExt::from_bytes_wide(&x_bytes); // get x cordinate (E::Base) on E::Scalar
            println!("x bytes on n = {:?}", x_bytes_on_n.clone());

            let integer_r = self.rns_scalar.new_from_big(fe_to_big(x_bytes_on_n));
            let integer_s = self.rns_scalar.new_from_big(fe_to_big(randomness_inv * (m_hash + x_bytes_on_n * sk)));

            let integer_m_hash = self.rns_scalar.new_from_big(fe_to_big(m_hash));

            let msg_hash = integer_m_hash.clone();

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;

                    let r_assigned = scalar_chip.assign_integer(&mut region, integer_r.clone().into(), offset)?;
                    let s_assigned = scalar_chip.assign_integer(&mut region, integer_s.clone().into(), offset)?;

                    let sig = AssignedEcdsaSig {
                        r: r_assigned.clone(),
                        s: s_assigned.clone(),
                    };

                    let pk_in_circuit = ecc_chip.assign_point(&mut region, Some(pk.into()), offset)?;

                    let pk_assigned = AssignedPublicKey {
                        point: pk_in_circuit,
                    };

                    let msg_hash = scalar_chip.assign_integer(&mut region, msg_hash.clone().into(), offset)?;

                    ecdsa_chip.verify(&mut region, &sig, &pk_assigned, &msg_hash, offset)
                },
            )?;

            // since we used `assert_in_field`, we need a range chip
            let range_chip = RangeChip::<C::ScalarExt>::new(config.ecdsa_verify_config.ecc_chip_config.range_config.clone(), self.rns_scalar.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_pasta_ecdsa_verifier() {
        // assuming that we are verifying signature (in Fp curve) on Fq curve
        // which means signature's scalar field is Fq, base field is Fp
        // which in turn means E::ScalarExt == C::Base, E::Base == C::ScalarExt
        // p > q
        use halo2::pasta::EpAffine as C;
        use halo2::pasta::EqAffine as E;

        let bit_len_limb = 68;
        let rns_base = Rns::<<E as CurveAffine>::Base, <C as CurveAffine>::ScalarExt>::construct(bit_len_limb);
        let rns_scalar = Rns::<<E as CurveAffine>::ScalarExt, <C as CurveAffine>::ScalarExt>::construct(bit_len_limb);

        // #[cfg(not(feature = "no_lookup"))]
        // let k: u32 = (rns_base.bit_len_lookup + 1) as u32;
        // #[cfg(feature = "no_lookup")]
        // let k: u32 = 8;

        let k = 20;

        // testcase: normal
        let circuit = TestCircuitEcdsaVerify::<E, C> {
            rns_base,
            rns_scalar,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }
}
