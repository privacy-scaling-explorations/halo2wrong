use super::EccConfig;
use crate::circuit::integer::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{MainGate, MainGateInstructions};
use crate::circuit::{AssignedCondition, AssignedInteger};
use crate::rns::{Integer, Rns};
use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::{Region, Layouter};
use halo2::plonk::Error;

use crate::circuit::ecc::{Point, AssignedPoint};

pub trait GeneralEccInstruction<Emulated: CurveAffine, N: FieldExt> {
    fn assign_point(&self, region: &mut Region<'_, N>, point: Emulated, offset: &mut usize) -> Result<AssignedPoint<N>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, N>, point: &AssignedPoint<N>, offset: &mut usize) -> Result<(), Error>;

    fn select(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;

    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;

    fn assert_equal(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<N>,
        p1: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn add(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<N>,
        p1: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;

    fn double(&self, region: &mut Region<'_, N>, p: AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, N>,
        p: AssignedPoint<N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;

    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error>;
}

pub struct GeneralEccChip<Emulated: CurveAffine, F: FieldExt> {
    pub (super) config: EccConfig,
    pub (super) rns_base_field: Rns<Emulated::Base, F>,
    pub (super) rns_scalar_field: Rns<Emulated::Scalar, F>,

    // We need following assigned constants for ecc operations
    pub (super) a: AssignedInteger<F>,
    pub (super) b: AssignedInteger<F>,
    pub (super) identity: AssignedPoint<F>,
}

// Ecc operation mods
mod add;

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
    pub (super) fn new(
        layouter: &mut impl Layouter<N>,
        config: EccConfig,
        rns_base_field: Rns<Emulated::Base, N>,
        rns_scalar_field: Rns<Emulated::ScalarExt, N>
    ) -> Result<Self, Error> {
        let main_gate_config = config.main_gate_config.clone();
        let main_gate = MainGate::<N>::new(main_gate_config);
        let base_chip = IntegerChip::<Emulated::Base, N>::new(config.integer_chip_config.clone(), rns_base_field.clone());

        let a = rns_base_field.new(Emulated::a());
        let b = rns_base_field.new(Emulated::b());
        let zero = rns_base_field.new_from_big(0u32.into());

        // for constants a, b and identity, we assign it once and borrow them in
        // other operations to avoid duplication
        let (a, b, identity) = {
            let mut ca: Option<AssignedInteger<N>> = None;
            let mut cb: Option<AssignedInteger<N>> = None;
            let mut identity: Option<AssignedPoint<N>> = None;
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    ca = Some (base_chip.assign_integer(&mut region, Some(a.clone()), offset)?);
                    cb = Some (base_chip.assign_integer(&mut region, Some(b.clone()), offset)?);
                    let z = base_chip.assign_integer(&mut region, Some(zero.clone()), offset)?;
                    let c = main_gate.assign_bit(&mut region, Some(N::one()), offset)?;
                    identity = Some(AssignedPoint::new(z.clone(), z, c));
                    Ok(())
                },
            )?;
            (ca.unwrap(), cb.unwrap(), identity.unwrap())
        };

        Ok (Self {
            config,
            rns_base_field,
            rns_scalar_field,
            a,
            b,
            identity,
        })
    }

    fn scalar_field_chip(&self) -> IntegerChip<Emulated::ScalarExt, N> {
        IntegerChip::<Emulated::ScalarExt, N>::new(self.config.integer_chip_config.clone(), self.rns_scalar_field.clone())
    }

    fn base_field_chip(&self) -> IntegerChip<Emulated::Base, N> {
        IntegerChip::<Emulated::Base, N>::new(self.config.integer_chip_config.clone(), self.rns_base_field.clone())
    }

    fn main_gate(&self) -> MainGate<N> {
        MainGate::<N>::new(self.config.main_gate_config.clone())
    }

    fn parameter_a(&self) -> Integer<N> {
        self.rns_base_field.new(Emulated::a())
    }

    fn parameter_b(&self) -> Integer<N> {
        self.rns_base_field.new(Emulated::b())
    }

    fn is_a_0(&self) -> bool {
        Emulated::a() == Emulated::Base::zero()
    }

    fn into_rns_point(&self, point: Emulated) -> Point<N> {
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
        unimplemented!();
    }

    fn assign_point(&self, region: &mut Region<'_, N>, point: Emulated, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        let integer_chip = self.base_field_chip();
        let point = self.into_rns_point(point);
        // FIX: This won't help for a prover assigns the infinity
        assert!(!point.is_identity);
        let x = integer_chip.assign_integer(region, Some(point.x), offset)?;
        let y = integer_chip.assign_integer(region, Some(point.y), offset)?;
        let z = self.main_gate().assign_bit(region, Some(N::zero()), offset)?;
        Ok(AssignedPoint::new(x, y, z))
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<N>,
        p1: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let integer_chip = self.base_field_chip();
        integer_chip.assert_equal(region, &p0.x, &p1.x, offset)?;
        integer_chip.assert_equal(region, &p0.y, &p1.y, offset)?;
        main_gate.assert_equal(region, p0.z.clone(), p1.z.clone(), offset)?;
        Ok(())
    }

    fn select(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        let main_gate = self.main_gate();
        let integer_chip = self.base_field_chip();
        let x = integer_chip.cond_select(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.cond_select(region, &p1.y, &p2.y, c, offset)?;
        let c: AssignedCondition<N> = main_gate.cond_select(region, p1.z.clone(), p2.z.clone(), c, offset)?.into();
        Ok(AssignedPoint::new(x, y, c))
    }

    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        let main_gate = self.main_gate();
        let integer_chip = self.base_field_chip();
        let p2 = self.into_rns_point(p2);
        let x = integer_chip.cond_select_or_assign(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.cond_select_or_assign(region, &p1.y, &p2.y, c, offset)?;
        let c: AssignedCondition<N> = main_gate
            .cond_select_or_assign(region, p1.z.clone(), if p2.is_identity { N::one() } else { N::zero() }, c, offset)?
            .into();
        Ok(AssignedPoint::new(x, y, c))
    }

    fn add(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<N>,
        p1: &AssignedPoint<N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        self._add(region, p0, p1, offset)
    }

    fn double(&self, region: &mut Region<'_, N>, p: AssignedPoint<N>, offset: &mut usize) -> Result<AssignedPoint<N>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, N>,
        p: AssignedPoint<N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        unimplemented!();
    }

    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<N>, Error> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use halo2::arithmetic::{CurveAffine, FieldExt, Field};
    use crate::circuit::integer::{IntegerChip, IntegerConfig};
    use crate::circuit::main_gate::{MainGate, MainGateConfig, MainGateInstructions};
    use crate::circuit::range::{RangeChip, RangeInstructions, RangeConfig};
    use crate::circuit::ecc::{Point, EccConfig};
    use crate::circuit::ecc::general_ecc::{GeneralEccChip, GeneralEccInstruction};
    use crate::rns::{Integer, Limb, Rns};
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use group::{Curve, prime::PrimeCurveAffine};

    // Testing EpAffine over Fq
    use halo2::pasta::EpAffine as C;
    use halo2::pasta::Fq as Native;

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
        integer_chip_config: IntegerConfig,
        ecc_chip_config: EccConfig,
        range_config: RangeConfig,
    }

    impl TestCircuitConfig {
        fn overflow_bit_lengths() -> Vec<usize> {
            vec![2, 3]
        }
    }

    #[derive(Default, Clone, Debug)]
    struct TestEcc<C: CurveAffine, N: FieldExt> {
        x: Option<C>,
        y: Option<C>,
        z: Option<C>,
        rns_base: Rns<C::Base, N>,
        rns_scalar: Rns<C::ScalarExt, N>,
    }

    impl<C: CurveAffine, N: FieldExt> Circuit<N> for TestEcc<C, N> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
            let main_gate_config = MainGate::<N>::configure(meta);
            let overflow_bit_lengths = TestCircuitConfig::overflow_bit_lengths();
            let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
            let integer_chip_config = IntegerChip::<C::Base, N>::configure(meta, &range_config, &main_gate_config);
            let ecc_chip_config = EccConfig {
                main_gate_config: main_gate_config.clone(),
                integer_chip_config: integer_chip_config.clone()
            };
            TestCircuitConfig {
                range_config,
                integer_chip_config,
                main_gate_config,
                ecc_chip_config,
            }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
            let ecc_chip = GeneralEccChip::<C, N>::new(
                &mut layouter,
                config.ecc_chip_config,
                self.rns_base.clone(),
                self.rns_scalar.clone()
            )?;
            let offset = &mut 0;
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let px = match &self.x {
                        Some(x) => ecc_chip.assign_point(&mut region, x.clone(), offset)?,
                        None => ecc_chip.identity.clone(),
                    };
                    let py = match &self.y {
                        Some(x) => ecc_chip.assign_point(&mut region, x.clone(), offset)?,
                        None => ecc_chip.identity.clone(),
                    };
                    let pz = match &self.z {
                        Some(x) => ecc_chip.assign_point(&mut region, x.clone(), offset)?,
                        None => ecc_chip.identity.clone(),
                    };
                    let r = ecc_chip.add(&mut region, &px, &py, offset)?;
                    ecc_chip.assert_equal(&mut region, &r, &pz, offset)?;
                    Ok(())
                },
            )?;


            let range_chip = RangeChip::<N>::new(config.range_config, self.rns_base.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    fn create_point(a: Option<u64>) -> Option<C>{
        a.map(|a| {
            let ma = <C as CurveAffine>::ScalarExt::from_raw([a,0,0,0]);
            let generator = <C as PrimeCurveAffine> :: generator();
            (generator * ma).into()
        })
    }

    fn test_ecc_add_circuit(a:Option<u64>, b:Option<u64>, c:Option<u64>) {
        let bit_len_limb = 64;

        let rns_base = Rns::<<C as CurveAffine>::Base, Native>::construct(bit_len_limb);
        let rns_scalar = Rns::<<C as CurveAffine>::ScalarExt, Native>::construct(bit_len_limb);

        #[cfg(not(feature = "no_lookup"))]
        let k: u32 = (rns_base.bit_len_lookup + 1) as u32;
        #[cfg(feature = "no_lookup")]
        let k: u32 = 8;

        let x = create_point(a);
        let y = create_point(b);
        let z = create_point(c);

        let circuit = TestEcc::<C, Native> {
            x: x,
            y: y,
            z: z,
            rns_base: rns_base.clone(),
            rns_scalar: rns_scalar.clone(),
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_eq!(prover.verify(), Ok(()));
    }


    #[test]
    fn test_ecc_add_circuit_eq () {
      test_ecc_add_circuit(Some(2), Some(2), Some(4));
    }

    #[test]
    fn test_ecc_add_circuit_neq () {
      test_ecc_add_circuit(Some(2), Some(3), Some(5));
    }

    #[test]
    fn test_ecc_add_circuit_zero_left () {
      test_ecc_add_circuit(None, Some(3), Some(3));
    }
}
