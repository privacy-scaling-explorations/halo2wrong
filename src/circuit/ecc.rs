use crate::rns::Integer;
use crate::circuit::main_gate::{MainGateConfig};

use super::{AssignedCondition, AssignedInteger, Assigned};
use super::main_gate::{MainGate, MainGateInstructions};
use super::integer::{IntegerConfig, IntegerChip, IntegerInstructions};
use halo2::arithmetic::{FieldExt, CurveAffine};
use halo2::circuit::{Region, Layouter};
use halo2::plonk::Error;
use std::marker::PhantomData;
use crate::NUMBER_OF_LIMBS;

mod base_field_ecc;
mod external_ecc;

// Ecc operation mods
mod add;

/* Emulate CurveAffine point undert field F */
#[derive(Default, Clone, Debug)]
pub struct Point<C: CurveAffine, F: FieldExt> {
    x: Integer<F>,
    y: Integer<F>,
    _marker: PhantomData<C::Base>
}

impl<C: CurveAffine, F: FieldExt> Point<C, F> {
    fn new(x: Integer<F>, y: Integer<F>) -> Self {
        Point { x, y, _marker:PhantomData }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedPoint<C: CurveAffine, F: FieldExt > {
    x: AssignedInteger<F>,
    y: AssignedInteger<F>,
    // indicate whether the poinit is the identity point of curve or not
    z: AssignedCondition<F>,
    _marker: PhantomData<C::Base>
}

impl<C: CurveAffine, F: FieldExt> AssignedPoint<C, F> {
    pub fn new(
        x:AssignedInteger<F>,
        y:AssignedInteger<F>,
        z:AssignedCondition<F>
    ) -> AssignedPoint<C,F> {
        AssignedPoint{ x, y, z, _marker:PhantomData }
    }
    pub fn is_identity(&self) -> AssignedCondition<F> {
        self.z.clone()
    }
}

/// Linear combination term
pub enum Term<C: CurveAffine, F: FieldExt> {
    Assigned(AssignedPoint<C, F>, F),
    Unassigned(Option<Point<C, F>>, F),
}

#[derive(Clone, Debug)]
pub struct EccConfig {
    integer_chip_config: IntegerConfig,
    main_gate_config: MainGateConfig,
}

// we need template arg C to extract curve constants including a and b
pub struct EccChip<C: CurveAffine, F: FieldExt> {
    config: EccConfig,
    integer_chip: IntegerChip<C::Base, F>,
    // We need to assign following integers based on constants of curve C
    a: AssignedInteger<F>,
    b: AssignedInteger<F>,
    identity: AssignedPoint<C, F>,
}


// Generic ecc operations that does not care about whether F equals C::ScalarExt or not
pub trait GenericEccInstruction<External: CurveAffine, N: FieldExt> {
    fn assign_point(&self, region: &mut Region<'_, N>, point: Point<External, N>, offset: &mut usize) -> Result<AssignedPoint<External, N>, Error>;

    fn assert_equal(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<External, N>,
        p1: &AssignedPoint<External, N>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn add(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<External, N>,
        p1: &AssignedPoint<External, N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External, N>, Error>;
}

impl<External: CurveAffine, N: FieldExt> GenericEccInstruction<External, N> for EccChip<External, N> {

    fn assign_point(&self, region: &mut Region<'_, N>, point: Point<External, N>, offset: &mut usize) -> Result<AssignedPoint<External, N>, Error> {
        let x = self.integer_chip.assign_integer(region, Some(point.x.clone()), offset)?.clone();
        let y = self.integer_chip.assign_integer(region, Some(point.y.clone()), offset)?.clone();
        let z = self.main_gate().assign_bit(region, Some(N::zero()), offset)?.clone();
        Ok(AssignedPoint::new(x,y,z))
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<External, N>,
        p1: &AssignedPoint<External, N>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        self.integer_chip.assert_equal(region, &p0.x, &p1.x, offset)?;
        self.integer_chip.assert_equal(region, &p0.y, &p1.y, offset)?;
        main_gate.assert_equal(region, p0.z.clone(), p1.z.clone(), offset)?;
        Ok(())
    }

    fn add(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<External, N>,
        p1: &AssignedPoint<External, N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<External, N>, Error> {
        self._add(region, p0, p1, offset)
    }
}


impl<C: CurveAffine, F: FieldExt> EccChip<C, F> {
    fn new(
        layouter: &mut impl Layouter<F>,
        config: EccConfig,
        integer_chip: IntegerChip<C::Base, F>
    ) -> Result<Self, Error> {
        let main_gate_config = config.main_gate_config.clone();
        let main_gate = MainGate::<F>::new(main_gate_config);

        // Prepare constant_a and constant_b based on curve constants
        let ca = Integer::<F>::from_bytes_le(
                &C::a().to_bytes(),
                NUMBER_OF_LIMBS,
                integer_chip.rns.bit_len_limb
        );
        let cb = Integer::<F>::from_bytes_le(
                &C::b().to_bytes(),
                NUMBER_OF_LIMBS,
                integer_chip.rns.bit_len_limb
        );

        let zero = integer_chip.rns.new_from_big(0u32.into());

        let (a, b, identity) = {
            let mut a: Option<AssignedInteger<F>> = None;
            let mut b: Option<AssignedInteger<F>> = None;
            let mut identity: Option<AssignedPoint<C, F>> = None;
            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    a = Some (integer_chip.assign_integer(&mut region, Some(ca.clone()), offset)?);
                    b = Some (integer_chip.assign_integer(&mut region, Some(cb.clone()), offset)?);
                    let z = integer_chip.assign_integer(&mut region, Some(zero.clone()), offset)?;
                    let c = main_gate.assign_bit(&mut region, Some(F::one()), offset)?;
                    identity = Some(AssignedPoint::new(z.clone(), z, c));
                    Ok(())
                },
            )?;
            (a.unwrap(), b.unwrap(), identity.unwrap())
        };

        Ok(EccChip {config, integer_chip, a, b, identity})
    }

    fn select(
        &self,
        region: &mut Region<'_, F>,
        c: &AssignedCondition<F>,
        p1: &AssignedPoint<C,F>,
        p2: &AssignedPoint<C,F>,
        offset: &mut usize
    ) -> Result<AssignedPoint<C,F>, Error> {
        let main_gate = self.main_gate();
        let x = self.integer_chip.cond_select(region, &p1.x, &p2.x, c, offset)?;
        let y = self.integer_chip.cond_select(region, &p1.y, &p2.y, c, offset)?;
        let c = main_gate.cond_select(region, p1.z.clone(), p2.z.clone(), c, offset)?;
        let c = AssignedCondition::new(c.cell(), c.value());
        Ok(AssignedPoint::new(x, y, c))
    }

    fn main_gate(&self) -> MainGate<F> {
        let main_gate_config = self.config.main_gate_config.clone();
        MainGate::<F>::new(main_gate_config)
    }
}

#[cfg(test)]
mod tests {
    use halo2::arithmetic::{CurveAffine, FieldExt, Field};
    use super::{IntegerChip, IntegerConfig, IntegerInstructions};
    use crate::circuit::AssignedValue;
    use crate::circuit::main_gate::{MainGate, MainGateConfig, MainGateInstructions};
    use crate::circuit::range::{RangeChip, RangeInstructions, RangeConfig};
    use crate::circuit::ecc::{Point, EccChip, GenericEccInstruction, EccConfig};
    use crate::rns::{Integer, Limb, Rns};
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use group::{Curve, prime::PrimeCurveAffine};
    use crate::NUMBER_OF_LIMBS;

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
        x: Option<Point<C, N>>,
        y: Option<Point<C, N>>,
        z: Option<Point<C, N>>,
        rns: Rns<C::Base, N>,
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
            let integer_chip = IntegerChip::<C::Base, N>::new(config.integer_chip_config.clone(), self.rns.clone());

            let ecc_chip = EccChip::<C, N>::new(&mut layouter, config.ecc_chip_config, integer_chip)?;
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


            let range_chip = RangeChip::<N>::new(config.range_config, self.rns.bit_len_lookup);
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_limb_range_table(&mut layouter)?;
            #[cfg(not(feature = "no_lookup"))]
            range_chip.load_overflow_range_tables(&mut layouter)?;

            Ok(())
        }
    }

    fn create_point(a:Option<u64>) -> Option<Point<C, Native>>{
        let bit_len_limb = 64;
        a.map(|a| {
            let ma = <C as CurveAffine>::ScalarExt::from_raw([a,0,0,0]);
            let generator = <C as PrimeCurveAffine> :: generator();
            let pa = generator * ma;
            let a = pa
                .to_affine()
                .coordinates()
                .unwrap();
            let x = Integer::<<C as CurveAffine>::ScalarExt>::from_bytes_le(
                &a.x().to_bytes(), NUMBER_OF_LIMBS, bit_len_limb);
            let y = Integer::<<C as CurveAffine>::ScalarExt>::from_bytes_le(
                &a.y().to_bytes(), NUMBER_OF_LIMBS, bit_len_limb);
            Point::new(x, y)
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
            rns: rns_base.clone(),
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
