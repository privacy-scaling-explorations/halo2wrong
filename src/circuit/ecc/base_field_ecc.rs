use super::EccConfig;
use crate::circuit::ecc::{AssignedPoint, Point};
use crate::circuit::integer::{IntegerChip, IntegerInstructions};
use crate::rns::{Integer, Rns};
use halo2::arithmetic::{CurveAffine, Field};
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::main_gate::five::main_gate::MainGate;
use halo2arith::{halo2, AssignedCondition, AssignedValue, MainGateInstructions};

pub trait BaseFieldEccInstruction<C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: C, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<(), Error>;

    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: &AssignedPoint<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn select(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        p2: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn select_or_assign(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        p2: C,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn add(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: &AssignedPoint<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C::ScalarExt>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn mul_fix(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: C,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error>;
}

pub struct BaseFieldEccChip<C: CurveAffine> {
    config: EccConfig,
    rns: Rns<C::Base, C::ScalarExt>,
}

impl<C: CurveAffine> BaseFieldEccChip<C> {
    #[allow(unused_variables)]
    fn new(config: EccConfig, rns: Rns<C::Base, C::ScalarExt>) -> Result<Self, Error> {
        unimplemented!();
    }

    fn integer_chip(&self) -> IntegerChip<C::Base, C::ScalarExt> {
        let integer_chip_config = self.config.integer_chip_config();
        IntegerChip::<C::Base, C::ScalarExt>::new(integer_chip_config, self.rns.clone())
    }

    fn main_gate(&self) -> MainGate<C::ScalarExt> {
        MainGate::<_>::new(self.config.main_gate_config.clone())
    }

    #[cfg(feature = "zcash")]
    fn parameter_a(&self) -> Integer<C::Base, C::ScalarExt> {
        self.rns.new(C::a())
    }

    #[cfg(feature = "kzg")]
    fn parameter_a(&self) -> Integer<C::Base, C::ScalarExt> {
        self.rns.new(C::Base::zero())
    }

    fn parameter_b(&self) -> Integer<C::Base, C::ScalarExt> {
        self.rns.new(C::b())
    }

    #[cfg(feature = "zcash")]
    fn is_a_0(&self) -> bool {
        C::a() == C::Base::zero()
    }

    #[cfg(feature = "kzg")]
    fn is_a_0(&self) -> bool {
        true
    }

    fn into_rns_point(&self, point: C) -> Point<C::Base, C::ScalarExt> {
        let coords = point.coordinates();
        if coords.is_some().into() {
            let coords = coords.unwrap();
            let x = self.rns.new(*coords.x());
            let y = self.rns.new(*coords.y());
            Point { x, y, is_identity: false }
        } else {
            Point {
                x: self.rns.zero(),
                y: self.rns.zero(),
                is_identity: true,
            }
        }
    }
}

impl<C: CurveAffine> BaseFieldEccInstruction<C> for BaseFieldEccChip<C> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: C, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.integer_chip();
        let point = self.into_rns_point(point);
        // FIX: This won't help for a prover assigns the infinity
        assert!(!point.is_identity);
        let x = integer_chip.assign_integer(region, Some(point.x).into(), offset)?;
        let y = integer_chip.assign_integer(region, Some(point.y).into(), offset)?;
        let z = self.main_gate().assign_bit(region, &Some(C::ScalarExt::zero()).into(), offset)?;
        Ok(AssignedPoint::new(x, y, z))
    }

    #[allow(unused_variables)]
    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: &AssignedPoint<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let integer_chip = self.integer_chip();
        integer_chip.assert_equal(region, &p0.x, &p1.x, offset)?;
        integer_chip.assert_equal(region, &p0.y, &p1.y, offset)?;
        main_gate.assert_equal(region, p0.z.clone(), p1.z.clone(), offset)?;
        Ok(())
    }

    fn select(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        p2: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let main_gate = self.main_gate();
        let integer_chip = self.integer_chip();
        let x = integer_chip.cond_select(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.cond_select(region, &p1.y, &p2.y, c, offset)?;
        let c: AssignedCondition<C::ScalarExt> = main_gate.cond_select(region, p1.z.clone(), p2.z.clone(), c, offset)?.into();
        Ok(AssignedPoint::new(x, y, c))
    }

    fn select_or_assign(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        p2: C,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let main_gate = self.main_gate();
        let integer_chip = self.integer_chip();
        let p2 = self.into_rns_point(p2);
        let x = integer_chip.cond_select_or_assign(region, &p1.x, &p2.x, c, offset)?;
        let y = integer_chip.cond_select_or_assign(region, &p1.y, &p2.y, c, offset)?;
        let c: AssignedCondition<C::ScalarExt> = main_gate
            .cond_select_or_assign(
                region,
                p1.z.clone(),
                if p2.is_identity { C::ScalarExt::one() } else { C::ScalarExt::zero() },
                c,
                offset,
            )?
            .into();
        Ok(AssignedPoint::new(x, y, c))
    }

    #[allow(unused_variables)]
    fn add(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: &AssignedPoint<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        unimplemented!();
    }

    #[allow(unused_variables)]
    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        unimplemented!();
    }

    #[allow(unused_variables)]
    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C::ScalarExt>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        unimplemented!();
    }

    #[allow(unused_variables)]
    fn mul_fix(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: C,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        unimplemented!();
    }
}
