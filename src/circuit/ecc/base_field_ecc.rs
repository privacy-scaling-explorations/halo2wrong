use crate::circuit::integer::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{MainGate, MainGateInstructions};
use crate::circuit::{AssignedCondition, AssignedInteger, AssignedValue};
use crate::rns::{Integer, Rns};
use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;

use super::EccConfig;

#[derive(Default, Clone, Debug)]
struct Point<N: FieldExt> {
    x: Integer<N>,
    y: Integer<N>,
    is_identity: bool,
}

#[derive(Clone, Debug)]
pub struct AssignedPoint<C: CurveAffine> {
    x: AssignedInteger<C::ScalarExt>,
    y: AssignedInteger<C::ScalarExt>,
    // indicate whether the poinit is the identity point of curve or not
    z: AssignedCondition<C::ScalarExt>,
}

impl<C: CurveAffine> AssignedPoint<C> {
    pub fn new(x: AssignedInteger<C::ScalarExt>, y: AssignedInteger<C::ScalarExt>, z: AssignedCondition<C::ScalarExt>) -> AssignedPoint<C> {
        AssignedPoint { x, y, z }
    }

    pub fn is_identity(&self) -> AssignedCondition<C::ScalarExt> {
        self.z.clone()
    }
}

pub trait BaseFieldEccInstruction<C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: C, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error>;

    fn assert_equal(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error>;

    fn select(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C>,
        p2: &AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;

    fn select_or_assign(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        c: &AssignedCondition<C::ScalarExt>,
        p1: &AssignedPoint<C>,
        p2: C,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
}

pub struct BaseFieldEccChip<C: CurveAffine> {
    config: EccConfig,
    rns: Rns<C::Base, C::ScalarExt>,
}

impl<C: CurveAffine> BaseFieldEccChip<C> {
    fn new(config: EccConfig, rns: Rns<C::Base, C::ScalarExt>) -> Self {
        Self { config, rns }
    }

    fn integer_chip(&self) -> IntegerChip<C::Base, C::ScalarExt> {
        IntegerChip::<C::Base, C::ScalarExt>::new(self.config.integer_chip_config.clone(), self.rns.clone())
    }

    fn main_gate(&self) -> MainGate<C::ScalarExt> {
        MainGate::<_>::new(self.config.main_gate_config.clone())
    }

    fn parameter_a(&self) -> Integer<C::ScalarExt> {
        self.rns.new(C::a())
    }

    fn parameter_b(&self) -> Integer<C::ScalarExt> {
        self.rns.new(C::b())
    }

    fn is_a_0(&self) -> bool {
        C::a() == C::Base::zero()
    }

    fn into_rns_point(&self, point: C) -> Point<C::ScalarExt> {
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
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: C, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        let integer_chip = self.integer_chip();
        let point = self.into_rns_point(point);
        // FIX: This won't help for a prover assigns the infinity
        assert!(!point.is_identity);
        let x = integer_chip.assign_integer(region, Some(point.x), offset)?;
        let y = integer_chip.assign_integer(region, Some(point.y), offset)?;
        let z = self.main_gate().assign_bit(region, Some(C::ScalarExt::zero()), offset)?;
        Ok(AssignedPoint::new(x, y, z))
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
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
        p1: &AssignedPoint<C>,
        p2: &AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
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
        p1: &AssignedPoint<C>,
        p2: C,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
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

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }
}
