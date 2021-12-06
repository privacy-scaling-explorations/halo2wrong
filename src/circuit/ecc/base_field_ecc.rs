use crate::circuit::integer::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{MainGate, MainGateInstructions};
use crate::circuit::{AssignedCondition, AssignedInteger, AssignedValue};
use crate::circuit::ecc::general_ecc::{GeneralEccChip, GeneralEccInstruction};
use crate::rns::{Integer, Rns};
use halo2::arithmetic::{CurveAffine, Field};
use halo2::circuit::{Region, Layouter};
use halo2::plonk::Error;

use super::EccConfig;

use crate::circuit::ecc::{Point, AssignedPoint};

pub trait BaseFieldEccInstruction<C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: C, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<(), Error>;

    fn assert_equal(&self, region: &mut Region<'_, C::ScalarExt>, p0: &AssignedPoint<C::ScalarExt>, p1: &AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<(), Error>;

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

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: &AssignedPoint<C::ScalarExt>, p1: &AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C::ScalarExt>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error>;

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error>;
}

pub struct BaseFieldEccChip<C: CurveAffine> {
    config: EccConfig,
    rns: Rns<C::Base, C::ScalarExt>,
}

impl<C: CurveAffine> BaseFieldEccChip<C> {
    fn from_general(g: GeneralEccChip<C, C::ScalarExt>) -> Self {
        Self {
            config: g.config,
            rns: g.rns_base_field,
        }
    }
    fn as_general(&self) -> GeneralEccChip<C, C::ScalarExt> {
        GeneralEccChip {
            config: self.config.clone(),
            rns_base_field: self.rns.clone(),
            rns_scalar_field: Rns::<C::ScalarExt, C::ScalarExt>::construct(self.rns.bit_len_limb),
        }
    }
    fn new(
        config: EccConfig,
        rns: Rns<C::Base, C::ScalarExt>,
    ) -> Result<Self, Error> {
        let rns_ext = Rns::<C::ScalarExt, C::ScalarExt>::construct(rns.bit_len_limb);
        let general_chip = GeneralEccChip::new(config, rns, rns_ext)?;
        Ok(Self::from_general(general_chip))
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
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: C, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let integer_chip = self.integer_chip();
        let point = self.into_rns_point(point);
        // FIX: This won't help for a prover assigns the infinity
        assert!(!point.is_identity);
        let x = integer_chip.assign_integer(region, Some(point.x), offset)?;
        let y = integer_chip.assign_integer(region, Some(point.y), offset)?;
        let z = self.main_gate().assign_bit(region, Some(C::ScalarExt::zero()), offset)?;
        Ok(AssignedPoint::new(x, y, z))
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(&self, region: &mut Region<'_, C::ScalarExt>, p0: &AssignedPoint<C::ScalarExt>, p1: &AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<(), Error> {
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

    fn add(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: &AssignedPoint<C::ScalarExt>,
        p1: &AssignedPoint<C::ScalarExt>,
        offset: &mut usize
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        // Addition does not involve any scalar operation thus is the same as
        // it is in generic ecc.
        self.as_general().add(region, p0, p1, offset)
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C::ScalarExt>,
        e: AssignedValue<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        unimplemented!();
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: C, e: AssignedValue<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        unimplemented!();
    }
}
