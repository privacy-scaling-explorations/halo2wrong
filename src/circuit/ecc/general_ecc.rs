use super::EccConfig;
use crate::circuit::integer::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{MainGate, MainGateInstructions};
use crate::circuit::{AssignedCondition, AssignedInteger};
use crate::rns::{Integer, Rns};
use halo2::arithmetic::{CurveAffine, Field, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use std::marker::PhantomData;

#[derive(Default, Clone, Debug)]
pub struct Point<N: FieldExt> {
    x: Integer<N>,
    y: Integer<N>,
    is_identity: bool,
}

#[derive(Clone, Debug)]
pub struct AssignedPoint<Emulated: CurveAffine, N: FieldExt> {
    x: AssignedInteger<N>,
    y: AssignedInteger<N>,
    // indicate whether the poinit is the identity point of curve or not
    z: AssignedCondition<N>,
    _marker: PhantomData<Emulated>,
}

impl<C: CurveAffine, F: FieldExt> AssignedPoint<C, F> {
    pub fn new(x: AssignedInteger<F>, y: AssignedInteger<F>, z: AssignedCondition<F>) -> AssignedPoint<C, F> {
        AssignedPoint { x, y, z, _marker: PhantomData }
    }

    pub fn is_identity(&self) -> AssignedCondition<F> {
        self.z.clone()
    }
}

pub trait GeneralEccInstruction<Emulated: CurveAffine, N: FieldExt> {
    fn assign_point(&self, region: &mut Region<'_, N>, point: Emulated, offset: &mut usize) -> Result<AssignedPoint<Emulated, N>, Error>;

    fn assert_is_on_curve(&self, region: &mut Region<'_, N>, point: &AssignedPoint<Emulated, N>, offset: &mut usize) -> Result<(), Error>;

    fn select(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<Emulated, N>,
        p2: &AssignedPoint<Emulated, N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error>;

    fn select_or_assign(
        &self,
        region: &mut Region<'_, N>,
        c: &AssignedCondition<N>,
        p1: &AssignedPoint<Emulated, N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error>;

    fn assert_equal(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<Emulated, N>,
        p1: &AssignedPoint<Emulated, N>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn add(
        &self,
        region: &mut Region<'_, N>,
        p0: &AssignedPoint<Emulated, N>,
        p1: &AssignedPoint<Emulated, N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error>;

    fn double(&self, region: &mut Region<'_, N>, p: AssignedPoint<Emulated, N>, offset: &mut usize) -> Result<AssignedPoint<Emulated, N>, Error>;

    fn mul_var(
        &self,
        region: &mut Region<'_, N>,
        p: AssignedPoint<Emulated, N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error>;

    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error>;
}

pub struct GeneralEccChip<Emulated: CurveAffine, F: FieldExt> {
    config: EccConfig,
    rns_base_field: Rns<Emulated::Base, F>,
    rns_scalar_field: Rns<Emulated::Scalar, F>,
}

impl<Emulated: CurveAffine, N: FieldExt> GeneralEccChip<Emulated, N> {
    fn new(config: EccConfig, rns_base_field: Rns<Emulated::Base, N>, rns_scalar_field: Rns<Emulated::ScalarExt, N>) -> Self {
        Self {
            config,
            rns_base_field,
            rns_scalar_field,
        }
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
    fn assert_is_on_curve(&self, region: &mut Region<'_, N>, point: &AssignedPoint<Emulated, N>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assign_point(&self, region: &mut Region<'_, N>, point: Emulated, offset: &mut usize) -> Result<AssignedPoint<Emulated, N>, Error> {
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
        p0: &AssignedPoint<Emulated, N>,
        p1: &AssignedPoint<Emulated, N>,
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
        p1: &AssignedPoint<Emulated, N>,
        p2: &AssignedPoint<Emulated, N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error> {
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
        p1: &AssignedPoint<Emulated, N>,
        p2: Emulated,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error> {
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
        p0: &AssignedPoint<Emulated, N>,
        p1: &AssignedPoint<Emulated, N>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, N>, p: AssignedPoint<Emulated, N>, offset: &mut usize) -> Result<AssignedPoint<Emulated, N>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, N>,
        p: AssignedPoint<Emulated, N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error> {
        unimplemented!();
    }

    fn mul_fix(
        &self,
        region: &mut Region<'_, N>,
        p: Point<N>,
        e: AssignedInteger<Emulated::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<Emulated, N>, Error> {
        unimplemented!();
    }
}
