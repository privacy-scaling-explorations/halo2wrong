use crate::circuit::main_gate::{MainGate, MainGateConfig, MainGateInstructions};
use crate::circuit::range::{RangeChip, RangeConfig, RangeInstructions};
use crate::int::{Integer, BIT_LEN_LOOKUP_LIMB};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct IntegerConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

pub struct IntegerChip<F: FieldExt> {
    config: IntegerConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for IntegerChip<F> {
    type Config = IntegerConfig;
    type Loaded = ();
    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

trait IntegerInstructions<'a, Wrong: FieldExt, Native: FieldExt>: Chip<Native> {
    fn assign_integer(
        &self,
        region: &mut Region<'_, Native>,
        integer: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<(), Error>;

    fn add(
        &self,
        region: &mut Region<'_, Native>,
        a: Option<&mut Integer<'a, Wrong, Native>>,
        b: Option<&mut Integer<'a, Wrong, Native>>,
    ) -> Result<Integer<'a, Wrong, Native>, Error>;

    fn reduce(
        &self,
        region: &mut Region<'_, Native>,
        a: Option<&Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error>;
}

impl<'a, Wrong: FieldExt, Native: FieldExt> IntegerInstructions<'a, Wrong, Native>
    for IntegerChip<Native>
{
    fn assign_integer(
        &self,
        region: &mut Region<'_, Native>,
        integer: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<(), Error> {
        let range_chip = self.range_chip();

        let integer = integer.ok_or(Error::SynthesisError)?;
        for limb in integer.decomposed.limbs.iter_mut() {
            range_chip.range_limb(region, Some(limb)).unwrap();
        }
        Ok(())
    }

    fn add(
        &self,
        region: &mut Region<'_, Native>,
        a: Option<&mut Integer<'a, Wrong, Native>>,
        b: Option<&mut Integer<'a, Wrong, Native>>,
    ) -> Result<Integer<'a, Wrong, Native>, Error> {
        let a = a.ok_or(Error::SynthesisError)?;
        let b = b.ok_or(Error::SynthesisError)?;
        let mut c: Integer<_, _> = a.add(b).clone();
        let main_gate = self.main_gate();

        for ((a, b), c) in a
            .decomposed
            .limbs
            .iter_mut()
            .zip(b.decomposed.limbs.iter_mut())
            .zip(c.decomposed.limbs.iter_mut())
        {
            // expect operands are assigned
            let a_cell = a.cell.ok_or(Error::SynthesisError)?;
            let b_cell = b.cell.ok_or(Error::SynthesisError)?;

            let (a_new_cell, b_new_cell, c_cell) =
                main_gate.add(region, Some((a.fe(), b.fe(), c.fe())))?;

            // cycle equal limbs
            region.constrain_equal(a_cell, a_new_cell)?;
            region.constrain_equal(b_cell, b_new_cell)?;

            // update cells of operands
            a.cell = Some(a_new_cell);
            b.cell = Some(b_new_cell);

            // assing cell to the result
            c.cell = Some(c_cell)
        }

        Ok(c)
    }

    fn reduce(
        &self,
        region: &mut Region<'_, Native>,
        a: Option<&Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error> {
        unimplemented!();
    }
}

impl<F: FieldExt> IntegerChip<F> {
    pub fn new(config: IntegerConfig) -> Self {
        IntegerChip {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    ) -> IntegerConfig {
        IntegerConfig {
            main_gate_config,
            range_config,
        }
    }

    fn range_chip(&self) -> RangeChip<F> {
        RangeChip::<F>::new(self.config.range_config.clone())
    }

    fn main_gate(&self) -> MainGate<F> {
        MainGate::<F>::new(self.config.main_gate_config.clone())
    }
}
