use crate::circuit::main_gate::{MainGate, MainGateConfig, MainGateInstructions};
use crate::circuit::range::{RangeChip, RangeConfig, RangeInstructions};
use crate::rns::{Integer, Quotient, Rns};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};
use std::marker::PhantomData;

mod add;
mod mul;
mod reduce;
mod sub;

#[derive(Clone, Debug)]
pub struct IntegerConfig {
    range_config: RangeConfig,

    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub d: Column<Advice>,

    pub sa: Column<Fixed>,
    pub sb: Column<Fixed>,
    pub sc: Column<Fixed>,
    pub sd: Column<Fixed>,
    pub sd_next: Column<Fixed>,
    pub sm: Column<Fixed>,
    pub s_constant: Column<Fixed>,
}

pub struct IntegerChip<Wrong: FieldExt, Native: FieldExt> {
    config: IntegerConfig,
    rns: Rns<Wrong, Native>,
}

// impl<W: FieldExt, N: FieldExt> Chip<N> for IntegerChip<W, N> {
//     type Config = IntegerConfig;
//     type Loaded = ();
//     fn config(&self) -> &Self::Config {
//         &self.config
//     }
//     fn loaded(&self) -> &Self::Loaded {
//         &()
//     }
// }

trait IntegerInstructions<F: FieldExt> {
    fn add(&self, region: &mut Region<'_, F>, a: Option<&mut Integer<F>>, b: Option<&mut Integer<F>>) -> Result<Integer<F>, Error>;
    fn mul(&self, region: &mut Region<'_, F>, a: Option<&mut Integer<F>>, b: Option<&mut Integer<F>>) -> Result<Integer<F>, Error>;
    fn sub(&self, region: &mut Region<'_, F>, a: Option<&mut Integer<F>>, b: Option<&mut Integer<F>>) -> Result<Integer<F>, Error>;
    fn reduce(&self, region: &mut Region<'_, F>, a: Option<&Integer<F>>) -> Result<Integer<F>, Error>;
}

impl<W: FieldExt, N: FieldExt> IntegerInstructions<N> for IntegerChip<W, N> {
    fn add(&self, region: &mut Region<'_, N>, a: Option<&mut Integer<N>>, b: Option<&mut Integer<N>>) -> Result<Integer<N>, Error> {
        self._add(region, a, b)
    }
    fn reduce(&self, region: &mut Region<'_, N>, a: Option<&Integer<N>>) -> Result<Integer<N>, Error> {
        self._reduce(region, a)
    }
    fn sub(&self, region: &mut Region<'_, N>, a: Option<&mut Integer<N>>, b: Option<&mut Integer<N>>) -> Result<Integer<N>, Error> {
        self._sub(region, a, b)
    }
    fn mul(&self, region: &mut Region<'_, N>, a: Option<&mut Integer<N>>, b: Option<&mut Integer<N>>) -> Result<Integer<N>, Error> {
        self._mul(region, a, b)
    }
}

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub fn new(config: IntegerConfig, rns: Rns<W, N>) -> Self {
        IntegerChip { config, rns }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<N>,
        range_config: RangeConfig,
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,
        sa: Column<Fixed>,
        sb: Column<Fixed>,
        sc: Column<Fixed>,
        sd: Column<Fixed>,
        sd_next: Column<Fixed>,
        sm: Column<Fixed>,
        s_constant: Column<Fixed>,
    ) -> IntegerConfig {
        IntegerConfig {
            range_config,
            a,
            b,
            c,
            d,
            sa,
            sb,
            sc,
            sd,
            sd_next,
            sm,
            s_constant,
        }
    }

    fn range_chip(&self) -> RangeChip<N> {
        RangeChip::<N>::new(self.config.range_config.clone())
    }
}
