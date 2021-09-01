use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Chip, Layouter, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};
use halo2::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct MainGateConfig {
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

pub struct MainGate<F: FieldExt> {
    pub config: MainGateConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MainGate<F> {
    pub fn new(config: MainGateConfig) -> Self {
        MainGate {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> MainGateConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();

        let sa = meta.fixed_column();
        let sb = meta.fixed_column();
        let sc = meta.fixed_column();
        let sd = meta.fixed_column();
        let sd_next = meta.fixed_column();
        let sm = meta.fixed_column();
        let s_constant = meta.fixed_column();

        meta.enable_equality(a.into());
        meta.enable_equality(b.into());
        meta.enable_equality(c.into());
        meta.enable_equality(d.into());

        // main gate

        meta.create_gate("main_gate", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let d_next = meta.query_advice(d, Rotation::next());
            let d = meta.query_advice(d, Rotation::cur());

            let sa = meta.query_fixed(sa, Rotation::cur());
            let sb = meta.query_fixed(sb, Rotation::cur());
            let sc = meta.query_fixed(sc, Rotation::cur());
            let sd = meta.query_fixed(sd, Rotation::cur());
            let sd_next = meta.query_fixed(sd_next, Rotation::cur());
            let sm = meta.query_fixed(sm, Rotation::cur());
            let s_constant = meta.query_fixed(s_constant, Rotation::cur());

            vec![
                a.clone() * sa + b.clone() * sb + a * b * sm - (c * sc)
                    + sd * d
                    + sd_next * d_next
                    + s_constant,
            ]
        });

        MainGateConfig {
            a,
            b,
            c,
            d,
            sa,
            sb,
            sc,
            sd,
            sd_next,
            s_constant,
            sm,
        }
    }
}

pub trait MainGateInstructions<F: FieldExt> {
    fn add(
        &self,
        region: &mut Region<'_, F>,
        input: Option<(F, F, F)>,
    ) -> Result<(Cell, Cell, Cell), Error>;

    fn mul(
        &self,
        region: &mut Region<'_, F>,
        input: Option<(F, F, F)>,
    ) -> Result<(Cell, Cell, Cell), Error>;

    fn add_mul_constant(
        &self,
        region: &mut Region<'_, F>,
        input: Option<(F, F, F, F)>,
    ) -> Result<(Cell, Cell, Cell), Error>;
}

impl<F: FieldExt> MainGateInstructions<F> for MainGate<F> {
    fn add(
        &self,
        region: &mut Region<'_, F>,

        input: Option<(F, F, F)>,
    ) -> Result<(Cell, Cell, Cell), Error> {
        let input = input.ok_or(Error::SynthesisError)?;

        let lhs = region.assign_advice(|| "lhs", self.config.a, 0, || Ok(input.0))?;
        let rhs = region.assign_advice(|| "rhs", self.config.b, 0, || Ok(input.1))?;
        let out = region.assign_advice(|| "out", self.config.c, 0, || Ok(input.2))?;

        region.assign_fixed(|| "a", self.config.sa, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "b", self.config.sb, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "c", self.config.sc, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "d", self.config.sd, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "a * b", self.config.sm, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(F::zero()))?;

        Ok((lhs, rhs, out))
    }

    fn mul(
        &self,
        region: &mut Region<'_, F>,
        input: Option<(F, F, F)>,
    ) -> Result<(Cell, Cell, Cell), Error> {
        let input = input.ok_or(Error::SynthesisError)?;

        let lhs = region.assign_advice(|| "lhs", self.config.a, 0, || Ok(input.0))?;
        let rhs = region.assign_advice(|| "rhs", self.config.b, 0, || Ok(input.1))?;
        let out = region.assign_advice(|| "out", self.config.c, 0, || Ok(input.2))?;

        region.assign_fixed(|| "a", self.config.sa, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "b", self.config.sb, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "c", self.config.sc, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "d", self.config.sd, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "a * b", self.config.sm, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(F::zero()))?;

        Ok((lhs, rhs, out))
    }

    fn add_mul_constant(
        &self,
        region: &mut Region<'_, F>,
        input: Option<(F, F, F, F)>,
    ) -> Result<(Cell, Cell, Cell), Error> {
        let input = input.ok_or(Error::SynthesisError)?;

        // a + b * constant = c

        let lhs = region.assign_advice(|| "a", self.config.a, 0, || Ok(input.0))?;
        let rhs = region.assign_advice(|| "b", self.config.b, 0, || Ok(input.1))?;
        let out = region.assign_advice(|| "c", self.config.c, 0, || Ok(input.3))?;

        region.assign_fixed(|| "a", self.config.sa, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "b", self.config.sb, 0, || Ok(input.2))?;
        region.assign_fixed(|| "c", self.config.sc, 0, || Ok(F::one()))?;
        region.assign_fixed(|| "d", self.config.sd, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "d_next", self.config.sd_next, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "a * b", self.config.sm, 0, || Ok(F::zero()))?;
        region.assign_fixed(|| "constant", self.config.s_constant, 0, || Ok(F::zero()))?;

        Ok((lhs, rhs, out))
    }
}
