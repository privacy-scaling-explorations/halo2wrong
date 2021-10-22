use super::{AssignedBit, AssignedCondition, AssignedValue};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};
use halo2::poly::Rotation;
use std::marker::PhantomData;

pub enum MainGateColumn {
    A = 0,
    B,
    C,
    D,
}

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
    pub s_mul: Column<Fixed>,
    pub s_constant: Column<Fixed>,
}

pub struct MainGate<F: FieldExt> {
    pub config: MainGateConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MainGate<F> {
    pub fn width(&self) -> usize {
        4
    }

    fn advice_columns(&self) -> Vec<Column<Advice>> {
        vec![self.config.a, self.config.b, self.config.c, self.config.d]
    }

    fn fixed_columns(&self) -> Vec<Column<Fixed>> {
        vec![self.config.sa, self.config.sb, self.config.sc, self.config.sd]
    }
}

#[derive(Clone, Debug)]
pub enum CombinationOption<F: FieldExt> {
    SingleLiner,
    CombineToNext(F),
}

pub enum AssignedCombinationTerm<'a, F: FieldExt> {
    Assigned(&'a mut AssignedValue<F>, F),
    Zero,
}

impl<'a, F: FieldExt> AssignedCombinationTerm<'a, F> {
    fn resolve(&self) -> CombinationTerm<F> {
        match self {
            Self::Assigned(assigned, base) => CombinationTerm::Value(assigned.value, *base),
            Self::Zero => CombinationTerm::Zero,
        }
    }

    fn cycle_cell(self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        match self {
            Self::Assigned(assigned, _) => assigned.cycle_cell(region, new_cell),
            _ => Ok(()),
        }
    }
}

pub enum CombinationTerm<F: FieldExt> {
    Value(Option<F>, F),
    Zero,
}

impl<F: FieldExt> CombinationTerm<F> {
    fn resolve(self) -> (Option<F>, F) {
        match self {
            Self::Value(coeff, base) => (coeff, base),
            Self::Zero => (Some(F::zero()), F::zero()),
        }
    }
}

// impl<F::FieldExt> CombinationTerm<F>{

// }

pub trait MainGateInstructions<F: FieldExt> {
    fn assign_value(&self, region: &mut Region<'_, F>, value: Option<F>, column: MainGateColumn, offset: usize) -> Result<AssignedValue<F>, Error>;

    fn assign_bit(&self, region: &mut Region<'_, F>, value: Option<F>, offset: &mut usize) -> Result<AssignedBit<F>, Error>;

    fn cond_swap(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        cond: &mut AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn assert_add(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        c: &mut AssignedValue<F>,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn assert_add_with_aux(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        c: &mut AssignedValue<F>,
        aux: F,
        offset: &mut usize,
    ) -> Result<(), Error>;

    fn cycle_to(&self, region: &mut Region<'_, F>, input: &mut AssignedValue<F>, column: MainGateColumn, offset: usize) -> Result<(), Error>;

    fn no_operation(&self, region: &mut Region<'_, F>, offset: &mut usize) -> Result<(), Error>;

    fn combine_assigned(
        &self,
        region: &mut Region<'_, F>,
        term_0: AssignedCombinationTerm<F>,
        term_1: AssignedCombinationTerm<F>,
        term_2: AssignedCombinationTerm<F>,
        term_3: AssignedCombinationTerm<F>,
        constant_aux: F,
        offset: &mut usize,
        options: CombinationOption<F>,
    ) -> Result<(), Error>;

    fn combine(
        &self,
        region: &mut Region<'_, F>,
        c_0: CombinationTerm<F>,
        c_1: CombinationTerm<F>,
        c_2: CombinationTerm<F>,
        c_3: CombinationTerm<F>,
        constant_aux: F,
        offset: &mut usize,
        options: CombinationOption<F>,
    ) -> Result<(Cell, Cell, Cell, Cell), Error>;
}

impl<F: FieldExt> MainGateInstructions<F> for MainGate<F> {
    fn assert_add_with_aux(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        c: &mut AssignedValue<F>,
        aux: F,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let a_new_cell = region.assign_advice(|| "a", self.config.a, *offset, || a.value())?;
        let b_new_cell = region.assign_advice(|| "b", self.config.b, *offset, || b.value())?;
        let c_new_cell = region.assign_advice(|| "c", self.config.c, *offset, || c.value())?;

        region.assign_fixed(|| "a", self.config.sa, *offset, || Ok(F::one()))?;
        region.assign_fixed(|| "b", self.config.sb, *offset, || Ok(F::one()))?;
        region.assign_fixed(|| "c", self.config.sc, *offset, || Ok(-F::one()))?;

        region.assign_fixed(|| "constant", self.config.s_constant, *offset, || Ok(aux))?;

        region.assign_fixed(|| "d", self.config.sd, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "d_next", self.config.sd_next, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "a * b", self.config.s_mul, *offset, || Ok(F::zero()))?;

        a.cycle_cell(region, a_new_cell)?;
        b.cycle_cell(region, b_new_cell)?;
        c.cycle_cell(region, c_new_cell)?;

        Ok(())
    }
    fn assert_add(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        c: &mut AssignedValue<F>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        self.assert_add_with_aux(region, a, b, c, F::zero(), offset)
    }

    fn cond_swap(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        cond: &mut AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let diff = a.value.map(|a| a - b.value.unwrap());
        let res = a.value.map(|a| {
            let b = b.value.unwrap();
            let cond = cond.bool_value.unwrap();
            if cond {
                a
            } else {
                b
            }
        });

        let mut offset = 0;

        let a_new_cell = region.assign_advice(|| "a", self.config.a, offset, || Ok(a.value.ok_or(Error::SynthesisError)?))?;
        let b_new_cell_0 = region.assign_advice(|| "b", self.config.b, offset, || Ok(b.value.ok_or(Error::SynthesisError)?))?;
        let _ = region.assign_advice(|| "c", self.config.c, offset, || Ok(F::zero()))?;
        let diff_cell = region.assign_advice(|| "d", self.config.d, offset, || Ok(diff.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "sa", self.config.sa, offset, || Ok(F::one()))?;
        region.assign_fixed(|| "sb", self.config.sb, offset, || Ok(-F::one()))?;
        region.assign_fixed(|| "sd", self.config.sd, offset, || Ok(F::one()))?;

        region.assign_fixed(|| "sc", self.config.sc, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "s_mul", self.config.s_mul, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd_next", self.config.sd_next, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(F::zero()))?;

        a.cycle_cell(region, a_new_cell)?;
        b.cycle_cell(region, b_new_cell_0)?;

        offset += 1;

        let diff_new_cell = region.assign_advice(|| "a", self.config.a, offset, || Ok(diff.ok_or(Error::SynthesisError)?))?;
        let cond_new_cell = region.assign_advice(|| "b", self.config.b, offset, || Ok(cond.value().ok_or(Error::SynthesisError)?))?;
        let b_new_cell_1 = region.assign_advice(|| "c", self.config.c, offset, || Ok(b.value.ok_or(Error::SynthesisError)?))?;
        let res_cell = region.assign_advice(|| "d", self.config.d, offset, || Ok(res.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "s_mul", self.config.s_mul, offset, || Ok(F::one()))?;
        region.assign_fixed(|| "sc", self.config.sd, offset, || Ok(F::one()))?;
        region.assign_fixed(|| "sd", self.config.sd, offset, || Ok(-F::one()))?;

        region.assign_fixed(|| "sa", self.config.sa, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sb", self.config.sb, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd_next", self.config.sd_next, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(F::zero()))?;

        region.constrain_equal(diff_cell, diff_new_cell)?;
        region.constrain_equal(b_new_cell_0, b_new_cell_1)?;
        region.constrain_equal(cond.cell, cond_new_cell)?;

        cond.cycle_cell(region, cond_new_cell)?;
        a.cycle_cell(region, a_new_cell)?;
        b.cycle_cell(region, b_new_cell_1)?;

        let res = AssignedValue::new(res_cell, res);

        Ok(res)
    }

    fn assign_bit(&self, region: &mut Region<'_, F>, value: Option<F>, offset: &mut usize) -> Result<AssignedBit<F>, Error> {
        // val * val - val  = 0

        // Layout:
        // | A   | B   | C   | D |
        // | --- | --- | --- | - |
        // | val | val | val | - |

        let cell_0 = region.assign_advice(|| "a", self.config.a, *offset, || Ok(value.ok_or(Error::SynthesisError)?))?;
        let cell_1 = region.assign_advice(|| "b", self.config.b, *offset, || Ok(value.ok_or(Error::SynthesisError)?))?;
        let cell_2 = region.assign_advice(|| "c", self.config.c, *offset, || Ok(value.ok_or(Error::SynthesisError)?))?;
        let _ = region.assign_advice(|| "d", self.config.d, *offset, || Ok(F::zero()))?;

        region.assign_fixed(|| "s_mul", self.config.s_mul, *offset, || Ok(F::one()))?;
        region.assign_fixed(|| "sc", self.config.sc, *offset, || Ok(-F::one()))?;

        region.assign_fixed(|| "sa", self.config.sa, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sb", self.config.sb, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd", self.config.sd, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd_next", self.config.sd_next, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, *offset, || Ok(F::zero()))?;

        region.constrain_equal(cell_0, cell_1)?;
        region.constrain_equal(cell_1, cell_2)?;

        *offset = *offset + 1;

        Ok(AssignedBit::<F>::new(cell_2, value))
    }

    fn combine_assigned(
        &self,
        region: &mut Region<'_, F>,
        term_0: AssignedCombinationTerm<F>,
        term_1: AssignedCombinationTerm<F>,
        term_2: AssignedCombinationTerm<F>,
        term_3: AssignedCombinationTerm<F>,
        constant_aux: F,
        offset: &mut usize,
        options: CombinationOption<F>,
    ) -> Result<(), Error> {
        let (cell_0, cell_1, cell_2, cell_3) = self.combine(
            region,
            term_0.resolve(),
            term_1.resolve(),
            term_2.resolve(),
            term_3.resolve(),
            constant_aux,
            offset,
            options,
        )?;
        term_0.cycle_cell(region, cell_0)?;
        term_1.cycle_cell(region, cell_1)?;
        term_2.cycle_cell(region, cell_2)?;
        term_3.cycle_cell(region, cell_3)?;
        Ok(())
    }

    fn combine(
        &self,
        region: &mut Region<'_, F>,
        term_0: CombinationTerm<F>,
        term_1: CombinationTerm<F>,
        term_2: CombinationTerm<F>,
        term_3: CombinationTerm<F>,
        constant_aux: F,
        offset: &mut usize,
        option: CombinationOption<F>,
    ) -> Result<(Cell, Cell, Cell, Cell), Error> {
        let (c_0, u_0) = term_0.resolve();
        let (c_1, u_1) = term_1.resolve();
        let (c_2, u_2) = term_2.resolve();
        let (c_3, u_3) = term_3.resolve();

        let cell_0 = region.assign_advice(|| "coeff_0", self.config.a, *offset, || Ok(c_0.ok_or(Error::SynthesisError)?))?;
        let cell_1 = region.assign_advice(|| "coeff_1", self.config.b, *offset, || Ok(c_1.ok_or(Error::SynthesisError)?))?;
        let cell_2 = region.assign_advice(|| "coeff_2", self.config.c, *offset, || Ok(c_2.ok_or(Error::SynthesisError)?))?;
        let cell_3 = region.assign_advice(|| "coeff_3", self.config.d, *offset, || Ok(c_3.ok_or(Error::SynthesisError)?))?;

        region.assign_fixed(|| "base_0", self.config.sa, *offset, || Ok(u_0))?;
        region.assign_fixed(|| "base_1", self.config.sb, *offset, || Ok(u_1))?;
        region.assign_fixed(|| "base_2", self.config.sc, *offset, || Ok(u_2))?;
        region.assign_fixed(|| "base_3", self.config.sd, *offset, || Ok(u_3))?;

        region.assign_fixed(|| "s_constant unused", self.config.s_constant, *offset, || Ok(constant_aux))?;
        region.assign_fixed(|| "s_mul unused", self.config.s_mul, *offset, || Ok(F::zero()))?;

        match option {
            CombinationOption::CombineToNext(base) => {
                region.assign_fixed(|| "sd_next", self.config.sd_next, *offset, || Ok(base))?;
            }
            CombinationOption::SingleLiner => {
                region.assign_fixed(|| "sd_next unused", self.config.sd_next, *offset, || Ok(F::zero()))?;
            }
        };

        *offset = *offset + 1;

        Ok((cell_0, cell_1, cell_2, cell_3))
    }

    fn assign_value(&self, region: &mut Region<'_, F>, value: Option<F>, column: MainGateColumn, offset: usize) -> Result<AssignedValue<F>, Error> {
        let column = match column {
            MainGateColumn::A => self.config.a,
            MainGateColumn::B => self.config.b,
            MainGateColumn::C => self.config.c,
            MainGateColumn::D => self.config.d,
        };
        let cell = region.assign_advice(|| "assign value", column, offset, || Ok(value.ok_or(Error::SynthesisError)?))?;

        Ok(AssignedValue::new(cell, value))
    }

    fn cycle_to(&self, region: &mut Region<'_, F>, input: &mut AssignedValue<F>, column: MainGateColumn, offset: usize) -> Result<(), Error> {
        let column = match column {
            MainGateColumn::A => self.config.a,
            MainGateColumn::B => self.config.b,
            MainGateColumn::C => self.config.c,
            MainGateColumn::D => self.config.d,
        };
        let value = input.value;
        let new_cell = region.assign_advice(|| "assign value", column, offset, || Ok(value.ok_or(Error::SynthesisError)?))?;
        input.cycle_cell(region, new_cell)?;
        Ok(())
    }

    fn no_operation(&self, region: &mut Region<'_, F>, offset: &mut usize) -> Result<(), Error> {
        region.assign_fixed(|| "s_mul", self.config.s_mul, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sc", self.config.sc, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sa", self.config.sa, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sb", self.config.sb, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd", self.config.sd, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd_next", self.config.sd_next, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, *offset, || Ok(F::zero()))?;
        *offset = *offset + 1;
        Ok(())
    }
}

impl<F: FieldExt> MainGate<F> {
    pub fn new(config: MainGateConfig) -> Self {
        MainGate { config, _marker: PhantomData }
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
        let s_mul = meta.fixed_column();
        let s_constant = meta.fixed_column();

        meta.enable_equality(a.into());
        meta.enable_equality(b.into());
        meta.enable_equality(c.into());
        meta.enable_equality(d.into());

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
            let s_mul = meta.query_fixed(s_mul, Rotation::cur());
            let s_constant = meta.query_fixed(s_constant, Rotation::cur());

            vec![a.clone() * sa + b.clone() * sb + a * b * s_mul + c * sc + sd * d + sd_next * d_next + s_constant]
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
            s_mul,
        }
    }
}

#[cfg(test)]
mod tests {

    use std::marker::PhantomData;

    use super::{CombinationOption, CombinationTerm, MainGate, MainGateConfig, MainGateInstructions};
    use halo2::arithmetic::FieldExt;
    use halo2::circuit::{Layouter, SimpleFloorPlanner};
    use halo2::dev::MockProver;
    use halo2::pasta::Fp;
    use halo2::plonk::{Circuit, ConstraintSystem, Error};

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        main_gate_config: MainGateConfig,
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitMainGate<F: FieldExt> {
        _marker: PhantomData<F>,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuitMainGate<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);
            TestCircuitConfig { main_gate_config }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            layouter.assign_region(
                || "assign region 0",
                |mut region| {
                    let _ = region.assign_advice(|| "a", config.main_gate_config.a, 0, || Ok(F::from_u64(10)))?;
                    let _ = region.assign_advice(|| "b", config.main_gate_config.b, 0, || Ok(F::from_u64(20)))?;
                    let _ = region.assign_advice(|| "c", config.main_gate_config.c, 0, || Ok(F::from_u64(30)))?;
                    let _ = region.assign_advice(|| "d", config.main_gate_config.d, 0, || Ok(F::zero()))?;

                    region.assign_fixed(|| "sa", config.main_gate_config.sa, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sb", config.main_gate_config.sb, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sc", config.main_gate_config.sc, 0, || Ok(-F::one()))?;
                    region.assign_fixed(|| "sd", config.main_gate_config.sd, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_mul", config.main_gate_config.s_mul, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sd_next", config.main_gate_config.sd_next, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_constant", config.main_gate_config.s_constant, 0, || Ok(F::zero()))?;

                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "assign region 1",
                |mut region| {
                    let _ = region.assign_advice(|| "a", config.main_gate_config.a, 0, || Ok(F::from_u64(10)))?;
                    let _ = region.assign_advice(|| "b", config.main_gate_config.b, 0, || Ok(F::from_u64(20)))?;
                    let _ = region.assign_advice(|| "c", config.main_gate_config.c, 0, || Ok(F::from_u64(230)))?;
                    let _ = region.assign_advice(|| "d", config.main_gate_config.d, 0, || Ok(F::zero()))?;

                    region.assign_fixed(|| "sa", config.main_gate_config.sa, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sb", config.main_gate_config.sb, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sc", config.main_gate_config.sc, 0, || Ok(-F::one()))?;
                    region.assign_fixed(|| "sd", config.main_gate_config.sd, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_mul", config.main_gate_config.s_mul, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sd_next", config.main_gate_config.sd_next, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_constant", config.main_gate_config.s_constant, 0, || Ok(F::zero()))?;

                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "assign region 2",
                |mut region| {
                    let _ = region.assign_advice(|| "a", config.main_gate_config.a, 0, || Ok(F::from_u64(10)))?;
                    let _ = region.assign_advice(|| "b", config.main_gate_config.b, 0, || Ok(F::from_u64(20)))?;
                    let _ = region.assign_advice(|| "c", config.main_gate_config.c, 0, || Ok(F::from_u64(201)))?;
                    let _ = region.assign_advice(|| "d", config.main_gate_config.d, 0, || Ok(F::zero()))?;

                    region.assign_fixed(|| "sa", config.main_gate_config.sa, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sb", config.main_gate_config.sb, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sc", config.main_gate_config.sc, 0, || Ok(-F::one()))?;
                    region.assign_fixed(|| "sd", config.main_gate_config.sd, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_mul", config.main_gate_config.s_mul, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "sd_next", config.main_gate_config.sd_next, 0, || Ok(-F::one()))?;
                    region.assign_fixed(|| "s_constant", config.main_gate_config.s_constant, 0, || Ok(F::zero()))?;

                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "assign region 3",
                |mut region| {
                    let _ = region.assign_advice(|| "a", config.main_gate_config.a, 0, || Ok(F::zero()))?;
                    let _ = region.assign_advice(|| "b", config.main_gate_config.b, 0, || Ok(F::zero()))?;
                    let _ = region.assign_advice(|| "c", config.main_gate_config.c, 0, || Ok(F::zero()))?;
                    let _ = region.assign_advice(|| "d", config.main_gate_config.d, 0, || Ok(F::from_u64(29)))?;

                    region.assign_fixed(|| "sa", config.main_gate_config.sa, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sb", config.main_gate_config.sb, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sc", config.main_gate_config.sc, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sd", config.main_gate_config.sd, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "s_mul", config.main_gate_config.s_mul, 0, || Ok(F::zero()))?;
                    region.assign_fixed(|| "sd_next", config.main_gate_config.sd_next, 0, || Ok(F::one()))?;
                    region.assign_fixed(|| "s_constant", config.main_gate_config.s_constant, 0, || Ok(F::zero()))?;

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_main_gate() {
        const K: u32 = 4;

        let circuit = TestCircuitMainGate::<Fp> { _marker: PhantomData };
        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        #[cfg(feature = "print_prover")]
        println!("{:?}", prover);
        assert_eq!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitCombination<F: FieldExt> {
        single_liner_coeffs: Option<Vec<F>>,
        single_liner_bases: Vec<F>,
        double_liner_coeffs: Option<Vec<F>>,
        double_liner_bases: Vec<F>,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuitCombination<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);
            TestCircuitConfig { main_gate_config }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let main_gate = MainGate::<F> {
                config: config.main_gate_config,
                _marker: PhantomData,
            };

            &mut layouter.assign_region(
                || "region 0",
                |mut region| {
                    let mut offset = 0;
                    let coeffs = self.single_liner_coeffs.clone();
                    let bases = self.single_liner_bases.clone();
                    let c_0 = coeffs.as_ref().map(|coeffs| coeffs[0]);
                    let c_1 = coeffs.as_ref().map(|coeffs| coeffs[1]);
                    let c_2 = coeffs.as_ref().map(|coeffs| coeffs[2]);
                    let c_3 = coeffs.as_ref().map(|coeffs| coeffs[3]);
                    let u_0 = bases[0];
                    let u_1 = bases[1];
                    let u_2 = bases[2];
                    let u_3 = bases[3];
                    main_gate.combine(
                        &mut region,
                        CombinationTerm::Value(c_0, u_0),
                        CombinationTerm::Value(c_1, u_1),
                        CombinationTerm::Value(c_2, u_2),
                        CombinationTerm::Value(c_3, u_3),
                        F::zero(),
                        &mut offset,
                        CombinationOption::SingleLiner,
                    )?;

                    let coeffs = self.double_liner_coeffs.clone().map(|coeffs| coeffs[0..4].to_vec());
                    let bases = self.double_liner_bases.clone()[0..4].to_vec();
                    let c_0 = coeffs.as_ref().map(|coeffs| coeffs[0]);
                    let c_1 = coeffs.as_ref().map(|coeffs| coeffs[1]);
                    let c_2 = coeffs.as_ref().map(|coeffs| coeffs[2]);
                    let c_3 = coeffs.as_ref().map(|coeffs| coeffs[3]);
                    let u_0 = bases[0];
                    let u_1 = bases[1];
                    let u_2 = bases[2];
                    let u_3 = bases[3];

                    let next = *self.double_liner_bases.last().unwrap();
                    main_gate.combine(
                        &mut region,
                        CombinationTerm::Value(c_0, u_0),
                        CombinationTerm::Value(c_1, u_1),
                        CombinationTerm::Value(c_2, u_2),
                        CombinationTerm::Value(c_3, u_3),
                        F::zero(),
                        &mut offset,
                        CombinationOption::CombineToNext(next),
                    )?;

                    let coeffs = self.double_liner_coeffs.clone().map(|coeffs| coeffs[4..8].to_vec());
                    let bases = self.double_liner_bases.clone()[4..8].to_vec();
                    let c_0 = coeffs.as_ref().map(|coeffs| coeffs[0]);
                    let c_1 = coeffs.as_ref().map(|coeffs| coeffs[1]);
                    let c_2 = coeffs.as_ref().map(|coeffs| coeffs[2]);
                    let c_3 = coeffs.as_ref().map(|coeffs| coeffs[3]);
                    let u_0 = bases[0];
                    let u_1 = bases[1];
                    let u_2 = bases[2];
                    let u_3 = bases[3];
                    main_gate.combine(
                        &mut region,
                        CombinationTerm::Value(c_0, u_0),
                        CombinationTerm::Value(c_1, u_1),
                        CombinationTerm::Value(c_2, u_2),
                        CombinationTerm::Value(c_3, u_3),
                        F::zero(),
                        &mut offset,
                        CombinationOption::SingleLiner,
                    )?;

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_main_gate_combination() {
        const K: u32 = 4;

        let a_0 = Fp::rand();
        let a_1 = Fp::rand();
        let a_2 = Fp::rand();
        let r_0 = Fp::rand();
        let r_1 = Fp::rand();
        let r_2 = Fp::rand();
        let r_3 = Fp::one();
        let a_3 = -(a_0 * r_0 + a_1 * r_1 + a_2 * r_2);

        let single_liner_coeffs = Some(vec![a_0, a_1, a_2, a_3]);
        let single_liner_bases = vec![r_0, r_1, r_2, r_3];

        let a_0 = Fp::rand();
        let a_1 = Fp::rand();
        let a_2 = Fp::rand();
        let a_3 = Fp::rand();
        let r_0 = Fp::rand();
        let r_1 = Fp::rand();
        let r_2 = Fp::rand();
        let r_3 = Fp::rand();
        // intermediate value
        let a_last = -(a_0 * r_0 + a_1 * r_1 + a_2 * r_2 + a_3 * r_3);
        let r_last = Fp::one();

        let a_4 = Fp::rand();
        let a_5 = Fp::rand();
        let r_4 = Fp::rand();
        let r_5 = Fp::rand();

        let r_6 = Fp::one();
        let a_6 = -(a_4 * r_4 + a_5 * r_5 + a_last * r_last);

        let double_liner_coeffs = Some(vec![a_0, a_1, a_2, a_3, a_4, a_5, a_6, a_last]);
        let double_liner_bases = vec![r_0, r_1, r_2, r_3, r_4, r_5, r_6, r_last];

        let circuit = TestCircuitCombination::<Fp> {
            single_liner_coeffs,
            single_liner_bases,
            double_liner_coeffs,
            double_liner_bases,
        };
        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        #[cfg(feature = "print_prover")]
        println!("{:#?}", prover);
        assert_eq!(prover.verify(), Ok(()));

        let single_liner_coeffs = Some(vec![a_0, a_1, a_2, a_3 + Fp::one()]);
        let single_liner_bases = vec![r_0, r_1, r_2, r_3];
        let double_liner_coeffs = Some(vec![a_0, a_1, a_2, a_3, a_4, a_5, a_6, a_last + Fp::one()]);
        let double_liner_bases = vec![r_0, r_1, r_2, r_3, r_4, r_5, r_6, r_last];

        let circuit = TestCircuitCombination::<Fp> {
            single_liner_coeffs,
            single_liner_bases,
            double_liner_coeffs,
            double_liner_bases,
        };
        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_ne!(prover.verify(), Ok(()));
    }

    #[derive(Default, Clone, Debug)]
    struct TestCircuitBitness<F: FieldExt> {
        value: Option<F>,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuitBitness<F> {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);
            TestCircuitConfig { main_gate_config }
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
            let main_gate = MainGate::<F> {
                config: config.main_gate_config,
                _marker: PhantomData,
            };

            &mut layouter.assign_region(
                || "region 0",
                |mut region| {
                    let mut offset = 0;
                    let value = self.value;
                    let _ = main_gate.assign_bit(&mut region, value, &mut offset)?;
                    let _ = main_gate.assign_bit(&mut region, value, &mut offset)?;
                    let _ = main_gate.assign_bit(&mut region, value, &mut offset)?;
                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_main_gate_bitness() {
        const K: u32 = 4;

        let value = Fp::one();

        let circuit = TestCircuitBitness::<Fp> { value: Some(value) };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        #[cfg(feature = "print_prover")]
        println!("{:#?}", prover);
        assert_eq!(prover.verify(), Ok(()));

        let value = Fp::zero();

        let circuit = TestCircuitBitness::<Fp> { value: Some(value) };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        #[cfg(feature = "print_prover")]
        println!("{:#?}", prover);
        assert_eq!(prover.verify(), Ok(()));

        let value = Fp::rand();

        let circuit = TestCircuitBitness::<Fp> { value: Some(value) };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        #[cfg(feature = "print_prover")]
        println!("{:#?}", prover);
        assert_ne!(prover.verify(), Ok(()));
    }
}
