use super::{AssignedCondition, AssignedValue};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
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
    pub s_mul: Column<Fixed>,
    pub s_constant: Column<Fixed>,
}

pub struct MainGate<F: FieldExt> {
    pub config: MainGateConfig,
    _marker: PhantomData<F>,
}

pub trait MainGateInstructions<F: FieldExt> {
    fn cond_swap(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        cond: &mut AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn bitness_check(&self, region: &mut Region<'_, F>, a: &mut AssignedValue<F>) -> Result<(), Error>;
}

impl<F: FieldExt> MainGateInstructions<F> for MainGate<F> {
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
            let cond = cond._value.unwrap();
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

    fn bitness_check(&self, region: &mut Region<'_, F>, a: &mut AssignedValue<F>) -> Result<(), Error> {
        // a*a - a == 0

        let offset = 0;

        let a_new_cell_0 = region.assign_advice(|| "a", self.config.a, offset, || Ok(a.value.ok_or(Error::SynthesisError)?))?;
        let a_new_cell_1 = region.assign_advice(|| "b", self.config.b, offset, || Ok(a.value.ok_or(Error::SynthesisError)?))?;
        let a_new_cell_2 = region.assign_advice(|| "c", self.config.c, offset, || Ok(a.value.ok_or(Error::SynthesisError)?))?;
        let _ = region.assign_advice(|| "d", self.config.d, offset, || Ok(F::zero()))?;

        region.assign_fixed(|| "s_mul", self.config.s_mul, offset, || Ok(F::one()))?;
        region.assign_fixed(|| "sc", self.config.sc, offset, || Ok(-F::one()))?;

        region.assign_fixed(|| "sa", self.config.sa, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sb", self.config.sb, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd", self.config.sd, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "sd_next", self.config.sd_next, offset, || Ok(F::zero()))?;
        region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(F::zero()))?;

        a.cycle_cell(region, a_new_cell_0)?;
        region.constrain_equal(a_new_cell_0, a_new_cell_1)?;
        region.constrain_equal(a_new_cell_1, a_new_cell_2)?;

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

    use super::{MainGate, MainGateConfig, MainGateInstructions};
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
    struct TestCircuit<F: FieldExt> {
        _marker: PhantomData<F>,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
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

            // layouter.assign_region(
            //     || "assign region 3",
            //     |mut region| {
            //         self.bitness_check(F::zero())?;
            //         Ok(())
            //     },
            // )?;

            Ok(())
        }
    }

    #[test]
    fn test_main_gate() {
        const K: u32 = 4;

        let circuit = TestCircuit::<Fp> { _marker: PhantomData };

        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        #[cfg(feature = "print_prover")]
        println!("{:?}", prover);

        assert_eq!(prover.verify(), Ok(()));
    }
}
