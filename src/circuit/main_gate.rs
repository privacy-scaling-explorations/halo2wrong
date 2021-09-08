use halo2::arithmetic::FieldExt;
use halo2::plonk::{Advice, Column, ConstraintSystem, Fixed};
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

    use super::{MainGate, MainGateConfig};
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

        // println!("{:?}", prover);
        assert_eq!(prover.verify(), Ok(()));
    }
}
