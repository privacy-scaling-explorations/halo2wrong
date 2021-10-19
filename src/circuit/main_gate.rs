use super::{AssignedCondition, AssignedValue};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Cell, Region};
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

pub trait MainGateInstructions<F: FieldExt> {
    fn cond_swap(
        &self,
        region: &mut Region<'_, F>,
        a: &mut AssignedValue<F>,
        b: &mut AssignedValue<F>,
        cond: &mut AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn bitness_check(&self, region: &mut Region<'_, F>, a: &mut AssignedValue<F>) -> Result<(), Error>;

    fn combine(
        &self,
        region: &mut Region<'_, F>,
        coeffs: Option<Vec<F>>,
        bases: Vec<F>,
        offset: &mut usize,
        options: CombinationOption<F>,
    ) -> Result<Vec<Cell>, Error>;
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
        a.cycle_cell(region, a_new_cell_1)?;
        a.cycle_cell(region, a_new_cell_2)?;

        Ok(())
    }

    fn combine(
        &self,
        region: &mut Region<'_, F>,
        coeffs: Option<Vec<F>>,
        bases: Vec<F>,
        offset: &mut usize,
        option: CombinationOption<F>,
    ) -> Result<Vec<Cell>, Error> {
        assert!(bases.len() == self.width());
        match coeffs.clone() {
            Some(coeffs) => {
                assert_eq!(coeffs.len(), bases.len());
            }
            _ => {}
        }

        let mut cells = Vec::new();
        for i in 0..self.width() {
            let coeff_i_cell = region.assign_advice(
                || format!("coeff {}", i),
                self.advice_columns()[i],
                *offset,
                || Ok(coeffs.as_ref().ok_or(Error::SynthesisError)?[i]),
            )?;
            region.assign_fixed(|| format!("base {}", i), self.fixed_columns()[i], *offset, || Ok(bases[i]))?;
            cells.push(coeff_i_cell);
        }

        region.assign_fixed(|| format!("s_constant unused"), self.config.s_constant, *offset, || Ok(F::zero()))?;
        region.assign_fixed(|| format!("s_mul unused"), self.config.s_mul, *offset, || Ok(F::zero()))?;

        match option {
            CombinationOption::CombineToNext(base) => {
                region.assign_fixed(|| format!("sd_next"), self.config.sd_next, *offset, || Ok(base))?;
            }
            CombinationOption::SingleLiner => {
                region.assign_fixed(|| format!("sd_next unused"), self.config.sd_next, *offset, || Ok(F::zero()))?;
            }
            _ => {
                panic!("option is not applicable")
            }
        };

        *offset = *offset + 1;

        Ok(cells)
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

    use super::{CombinationOption, MainGate, MainGateConfig, MainGateInstructions};
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
        _marker: PhantomData<F>,
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
                    main_gate.combine(&mut region, coeffs, bases, &mut offset, CombinationOption::SingleLiner)?;

                    let coeffs = self.double_liner_coeffs.clone().map(|coeffs| coeffs[0..4].to_vec());
                    let bases = self.double_liner_bases.clone()[0..4].to_vec();
                    let next = *self.double_liner_bases.last().unwrap();
                    main_gate.combine(&mut region, coeffs, bases, &mut offset, CombinationOption::CombineToNext(next))?;

                    let coeffs = self.double_liner_coeffs.clone().map(|coeffs| coeffs[4..8].to_vec());
                    let bases = self.double_liner_bases.clone()[4..8].to_vec();
                    main_gate.combine(&mut region, coeffs, bases, &mut offset, CombinationOption::SingleLiner)?;

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
            _marker: PhantomData,
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
            _marker: PhantomData,
        };
        let prover = match MockProver::run(K, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };

        assert_ne!(prover.verify(), Ok(()));
    }
}
