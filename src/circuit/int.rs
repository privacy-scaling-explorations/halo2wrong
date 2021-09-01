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
        a: Option<&mut Integer<Wrong, Native>>,
        b: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error>;

    fn sub(
        &self,
        region: &mut Region<'_, Native>,
        a: Option<&mut Integer<Wrong, Native>>,
        b: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error>;

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
        a: Option<&mut Integer<Wrong, Native>>,
        b: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error> {
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

    fn sub(
        &self,
        region: &mut Region<'_, Native>,
        a: Option<&mut Integer<Wrong, Native>>,
        b: Option<&mut Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error> {
        let a = a.ok_or(Error::SynthesisError)?;
        let b = b.ok_or(Error::SynthesisError)?;
        let mut c: Integer<_, _> = a.sub(b).clone();
        let aux = a.rns.aux.clone();

        let main_gate = self.main_gate();

        for (((a, b), c), aux) in a
            .decomposed
            .limbs
            .iter_mut()
            .zip(b.decomposed.limbs.iter_mut())
            .zip(c.decomposed.limbs.iter_mut())
            .zip(aux.limbs.iter())
        {
            // expect operands are assigned
            let a_cell = a.cell.ok_or(Error::SynthesisError)?;
            let b_cell = b.cell.ok_or(Error::SynthesisError)?;

            let (a_new_cell, b_new_cell, c_cell) =
                main_gate.sub_add_constant(region, Some((a.fe(), b.fe(), c.fe(), aux.fe())))?;

            // cycle equal limbs
            region.constrain_equal(a_cell, a_new_cell)?;
            region.constrain_equal(b_cell, b_new_cell)?;

            // update cells of operands
            a.cell = Some(a_new_cell);
            b.cell = Some(b_new_cell);

            // assing cell to the result
            c.cell = Some(c_cell)
        }

        self.reduce(region, Some(&c))?;

        Ok(c)
    }

    fn reduce(
        &self,
        region: &mut Region<'_, Native>,
        a: Option<&Integer<Wrong, Native>>,
    ) -> Result<Integer<Wrong, Native>, Error> {
        let main_gate = self.main_gate();
        let range_chip = self.range_chip();

        let a = a.ok_or(Error::SynthesisError)?;
        let left_shifter_r = a.rns.left_shifter_r;
        let left_shifter_2r = a.rns.left_shifter_2r;

        let reduced = a.reduce();

        let negative_modulus = reduced.negative_modulus;
        let a = &mut a.limbs();
        let intermediate_values = &mut reduced.t.clone();
        let quotient = &mut reduced.q.clone();
        let v_0 = &mut reduced.v_0.clone();
        let v_1 = &mut reduced.v_1.clone();

        // first constaint quotient is in 64 bit range
        range_chip.range_limb(region, Some(quotient))?;
        range_chip.range_limb(region, Some(v_0))?;
        range_chip.range_limb(region, Some(v_1))?;

        // t_i = a_i + p_i * q

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        // assign t_i
        // cycle a_i

        for ((ai, pi), t) in a
            .iter_mut()
            .zip(negative_modulus.iter())
            .zip(intermediate_values.iter_mut())
        {
            let a_cell = ai.cell.ok_or(Error::SynthesisError)?;
            // should be set above in range constaint
            let q_cell = quotient.cell.ok_or(Error::SynthesisError)?;

            let (a_new_cell, q_new_cell, t_assigned_cell) = main_gate
                .add_mul_constant(region, Some((ai.fe(), quotient.fe(), pi.fe(), t.fe())))?;

            // cycle equal limbs
            region.constrain_equal(a_cell, a_new_cell)?;
            region.constrain_equal(q_cell, q_new_cell)?;

            t.cell = Some(t_assigned_cell);
        }

        // constaint result limbs is in 64 bit range
        let result = &mut reduced.r.clone();
        for limb in result.decomposed.limbs.iter_mut() {
            range_chip.range_limb(region, Some(limb)).unwrap();
        }

        // u_0 = t_0 + 2^b * t_1 - r_0 - 2^b * r_1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_0 | t_1 | r_0 | r_1 |
        // | -   | -   | -   | u_0 |

        let u_0 = &mut reduced.u_0.clone();
        let offset = 0; // TODO:fix
        {
            let t_0_cell = intermediate_values[0].cell.ok_or(Error::SynthesisError)?;
            let t_1_cell = intermediate_values[1].cell.ok_or(Error::SynthesisError)?;
            let r_0_cell = result.decomposed.limbs[0]
                .cell
                .ok_or(Error::SynthesisError)?;
            let r_1_cell = result.decomposed.limbs[1]
                .cell
                .ok_or(Error::SynthesisError)?;

            // assign equation
            let t_0_new_cell = region.assign_advice(
                || "t_0",
                main_gate.config.a,
                offset,
                || Ok(intermediate_values[0].fe()),
            )?;
            region.assign_fixed(|| "a", main_gate.config.sa, offset, || Ok(Native::one()))?;

            let t_1_new_cell = region.assign_advice(
                || "t_1",
                main_gate.config.b,
                offset,
                || Ok(intermediate_values[1].fe()),
            )?;
            region.assign_fixed(|| "b", main_gate.config.sb, offset, || Ok(left_shifter_r))?;

            let r_0_new_cell = region.assign_advice(
                || "r_0",
                main_gate.config.c,
                offset,
                || Ok(result.decomposed.limbs[0].fe()),
            )?;
            region.assign_fixed(|| "c", main_gate.config.sc, offset, || Ok(Native::one()))?;

            let r_1_new_cell = region.assign_advice(
                || "r_1",
                main_gate.config.d,
                offset,
                || Ok(result.decomposed.limbs[1].fe()),
            )?;
            region.assign_fixed(|| "d", main_gate.config.sd, offset, || Ok(-left_shifter_r))?;

            let u_0_cell =
                region.assign_advice(|| "u_0", main_gate.config.d, offset + 1, || Ok(u_0.fe()))?;
            region.assign_fixed(
                || "d_next",
                main_gate.config.sd_next,
                0,
                || Ok(Native::one()),
            )?;

            // cycle cells
            region.constrain_equal(t_0_cell, t_0_new_cell)?;
            region.constrain_equal(t_1_cell, t_1_new_cell)?;
            region.constrain_equal(r_0_cell, r_0_new_cell)?;
            region.constrain_equal(r_1_cell, r_1_new_cell)?;

            // update cells
            intermediate_values[0].cell = Some(t_0_new_cell);
            intermediate_values[1].cell = Some(t_1_new_cell);
            result.decomposed.limbs[0].cell = Some(r_0_new_cell);
            result.decomposed.limbs[1].cell = Some(r_1_new_cell);

            // assing new cells
            u_0.cell = Some(u_0_cell);

            // zeroize unused selectors
            region.assign_fixed(|| "a * b", main_gate.config.sm, 0, || Ok(Native::zero()))?;
            region.assign_fixed(
                || "constant",
                main_gate.config.s_constant,
                0,
                || Ok(Native::zero()),
            )?;
        }

        // v_0 * 2B = u_0

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_0 | t_1 | r_0 | r_1 |
        // | -   | -   | v_0 | u_0 |

        {
            let v_0_cell = v_0.cell.ok_or(Error::SynthesisError)?;

            let v_0_new_cell =
                region.assign_advice(|| "v_0", main_gate.config.d, offset + 1, || Ok(v_0.fe()))?;
            region.assign_fixed(
                || "c",
                main_gate.config.sc,
                offset + 1,
                || Ok(left_shifter_2r),
            )?;
            // u_0 is set to `d` above at this offset
            region.assign_fixed(
                || "d",
                main_gate.config.sd,
                offset + 1,
                || Ok(Native::one()),
            )?;

            // cycle cells
            region.constrain_equal(v_0_cell, v_0_new_cell)?;

            // update_cells
            v_0.cell = Some(v_0_new_cell);

            // zeroize unused selectors
            region.assign_fixed(
                || "a",
                main_gate.config.sa,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "b",
                main_gate.config.sb,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "a * b",
                main_gate.config.sm,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "d_next",
                main_gate.config.sd_next,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "constant",
                main_gate.config.s_constant,
                0,
                || Ok(Native::zero()),
            )?;
        }

        // u_0 = t_0 + 2^b * t_1 - r_0 - 2^b * r_1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_2 | t_3 | r_2 | r_3 |
        // | -   | -   | -   | u_1 |

        let u_1 = &mut reduced.u_1.clone();
        let offset = offset + 2; // TODO:fix
        {
            let t_2_cell = intermediate_values[2].cell.ok_or(Error::SynthesisError)?;
            let t_3_cell = intermediate_values[3].cell.ok_or(Error::SynthesisError)?;
            let r_2_cell = result.decomposed.limbs[2]
                .cell
                .ok_or(Error::SynthesisError)?;
            let r_3_cell = result.decomposed.limbs[3]
                .cell
                .ok_or(Error::SynthesisError)?;

            // assign equation
            let t_2_new_cell = region.assign_advice(
                || "t_2",
                main_gate.config.a,
                offset,
                || Ok(intermediate_values[2].fe()),
            )?;
            region.assign_fixed(|| "a", main_gate.config.sa, offset, || Ok(Native::one()))?;

            let t_3_new_cell = region.assign_advice(
                || "t_3",
                main_gate.config.b,
                offset,
                || Ok(intermediate_values[3].fe()),
            )?;
            region.assign_fixed(|| "b", main_gate.config.sb, offset, || Ok(left_shifter_r))?;

            let r_2_new_cell = region.assign_advice(
                || "r_2",
                main_gate.config.c,
                offset,
                || Ok(result.decomposed.limbs[2].fe()),
            )?;
            region.assign_fixed(|| "c", main_gate.config.sc, offset, || Ok(Native::one()))?;

            let r_3_new_cell = region.assign_advice(
                || "r_1",
                main_gate.config.d,
                offset,
                || Ok(result.decomposed.limbs[3].fe()),
            )?;
            region.assign_fixed(|| "d", main_gate.config.sd, offset, || Ok(-left_shifter_r))?;

            let u_1_cell =
                region.assign_advice(|| "u_0", main_gate.config.d, offset + 1, || Ok(u_1.fe()))?;
            region.assign_fixed(
                || "d_next",
                main_gate.config.sd_next,
                0,
                || Ok(Native::one()),
            )?;

            // cycle cells
            region.constrain_equal(t_2_cell, t_2_new_cell)?;
            region.constrain_equal(t_3_cell, t_3_new_cell)?;
            region.constrain_equal(r_2_cell, r_2_new_cell)?;
            region.constrain_equal(r_3_cell, r_3_new_cell)?;

            // update cells
            intermediate_values[2].cell = Some(t_2_new_cell);
            intermediate_values[3].cell = Some(t_3_new_cell);
            result.decomposed.limbs[2].cell = Some(r_2_new_cell);
            result.decomposed.limbs[3].cell = Some(r_3_new_cell);

            // assing new cells
            u_1.cell = Some(u_1_cell);

            // zeroize unused selectors
            region.assign_fixed(
                || "a * b",
                main_gate.config.sm,
                offset,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "constant",
                main_gate.config.s_constant,
                offset,
                || Ok(Native::zero()),
            )?;
        }

        // v_1 * 2B = u_1

        // | A   | B   | C   | D   |
        // | --- | --- | --- | --- |
        // | t_2 | t_3 | r_2 | r_3 |
        // | -   | -   | v_1 | u_1 |

        {
            let v_1_cell = v_1.cell.ok_or(Error::SynthesisError)?;

            let v_1_new_cell =
                region.assign_advice(|| "v_1", main_gate.config.d, offset + 1, || Ok(v_1.fe()))?;

            region.assign_fixed(
                || "c",
                main_gate.config.sc,
                offset + 1,
                || Ok(left_shifter_2r),
            )?;
            // u_0 is set to `d` above at this offset
            region.assign_fixed(
                || "d",
                main_gate.config.sd,
                offset + 1,
                || Ok(Native::one()),
            )?;

            // cycle cells
            region.constrain_equal(v_1_cell, v_1_new_cell)?;

            // update_cells
            v_1.cell = Some(v_1_new_cell);

            // zeroize unused selectors
            region.assign_fixed(
                || "a",
                main_gate.config.sa,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "b",
                main_gate.config.sb,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "a * b",
                main_gate.config.sm,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "d_next",
                main_gate.config.sd_next,
                offset + 1,
                || Ok(Native::zero()),
            )?;
            region.assign_fixed(
                || "constant",
                main_gate.config.s_constant,
                0,
                || Ok(Native::zero()),
            )?;
        }

        Ok(result.clone())
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
