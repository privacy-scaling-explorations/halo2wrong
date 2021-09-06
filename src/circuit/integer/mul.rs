use super::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::{MainGate, MainGateConfig, MainGateInstructions};
use crate::circuit::range::{RangeChip, RangeConfig, RangeInstructions};
use crate::rns::{Integer, Quotient};
use halo2::arithmetic::FieldExt;
use halo2::circuit::{Chip, Region};
use halo2::plonk::{Advice, Column, ConstraintSystem, Error, Fixed};

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _mul(&self, region: &mut Region<'_, N>, a: Option<&mut Integer<N>>, b: Option<&mut Integer<N>>) -> Result<Integer<N>, Error> {
        let range_chip = self.range_chip();

        let mut offset = 0;

        let a = a.ok_or(Error::SynthesisError)?;
        let b = b.ok_or(Error::SynthesisError)?;
        let reduction_context = self.rns.mul(a, b);

        let a = &mut a.limbs();
        let b = &mut b.limbs();

        let quotient = &mut match reduction_context.quotient {
            Quotient::Long(quotient) => Ok(quotient.limbs),
            _ => Err(Error::SynthesisError),
        }?;

        let intermediate_values = &mut reduction_context.t.clone();
        let negative_modulus = reduction_context.negative_modulus;

        // range quotient
        for limb in quotient.iter_mut() {
            range_chip.range_limb(region, Some(limb)).unwrap();
        }

        // range residues
        let v_0 = &mut reduction_context.v_0.clone();
        let v_1 = &mut reduction_context.v_1.clone();

        range_chip.range_limb(region, Some(v_0))?;
        range_chip.range_limb(region, Some(v_1))?;

        {
            // t_0 = a_0 * b_0 + q_0 * p_0

            // | A   | B   | C   | D   |
            // | --- | --- | --- | --- |
            // | a_0 | b_0 | t_0 | q_0 |

            let a_0 = &mut a[0];
            let b_0 = &mut b[0];
            let t_0 = &mut intermediate_values[0];
            let q_0 = &mut quotient[0];
            let a_0_cell = a_0.cell.ok_or(Error::SynthesisError)?;
            let b_0_cell = b_0.cell.ok_or(Error::SynthesisError)?;
            let q_0_cell = q_0.cell.ok_or(Error::SynthesisError)?;

            let a_0_new_cell = region.assign_advice(|| "a_0", self.config.a, offset, || Ok(a_0.fe()))?;
            let b_0_new_cell = region.assign_advice(|| "b_0", self.config.b, offset, || Ok(b_0.fe()))?;
            let t_0_cell = region.assign_advice(|| "t_0", self.config.c, offset, || Ok(t_0.fe()))?;
            let q_0_new_cell = region.assign_advice(|| "q_0", self.config.d, offset, || Ok(q_0.fe()))?;

            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(negative_modulus[0].fe()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_0_cell, a_0_new_cell)?;
            region.constrain_equal(b_0_cell, b_0_new_cell)?;
            region.constrain_equal(q_0_cell, q_0_new_cell)?;

            // update cells
            a_0.cell = Some(a_0_new_cell);
            b_0.cell = Some(b_0_new_cell);
            q_0.cell = Some(q_0_new_cell);

            // assign new cell
            t_0.cell = Some(t_0_cell);
        }

        offset += 1;
        {
            // t_1 =    a_0 * b_1 + a_1 * b_0 + q_0 * p_1 + q_1 * p_0
            // t_1 =    a_0 * b_1 + q_0 * p_1 + tmp
            // tmp =    a_1 * b_0 + q_1 * p_0

            // | A   | B   | C    | D    |
            // | --- | --- | ---- | ---- |
            // | a_0 | b_1 | q_0  | t_1  |
            // | a_1 | b_0 | q_1  | tmp  |

            let tmp = a[1].fe() + b[0].fe() + quotient[1].fe() * negative_modulus[0].fe();

            let a_0_cell = a[0].cell.ok_or(Error::SynthesisError)?;
            let a_1_cell = a[1].cell.ok_or(Error::SynthesisError)?;
            let b_0_cell = b[0].cell.ok_or(Error::SynthesisError)?;
            let b_1_cell = b[1].cell.ok_or(Error::SynthesisError)?;
            let q_0_cell = quotient[0].cell.ok_or(Error::SynthesisError)?;
            let q_1_cell = quotient[1].cell.ok_or(Error::SynthesisError)?;

            let a_0_new_cell = region.assign_advice(|| "a_0", self.config.a, offset, || Ok(a[0].fe()))?;
            let b_1_new_cell = region.assign_advice(|| "b_1", self.config.b, offset, || Ok(b[1].fe()))?;
            let q_0_new_cell = region.assign_advice(|| "q_0", self.config.c, offset, || Ok(quotient[0].fe()))?;
            let t_1_cell = region.assign_advice(|| "t_1", self.config.d, offset, || Ok(intermediate_values[1].fe()))?;
            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[1].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_0_cell, a_0_new_cell)?;
            region.constrain_equal(b_1_cell, b_1_new_cell)?;
            region.constrain_equal(q_0_cell, q_0_new_cell)?;

            // update cells
            a[0].cell = Some(a_0_new_cell);
            b[1].cell = Some(b_1_new_cell);
            quotient[0].cell = Some(q_0_new_cell);

            // assign new cell
            intermediate_values[1].cell = Some(t_1_cell);

            offset += 1;

            let a_1_new_cell = region.assign_advice(|| "a_1", self.config.a, offset, || Ok(a[1].fe()))?;
            let b_0_new_cell = region.assign_advice(|| "b_0", self.config.b, offset, || Ok(b[0].fe()))?;
            let q_1_new_cell = region.assign_advice(|| "q_1", self.config.c, offset, || Ok(quotient[1].fe()))?;
            let _ = region.assign_advice(|| "tmp", self.config.d, offset, || Ok(tmp))?;
            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[0].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_1_cell, a_1_new_cell)?;
            region.constrain_equal(b_0_cell, b_0_new_cell)?;
            region.constrain_equal(q_1_cell, q_1_new_cell)?;

            // update cells
            a[1].cell = Some(a_1_new_cell);
            b[0].cell = Some(b_0_new_cell);
            quotient[1].cell = Some(q_1_new_cell);
        }

        offset += 1;

        {
            // t_2   =    a_0 * b_2 + a_1 * b_1e + a_2 * b_0 + q_0 * p_2 + q_1 * p_1 + q_2 * p_0
            // t_2   =    a_0 * b_2 + q_0 * p_2 + tmp_a
            // tmp_a =    a_1 * b_1 + q_1 * p_1 + tmp_b
            // tmp_b =    a_2 * b_0 + q_2 * p_0

            // | A   | B   | C   | D     |
            // | --- | --- | --- | ----- |
            // | a_0 | b_2 | q_0 | t_2   |
            // | a_1 | b_1 | q_1 | tmp_a |
            // | a_2 | b_0 | q_2 | tmp_b |

            let tmp_b = a[2].fe() + b[0].fe() + quotient[2].fe() * negative_modulus[0].fe();
            let tmp_a = a[1].fe() + b[1].fe() + quotient[1].fe() * negative_modulus[2].fe() + tmp_b;

            let a_0_cell = a[0].cell.ok_or(Error::SynthesisError)?;
            let a_1_cell = a[1].cell.ok_or(Error::SynthesisError)?;
            let a_2_cell = a[2].cell.ok_or(Error::SynthesisError)?;
            let b_0_cell = b[0].cell.ok_or(Error::SynthesisError)?;
            let b_1_cell = b[1].cell.ok_or(Error::SynthesisError)?;
            let b_2_cell = b[2].cell.ok_or(Error::SynthesisError)?;
            let q_0_cell = quotient[0].cell.ok_or(Error::SynthesisError)?;
            let q_1_cell = quotient[1].cell.ok_or(Error::SynthesisError)?;
            let q_2_cell = quotient[2].cell.ok_or(Error::SynthesisError)?;

            let a_0_new_cell = region.assign_advice(|| "a_0", self.config.a, offset, || Ok(a[0].fe()))?;
            let b_2_new_cell = region.assign_advice(|| "b_2", self.config.b, offset, || Ok(b[2].fe()))?;
            let q_0_new_cell = region.assign_advice(|| "q_0", self.config.c, offset, || Ok(quotient[0].fe()))?;
            let t_2_cell = region.assign_advice(|| "t_1", self.config.d, offset, || Ok(intermediate_values[2].fe()))?;
            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[2].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_0_cell, a_0_new_cell)?;
            region.constrain_equal(b_2_cell, b_2_new_cell)?;
            region.constrain_equal(q_0_cell, q_0_new_cell)?;

            // update cells
            a[0].cell = Some(a_0_new_cell);
            b[2].cell = Some(b_2_new_cell);
            quotient[0].cell = Some(q_0_new_cell);

            // assign new cell
            intermediate_values[2].cell = Some(t_2_cell);

            offset += 1;

            let a_1_new_cell = region.assign_advice(|| "a_1", self.config.a, offset, || Ok(a[1].fe()))?;
            let b_1_new_cell = region.assign_advice(|| "b_1", self.config.b, offset, || Ok(b[1].fe()))?;
            let q_1_new_cell = region.assign_advice(|| "q_1", self.config.c, offset, || Ok(quotient[1].fe()))?;
            let _ = region.assign_advice(|| "tmp_a", self.config.d, offset, || Ok(tmp_a))?;

            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[1].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_1_cell, a_1_new_cell)?;
            region.constrain_equal(b_1_cell, b_1_new_cell)?;
            region.constrain_equal(q_1_cell, q_1_new_cell)?;

            // update cells
            a[1].cell = Some(a_1_new_cell);
            b[1].cell = Some(b_1_new_cell);
            quotient[1].cell = Some(q_1_new_cell);

            offset += 1;

            let a_2_new_cell = region.assign_advice(|| "a_1", self.config.a, offset, || Ok(a[2].fe()))?;
            let b_0_new_cell = region.assign_advice(|| "b_1", self.config.b, offset, || Ok(b[0].fe()))?;
            let q_2_new_cell = region.assign_advice(|| "q_1", self.config.c, offset, || Ok(quotient[2].fe()))?;
            let _ = region.assign_advice(|| "tmp_a", self.config.d, offset, || Ok(tmp_b))?;

            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[0].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_2_cell, a_2_new_cell)?;
            region.constrain_equal(b_0_cell, b_0_new_cell)?;
            region.constrain_equal(q_2_cell, q_2_new_cell)?;

            // update cells
            a[2].cell = Some(a_2_new_cell);
            b[0].cell = Some(b_0_new_cell);
            quotient[2].cell = Some(q_2_new_cell);
        }

        offset += 1;

        {
            // t_3   =    a_0 * b_3 + a_1 * b_2 + a_1 * b_2 + a_3 * b_0 + q_0 * p_3 + q_1 * p_2 + q_2 * p_1 + q_3 * p_0

            // t_3   =    a_0 * b_3 + q_0 * p_3 + tmp_a
            // tmp_a =    a_1 * b_2 + q_1 * p_2 + tmp_b
            // tmp_b =    a_2 * b_1 + q_2 * p_1 + tmp_c
            // tmp_c =    a_3 * b_0 + q_3 * p_0

            // | A   | B   | C   | D     |
            // | --- | --- | --- | ----- |
            // | a_0 | b_3 | q_0 | t_3   |
            // | a_1 | b_1 | q_2 | tmp_b |
            // | a_2 | b_2 | q_1 | tmp_a |
            // | a_3 | b_0 | q_3 | tmp_c |

            let tmp_c = a[3].fe() + b[0].fe() + quotient[3].fe() * negative_modulus[0].fe();
            let tmp_b = a[2].fe() + b[0].fe() + quotient[2].fe() * negative_modulus[0].fe();
            let tmp_a = a[1].fe() + b[1].fe() + quotient[1].fe() * negative_modulus[2].fe() + tmp_b;

            let a_0_cell = a[0].cell.ok_or(Error::SynthesisError)?;
            let a_1_cell = a[1].cell.ok_or(Error::SynthesisError)?;
            let a_2_cell = a[2].cell.ok_or(Error::SynthesisError)?;
            let b_0_cell = b[0].cell.ok_or(Error::SynthesisError)?;
            let b_1_cell = b[1].cell.ok_or(Error::SynthesisError)?;
            let b_2_cell = b[2].cell.ok_or(Error::SynthesisError)?;
            let q_0_cell = quotient[0].cell.ok_or(Error::SynthesisError)?;
            let q_1_cell = quotient[1].cell.ok_or(Error::SynthesisError)?;
            let q_2_cell = quotient[2].cell.ok_or(Error::SynthesisError)?;

            let a_0_new_cell = region.assign_advice(|| "a_0", self.config.a, offset, || Ok(a[0].fe()))?;
            let b_2_new_cell = region.assign_advice(|| "b_2", self.config.b, offset, || Ok(b[2].fe()))?;
            let q_0_new_cell = region.assign_advice(|| "q_0", self.config.c, offset, || Ok(quotient[0].fe()))?;
            let t_2_cell = region.assign_advice(|| "t_1", self.config.d, offset, || Ok(intermediate_values[2].fe()))?;
            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[2].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_0_cell, a_0_new_cell)?;
            region.constrain_equal(b_2_cell, b_2_new_cell)?;
            region.constrain_equal(q_0_cell, q_0_new_cell)?;

            // update cells
            a[0].cell = Some(a_0_new_cell);
            b[2].cell = Some(b_2_new_cell);
            quotient[0].cell = Some(q_0_new_cell);

            // assign new cell
            intermediate_values[2].cell = Some(t_2_cell);

            offset += 1;

            let a_1_new_cell = region.assign_advice(|| "a_1", self.config.a, offset, || Ok(a[1].fe()))?;
            let b_1_new_cell = region.assign_advice(|| "b_1", self.config.b, offset, || Ok(b[1].fe()))?;
            let q_1_new_cell = region.assign_advice(|| "q_1", self.config.c, offset, || Ok(quotient[1].fe()))?;
            let _ = region.assign_advice(|| "tmp_a", self.config.d, offset, || Ok(tmp_a))?;

            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[1].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_1_cell, a_1_new_cell)?;
            region.constrain_equal(b_1_cell, b_1_new_cell)?;
            region.constrain_equal(q_1_cell, q_1_new_cell)?;

            // update cells
            a[1].cell = Some(a_1_new_cell);
            b[1].cell = Some(b_1_new_cell);
            quotient[1].cell = Some(q_1_new_cell);

            offset += 1;

            let a_2_new_cell = region.assign_advice(|| "a_1", self.config.a, offset, || Ok(a[2].fe()))?;
            let b_0_new_cell = region.assign_advice(|| "b_1", self.config.b, offset, || Ok(b[0].fe()))?;
            let q_2_new_cell = region.assign_advice(|| "q_1", self.config.c, offset, || Ok(quotient[2].fe()))?;
            let _ = region.assign_advice(|| "tmp_a", self.config.d, offset, || Ok(tmp_b))?;

            region.assign_fixed(|| "s_m", self.config.sm, offset, || Ok(N::one()))?;
            region.assign_fixed(|| "s_c", self.config.sc, offset, || Ok(negative_modulus[0].fe()))?;
            region.assign_fixed(|| "s_d", self.config.sd, offset, || Ok(-N::one()))?;
            region.assign_fixed(|| "s_d_next", self.config.sd_next, offset, || Ok(N::one()))?;

            // zeroize unused selectors
            region.assign_fixed(|| "s_a", self.config.sa, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_b", self.config.sb, offset, || Ok(N::zero()))?;
            region.assign_fixed(|| "s_constant", self.config.s_constant, offset, || Ok(N::zero()))?;

            // cycle equal limbs
            region.constrain_equal(a_2_cell, a_2_new_cell)?;
            region.constrain_equal(b_0_cell, b_0_new_cell)?;
            region.constrain_equal(q_2_cell, q_2_new_cell)?;

            // update cells
            a[2].cell = Some(a_2_new_cell);
            b[0].cell = Some(b_0_new_cell);
            quotient[2].cell = Some(q_2_new_cell);
        }

        unimplemented!();
    }
}
