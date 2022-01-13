use super::IntegerChip;
use crate::WrongExt;
use crate::circuit::AssignedInteger;
use crate::rns::MaybeReduced;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::main_gate::five::range::RangeInstructions;
use halo2arith::{halo2, CombinationOptionCommon, MainGateInstructions, Term};

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    fn assert_zero_v0_range_tune(&self) -> usize {
        // TODO
        self.rns.bit_len_limb
    }

    fn assert_zero_v1_range_tune(&self) -> usize {
        // TODO
        self.rns.bit_len_limb
    }

    fn assert_zero_quotient_range_tune(&self) -> usize {
        // TODO
        self.rns.bit_len_limb
    }

    pub(super) fn _assert_zero(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let (zero, one) = (N::zero(), N::one());
        let negative_wrong_modulus: Vec<N> = self.rns.negative_wrong_modulus_decomposed.clone();

        let a_int = self.rns.to_integer(a);
        let reduction_witness: MaybeReduced<W, N> = a_int.as_ref().map(|a_int| a_int.reduce()).into();
        let quotient = reduction_witness.short();
        let (t_0, t_1, t_2, t_3) = reduction_witness.intermediate_values();
        let (_, _, v_0, v_1) = reduction_witness.residues();

        // apply ranges

        let range_chip = self.range_chip();
        let quotient = &range_chip.range_value(region, &quotient.into(), self.assert_zero_quotient_range_tune(), offset)?;
        let v_0 = &range_chip.range_value(region, &v_0.into(), self.assert_zero_v0_range_tune(), offset)?;
        let v_1 = &range_chip.range_value(region, &v_1.into(), self.assert_zero_v1_range_tune(), offset)?;

        // | A   | B | C   | D |
        // | --- | - | --- | - |
        // | a_0 | q | t_0 | - |
        // | a_1 | q | t_1 | - |
        // | a_2 | q | t_2 | - |
        // | a_3 | q | t_3 | - |

        let (_, _, t_0, _, _) = main_gate.combine(
            region,
            [
                Term::Assigned(&a.limb(0), one),
                Term::Assigned(quotient, negative_wrong_modulus[0]),
                Term::Unassigned(t_0, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        let (_, _, t_1, _, _) = main_gate.combine(
            region,
            [
                Term::Assigned(&a.limb(1), one),
                Term::Assigned(quotient, negative_wrong_modulus[1]),
                Term::Unassigned(t_1, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        let (_, _, t_2, _, _) = main_gate.combine(
            region,
            [
                Term::Assigned(&a.limb(2), one),
                Term::Assigned(quotient, negative_wrong_modulus[2]),
                Term::Unassigned(t_2, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        let (_, _, t_3, _, _) = main_gate.combine(
            region,
            [
                Term::Assigned(&a.limb(3), one),
                Term::Assigned(quotient, negative_wrong_modulus[3]),
                Term::Unassigned(t_3, -one),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_0 = t_0 + t_1 * R
        // u_0 = v_0 * R^2
        // 0 = t_0 + t_1 * R - v_0 * R^2

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_0 | t_1 | v_0 | -     |

        let left_shifter_r = self.rns.left_shifter_r;
        let left_shifter_2r = self.rns.left_shifter_2r;

        main_gate.combine(
            region,
            [
                Term::Assigned(&t_0, one),
                Term::Assigned(&t_1, left_shifter_r),
                Term::Assigned(v_0, -left_shifter_2r),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // u_1 = t_2 + t_3 * R
        // v_1 * 2R = u_1 + v_0
        // 0 = t_2 + t_3 * R + v_0 - v_1 * 2R

        // | A   | B   | C   | D     |
        // | --- | --- | --- | ----- |
        // | t_2 | t_3 | v_0 | v_1   |

        main_gate.combine(
            region,
            [
                Term::Assigned(&t_2, one),
                Term::Assigned(&t_3, left_shifter_r),
                Term::Assigned(v_0, one),
                Term::Assigned(v_1, -left_shifter_2r),
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        // native red

        main_gate.combine(
            region,
            [
                Term::Assigned(&a.native(), -one),
                Term::Zero,
                Term::Assigned(quotient, self.rns.wrong_modulus_in_native_modulus),
                Term::Zero,
                Term::Zero,
            ],
            zero,
            offset,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(())
    }
}
