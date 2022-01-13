use super::{IntegerChip, IntegerInstructions, Range};
use crate::{circuit::AssignedInteger, WrongExt};
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;
use halo2arith::{halo2, Assigned, AssignedCondition, CombinationOptionCommon, MainGateInstructions, Term};

impl<W: WrongExt, N: FieldExt> IntegerChip<W, N> {
    pub(super) fn _invert(
        &self,
        region: &mut Region<'_, N>,
        a: &AssignedInteger<N>,
        offset: &mut usize,
    ) -> Result<(AssignedInteger<N>, AssignedCondition<N>), Error> {
        let main_gate = self.main_gate();

        let one = N::one();
        let integer_one = self.rns.new_from_big(1u32.into());

        let a_int = self.rns.to_integer(a);

        let inv_or_one = match a_int.as_ref() {
            Some(a) => match a.invert() {
                Some(a) => Some(a),
                None => Some(integer_one),
            },
            None => None,
        };

        // TODO: For range constraints, we have these options:
        // 1. extend mul to support prenormalized value.
        // 2. call normalize here.
        // 3. add wrong field range check on inv.
        let inv_or_one = self.range_assign_integer(region, inv_or_one.into(), Range::Remainder, offset)?;
        let a_mul_inv = &self.mul(region, &a, &inv_or_one, offset)?;

        // We believe the mul result is strictly less than wrong modulus, so we add strict constraints here.
        // The limbs[1..NUMBER_OF_LIMBS] of a_mul_inv should be 0.
        self.assert_strict_bit(region, a_mul_inv, offset)?;

        // If a_mul_inv is 0 (i.e. not 1), then inv_or_one must be 1.
        // inv_or_one = 1 <-> inv_or_one[0] = 1 /\ inv_or_one.natvie = 1.
        // Here we short x.limbs[i] as x[i].
        // 1. (a_mul_inv[0] - 1) * (inv_or_one.native - 1) = 0
        // 2. (a_mul_inv[0] - 1) * (inv_or_one[0] - 1) = 0
        main_gate.one_or_one(region, a_mul_inv.limb(0), inv_or_one.native(), offset)?;
        main_gate.one_or_one(region, a_mul_inv.limb(0), inv_or_one.limb(0), offset)?;

        // Align with main_gain.invert(), cond = 1 - a_mul_inv
        let cond = a_mul_inv.limb(0).value().map(|a_mul_inv| one - a_mul_inv);
        let (_, cond, _, _, _) = main_gate.combine(
            region,
            [
                Term::Assigned(&a_mul_inv.limbs[0], one),
                Term::Unassigned(cond, one),
                Term::Zero,
                Term::Zero,
                Term::Zero,
            ],
            -one,
            offset,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok((inv_or_one, cond.into()))
    }

    pub(crate) fn _invert_incomplete(&self, region: &mut Region<'_, N>, a: &AssignedInteger<N>, offset: &mut usize) -> Result<AssignedInteger<N>, Error> {
        let a_int = self.rns.to_integer(a);
        let inv = match a_int.as_ref() {
            Some(a) => match a.invert() {
                Some(a) => Some(a),
                None => {
                    // any number will fail it if a is zero
                    // no assertion here for now since we might want to fail in tests
                    Some(self.rns.new_from_big(666u32.into()))
                }
            },
            None => None,
        };

        let inv = self.range_assign_integer(region, inv.into(), Range::Remainder, offset)?;
        // let must_be_one = &self.mul(region, &a, &inv, offset)?;
        // self.assert_strict_one(region, must_be_one, offset)?;
        self._mul_into_one(region, &a, &inv, offset)?;

        Ok(inv)
    }
}
