use super::{IntegerChip, IntegerInstructions};
use crate::circuit::main_gate::MainGateInstructions;
use crate::circuit::AssignedInteger;
use crate::NUMBER_OF_LIMBS;
use halo2::arithmetic::FieldExt;
use halo2::circuit::Region;
use halo2::plonk::Error;

impl<W: FieldExt, N: FieldExt> IntegerChip<W, N> {
    pub(crate) fn _sub(&self, region: &mut Region<'_, N>, a: &mut AssignedInteger<N>, b: &mut AssignedInteger<N>) -> Result<AssignedInteger<N>, Error> {
        let main_gate = self.main_gate();
        let mut offset = 0;

        let c = a.integer().map(|integer_a| {
            let b_integer = b.integer().unwrap();
            self.rns.sub(&integer_a, &b_integer)
        });

        let c = &mut self.assign_integer(region, c, &mut offset)?;

        let aux: Vec<N> = self.rns.aux.limbs();

        for idx in 0..NUMBER_OF_LIMBS {
            let a_limb = &mut a.limb(idx);
            let b_limb = &mut b.limb(idx);
            let c_limb = &mut c.limb(idx);
            c_limb.negate();
            main_gate.assert_add_with_aux(region, a_limb, b_limb, c_limb, aux[idx], &mut offset)?;
            a.update_limb_cell(idx, a_limb.cell);
            b.update_limb_cell(idx, b_limb.cell);
            c.update_limb_cell(idx, c_limb.cell);

            offset += 1;
        }

        let a_native = &mut a.native_value_x();
        let b_native = &mut b.native_value_x();
        let c_native = &mut c.native_value_x();
        c_native.negate();
        main_gate.assert_add(region, a_native, b_native, c_native, &mut offset)?;
        a.update_native_cell(a_native.cell);
        b.update_native_cell(b_native.cell);
        c.update_native_cell(c_native.cell);

        Ok(c.clone())
    }
}
