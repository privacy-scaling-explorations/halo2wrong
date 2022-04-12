use halo2wrong::{
    utils::{big_to_fe, decompose, fe_to_big, power_of_two},
    RegionCtx,
};

use crate::halo2::{
    arithmetic::FieldExt,
    circuit::{Cell, Chip, Layouter, Region},
    plonk::Error,
};

use crate::{Assigned, AssignedCondition, AssignedValue, UnassignedValue};

#[derive(Clone)]
pub enum Term<F: FieldExt> {
    Assigned(AssignedValue<F>, F),
    Unassigned(Option<F>, F),
    Zero,
}

impl<F: FieldExt> Term<F> {
    pub(crate) fn empty<const WIDTH: usize>() -> [Self; WIDTH] {
        vec![Self::Zero; WIDTH].try_into().unwrap()
    }
}

macro_rules! terms {
    ($arr:expr) => {{
        let mut terms = Term::empty();
        for (term, e) in terms.iter_mut().zip($arr.into_iter()) {
            *term = e
        }
        &terms.clone()
    }};
}

macro_rules! terms_with_acc {
    ($arr:expr, $acc:expr) => {{
        let mut terms = Term::empty();
        for (term, e) in terms.iter_mut().zip($arr.into_iter()) {
            *term = e.clone()
        }
        terms[WIDTH - 1] = $acc;
        &terms.clone()
    }};
}

impl<'a, F: FieldExt> std::fmt::Debug for Term<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assigned(coeff, base) => f
                .debug_struct("Assigned")
                .field("cell", &coeff.cell())
                .field("value", &coeff.value())
                .field("base", base)
                .finish(),
            Self::Unassigned(coeff, base) => f
                .debug_struct("Unassigned")
                .field("coeff", coeff)
                .field("base", base)
                .finish(),
            Self::Zero => f.debug_struct("Zero").finish(),
        }
    }
}

impl<'a, F: FieldExt> Term<F> {
    pub fn assigned_to_mul(e: &AssignedValue<F>) -> Self {
        Term::Assigned(*e, F::zero())
    }

    pub fn assigned_to_add(e: &AssignedValue<F>) -> Self {
        Term::Assigned(*e, F::one())
    }

    pub fn assigned_to_sub(e: &AssignedValue<F>) -> Self {
        Term::Assigned(*e, -F::one())
    }

    pub fn unassigned_to_mul(e: Option<F>) -> Self {
        Term::Unassigned(e, F::zero())
    }

    pub fn unassigned_to_add(e: Option<F>) -> Self {
        Term::Unassigned(e, F::one())
    }

    pub fn unassigned_to_sub(e: Option<F>) -> Self {
        Term::Unassigned(e, -F::one())
    }

    pub fn coeff(&self) -> Option<F> {
        match self {
            Self::Assigned(assigned, _) => assigned.value(),
            Self::Unassigned(unassigned, _) => *unassigned,
            Self::Zero => Some(F::zero()),
        }
    }

    pub fn base(&self) -> F {
        match self {
            Self::Assigned(_, base) => *base,
            Self::Unassigned(_, base) => *base,
            Self::Zero => F::zero(),
        }
    }

    pub fn constrain_equal(&self, region: &mut Region<'_, F>, new_cell: Cell) -> Result<(), Error> {
        match self {
            Self::Assigned(assigned, _) => assigned.constrain_equal(region, new_cell),
            _ => Ok(()),
        }
    }

    pub fn compose(terms: &[Self], constant: F) -> Option<F> {
        terms
            .iter()
            .fold(Some(constant), |acc, term| match (acc, term.coeff()) {
                (Some(acc), Some(coeff)) => Some(acc + coeff * term.base()),
                _ => None,
            })
    }
}

pub trait ColumnTags<Column> {
    fn accumulator() -> Column;
    fn first() -> Column;
}

#[derive(Clone, Debug)]
pub enum CombinationOptionCommon<F: FieldExt> {
    OneLinerMul,
    OneLinerAdd,
    CombineToNextMul(F),
    CombineToNextScaleMul(F, F),
    CombineToNextAdd(F),
}

pub trait MainGateInstructions<F: FieldExt, const WIDTH: usize>: Chip<F> {
    type CombinationOption: From<CombinationOptionCommon<F>>;
    type MainGateColumn: ColumnTags<Self::MainGateColumn>;

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        value: AssignedValue<F>,
        row: usize,
    ) -> Result<(), Error>;

    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        Ok(self.combine(
            ctx,
            terms!([Term::unassigned_to_sub(Some(constant))]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[0])
    }

    fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: &UnassignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.assign_to_column(ctx, unassigned, Self::MainGateColumn::first())
    }

    fn assign_to_acc(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: &UnassignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.assign_to_column(ctx, unassigned, Self::MainGateColumn::accumulator())
    }

    fn assign_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        bit: &UnassignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        // val * val - val  = 0

        // Witness layout:
        // | A   | B   | C   | D |
        // | --- | --- | --- | - |
        // | val | val | val | - |

        let assigned = self.combine(
            ctx,
            terms!([
                Term::unassigned_to_mul(bit.value()),
                Term::unassigned_to_mul(bit.value()),
                Term::unassigned_to_sub(bit.value()),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        ctx.constrain_equal(assigned[0].cell(), assigned[1].cell())?;
        ctx.constrain_equal(assigned[1].cell(), assigned[2].cell())?;

        Ok(assigned[2].into())
    }

    fn assert_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedCondition<F>,
    ) -> Result<(), Error> {
        let assigned = self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(&a.into()),
                Term::assigned_to_mul(&a.into()),
                Term::assigned_to_sub(&a.into()),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        ctx.constrain_equal(assigned[0].cell(), assigned[1].cell())?;
        ctx.constrain_equal(assigned[1].cell(), assigned[2].cell())?;

        Ok(())
    }

    fn one_or_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        // (a-1) * (b-1)  = 0

        // Witness layout:
        // | A   | B   | C   | D |
        // | --- | --- | --- | - |
        // | val | val | -   | - |

        let one = F::one();
        self.combine(
            ctx,
            terms!([Term::assigned_to_sub(a), Term::assigned_to_sub(b),]),
            one,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(())
    }

    fn or(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c1: &AssignedCondition<F>,
        c2: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let c = match (c1.value(), c2.value()) {
            (Some(c1), Some(c2)) => Some(c1 + c2 - c1 * c2),
            _ => None,
        };

        let zero = F::zero();

        // c + c1 * c2 - c1 - c2 = 0

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_sub(&c1.into()),
                Term::assigned_to_sub(&c2.into()),
                Term::unassigned_to_add(c),
            ]),
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2]
            .into())
    }

    fn and(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c1: &AssignedCondition<F>,
        c2: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let c = match (c1.value(), c2.value()) {
            (Some(c1), Some(c2)) => Some(c1 * c2),
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(&c1.into()),
                Term::assigned_to_mul(&c2.into()),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2]
            .into())
    }

    fn not(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let not_c = c.value().map(|c| F::one() - c);

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_add(&c.into()),
                Term::unassigned_to_add(not_c),
            ]),
            -F::one(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1]
            .into())
    }

    fn div_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = match (a.value(), b.value()) {
            (Some(a), Some(b)) => {
                let b_maybe_inverted: Option<F> = b.invert().into();
                match b_maybe_inverted {
                    Some(b_inverted) => Some(a * b_inverted),
                    // Non inversion case will never be verified
                    _ => Some(F::zero()),
                }
            }
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(b),
                Term::unassigned_to_mul(c),
                Term::assigned_to_add(a),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[1])
    }

    fn div(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error> {
        let (b_inverted, cond) = self.invert(ctx, b)?;
        let res = self.mul(ctx, a, &b_inverted)?;
        Ok((res, cond))
    }

    fn invert_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let inverse = match a.value() {
            Some(a) => match a.invert().into() {
                Some(a) => Some(a),
                // Non inversion case will never be verified
                _ => Some(F::zero()),
            },
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([Term::assigned_to_mul(a), Term::unassigned_to_mul(inverse)]),
            -F::one(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[1])
    }

    fn invert(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedCondition<F>), Error> {
        let (one, zero) = (F::one(), F::zero());

        // Returns 'r' as a condition bit that defines if inversion successful or not

        // First enfoce 'r' to be a bit
        // (a * a') - 1 + r = 0
        // r * a' - r = 0
        // if r = 1 then a' = 1
        // if r = 0 then a' = 1/a

        // Witness layout:
        // | A | B  | C | D |
        // | - | -- | - | - |
        // | a | a' | r | - |
        // | r | a' | r | - |

        let (r, a_inv) = match a.value() {
            Some(a) => match a.invert().into() {
                Some(e) => (Some(zero), Some(e)),
                None => (Some(one), Some(one)),
            },
            _ => (None, None),
        };

        let r = &self.assign_bit(ctx, &r.into())?;

        // (a * a') - 1 + r = 0
        // | A | B  | C | D |
        // | - | -- | - | - |
        // | a | a' | r | - |

        let a_inv = self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(a),
                Term::unassigned_to_mul(a_inv),
                Term::assigned_to_add(&r.into()),
            ]),
            -one,
            CombinationOptionCommon::OneLinerMul.into(),
        )?[1];

        // r * a' - r = 0
        // | A | B  | C | D |
        // | - | -- | - | - |
        // | r | a' | r | - |

        self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(&r.into()),
                Term::assigned_to_mul(&a_inv),
                Term::assigned_to_sub(&r.into()),
            ]),
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok((a_inv, *r))
    }

    fn assert_equal_to_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: F,
    ) -> Result<(), Error> {
        self.combine(
            ctx,
            terms!([Term::assigned_to_add(a)]),
            -b,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(())
    }

    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.combine(
            ctx,
            terms!([Term::assigned_to_add(a), Term::assigned_to_sub(b)]),
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(())
    }

    fn assert_not_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        // (a - b) must have an inverse
        let c = self.sub_with_constant(ctx, a, b, F::zero())?;
        self.assert_not_zero(ctx, &c)
    }

    fn is_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let (one, zero) = (F::one(), F::zero());

        // Given a and b equation below is enforced
        // 0 = (a - b) * (r * (1 - x) + x) + r - 1
        // Where r and x is witnesses and r is enforced to be a bit

        // Witness layout:
        // | A   | B | C | D |
        // | --- | - | - | - |
        // | dif | a | b | - |
        // | r   | x | u | - |
        // | dif | u | r | - |

        let (x, r) = match (a.value(), b.value()) {
            (Some(a), Some(b)) => {
                let c = a - b;
                match c.invert().into() {
                    Some(inverted) => (Some(inverted), Some(zero)),
                    None => (Some(one), Some(one)),
                }
            }
            _ => (None, None),
        };

        let r = &self.assign_bit(ctx, &r.into())?;
        let dif = self.sub(ctx, a, b)?;

        // 0 = rx - r - x + u
        // | A   | B | C | D |
        // | --- | - | - | - |
        // | r   | x | u | - |

        let u = match (r.value(), x) {
            (Some(r), Some(x)) => Some(r - r * x + x),
            _ => None,
        };

        let u = self.combine(
            ctx,
            terms!([
                Term::assigned_to_sub(&r.into()),
                Term::unassigned_to_sub(x),
                Term::unassigned_to_add(u),
            ]),
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2];

        // 0 = u * dif + r - 1
        // | A   | B | C | D |
        // | --- | - | - | - |
        // | dif | u | r | - |

        self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(&dif),
                Term::assigned_to_mul(&u),
                Term::assigned_to_add(&r.into()),
            ]),
            -one,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(*r)
    }

    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.assert_equal_to_constant(ctx, a, F::zero())
    }

    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        // Non-zero element must have an inverse
        // a * w - 1 = 0

        let w = match a.value() {
            Some(a) => match a.invert().into() {
                Some(inverted) => Some(inverted),
                // Non inversion case will never be verified
                _ => Some(F::zero()),
            },
            _ => None,
        };

        self.combine(
            ctx,
            terms!([Term::assigned_to_mul(a), Term::unassigned_to_mul(w)]),
            -F::one(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(())
    }

    fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let (_, is_zero) = self.invert(ctx, a)?;
        Ok(is_zero)
    }

    fn assert_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.assert_equal_to_constant(ctx, a, F::one())
    }

    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| a + constant);
        Ok(self.combine(
            ctx,
            terms!([Term::assigned_to_add(a), Term::unassigned_to_sub(c)]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1])
    }

    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.sub_with_constant(ctx, a, b, F::zero())
    }

    fn sub_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = match (a.value(), b.value()) {
            (Some(a), Some(b)) => Some(a - b + constant),
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_add(a),
                Term::assigned_to_sub(b),
                Term::unassigned_to_sub(c),
            ]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2])
    }

    fn neg_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| -a + constant);

        Ok(self.combine(
            ctx,
            terms!([Term::assigned_to_sub(a), Term::unassigned_to_sub(c)]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1])
    }

    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| a + a);
        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_add(a),
                Term::assigned_to_add(a),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2])
    }

    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| a + a + a);
        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_add(a),
                Term::assigned_to_add(a),
                Term::assigned_to_add(a),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[3])
    }

    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = match (a.value(), b.value()) {
            (Some(a), Some(b)) => Some(a * b),
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2])
    }

    fn mul_add(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        to_add: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = match (a.value(), b.value(), to_add.value()) {
            (Some(a), Some(b), Some(to_add)) => Some((a * b) + to_add),
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::assigned_to_add(to_add),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[3])
    }

    fn mul_add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        to_add: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = match (a.value(), b.value()) {
            (Some(a), Some(b)) => Some((a * b) + to_add),
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::unassigned_to_sub(c),
            ]),
            to_add,
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2])
    }

    fn nand(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedCondition<F>,
        b: &AssignedCondition<F>,
    ) -> Result<(), Error> {
        self.combine(
            ctx,
            terms!([
                Term::assigned_to_mul(&a.into()),
                Term::assigned_to_mul(&b.into()),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;
        Ok(())
    }

    fn assign_to_column(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: &UnassignedValue<F>,
        column: Self::MainGateColumn,
    ) -> Result<AssignedValue<F>, Error>;

    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.add_with_constant(ctx, a, b, F::zero())
    }

    fn add_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = match (a.value(), b.value()) {
            (Some(a), Some(b)) => Some(a + b + constant),
            _ => None,
        };

        Ok(self.combine(
            ctx,
            terms!([
                Term::assigned_to_add(a),
                Term::assigned_to_add(b),
                Term::unassigned_to_sub(c),
            ]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2])
    }

    fn sub_sub_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b_0: &AssignedValue<F>,
        b_1: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        to_be_selected: &AssignedValue<F>,
        to_be_assigned: F,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let w: Option<(F, F)> = a.value().map(|value| {
            use num_bigint::BigUint;
            use num_traits::{One, Zero};
            let value = &fe_to_big(value);
            let half = big_to_fe(value / 2usize);
            let sign = (value & BigUint::one() != BigUint::zero()).into();
            (sign, half)
        });

        let sign = self.assign_bit(ctx, &w.map(|w| w.0).into())?;

        self.combine(
            ctx,
            terms!([
                Term::Unassigned(w.map(|w| w.1), F::from(2)),
                Term::Assigned(sign.into(), F::one()),
                Term::Assigned(*a, -F::one()),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(sign)
    }

    fn to_bits(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        composed: &AssignedValue<F>,
        number_of_bits: usize,
    ) -> Result<Vec<AssignedCondition<F>>, Error> {
        assert!(number_of_bits <= F::NUM_BITS as usize);

        let decomposed_value = composed
            .value()
            .map(|value| decompose(value, number_of_bits, 1));

        let (terms, bits): (Vec<Term<F>>, Vec<AssignedCondition<F>>) = (0..number_of_bits)
            .map(|i| {
                let bit = decomposed_value.as_ref().map(|bits| bits[i]);
                let bit = self.assign_bit(ctx, &bit.into())?;
                let base = power_of_two(i);
                Ok((Term::Assigned(bit.into(), base), bit))
            })
            .collect::<Result<Vec<(Term<F>, AssignedCondition<F>)>, Error>>()?
            .iter()
            .cloned()
            .unzip();

        let result = self.compose(ctx, &terms[..], F::zero())?;
        self.assert_equal(ctx, &result, composed)?;
        Ok(bits)
    }

    fn compose(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        terms: &[Term<F>],
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        assert!(!terms.is_empty(), "At least one term is expected");

        // Last cell will be allocated for result or intermediate sums.
        let chunk_width: usize = WIDTH - 1;
        let number_of_chunks = (terms.len() - 1) / chunk_width + 1;

        // `remaining` at first set to the sum of terms.
        let mut remaining = Term::compose(terms, constant);
        // `result` will be assigned in the first iteration.
        // First iteration is guaranteed to be present disallowing empty
        let mut result = None;

        for (i, chunk) in terms.chunks(chunk_width).enumerate() {
            // Add constant at the very first composition row
            let constant = if i == 0 { constant } else { F::zero() };

            let intermediate = Term::Unassigned(remaining, -F::one());
            remaining = match (Term::compose(chunk, constant), remaining) {
                (Some(composed), Some(remaining)) => Some(remaining - composed),
                _ => None,
            };
            let combination_option = if i == number_of_chunks - 1 {
                // Final round sanity check
                if let Some(value) = remaining {
                    assert_eq!(value, F::zero())
                };

                CombinationOptionCommon::OneLinerAdd
            } else {
                CombinationOptionCommon::CombineToNextAdd(F::one())
            };

            let combined = self.combine(
                ctx,
                terms_with_acc!(chunk, intermediate),
                constant,
                combination_option.into(),
            )?;
            if i == 0 {
                result = Some(combined[WIDTH - 1]);
            }
        }
        Ok(result.unwrap())
    }

    fn no_operation(&self, ctx: &mut RegionCtx<'_, '_, F>) -> Result<(), Error>;

    fn combine(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        terms: &[Term<F>; WIDTH],
        constant: F,
        options: Self::CombinationOption,
    ) -> Result<[AssignedValue<F>; WIDTH], Error>;

    fn break_here(&self, ctx: &mut RegionCtx<'_, '_, F>) -> Result<(), Error> {
        self.combine(
            ctx,
            &Term::empty(),
            F::one(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;
        Ok(())
    }
}
