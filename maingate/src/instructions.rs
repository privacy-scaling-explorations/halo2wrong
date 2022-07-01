//! Basic arithmetic, logic and branching instructions for a standard like PLONK
//! gate. While many of implmentations takes place here they can be overriden
//! for optimisation purposes.

use halo2wrong::{
    halo2::plonk::Selector,
    utils::{big_to_fe, decompose, fe_to_big, power_of_two},
    RegionCtx,
};

use crate::{
    halo2::{
        arithmetic::{Field, FieldExt},
        circuit::{Chip, Layouter, Value},
        plonk::Error,
    },
    ColumnTags, MainGateColumn,
};

use crate::{AssignedCondition, AssignedValue};

/// `Term`s are input arguments for the current rows that is about to be
/// constrained in the main gate equation. Three types or terms can be expected.
/// `Assigned` is a witness that is already assigned and is about to be copy
/// constrained at current level. `Unassigned` a new witness value which will be
/// turned into a `AssignedValue`. `Zero` should be used for unused cells at the
/// current row. Non zero terms has a field element couples which are
/// multiplication factors of the term and will be assigned as fixed value in
/// synthesis time. For example in and addition circuit:
/// `... + assigned_or_unassigned_witness_0 * fixed_0 +
/// assigned_or_unassigned_witness_1 * fixed_1 + ... `
#[derive(Clone)]
pub enum Term<F: FieldExt> {
    /// Assigned value and fixed scalar
    Assigned(AssignedValue<F>, F),
    /// Unassigned witness and fixed scalar
    Unassigned(Value<F>, F),
    /// Empty term
    Zero,
}

impl<F: FieldExt> Term<F> {
    /// Given constant `WIDTH` returns all zero terms
    pub(crate) fn empty<const WIDTH: usize>() -> [Self; WIDTH] {
        vec![Self::Zero; WIDTH].try_into().unwrap()
    }

    pub(crate) fn is_zero(&self) -> bool {
        matches!(self, Term::Zero)
    }
}

/// This macro converts an array of terms sized less than `WIDTH` to the `WIDTH`
/// sized array
macro_rules! terms {
    ($arr:expr) => {{
        assert!($arr.len() < WIDTH + 1);
        let mut terms = Term::empty();
        for (term, e) in terms.iter_mut().zip($arr.into_iter()) {
            *term = e
        }
        &terms.clone()
    }};
}

/// This macro converts an array of -unchecked sized- terms to the `WIDTH`
/// sized array
macro_rules! terms_unsafe {
    ($arr:expr) => {{
        let mut terms = Term::empty();
        for (term, e) in terms.iter_mut().zip($arr.into_iter()) {
            *term = e.clone()
        }
        &terms.clone()
    }};
}

/// This macro converts an array of terms sized less than `WIDTH - 1` to the
/// `WIDTH` sized array as well as it assigns $acc value as the last term of the
/// result
macro_rules! terms_with_acc {
    // TODO/FIX: for other implementations of a standart like gate aggregation cell might be
    // different than last one
    ($arr:expr, $acc:expr) => {{
        assert!($arr.len() < WIDTH);
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
    /// Wrap an assigned value that is about to be multiplied by other term
    pub fn assigned_to_mul(e: &AssignedValue<F>) -> Self {
        Term::Assigned(e.clone(), F::zero())
    }

    /// Wrap an assigned value that is about to be added to the other terms
    pub fn assigned_to_add(e: &AssignedValue<F>) -> Self {
        Term::Assigned(e.clone(), F::one())
    }

    /// Wrap an assigned value that is about to be subtracted from the other
    /// terms
    pub fn assigned_to_sub(e: &AssignedValue<F>) -> Self {
        Term::Assigned(e.clone(), -F::one())
    }

    /// Wrap an unassigned value that is about to be multiplied by other term
    pub fn unassigned_to_mul(e: Value<F>) -> Self {
        Term::Unassigned(e, F::zero())
    }

    /// Wrap an unassigned value that is about to be added to the other terms
    pub fn unassigned_to_add(e: Value<F>) -> Self {
        Term::Unassigned(e, F::one())
    }

    /// Wrap an unassigned value that is about to be subtracted from the other
    /// terms
    pub fn unassigned_to_sub(e: Value<F>) -> Self {
        Term::Unassigned(e, -F::one())
    }

    /// Retuns the witness part of this term
    pub fn coeff(&self) -> Value<F> {
        match self {
            Self::Assigned(assigned, _) => assigned.value().copied(),
            Self::Unassigned(unassigned, _) => *unassigned,
            Self::Zero => Value::known(F::zero()),
        }
    }

    /// Retuns the fixed part of this term
    pub fn base(&self) -> F {
        match self {
            Self::Assigned(_, base) => *base,
            Self::Unassigned(_, base) => *base,
            Self::Zero => F::zero(),
        }
    }

    /// Composes terms as
    /// `w_0 * s_0 + w_1 * s_1 + ...`
    /// And retuns the calculated witness
    pub fn compose(terms: &[Self], constant: F) -> Value<F> {
        terms.iter().fold(Value::known(constant), |acc, term| {
            acc.zip(term.coeff())
                .map(|(acc, coeff)| acc + coeff * term.base())
        })
    }
}

/// Common combination options defines the behaviour of the `main_gate` at the
/// current row. Options here can be applied most of the standart like circuits
/// when it has one multiplication gate one addition gate and one further
/// rotation gate.
#[derive(Clone, Debug)]
pub enum CombinationOptionCommon<F: FieldExt> {
    /// Opens only single multiplication gate
    OneLinerMul,
    /// All multiplications gates are closed
    OneLinerAdd,
    /// Opens only single multiplication gate and combines terms to the next
    /// row
    CombineToNextMul(F),
    /// Opens only single multiplication gate and combines terms to the next
    /// row and scales the multiplied factors with constant as `constant *
    /// witness_0 * witness_1`
    CombineToNextScaleMul(F, F),
    /// All multipcation gates are closed and combines terms to the next
    /// row
    CombineToNextAdd(F),
}

/// Instructions covers many basic constaints such as assignments, logical and
/// arithmetic operations. Also includes general purpose `combine` and  `apply`
/// functions to let user to build custom constaints using this main gate
pub trait MainGateInstructions<F: FieldExt, const WIDTH: usize>: Chip<F> {
    /// Options for implementors to implement some more custom functionalities
    type CombinationOption: From<CombinationOptionCommon<F>>;
    /// Position related customisations should be defined as ['MainGateColumn']
    type MainGateColumn: ColumnTags<Self::MainGateColumn>;

    /// Expect an assigned value to be equal to a public input
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        value: AssignedValue<F>,
        row: usize,
    ) -> Result<(), Error>;

    /// Constrain a witness to be equal to a fixed value. This should allow us
    /// to move a fixed value around
    fn assign_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let e = &self.apply(
            ctx,
            terms!([Term::unassigned_to_sub(Value::known(constant))]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[0];

        Ok(e.clone())
    }

    /// Assigns a value at the current row
    fn assign_value(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.assign_to_column(ctx, unassigned, Self::MainGateColumn::first())
    }

    /// Assigns a value to the column that is allocated for accumulation purpose
    fn assign_to_acc(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        unassigned: Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.assign_to_column(ctx, unassigned, Self::MainGateColumn::next())
    }

    /// Assigns new witness to the specified column
    fn assign_to_column(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        value: Value<F>,
        column: Self::MainGateColumn,
    ) -> Result<AssignedValue<F>, Error>;

    /// Assigns given value and enforces that the value is `0` or `1`
    /// `val * val - val  = 0`
    fn assign_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        bit: Value<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let assigned = &self.apply(
            ctx,
            terms!([
                Term::unassigned_to_mul(bit),
                Term::unassigned_to_mul(bit),
                Term::unassigned_to_sub(bit),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        ctx.constrain_equal(assigned[0].cell(), assigned[1].cell())?;
        ctx.constrain_equal(assigned[1].cell(), assigned[2].cell())?;

        Ok(assigned[2].clone())
    }

    /// Enforces given witness value is `0` or `1`
    /// `val * val - val  = 0`
    fn assert_bit(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        bit: &AssignedCondition<F>,
    ) -> Result<(), Error> {
        let assigned = self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(bit),
                Term::assigned_to_mul(bit),
                Term::assigned_to_sub(bit),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        ctx.constrain_equal(assigned[0].cell(), assigned[1].cell())?;
        ctx.constrain_equal(assigned[1].cell(), assigned[2].cell())?;

        Ok(())
    }

    /// Enforces one of given two values is `1`
    /// `(a-1) * (b-1)  = 0`
    fn one_or_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedCondition<F>,
        b: &AssignedCondition<F>,
    ) -> Result<(), Error> {
        self.apply(
            ctx,
            terms!([Term::assigned_to_sub(a), Term::assigned_to_sub(b),]),
            F::one(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(())
    }

    /// Assigns new value equal to `1` if `c1 | c0 = 1`,
    /// equal to `0` if `c1 | c0 = 0`,
    // `new_assigned_value + c1 * c2 - c1 - c2 = 0`.
    fn or(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c1: &AssignedCondition<F>,
        c2: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        // Find the new witness
        let c = c1
            .value()
            .zip(c2.value())
            .map(|(c1, c2)| *c1 + *c2 - *c1 * *c2);

        let ret = &self.apply(
            ctx,
            terms!([
                Term::assigned_to_sub(c1),
                Term::assigned_to_sub(c2),
                Term::unassigned_to_add(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2];

        Ok(ret.clone())
    }

    /// Assigns new value equal to `1` if `c1 && c0 = 1`,
    /// equal to `0` if `c1 && c0 = 0`
    fn and(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c1: &AssignedCondition<F>,
        c2: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        // Find the new witness
        let c = c1.value().zip(c2.value()).map(|(c1, c2)| *c1 * *c2);

        Ok((&self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(c1),
                Term::assigned_to_mul(c2),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2])
            .clone())
    }

    /// Assigns new value that is logic inverse of the given assigned value.
    fn not(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        c: &AssignedCondition<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        // Find the new witness
        let not_c = c.value().map(|c| F::one() - c);

        Ok((&self.apply(
            ctx,
            terms!([Term::assigned_to_add(c), Term::unassigned_to_add(not_c),]),
            -F::one(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1])
            .clone())
    }

    /// Assigns new witness that should be equal to `a/b`. This function is
    /// unsafe because if witenss `b` is zero it cannot find a valid witness.
    fn div_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        // Find the new witness
        let c = a.value().zip(b.value()).map(|(a, b)| {
            // Non inversion case will never be verified
            Option::<F>::from(b.invert())
                .map(|b_inverted| *a * b_inverted)
                .unwrap_or_else(F::zero)
        });

        Ok((&self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(b),
                Term::unassigned_to_mul(c),
                Term::assigned_to_add(a),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[1])
            .clone())
    }

    /// Assigns new witness that should be equal to `a/b`. if `b` is non
    /// invertible expect `cond` flag is assigned to `0` otherwise `1`.
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

    /// Assigns new witness that should be equal to `1/a`. This function is
    /// unsafe because if the witness eqauls to zero a valid witness cannot be
    /// found.
    fn invert_unsafe(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let inverse = a.value().map(|a| {
            // Non inversion case will never be verified.
            a.invert().unwrap_or_else(F::zero)
        });

        Ok((&self.apply(
            ctx,
            terms!([Term::assigned_to_mul(a), Term::unassigned_to_mul(inverse)]),
            -F::one(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[1])
            .clone())
    }

    /// Assigns new witness that should be equal to `1/a`. if `a` is non
    /// invertible expect `cond` flag is assigned to `0` otherwise `1`.
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
        // | A | B  | C |
        // | - | -- | - |
        // | a | a' | r |
        // | r | a' | r |

        let (r, a_inv) = a
            .value()
            .map(|a| {
                Option::from(a.invert())
                    .map(|a_inverted| (zero, a_inverted))
                    .unwrap_or_else(|| (one, one))
            })
            .unzip();

        let r = self.assign_bit(ctx, r)?;

        // (a * a') - 1 + r = 0
        // | A | B  | C |
        // | - | -- | - |
        // | a | a' | r |

        let a_inv = (&self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(a),
                Term::unassigned_to_mul(a_inv),
                Term::assigned_to_add(&r),
            ]),
            -one,
            CombinationOptionCommon::OneLinerMul.into(),
        )?[1])
            .clone();

        // r * a' - r = 0
        // | A | B  | C |
        // | - | -- | - |
        // | r | a' | r |

        self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(&r),
                Term::assigned_to_mul(&a_inv),
                Term::assigned_to_sub(&r),
            ]),
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok((a_inv, r))
    }

    /// Enforces an assinged value to be equal to a fixed value.
    fn assert_equal_to_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: F,
    ) -> Result<(), Error> {
        self.apply(
            ctx,
            terms!([Term::assigned_to_add(a)]),
            -b,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(())
    }

    /// Enforces two witnesses are equal.
    fn assert_equal(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.apply(
            ctx,
            terms!([Term::assigned_to_add(a), Term::assigned_to_sub(b)]),
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(())
    }

    /// Enforces two witness is not equal
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

    /// Assigns new value that flags if two value is equal
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
        // | A   | B | C |
        // | --- | - | - |
        // | dif | a | b |
        // | r   | x | u |
        // | dif | u | r |

        let (x, r) = a
            .value()
            .zip(b.value())
            .map(|(a, b)| {
                let c = *a - b;
                Option::from(c.invert())
                    .map(|c_inverted| (c_inverted, zero))
                    .unwrap_or_else(|| (one, one))
            })
            .unzip();

        let r = self.assign_bit(ctx, r)?;
        let dif = self.sub(ctx, a, b)?;

        // 0 = rx - r - x + u
        // | A   | B | C |
        // | --- | - | - |
        // | r   | x | u |

        let u = x.zip(r.value()).map(|(x, r)| *r - *r * x + x);

        let u = (&self.apply(
            ctx,
            terms!([
                Term::assigned_to_sub(&r),
                Term::unassigned_to_sub(x),
                Term::unassigned_to_add(u),
            ]),
            zero,
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2])
            .clone();

        // 0 = u * dif + r - 1
        // | A   | B | C |
        // | --- | - | - |
        // | dif | u | r |

        self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(&dif),
                Term::assigned_to_mul(&u),
                Term::assigned_to_add(&r),
            ]),
            -one,
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(r)
    }

    /// Enforces that assigned value is zero % w
    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.assert_equal_to_constant(ctx, a, F::zero())
    }

    /// Enforces that assigned value is not zero.
    fn assert_not_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        // Non-zero element must have an inverse
        // a * w - 1 = 0

        let w = a.value().map(|a| {
            // Non inversion case will never be verified.
            a.invert().unwrap_or_else(F::zero)
        });

        self.apply(
            ctx,
            terms!([Term::assigned_to_mul(a), Term::unassigned_to_mul(w)]),
            -F::one(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;

        Ok(())
    }

    /// Assigns new bit flag `1` if given value eqauls to `0` otherwise assigns
    /// `0`
    fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let (_, is_zero) = self.invert(ctx, a)?;
        Ok(is_zero)
    }

    /// Assigns new bit flag `1` if given value eqauls to `1` otherwise assigns
    /// `0`
    fn assert_one(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<(), Error> {
        self.assert_equal_to_constant(ctx, a, F::one())
    }

    /// Assigns a new witness `r` as:
    /// `r = a + constant`
    fn add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| *a + constant);
        Ok((&self.apply(
            ctx,
            terms!([Term::assigned_to_add(a), Term::unassigned_to_sub(c)]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1])
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = a - b`
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.sub_with_constant(ctx, a, b, F::zero())
    }

    /// Assigns a new witness `r` as:
    /// `r = a - b + constant`
    fn sub_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().zip(b.value()).map(|(a, b)| *a - b + constant);

        Ok((&self.apply(
            ctx,
            terms!([
                Term::assigned_to_add(a),
                Term::assigned_to_sub(b),
                Term::unassigned_to_sub(c),
            ]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2])
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = -a + constant`
    fn neg_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| -*a + constant);

        Ok((&self.apply(
            ctx,
            terms!([Term::assigned_to_sub(a), Term::unassigned_to_sub(c)]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[1])
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = a + a`
    fn mul2(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| *a + a);
        Ok((&self.apply(
            ctx,
            terms!([
                Term::assigned_to_add(a),
                Term::assigned_to_add(a),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2])
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = a + a + a`
    fn mul3(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().map(|a| *a + a + a);
        Ok((&self.apply(
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
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = a * b`
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().zip(b.value()).map(|(a, b)| *a * b);

        Ok((&self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::unassigned_to_sub(c),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2])
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = a * b + to_add`
    fn mul_add(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        to_add: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a
            .value()
            .zip(b.value())
            .zip(to_add.value())
            .map(|((a, b), to_add)| *a * b + to_add);

        Ok((&self.apply(
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
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = a * b + constant`
    fn mul_add_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        to_add: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().zip(b.value()).map(|(a, b)| *a * b + to_add);

        Ok((&self.apply(
            ctx,
            terms!([
                Term::assigned_to_mul(a),
                Term::assigned_to_mul(b),
                Term::unassigned_to_sub(c),
            ]),
            to_add,
            CombinationOptionCommon::OneLinerMul.into(),
        )?[2])
            .clone())
    }

    /// Assigns a new bit witness `r` to `0` if both given witneeses are not `0`
    /// otherwise `1`
    fn nand(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedCondition<F>,
        b: &AssignedCondition<F>,
    ) -> Result<(), Error> {
        self.apply(
            ctx,
            terms!([Term::assigned_to_mul(a), Term::assigned_to_mul(b),]),
            F::zero(),
            CombinationOptionCommon::OneLinerMul.into(),
        )?;
        Ok(())
    }

    /// Assigns a new witness `r` as:
    /// `r = a * b`
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        self.add_with_constant(ctx, a, b, F::zero())
    }

    /// Assigns a new witness `r` as:
    /// `r = a * b + constant`
    fn add_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().zip(b.value()).map(|(a, b)| *a + b + constant);

        Ok((&self.apply(
            ctx,
            terms!([
                Term::assigned_to_add(a),
                Term::assigned_to_add(b),
                Term::unassigned_to_sub(c),
            ]),
            constant,
            CombinationOptionCommon::OneLinerAdd.into(),
        )?[2])
            .clone())
    }

    /// Assigns a new witness `r` as:
    /// `r = a - b_0 - b_1 + constant`
    fn sub_sub_with_constant(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b_0: &AssignedValue<F>,
        b_1: &AssignedValue<F>,
        constant: F,
    ) -> Result<AssignedValue<F>, Error>;

    /// Assings new witness that equals to `a` if `cond` is true or assigned to
    /// `b` if `cond is false
    fn select(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
        b: &AssignedValue<F>,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Assings new witness that equals to `to_be_selected` if `cond` is true or
    /// assigned to `to_be_assigned` which is a constat if `cond is false
    fn select_or_assign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        to_be_selected: &AssignedValue<F>,
        to_be_assigned: F,
        cond: &AssignedCondition<F>,
    ) -> Result<AssignedValue<F>, Error>;

    /// Assignes new value equals to `1` if first bit of `a` is `1` or assigns
    /// `0` if first bit of `a` is `0`
    fn sign(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedCondition<F>, Error> {
        let w: Value<(F, F)> = a.value().map(|value| {
            use num_bigint::BigUint;
            use num_traits::{One, Zero};
            let value = &fe_to_big(*value);
            let half = big_to_fe(value / 2usize);
            let sign = ((value & BigUint::one() != BigUint::zero()) as u64).into();
            (sign, half)
        });

        let sign = self.assign_bit(ctx, w.map(|w| w.0))?;

        self.apply(
            ctx,
            terms!([
                Term::Unassigned(w.map(|w| w.1), F::from(2)),
                Term::Assigned(sign.clone(), F::one()),
                Term::Assigned(a.clone(), -F::one()),
            ]),
            F::zero(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;

        Ok(sign)
    }

    /// Assigns array values of bit values which is equal to decomposition of
    /// given assigned value
    fn to_bits(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        composed: &AssignedValue<F>,
        number_of_bits: usize,
    ) -> Result<Vec<AssignedCondition<F>>, Error> {
        assert!(number_of_bits <= F::NUM_BITS as usize);

        let decomposed_value = composed
            .value()
            .map(|value| decompose(*value, number_of_bits, 1));

        let (terms, bits): (Vec<Term<F>>, Vec<AssignedCondition<F>>) = (0..number_of_bits)
            .map(|i| {
                let bit = decomposed_value.as_ref().map(|bits| bits[i]);
                let bit = self.assign_bit(ctx, bit)?;
                let base = power_of_two(i);
                Ok((Term::Assigned(bit.clone(), base), bit))
            })
            .collect::<Result<Vec<(Term<F>, AssignedCondition<F>)>, Error>>()?
            .iter()
            .cloned()
            .unzip();

        let result = self.compose(ctx, &terms[..], F::zero())?;
        self.assert_equal(ctx, &result, composed)?;
        Ok(bits)
    }

    /// Assigns a new witness composed of given array of terms
    /// `result = constant + term_0 + term_1 + ... `
    /// where `term_i = a_i * q_i`
    fn decompose<T: FnMut(bool) -> Vec<Selector>>(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        terms: &[Term<F>],
        constant: F,
        mut fetch_tables: T,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        assert!(!terms.is_empty(), "At least one term is expected");

        // Remove zero iterms
        let terms: Vec<Term<F>> = terms
            .to_vec()
            .into_iter()
            .filter(|e| !e.is_zero())
            .collect();

        // Last cell will be allocated for result or intermediate sums.
        let chunk_width: usize = WIDTH - 1;
        let number_of_chunks = (terms.len() - 1) / chunk_width + 1;

        // `remaining` at first set to the sum of terms.
        let mut remaining = Term::compose(&terms[..], constant);
        // `result` will be assigned in the first iteration.
        // First iteration is guaranteed to be present disallowing empty
        let mut result = None;
        let last_term_index: usize = MainGateColumn::last_term_index();

        let mut assigned: Vec<AssignedValue<F>> = vec![];
        for (i, chunk) in terms.chunks(chunk_width).enumerate() {
            let intermediate = Term::Unassigned(remaining, -F::one());
            let constant = if i == 0 { constant } else { F::zero() };
            let mut chunk = chunk.to_vec();

            let composed = Term::compose(&chunk[..], constant);

            remaining = composed
                .zip(remaining)
                .map(|(composed, remaining)| remaining - composed);

            let is_final = i == number_of_chunks - 1;
            // Final round
            let combination_option = if is_final {
                // Sanity check
                remaining.assert_if_known(Field::is_zero_vartime);

                // Assign last term to the first column to enable overflow range check
                let last_term = chunk.pop().unwrap();
                chunk.insert(last_term_index, last_term);

                CombinationOptionCommon::OneLinerAdd
            // Intermediate round should accumulate the sum
            } else {
                CombinationOptionCommon::CombineToNextAdd(F::one())
            };

            // Enable tables if there is any
            let tables = fetch_tables(is_final);
            for table in tables {
                ctx.enable(table)?;
            }

            let chunk_len = chunk.len();
            let combined = self.apply(
                ctx,
                terms_with_acc!(chunk, intermediate),
                constant,
                combination_option.into(),
            )?;

            // Set the result at the first iter
            if i == 0 {
                result = Some(combined[WIDTH - 1].clone());
            }

            let mut combined = combined[..chunk_len].to_vec();
            if is_final {
                // Rewind the overflow range trick
                let last_term = combined.remove(last_term_index);
                combined.push(last_term);
            }
            assigned.extend(combined.into_iter().take(chunk_len));
        }
        Ok((result.unwrap(), assigned))
    }

    /// Assigns a new witness composed of given array of terms
    /// `result = constant + term_0 + term_1 + ... `
    /// where `term_i = a_i * q_i`
    fn compose(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        terms: &[Term<F>],
        constant: F,
    ) -> Result<AssignedValue<F>, Error> {
        assert!(!terms.is_empty(), "At least one term is expected");
        let (composed, _) = self.decompose(ctx, terms, constant, |_| vec![])?;

        Ok(composed)
    }

    /// Given array of terms asserts sum is equal to zero
    /// `constant + term_0 + term_1 + ... `
    /// where `term_i = a_i * q_i`
    fn assert_zero_sum(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        terms: &[Term<F>],
        constant: F,
    ) -> Result<(), Error> {
        assert!(!terms.is_empty(), "At least one term is expected");

        // Remove zero iterms
        let terms: Vec<Term<F>> = terms
            .to_vec()
            .into_iter()
            .filter(|e| !e.is_zero())
            .collect();

        let one_liner = terms.len() <= WIDTH;

        // Apply the first chunk
        self.apply(
            ctx,
            terms_unsafe!(*terms),
            constant,
            if one_liner {
                CombinationOptionCommon::OneLinerAdd
            } else {
                CombinationOptionCommon::CombineToNextAdd(-F::one())
            }
            .into(),
        )?;

        // And the rest if there are more terms
        if !one_liner {
            let chunk_width: usize = WIDTH - 1;
            let mut intermediate_sum = Term::compose(&terms[..WIDTH], constant);
            let terms = &terms[WIDTH..];
            let number_of_chunks = (terms.len() - 1) / chunk_width + 1;

            for (i, chunk) in terms.chunks(chunk_width).enumerate() {
                self.apply(
                    ctx,
                    terms_with_acc!(chunk, Term::Unassigned(intermediate_sum, F::one())),
                    F::zero(),
                    if i == number_of_chunks - 1 {
                        CombinationOptionCommon::OneLinerAdd
                    } else {
                        CombinationOptionCommon::CombineToNextAdd(-F::one())
                    }
                    .into(),
                )?;

                intermediate_sum = intermediate_sum
                    .zip(Term::compose(chunk, F::zero()))
                    .map(|(cur, result)| cur + result);

                // // Sanity check for prover
                // if i == number_of_chunks - 1 {
                //     if let Some(value) = intermediate_sum {
                //         assert_eq!(value, F::zero())
                //     };
                // }
            }
        }
        Ok(())
    }

    /// Increments the offset with all zero selectors
    fn no_operation(&self, ctx: &mut RegionCtx<'_, '_, F>) -> Result<(), Error>;

    /// Given specific option combines `WIDTH` sized terms and assigns new
    /// value.
    fn apply(
        &self,
        ctx: &mut RegionCtx<'_, '_, F>,
        terms: &[Term<F>; WIDTH],
        constant: F,
        options: Self::CombinationOption,
    ) -> Result<[AssignedValue<F>; WIDTH], Error>;

    /// Intentionally introduce not to be satisfied witnesses. Use only for
    /// debug purposes.
    fn break_here(&self, ctx: &mut RegionCtx<'_, '_, F>) -> Result<(), Error> {
        self.apply(
            ctx,
            &Term::empty(),
            F::one(),
            CombinationOptionCommon::OneLinerAdd.into(),
        )?;
        Ok(())
    }
}
