//! This module contains implementations for the Pallas and Vesta elliptic curve
//! groups.

use core::cmp;
use core::fmt;
use core::iter::Sum;
use core::ops::{Add, Mul, Neg, Sub};

#[cfg(not(feature = "kzg"))]
use alloc::boxed::Box;

use core::convert::TryInto;
use ff::{Field, PrimeField};
use group::{
    cofactor::{CofactorCurve, CofactorGroup},
    prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup},
    Curve as _, Group as _, GroupEncoding,
};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{Fp, Fq};

use halo2wrong::halo2::arithmetic::{Coordinates, CurveAffine, CurveExt, Group};

macro_rules! new_curve_impl {
    (($($privacy:tt)*), $name:ident, $name_affine:ident, $base:ident, $scalar:ident,
     $curve_id:literal, $a_raw:expr, $b_raw:expr, $curve_type:ident) => {
        /// Represents a point in the projective coordinate space.
        #[derive(Copy, Clone, Debug)]
        $($privacy)* struct $name {
            x: $base,
            y: $base,
            z: $base,
        }

        impl $name {
            const fn curve_constant_a() -> $base {
                $base::from_raw($a_raw)
            }

            const fn curve_constant_b() -> $base {
                $base::from_raw($b_raw)
            }
        }

        /// Represents a point in the affine coordinate space (or the point at
        /// infinity).
        #[derive(Copy, Clone)]
        $($privacy)* struct $name_affine {
            x: $base,
            y: $base,
            infinity: Choice,
        }

        impl fmt::Debug for $name_affine {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                if self.infinity.into() {
                    write!(f, "Infinity")
                } else {
                    write!(f, "({:?}, {:?})", self.x, self.y)
                }
            }
        }

        impl group::Group for $name {
            type Scalar = $scalar;

            fn random(mut rng: impl RngCore) -> Self {
                loop {
                    let x = $base::random(&mut rng);
                    let ysign = (rng.next_u32() % 2) as u8;

                    let x3 = x.square() * x;
                    let y = (x3 + $name::curve_constant_b()).sqrt();
                    if let Some(y) = Option::<$base>::from(y) {
                        let sign = y.is_odd().unwrap_u8();
                        let y = if ysign ^ sign == 0 { y } else { -y };

                        let p = $name_affine {
                            x,
                            y,
                            infinity: Choice::from(0u8),
                        };
                        break p.to_curve();
                    }
                }
            }

            impl_projective_curve_specific!($name, $base, $curve_type);

            fn identity() -> Self {
                Self {
                    x: $base::zero(),
                    y: $base::zero(),
                    z: $base::zero(),
                }
            }

            fn is_identity(&self) -> Choice {
                self.z.is_zero()
            }
        }

        impl group::WnafGroup for $name {
            fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
                // Copied from bls12_381::g1, should be updated.
                const RECOMMENDATIONS: [usize; 12] =
                    [1, 3, 7, 20, 43, 120, 273, 563, 1630, 3128, 7933, 62569];

                let mut ret = 4;
                for r in &RECOMMENDATIONS {
                    if num_scalars > *r {
                        ret += 1;
                    } else {
                        break;
                    }
                }

                ret
            }
        }

        impl CurveExt for $name {
            type ScalarExt = $scalar;
            type Base = $base;
            type AffineExt = $name_affine;

            const CURVE_ID: &'static str = $curve_id;

            impl_projective_curve_ext!($name, $base, $curve_type);

            #[cfg(not(feature = "kzg"))]
            fn a() -> Self::Base {
                $name::curve_constant_a()
            }

            fn b() -> Self::Base {
                $name::curve_constant_b()
            }

            fn new_jacobian(x: Self::Base, y: Self::Base, z: Self::Base) -> CtOption<Self> {
                let p = $name { x, y, z };
                CtOption::new(p, p.is_on_curve())
            }

            fn jacobian_coordinates(&self) -> ($base, $base, $base) {
               (self.x, self.y, self.z)
            }

            fn is_on_curve(&self) -> Choice {
                // Y^2 = X^3 + AX(Z^4) + b(Z^6)
                // Y^2 - (X^2 + A(Z^4))X = b(Z^6)

                let z2 = self.z.square();
                let z4 = z2.square();
                let z6 = z4 * z2;
                (self.y.square() - (self.x.square() + $name::curve_constant_a() * z4) * self.x)
                    .ct_eq(&(z6 * $name::curve_constant_b()))
                    | self.z.is_zero()
            }
        }

        impl group::Curve for $name {
            type AffineRepr = $name_affine;

            fn batch_normalize(p: &[Self], q: &mut [Self::AffineRepr]) {
                assert_eq!(p.len(), q.len());

                let mut acc = $base::one();
                for (p, q) in p.iter().zip(q.iter_mut()) {
                    // We use the `x` field of $name_affine to store the product
                    // of previous z-coordinates seen.
                    q.x = acc;

                    // We will end up skipping all identities in p
                    acc = $base::conditional_select(&(acc * p.z), &acc, p.is_identity());
                }

                // This is the inverse, as all z-coordinates are nonzero and the ones
                // that are not are skipped.
                acc = acc.invert().unwrap();

                for (p, q) in p.iter().rev().zip(q.iter_mut().rev()) {
                    let skip = p.is_identity();

                    // Compute tmp = 1/z
                    let tmp = q.x * acc;

                    // Cancel out z-coordinate in denominator of `acc`
                    acc = $base::conditional_select(&(acc * p.z), &acc, skip);

                    // Set the coordinates to the correct value
                    let tmp2 = tmp.square();
                    let tmp3 = tmp2 * tmp;

                    q.x = p.x * tmp2;
                    q.y = p.y * tmp3;
                    q.infinity = Choice::from(0u8);

                    *q = $name_affine::conditional_select(&q, &$name_affine::identity(), skip);
                }
            }

            fn to_affine(&self) -> Self::AffineRepr {
                let zinv = self.z.invert().unwrap_or($base::zero());
                let zinv2 = zinv.square();
                let x = self.x * zinv2;
                let zinv3 = zinv2 * zinv;
                let y = self.y * zinv3;

                let tmp = $name_affine {
                    x,
                    y,
                    infinity: Choice::from(0u8),
                };

                $name_affine::conditional_select(&tmp, &$name_affine::identity(), zinv.is_zero())
            }
        }

        impl PrimeGroup for $name {}

        impl CofactorGroup for $name {
            type Subgroup = $name;

            fn clear_cofactor(&self) -> Self {
                // This is a prime-order group, with a cofactor of 1.
                *self
            }

            fn into_subgroup(self) -> CtOption<Self::Subgroup> {
                // Nothing to do here.
                CtOption::new(self, 1.into())
            }

            fn is_torsion_free(&self) -> Choice {
                // Shortcut: all points in a prime-order group are torsion free.
                1.into()
            }
        }

        impl PrimeCurve for $name {
            type Affine = $name_affine;
        }

        impl CofactorCurve for $name {
            type Affine = $name_affine;
        }

        impl<'a> From<&'a $name_affine> for $name {
            fn from(p: &'a $name_affine) -> $name {
                p.to_curve()
            }
        }

        impl From<$name_affine> for $name {
            fn from(p: $name_affine) -> $name {
                p.to_curve()
            }
        }

        impl Default for $name {
            fn default() -> $name {
                $name::identity()
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                // Is (xz^2, yz^3, z) equal to (x'z'^2, yz'^3, z') when converted to affine?

                let z = other.z.square();
                let x1 = self.x * z;
                let z = z * other.z;
                let y1 = self.y * z;
                let z = self.z.square();
                let x2 = other.x * z;
                let z = z * self.z;
                let y2 = other.y * z;

                let self_is_zero = self.is_identity();
                let other_is_zero = other.is_identity();

                (self_is_zero & other_is_zero) // Both point at infinity
                            | ((!self_is_zero) & (!other_is_zero) & x1.ct_eq(&x2) & y1.ct_eq(&y2))
                // Neither point at infinity, coordinates are the same
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl cmp::Eq for $name {}

        impl ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                $name {
                    x: $base::conditional_select(&a.x, &b.x, choice),
                    y: $base::conditional_select(&a.y, &b.y, choice),
                    z: $base::conditional_select(&a.z, &b.z, choice),
                }
            }
        }

        impl<'a> Neg for &'a $name {
            type Output = $name;

            fn neg(self) -> $name {
                $name {
                    x: self.x,
                    y: -self.y,
                    z: self.z,
                }
            }
        }

        impl Neg for $name {
            type Output = $name;

            fn neg(self) -> $name {
                -&self
            }
        }

        impl<T> Sum<T> for $name
        where
            T: core::borrow::Borrow<$name>,
        {
            fn sum<I>(iter: I) -> Self
            where
                I: Iterator<Item = T>,
            {
                iter.fold(Self::identity(), |acc, item| acc + item.borrow())
            }
        }

        impl<'a, 'b> Add<&'a $name> for &'b $name {
            type Output = $name;

            fn add(self, rhs: &'a $name) -> $name {
                if bool::from(self.is_identity()) {
                    *rhs
                } else if bool::from(rhs.is_identity()) {
                    *self
                } else {
                    let z1z1 = self.z.square();
                    let z2z2 = rhs.z.square();
                    let u1 = self.x * z2z2;
                    let u2 = rhs.x * z1z1;
                    let s1 = self.y * z2z2 * rhs.z;
                    let s2 = rhs.y * z1z1 * self.z;

                    if u1 == u2 {
                        if s1 == s2 {
                            self.double()
                        } else {
                            $name::identity()
                        }
                    } else {
                        let h = u2 - u1;
                        let i = (h + h).square();
                        let j = h * i;
                        let r = s2 - s1;
                        let r = r + r;
                        let v = u1 * i;
                        let x3 = r.square() - j - v - v;
                        let s1 = s1 * j;
                        let s1 = s1 + s1;
                        let y3 = r * (v - x3) - s1;
                        let z3 = (self.z + rhs.z).square() - z1z1 - z2z2;
                        let z3 = z3 * h;

                        $name {
                            x: x3, y: y3, z: z3
                        }
                    }
                }
            }
        }

        impl<'a, 'b> Add<&'a $name_affine> for &'b $name {
            type Output = $name;

            fn add(self, rhs: &'a $name_affine) -> $name {
                if bool::from(self.is_identity()) {
                    rhs.to_curve()
                } else if bool::from(rhs.is_identity()) {
                    *self
                } else {
                    let z1z1 = self.z.square();
                    let u2 = rhs.x * z1z1;
                    let s2 = rhs.y * z1z1 * self.z;

                    if self.x == u2 {
                        if self.y == s2 {
                            self.double()
                        } else {
                            $name::identity()
                        }
                    } else {
                        let h = u2 - self.x;
                        let hh = h.square();
                        let i = hh + hh;
                        let i = i + i;
                        let j = h * i;
                        let r = s2 - self.y;
                        let r = r + r;
                        let v = self.x * i;
                        let x3 = r.square() - j - v - v;
                        let j = self.y * j;
                        let j = j + j;
                        let y3 = r * (v - x3) - j;
                        let z3 = (self.z + h).square() - z1z1 - hh;

                        $name {
                            x: x3, y: y3, z: z3
                        }
                    }
                }
            }
        }

        impl<'a, 'b> Sub<&'a $name> for &'b $name {
            type Output = $name;

            fn sub(self, other: &'a $name) -> $name {
                self + (-other)
            }
        }

        impl<'a, 'b> Sub<&'a $name_affine> for &'b $name {
            type Output = $name;

            fn sub(self, other: &'a $name_affine) -> $name {
                self + (-other)
            }
        }

        #[allow(clippy::suspicious_arithmetic_impl)]
        impl<'a, 'b> Mul<&'b $scalar> for &'a $name {
            type Output = $name;

            fn mul(self, other: &'b $scalar) -> Self::Output {
                // TODO: make this faster

                let mut acc = $name::identity();

                // This is a simple double-and-add implementation of point
                // multiplication, moving from most significant to least
                // significant bit of the scalar.
                //
                // NOTE: We skip the leading bit because it's always unset.
                for bit in other
                    .to_repr()
                    .iter()
                    .rev()
                    .flat_map(|byte| (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8)))

                {
                    acc = acc.double();
                    acc = $name::conditional_select(&acc, &(acc + self), bit);
                }

                acc
            }
        }

        impl<'a> Neg for &'a $name_affine {
            type Output = $name_affine;

            fn neg(self) -> $name_affine {
                $name_affine {
                    x: self.x,
                    y: -self.y,
                    infinity: self.infinity,
                }
            }
        }

        impl Neg for $name_affine {
            type Output = $name_affine;

            fn neg(self) -> $name_affine {
                -&self
            }
        }

        impl<'a, 'b> Add<&'a $name> for &'b $name_affine {
            type Output = $name;

            fn add(self, rhs: &'a $name) -> $name {
                rhs + self
            }
        }

        impl<'a, 'b> Add<&'a $name_affine> for &'b $name_affine {
            type Output = $name;

            fn add(self, rhs: &'a $name_affine) -> $name {
                if bool::from(self.is_identity()) {
                    rhs.to_curve()
                } else if bool::from(rhs.is_identity()) {
                    self.to_curve()
                } else {
                    if self.x == rhs.x {
                        if self.y == rhs.y {
                            self.to_curve().double()
                        } else {
                            $name::identity()
                        }
                    } else {
                        let h = rhs.x - self.x;
                        let hh = h.square();
                        let i = hh + hh;
                        let i = i + i;
                        let j = h * i;
                        let r = rhs.y - self.y;
                        let r = r + r;
                        let v = self.x * i;
                        let x3 = r.square() - j - v - v;
                        let j = self.y * j;
                        let j = j + j;
                        let y3 = r * (v - x3) - j;
                        let z3 = h + h;

                        $name {
                            x: x3, y: y3, z: z3
                        }
                    }
                }
            }
        }

        impl<'a, 'b> Sub<&'a $name_affine> for &'b $name_affine {
            type Output = $name;

            fn sub(self, other: &'a $name_affine) -> $name {
                self + (-other)
            }
        }

        impl<'a, 'b> Sub<&'a $name> for &'b $name_affine {
            type Output = $name;

            fn sub(self, other: &'a $name) -> $name {
                self + (-other)
            }
        }

        #[allow(clippy::suspicious_arithmetic_impl)]
        impl<'a, 'b> Mul<&'b $scalar> for &'a $name_affine {
            type Output = $name;

            fn mul(self, other: &'b $scalar) -> Self::Output {
                // TODO: make this faster

                let mut acc = $name::identity();

                // This is a simple double-and-add implementation of point
                // multiplication, moving from most significant to least
                // significant bit of the scalar.
                //
                // NOTE: We skip the leading bit because it's always unset.
                for bit in other
                    .to_repr()
                    .iter()
                    .rev()
                    .flat_map(|byte| (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8)))
                {
                    acc = acc.double();
                    acc = $name::conditional_select(&acc, &(acc + self), bit);
                }

                acc
            }
        }

        impl PrimeCurveAffine for $name_affine {
            type Curve = $name;
            type Scalar = $scalar;

            impl_affine_curve_specific!($name, $base, $curve_type);

            fn identity() -> Self {
                Self {
                    x: $base::zero(),
                    y: $base::zero(),
                    infinity: Choice::from(1u8),
                }
            }

            fn is_identity(&self) -> Choice {
                self.infinity
            }

            fn to_curve(&self) -> Self::Curve {
                $name {
                    x: self.x,
                    y: self.y,
                    z: $base::conditional_select(&$base::one(), &$base::zero(), self.infinity),
                }
            }
        }

        impl group::cofactor::CofactorCurveAffine for $name_affine {
            type Curve = $name;
            type Scalar = $scalar;

            fn identity() -> Self {
                <Self as PrimeCurveAffine>::identity()
            }

            fn generator() -> Self {
                <Self as PrimeCurveAffine>::generator()
            }

            fn is_identity(&self) -> Choice {
                <Self as PrimeCurveAffine>::is_identity(self)
            }

            fn to_curve(&self) -> Self::Curve {
                <Self as PrimeCurveAffine>::to_curve(self)
            }
        }



        impl CurveAffine for $name_affine {
            type ScalarExt = $scalar;
            type Base = $base;
            type CurveExt = $name;

            fn is_on_curve(&self) -> Choice {
                // y^2 - x^3 - ax ?= b
                (self.y.square() - (self.x.square() + &$name::curve_constant_a()) * self.x).ct_eq(&$name::curve_constant_b())
                    | self.infinity
            }

            fn coordinates(&self) -> CtOption<Coordinates<Self>> {
                // CtOption::new(Coordinates { x: self.x, y: self.y }, !self.is_identity())
                unimplemented!()
            }

            fn from_xy(x: Self::Base, y: Self::Base) -> CtOption<Self> {
                let p = $name_affine {
                    x, y, infinity: 0u8.into()
                };
                CtOption::new(p, p.is_on_curve())
            }

            #[cfg(not(feature = "kzg"))]
            fn a() -> Self::Base {
                $name::curve_constant_a()
            }

            fn b() -> Self::Base {
                $name::curve_constant_b()
            }
        }

        impl Default for $name_affine {
            fn default() -> $name_affine {
                $name_affine::identity()
            }
        }

        impl<'a> From<&'a $name> for $name_affine {
            fn from(p: &'a $name) -> $name_affine {
                p.to_affine()
            }
        }

        impl From<$name> for $name_affine {
            fn from(p: $name) -> $name_affine {
                p.to_affine()
            }
        }

        impl ConstantTimeEq for $name_affine {
            fn ct_eq(&self, other: &Self) -> Choice {
                let z1 = self.infinity;
                let z2 = other.infinity;

                (z1 & z2) | ((!z1) & (!z2) & (self.x.ct_eq(&other.x)) & (self.y.ct_eq(&other.y)))
            }
        }

        impl PartialEq for $name_affine {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl cmp::Eq for $name_affine {}

        impl ConditionallySelectable for $name_affine {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                $name_affine {
                    x: $base::conditional_select(&a.x, &b.x, choice),
                    y: $base::conditional_select(&a.y, &b.y, choice),
                    infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
                }
            }
        }

        impl_binops_additive!($name, $name);
        impl_binops_additive!($name, $name_affine);
        impl_binops_additive_specify_output!($name_affine, $name_affine, $name);
        impl_binops_additive_specify_output!($name_affine, $name, $name);
        impl_binops_multiplicative!($name, $scalar);
        impl_binops_multiplicative_mixed!($name_affine, $scalar, $name);

        impl Group for $name {
            type Scalar = $scalar;

            fn group_zero() -> Self {
                Self::identity()
            }
            fn group_add(&mut self, rhs: &Self) {
                *self += *rhs;
            }
            fn group_sub(&mut self, rhs: &Self) {
                *self -= *rhs;
            }
            fn group_scale(&mut self, by: &Self::Scalar) {
                *self *= *by;
            }
        }
    };
}

macro_rules! impl_projective_curve_specific {
    ($name:ident, $base:ident, general) => {
        /// Unimplemented: there is no standard generator for this curve.
        fn generator() -> Self {
            // Reference: https://neuromancer.sk/std/secg/secp256k1
            Self {
                x: $base::from_raw([0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac]),
                y: $base::from_raw([0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465]),
                z: $base::one(),
            }
        }

        fn double(&self) -> Self {
            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
            //
            // There are no points of order 2.

            let xx = self.x.square();
            let yy = self.y.square();
            let a = yy.square();
            let zz = self.z.square();
            let s = ((self.x + yy).square() - xx - a).double();
            let m = xx.double() + xx + $name::curve_constant_a() * zz.square();
            let x3 = m.square() - s.double();
            let a = a.double();
            let a = a.double();
            let a = a.double();
            let y3 = m * (s - x3) - a;
            let z3 = (self.y + self.z).square() - yy - zz;

            let tmp = $name { x: x3, y: y3, z: z3 };

            $name::conditional_select(&tmp, &$name::identity(), self.is_identity())
        }
    };
}

macro_rules! impl_projective_curve_ext {
    ($name:ident, $base:ident, special_a0_b5) => {
        fn hash_to_curve<'a>(domain_prefix: &'a str) -> Box<dyn Fn(&[u8]) -> Self + 'a> {
            unimplemented!();
        }

        /// Apply the curve endomorphism by multiplying the x-coordinate
        /// by an element of multiplicative order 3.
        #[cfg(not(feature = "kzg"))]
        fn endo(&self) -> Self {
            unimplemented!();
        }
    };
    ($name:ident, $base:ident, general) => {
        /// Unimplemented: hashing to this curve is not supported
        #[cfg(not(feature = "kzg"))]
        fn hash_to_curve<'a>(_domain_prefix: &'a str) -> Box<dyn Fn(&[u8]) -> Self + 'a> {
            unimplemented!()
        }

        /// Unimplemented: no endomorphism is supported for this curve.
        #[cfg(not(feature = "kzg"))]
        fn endo(&self) -> Self {
            unimplemented!()
        }
    };
}

macro_rules! impl_affine_curve_specific {
    ($name:ident, $base:ident, general) => {
        /// Unimplemented: there is no standard generator for this curve.
        fn generator() -> Self {
            // Reference: https://neuromancer.sk/std/secg/secp256k1
            Self {
                x: $base::from_raw([0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac]),
                y: $base::from_raw([0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465]),

                infinity: Choice::from(0u8),
            }
        }
    };
}

/// Represents a point in bytes.
#[derive(Copy, Clone)]
pub struct Serialized([u8; 64]);

impl Default for Serialized {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl core::fmt::Debug for Serialized {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0[..].fmt(f)
    }
}

impl AsRef<[u8]> for Serialized {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Serialized {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl GroupEncoding for Secp256k1Affine {
    type Repr = Serialized;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let bytes = bytes.as_ref();

        if bytes == Serialized::default().as_ref() {
            return CtOption::new(
                Secp256k1Affine {
                    x: Fp::zero(),
                    y: Fp::zero(),
                    infinity: Choice::from(1u8),
                },
                Choice::from(1u8),
            );
        }

        let x_bytes: [u8; 32] = bytes[0..32].try_into().unwrap();
        let y_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();

        let invalid = CtOption::new(
            Secp256k1Affine {
                x: Fp::zero(),
                y: Fp::zero(),
                infinity: Choice::from(0u8),
            },
            Choice::from(0u8),
        );

        let x = Fp::from_repr(x_bytes);
        let y = Fp::from_repr(y_bytes);

        if (x.is_none() | y.is_none()).into() {
            return invalid;
        } else {
            let res = Secp256k1Affine {
                x: x.unwrap(),
                y: y.unwrap(),
                infinity: Choice::from(0u8),
            };
            CtOption::new(res, res.is_on_curve())
        }
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // We can't avoid curve checks when parsing a compressed encoding.
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Serialized {
        // TODO: not constant time
        if bool::from(self.is_identity()) {
            Serialized::default()
        } else {
            let x_bytes = self.x.to_repr();
            let y_bytes = self.y.to_repr();
            let mut ser: [u8; 64] = [0; 64];
            ser[0..32].copy_from_slice(&x_bytes[..]);
            ser[32..64].copy_from_slice(&y_bytes[..]);
            Serialized(ser)
        }
    }
}

impl GroupEncoding for Secp256k1 {
    type Repr = Serialized;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        Secp256k1Affine::from_bytes(bytes).map(Self::from)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // We can't avoid curve checks when parsing a compressed encoding.
        Secp256k1Affine::from_bytes(bytes).map(Self::from)
    }

    fn to_bytes(&self) -> Self::Repr {
        Secp256k1Affine::from(self).to_bytes()
    }
}

new_curve_impl!(
    (pub),
    Secp256k1,
    Secp256k1Affine,
    Fp,
    Fq,
    "secp256k1",
    [0, 0, 0, 0],
    [7, 0, 0, 0],
    general
);

#[cfg(test)]
#[test]
fn test_generator() {
    assert_eq!(Secp256k1::generator().is_on_curve().unwrap_u8(), 1u8)
}

#[test]
fn test_curve() {
    use group::tests::curve_tests;
    curve_tests::<Secp256k1>();
}
