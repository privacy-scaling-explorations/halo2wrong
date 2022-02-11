#![allow(dead_code)]
#![feature(trait_alias)]

mod ecc;

pub use crate::ecc::{AssignedPoint, BaseFieldEccChip, EccConfig, GeneralEccChip};
pub use integer;
pub use integer::halo2;
pub use integer::maingate;

cfg_if::cfg_if! {
  if #[cfg(feature = "kzg")] {
    pub trait WrongExt = halo2::arithmetic::BaseExt;
  } else {
    pub trait WrongExt = halo2::arithmetic::FieldExt;

  }
}
