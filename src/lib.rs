#![allow(dead_code)]
#![feature(trait_alias)]

mod circuit;
mod rns;

pub(crate) const NUMBER_OF_LIMBS: usize = 4;
pub(crate) const NUMBER_OF_LOOKUP_LIMBS: usize = 4;

pub use halo2arith::halo2;

cfg_if::cfg_if! {
  if #[cfg(feature = "kzg")] {
    pub trait WrongExt = halo2::arithmetic::BaseExt;
  } else {
    pub trait WrongExt = halo2::arithmetic::FieldExt;

  }
}
