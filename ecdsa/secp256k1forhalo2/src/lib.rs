//! Implementation of the Pallas / Vesta curve cycle.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(unknown_lints)]
#![allow(clippy::op_ref, clippy::same_item_push, clippy::upper_case_acronyms)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

// #[cfg(any(feature = "std", test))]
// #[macro_use]
// extern crate std;

extern crate alloc;

#[macro_use]
mod macros;
mod curves;
mod fields;

pub mod arithmetic;

pub use curves::*;
pub use fields::*;

pub extern crate group;
