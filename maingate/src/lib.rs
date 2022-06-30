//! `maingate` defines basic instructions for a starndart like PLONK gate and
//! implments a 5 width gate with two multiplication and one rotation
//! customisation

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

use halo2wrong::halo2::circuit::AssignedCell;

#[macro_use]
mod instructions;
mod main_gate;
mod range;

pub use halo2wrong::{halo2, utils::*, RegionCtx};
pub use instructions::{CombinationOptionCommon, MainGateInstructions, Term};
pub use main_gate::*;
pub use range::*;

#[cfg(test)]
use halo2wrong::curves;

/// AssignedValue
pub type AssignedValue<F> = AssignedCell<F, F>;
/// AssignedCondition
pub type AssignedCondition<F> = AssignedCell<F, F>;
