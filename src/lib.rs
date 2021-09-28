mod circuit;
mod rns;

pub(crate) const BIT_LEN_CRT_MODULUS: usize = 256;
pub(crate) const NUMBER_OF_LIMBS: usize = 4;
pub(crate) const BIT_LEN_LIMB: usize = 64; // BIT_LEN_CRT_MODULUS / NUMBER_OF_LIMBS

pub(crate) const NUMBER_OF_LOOKUP_LIMBS: usize = 4;
pub(crate) const BIT_LEN_LIMB_LOOKUP: usize = 16; // BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS
