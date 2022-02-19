cfg_if::cfg_if! {
  if #[cfg(feature = "kzg")] {
      pub use halo2_kzg as halo2;
  } else {
      // default feature
      pub use halo2_zcash as halo2;
  }
}
