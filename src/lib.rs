//! A threshold crypto system with distributed key generation.
//!

#![deny(missing_docs)]

///
pub mod error;
///
pub mod key_generation;
///
pub mod threshold_crypto;
///
pub(crate) mod util;

use pairing::bls12_381::{Fr, G2};
use util::Polynomial;

///
pub struct NodeInfo {
    ///
    pub id: u32,
    ///
    pub pk: G2,
    ///
    sk: Fr,
    ///
    poly: Polynomial,
}
