use crate::{util::Polynomial, NodeInfo};
use pairing::{
    bls12_381::{Fr, G1, G2},
    CurveProjective, Field,
};

impl NodeInfo {
    ///
    pub fn new(id: u32, order: u32) -> Self {
        NodeInfo {
            id,
            pk: G2::zero(),
            sk: Fr::zero(),
            poly: Polynomial::new(order),
        }
    }
}
