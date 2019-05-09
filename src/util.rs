use pairing::bls12_381::Fr;
use rand::{thread_rng, Rand};

pub(crate) struct Polynomial {
    pub(crate) order: u32,
    pub(crate) coef: Vec<Fr>,
}

impl Polynomial {
    pub(crate) fn new(order: u32) -> Self {
        Polynomial {
            order,
            coef: generate_coef(order),
        }
    }
}

pub(crate) fn generate_coef(order: u32) -> Vec<Fr> {
    let mut res = Vec::new();
    let rng = &mut thread_rng();
    for _ in 0..order {
        res.push(Fr::rand(rng));
    }
    res
}
