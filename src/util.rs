use pairing::bls12_381::Fr;
use rand::{thread_rng, Rand};

pub(crate) struct Polynomial(pub(crate) Vec<Fr>);

impl Polynomial {
    pub(crate) fn new(order: usize) -> Self {
        Polynomial(generate_coef(order))
    }
}

pub(crate) fn generate_coef(order: usize) -> Vec<Fr> {
    let mut res = Vec::new();
    let rng = &mut thread_rng();
    for _ in 0..order {
        res.push(Fr::rand(rng));
    }
    res
}
