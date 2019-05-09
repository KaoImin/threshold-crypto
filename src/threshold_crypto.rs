use crate::{error::Error, key_generation::KeyGenerator, util::Polynomial};

use blake2b_simd::Params;
use pairing::{
    bls12_381::{Fr, G1, G2},
    CurveProjective, Field, PrimeField,
};
use rand::{thread_rng, Rng};
use rand04_compat::RngExt;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

///
pub struct NodeInfo {
    ///
    pub id: u32,
    ///
    pub pk: Option<G2>,
    ///
    pub mpk: Option<G2>,
    ///
    sk: Option<Fr>,
    ///
    poly: Polynomial,
    ///
    key_gen: KeyGenerator,
}

impl NodeInfo {
    ///
    pub fn new(id: u32, n: usize, t: usize) -> Self {
        if n < t || t == 0 || n == 0 {
            panic!("Error");
        }

        let real_id = if id == 0 {
            let mut rng = thread_rng();
            rng.gen_range(1, ::std::u32::MAX)
        } else {
            id
        };

        NodeInfo {
            id: real_id,
            mpk: None,
            pk: None,
            sk: None,
            poly: Polynomial::new(t),
            key_gen: KeyGenerator::new(real_id, n, t),
        }
    }

    ///
    pub fn set_node_coefs(&mut self, secret_id: u32, coefs: &[G2]) -> Result<(), Error> {
        self.key_gen.set_node_coef(secret_id, coefs)
    }

    ///
    pub fn set_node_secrets(&mut self, secret_id: u32, secret: Fr) -> Result<(), Error> {
        self.key_gen.set_node_secret(secret_id, secret)
    }

    ///
    pub fn cal_coef(&self) -> Vec<G2> {
        let mut res: Vec<G2> = Vec::new();
        for c in self.poly.coef.iter() {
            let mut tmp = G2::one();
            tmp.mul_assign(*c);
            res.push(tmp);
        }
        res
    }

    ///
    pub fn calc_secret(&self, to_usr: u32) -> Fr {
        let j_fr = Fr::from_str(&to_usr.to_string()).unwrap();
        let mut jk = Fr::one();
        let mut res = Fr::zero();

        for c in self.poly.coef.iter() {
            let mut tmp = *c;
            tmp.mul_assign(&jk);
            res.add_assign(&tmp);
            jk.mul_assign(&j_fr);
        }
        res
    }

    ///
    pub fn verify(&self, secret_id: u32) -> bool {
        self.key_gen.verify(secret_id)
    }

    ///
    pub fn get_qual(&mut self) -> Vec<u32> {
        self.key_gen.get_qual()
    }

    ///
    pub fn gen_pk_sk(&mut self) -> Result<(), Error> {
        self.key_gen.gen_coefs()?;
        self.sk = self.key_gen.gen_sk();
        self.pk = self.key_gen.gen_pk(self.id);
        self.mpk = self.key_gen.gen_mpk();
        Ok(())
    }

    ///
    pub fn cal_signature(&self, msg: &[u8]) -> G1 {
        let tmp = Params::new()
            .hash_length(32)
            .to_state()
            .update(msg)
            .finalize()
            .as_bytes()
            .to_vec();

        let mut hash = [0 as u8; 32];
        for i in 0..32 {
            hash[i] = tmp[i];
        }
        ChaChaRng::from_seed(hash).gen04()
    }
}
