use crate::{error::Error, key_generation::KeyGenerator, util::Polynomial};

use blake2b_simd::Params;
use pairing::{
    bls12_381::{Fr, G1Affine, G2Affine, G1, G2},
    CurveAffine, CurveProjective, Field, PrimeField,
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
        for c in self.poly.0.iter() {
            let mut tmp = G2::one();
            tmp.mul_assign(*c);
            res.push(tmp);
        }
        res
    }

    ///
    pub fn cal_secret(&self, to_usr: u32) -> Fr {
        let j_fr = Fr::from_str(&to_usr.to_string()).unwrap();
        let mut jk = Fr::one();
        let mut res = Fr::zero();

        for c in self.poly.0.iter() {
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
        hash[..32].clone_from_slice(&tmp[..32]);
        ChaChaRng::from_seed(hash).gen04()
    }

    ///
    pub fn verify_single_signature(&self, hmsg: &G1, sig: &G1) -> bool {
        self.mpk.map_or_else(
            || false,
            |mpk| {
                G1Affine::from(*sig).pairing_with(&G2Affine::from(G2::one()))
                    == G1Affine::from(*hmsg).pairing_with(&G2Affine::from(mpk))
            },
        )
    }

    ///
    pub fn cal_lambda(st: usize, ed: usize, exc: usize, ids: &[u32]) -> Fr {
        let mut up = Fr::one();
        let mut down = Fr::one();
        let k = ids[exc];

        for (i, item) in ids.iter().enumerate().take(ed).skip(st) {
            if i == exc {
                continue;
            }
            let j = item;
            // up
            let mut res = i64::from(0 - j);
            if res >= 0 {
                let num = Fr::from_str(&res.to_string()).unwrap();
                up.mul_assign(&num);
            } else {
                let num = Fr::from_str(&(-res as u32).to_string()).unwrap();
                up.mul_assign(&num);
            }

            res = i64::from(k - j);
            if res >= 0 {
                let num = Fr::from_str(&res.to_string()).unwrap();
                down.mul_assign(&num);
            } else {
                let num = Fr::from_str(&(-res as u32).to_string()).unwrap();
                down.mul_assign(&num);
            }
        }
        down.inverse();
        up.mul_assign(&down);
        up
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::FrRepr;
    use rand::Rand;

    #[test]
    fn test_pairing() {
        let rng_0 = &mut rand::thread_rng();
        let rng_1 = &mut rand::thread_rng();
        let mut g1_1 = G1::one();
        let mut g2_1 = G2::one();
        let mut g1_2 = G1::one();
        let mut g2_2 = G2::one();
        let g1_3 = G1::one();
        let g2_3 = G2::one();
        let mut a = Fr::rand(rng_0);
        let b = Fr::rand(rng_1);
        g1_1.mul_assign(a);
        g2_1.mul_assign(b);
        g1_2.mul_assign(b);
        g2_2.mul_assign(a);
        a.mul_assign(&b);
        let part_0 = G1Affine::from(g1_1).pairing_with(&G2Affine::from(g2_1));
        let part_1 = G1Affine::from(g1_2).pairing_with(&G2Affine::from(g2_2));
        let part_2 = G1Affine::from(g1_3)
            .pairing_with(&G2Affine::from(g2_3))
            .pow(FrRepr::from(a));
        assert!(part_0 == part_1);
        assert!(part_0 == part_2);
    }

    #[test]
    fn test_abel() {
        let rng_0 = &mut rand::thread_rng();
        let rng_1 = &mut rand::thread_rng();
        let i = G1::rand(rng_0);
        let mut j = G1::rand(rng_1);
        let mut tmp = i.clone();
        tmp.add_assign(&j);
        j.add_assign(&i);
        assert!(j == tmp);
    }
}
