use crate::error::Error;
use pairing::{
    bls12_381::{Fr, G2},
    CurveProjective, Field, PrimeField,
};
use std::collections::BTreeMap;

///
pub(crate) struct KeyGenerator {
    ///
    pub(crate) a: BTreeMap<u32, Vec<G2>>,
    ///
    pub(crate) qual: Vec<u32>,
    ///
    pub(crate) coef: Vec<G2>,
    ///
    pub(crate) n: usize,
    ///
    pub(crate) t: usize,
    ///
    local_id: u32,
    ///
    user_poly_secret: BTreeMap<u32, Fr>,
}

impl KeyGenerator {
    ///
    pub(crate) fn new(local_id: u32, n: usize, t: usize) -> Self {
        KeyGenerator {
            a: BTreeMap::new(),
            qual: Vec::new(),
            local_id,
            coef: Vec::new(),
            user_poly_secret: BTreeMap::new(),
            n,
            t,
        }
    }

    ///
    pub(crate) fn get_mpk(&self) -> Result<G2, Error> {
        if self.coef.is_empty() {
            return Err(Error::NoPolyCoef);
        }
        Ok(self.coef[0])
    }

    ///
    pub(crate) fn set_node_coef(&mut self, secret_id: u32, coefs: &[G2]) -> Result<(), Error> {
        if coefs.len() != self.t {
            return Err(Error::NumOfTermsErr);
        }
        self.a
            .insert(secret_id, coefs.to_vec())
            .map_or_else(|| Ok(()), |_| Err(Error::CoefsInexistence))
    }

    ///
    pub(crate) fn set_node_secret(&mut self, secret_id: u32, secret: Fr) -> Result<(), Error> {
        self.user_poly_secret
            .insert(secret_id, secret)
            .map_or_else(|| Ok(()), |_| Err(Error::SecretInexistence))
    }

    ///
    pub(crate) fn verify(&self, id: u32) -> bool {
        let res = self.user_poly_secret.get(&id).and_then(|secret| {
            self.a.get(&id).and_then(|coefs| {
                let mut lhs = G2::one();
                let mut rhs = G2::zero();
                let j_fr = Fr::from_str(&self.local_id.to_string()).unwrap();
                let mut jk = Fr::one();
                lhs.mul_assign(*secret);

                for item in coefs.iter().take(self.t) {
                    let mut tmp = *item;
                    tmp.mul_assign(jk);
                    rhs.add_assign(&tmp);
                    jk.mul_assign(&j_fr);
                }
                Some(lhs == rhs)
            })
        });
        res.unwrap_or(false)
    }

    ///
    pub(crate) fn gen_sk(&self) -> Option<Fr> {
        let mut sk = Fr::zero();
        for id in self.qual.iter() {
            if let Some(one_sk) = self.user_poly_secret.get(id) {
                sk.add_assign(one_sk);
            } else {
                return None;
            }
        }
        Some(sk)
    }

    ///
    pub(crate) fn gen_pk(&self, local_id: u32) -> Option<G2> {
        let mut pk = G2::zero();
        let i_fr = Fr::from_str(&local_id.to_string()).unwrap();
        let mut ik = Fr::one();

        for i in 0..self.t {
            let mut ak = self.coef[i];
            ak.mul_assign(ik);
            pk.add_assign(&ak);
            ik.mul_assign(&i_fr);
        }
        Some(pk)
    }

    ///
    pub(crate) fn gen_mpk(&self) -> Option<G2> {
        if self.coef.is_empty() {
            return None;
        }
        Some(self.coef[0])
    }

    ///
    pub(crate) fn get_qual(&mut self) -> Vec<u32> {
        let ids: Vec<u32> = self.a.keys().cloned().collect();
        for i in ids.iter() {
            if self.verify(*i) {
                self.qual.push(*i);
            } else {
                self.clean_veto_id(*i);
            }
        }
        self.qual.clone()
    }

    ///
    pub(crate) fn gen_coefs(&mut self) -> Result<(), Error> {
        for i in 0..self.t {
            let mut res = G2::zero();
            for j in self.qual.iter() {
                if let Some(coef) = self.a.get(&j) {
                    res.add_assign(&coef[i]);
                } else {
                    return Err(Error::NoCoef(*j));
                }
            }
            self.coef.push(res);
        }
        Ok(())
    }

    ///
    fn clean_veto_id(&mut self, id: u32) {
        self.a.remove(&id);
        self.user_poly_secret.remove(&id);
    }
}
