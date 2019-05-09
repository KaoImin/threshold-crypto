use crate::{util::generate_coef, NodeInfo};
use pairing::{
    bls12_381::{Fr, G1, G2},
    CurveProjective, Field, PrimeField,
};

///
pub struct KeyGenerator {
    ///
    pub a: Vec<Vec<G2>>,
    ///
    pub qual: Vec<u32>,
    ///
    pub veto: Vec<Vec<u32>>,
    ///
    pub pk: Vec<G2>,
    ///
    pub n: u32,
    ///
    pub t: u32,
    ///
    s: Vec<Vec<Fr>>,
}

impl KeyGenerator {
    ///
    pub fn new(nodes: &mut Vec<NodeInfo>, n: u32, t: u32) -> Self {
        let mut a: Vec<Vec<G2>> = Vec::new();
        let mut s: Vec<Vec<Fr>> = Vec::new();
        let mut veto: Vec<Vec<u32>> = Vec::new();

        for node in nodes {
            a.push(node.broadcast_a());
            s.push(node.broadcast_s(n));
            veto.push(Vec::new());
        }

        KeyGenerator {
            a,
            s,
            veto,
            qual: Vec::new(),
            pk: Vec::new(),
            n,
            t,
        }
    }

    ///
    pub fn cal_secret(&self, nodes: &mut NodeInfo) -> Vec<Fr> {
        let mut res = Vec::new();
        for s in &self.s {
            res.push(s[(nodes.id - 1) as usize]);
        }
        res
    }

    ///
    pub fn gen_qual(&mut self, nodes: &mut Vec<NodeInfo>) {
        for to_usr in 0..self.veto.len() {
            if self.veto[to_usr].is_empty() {
                self.qual.push(to_usr as u32);
            } else {
                for from_usr in &self.veto[to_usr] {
                    let sk = nodes[*from_usr as usize].cal_secret(to_usr as u32);
                    let mut res = true;
                    for node in nodes.iter() {
                        if !node.verify_specific(sk, *from_usr as u32, to_usr as u32, &self.a) {
                            res = false;
                            break;
                        }
                    }

                    if res {
                        self.qual.push(to_usr as u32);
                    }
                }
            }
        }

        for i in 0..self.t {
            let mut res = G2::zero();
            for j in 0..self.qual.len() {
                 res.add_assign(&self.a[j as usize][i as usize]);
            }
            self.pk.push(res);
        }
    }
}

impl NodeInfo {
    fn broadcast_a(&mut self) -> Vec<G2> {
        let mut res: Vec<G2> = Vec::new();
        for value in &self.poly.coef {
            let mut g2 = G2::one();
            g2.mul_assign(*value);
            res.push(g2);
        }
        res
    }

    fn broadcast_s(&mut self, n: u32) -> Vec<Fr> {
        let mut res: Vec<Fr> = Vec::new();
        for i in 0..n {
            res.push(self.cal_secret(i + 1));
        }
        res
    }

    fn cal_secret(&mut self, aim: u32) -> Fr {
        // TODO
        let j_fr: Fr = Fr::from_str(&aim.to_string()).unwrap();
        let mut jk = Fr::one();
        let mut res = Fr::zero();
        for coef in &self.poly.coef {
            jk.mul_assign(coef);
            res.add_assign(&jk);
            jk.mul_assign(&j_fr);
        }
        res
    }

    fn verify_specific(&self, sk: Fr, from_usr: u32, to_usr: u32, pool: &[Vec<G2>]) -> bool {
        let mut lhs = G2::one();
        let mut rhs = G2::zero();
        let j_fr: Fr = Fr::from_str(&to_usr.to_string()).unwrap();
        let mut jk = Fr::one();
        lhs.mul_assign(sk);

        for i in 0..self.poly.order {
            let mut tmp = pool[from_usr as usize][i as usize];
            tmp.mul_assign(jk);
            rhs.add_assign(&tmp);
            jk.mul_assign(&j_fr);
        }

        lhs == rhs
    }
}
