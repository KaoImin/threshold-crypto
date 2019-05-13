use rand::Rng;
use threshold_crypto::NodeInfo;

#[test]
fn test() {
    let n: usize = 4;
    let t: usize = 3;
    let rng = &mut rand::thread_rng();
    let mut nodes = Vec::new();

    for _ in 0..n {
        let id = rng.gen_range(1, std::u32::MAX);
        nodes.push(NodeInfo::new(id, n, t));
    }

    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            let id = nodes[j].id;
            let coef = nodes[j].cal_coef();
            let sec = nodes[j].cal_secret(nodes[i].id);

            assert_eq!(nodes[i].set_node_coefs(id, &coef).is_ok(), true);
            assert_eq!(nodes[i].set_node_secrets(id, sec).is_ok(), true);
        }
    }
}
