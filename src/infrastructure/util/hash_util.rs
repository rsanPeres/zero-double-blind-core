use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

pub fn deterministic_seed_from_str(label: &str, count: usize) -> Vec<Bn254Fr> {
    (0..count)
        .map(|i| {
            let mut hasher = Sha256::new();
            hasher.update(label.as_bytes());
            hasher.update(&[i as u8]);
            let hash = hasher.finalize();
            Bn254Fr::from_le_bytes_mod_order(&hash)
        })
        .collect()
}
