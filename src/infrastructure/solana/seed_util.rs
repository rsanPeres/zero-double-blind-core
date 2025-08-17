use solana_sdk::bs58;
use std::env;

pub fn make_solana_seed32() -> String {
    let label = env::var("HASH_SECRET").unwrap_or_else(|_| "".to_string());
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    if let Ok(secret) = env::var("HASH_SECRET") {
        h.update(secret.as_bytes());
    }
    let bytes = &h.finalize()[..16];               // 16B -> ~22 chars em base58
    let mut s = bs58::encode(bytes).into_string();
    s.truncate(32);                                // Solana exige ≤ 32 chars
    s
}
