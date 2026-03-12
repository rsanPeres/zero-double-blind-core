/// Deterministic Solana seed generation.
///
/// The seed is derived from `HASH_SECRET` (env-var) via SHA-256, then
/// base58-encoded and truncated to 32 characters (Solana's hard limit for
/// `create_with_seed`).
///
/// # Bug fixed
/// The original code read `HASH_SECRET` **twice** and called `h.update()`
/// a second time inside an `if let Ok(secret)` block.  When the variable
/// *was* set the value was hashed twice; when it was *not* set the hash was
/// computed from an empty string.  Both cases produced wrong or misleading
/// results.  Now the variable is read exactly once.
use solana_sdk::bs58;
use std::env;

/// Returns a deterministic, ≤32-character base58 seed derived from
/// `HASH_SECRET`.
///
/// If the env-var is absent the seed is derived from an empty string and is
/// **not secret** — a warning is printed to stderr.
pub fn make_solana_seed32() -> String {
    use sha2::{Digest, Sha256};

    let secret = env::var("HASH_SECRET").unwrap_or_else(|_| {
        eprintln!(
            "[seed_util] WARNING: HASH_SECRET is not set. \
             Seed will be derived from an empty string and is NOT secret."
        );
        String::new()
    });

    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    let digest = h.finalize();

    // First 16 bytes → ~22 base58 chars, safely within the 32-char limit.
    let mut s = bs58::encode(&digest[..16]).into_string();
    s.truncate(32); // Solana: seed.len() must be ≤ 32
    s
}