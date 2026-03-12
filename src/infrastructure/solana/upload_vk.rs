//! Application-layer orchestrator: ark `VerifyingKey<Bn254>` → on-chain VK.
//!
//! This module is the public entry-point for VK provisioning.  It:
//!
//! 1. Encodes the arkworks VK to the G16V binary format.
//! 2. Derives a collision-safe seed: `"VK-{sha256_prefix_24hex}"` (27 chars,
//!    always fits in Solana's 32-char limit, never starts with `"RND-"`).
//! 3. Delegates upload and sealing to [`vk_uploader::upload_vk`].
//! 4. Post-upload sanity: verifies the on-chain account starts with `"VKH1"`.
//!
//! # Example
//! ```ignore
//! // env-vars: RPC_URL, PROGRAM_ID
//! let (seed, vk_pk) = provision_vk(&ark_verifying_key)?;
//! // vk_pk is now safe to pass to round_submitter::submit_round
//! ```

use std::thread::sleep;
use std::time::Duration;
use anyhow::{Context, Result};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};

use crate::infrastructure::solana::{keypair_loader, vk_codec, vk_uploader};

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes `vk`, uploads it on-chain, and returns `(seed, vk_pubkey)`.
///
/// The seed is derived deterministically from the VK payload hash so calling
/// this function twice with the same VK is a no-op (idempotent).
///
/// # Environment variables required
/// * `RPC_URL`    — Solana RPC endpoint.
/// * `PROGRAM_ID` — On-chain ZK-verifier program ID.
///
/// # Errors
/// Returns an error if `RPC_URL` is not set, `PROGRAM_ID` is not set or not a
/// valid Pubkey, the keypair cannot be loaded, or any on-chain transaction
/// fails.
pub fn provision_vk(vk: &VerifyingKey<Bn254>) -> Result<(String, Pubkey)> {
    let (rpc_url, program_id) = read_env_config()?;
    let rpc = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
    let payer = keypair_loader::load_keypair().context("failed to load payer keypair")?;

    provision_vk_with(vk, &rpc, &program_id, &payer)
}

/// Same as [`provision_vk`] but accepts explicit dependencies — useful for
/// testing and for callers that already hold an `RpcClient`.
pub fn provision_vk_with(
    vk: &VerifyingKey<Bn254>,
    rpc: &RpcClient,
    program_id: &Pubkey,
    payer: &solana_sdk::signature::Keypair,
) -> Result<(String, Pubkey)> {
    // ── 1. Encode VK to G16V bytes ─────────────────────────────
    let vk_bytes = vk_codec::vk_to_g16v_bytes_uncompressed(vk);

    // ── 2. Derive deterministic, namespace-safe seed ───────────
    //    Format: "VK-" + first 24 hex chars of SHA-256 = 27 chars total.
    //    * Always fits in Solana's 32-char seed limit.
    //    * "VK-" prefix guarantees it never collides with "RND-" round seeds.
    let hash = Sha256::digest(&vk_bytes);
    let seed = format!("VK-{}", &hex::encode(hash)[..24]);
    debug_assert_eq!(seed.len(), 27, "seed must be exactly 27 chars");

    eprintln!("[upload_vk] rpc............: {}", rpc.url());
    eprintln!("[upload_vk] program........: {program_id}");
    eprintln!("[upload_vk] seed (27 chars): '{seed}'");
    eprintln!("[upload_vk] vk_bytes.......: {} bytes", vk_bytes.len());

    // ── 3. Upload and seal ─────────────────────────────────────
    let vk_pk = vk_uploader::upload_vk(rpc, program_id, payer, &seed, &vk_bytes)
        .context("vk_uploader::upload_vk failed")?;

    // ── 4. Post-upload sanity: confirm the magic header ────────
    let acc = rpc
        .get_account(&vk_pk)
        .context("failed to read VK account after upload")?;
    let head = acc.data.get(0..4).unwrap_or(&[]);
    let head_str = std::str::from_utf8(head).unwrap_or("????");

    sleep(Duration::from_millis(3000));

    anyhow::ensure!(
        head_str == "VKH1",
        "post-upload sanity failed: vk_pk={vk_pk} does not start with 'VKH1' \
         (got '{head_str}') — check for seed collisions"
    );

    sleep(Duration::from_millis(30000));

    eprintln!("[upload_vk] VK provisioned: vk_pk={vk_pk}  seed='{seed}'");
    Ok((seed, vk_pk))
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Reads and validates `RPC_URL` and `PROGRAM_ID` from the environment.
fn read_env_config() -> Result<(String, Pubkey)> {
    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| {
        eprintln!(
            "[upload_vk] WARNING: RPC_URL not set; \
             falling back to 'https://api.devnet.solana.com'"
        );
        "https://api.devnet.solana.com".to_string()
    });

    let program_id: Pubkey = std::env::var("PROGRAM_ID")
        .context("PROGRAM_ID environment variable is not set")?
        .parse()
        .context("PROGRAM_ID is not a valid base-58 Pubkey")?;

    Ok((rpc_url, program_id))
}