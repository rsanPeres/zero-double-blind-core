//! Compatibility shim — thin wrapper over the refactored modules.
//!
//! The original `solana_client.rs` was an 885-line monolith.  All logic has
//! been moved into focused modules:
//!
//! | Old function          | Now lives in          |
//! |-----------------------|-----------------------|
//! | `payer()`             | `keypair_loader`      |
//! | `load_default_keypair`| `keypair_loader`      |
//! | `rent_exempt_lamports`| `account_manager`     |
//! | `upload_vk_in_chunks` | `vk_uploader` + `upload_vk` |
//! | `submit_round`        | `round_submitter`     |
//!
//! This file re-exports or wraps those functions to keep any existing
//! call-sites working without modification.
//!
//! **New code should import from the specific modules directly.**

use anyhow::Result;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Keypair};

use crate::infrastructure::solana::{account_manager, keypair_loader, round_submitter, vk_uploader};

// ── Keypair helpers ──────────────────────────────────────────────────────────

/// Loads the default keypair, panicking on failure.
/// Prefer [`keypair_loader::load_keypair`] in library code.
pub fn payer() -> Keypair {
    keypair_loader::payer()
}

/// Loads the default keypair, returning an error on failure.
pub fn load_default_keypair() -> Result<Keypair> {
    keypair_loader::load_keypair()
}

// ── Rent helper ──────────────────────────────────────────────────────────────

/// Returns the rent-exempt minimum lamports for `space` bytes.
/// Retries on RPC failure and falls back to `Rent::default()`.
pub fn rent_exempt_lamports(rpc: &RpcClient, space: usize) -> u64 {
    account_manager::rent_exempt_lamports(rpc, space)
}

// ── VK upload ────────────────────────────────────────────────────────────────

/// Uploads a raw G16V payload on-chain in chunks, idempotently.
///
/// # Migration note
/// For new code, use [`crate::upload_vk::provision_vk`] which accepts an
/// arkworks `VerifyingKey<Bn254>` directly.  This wrapper accepts raw bytes
/// and a caller-chosen seed, preserving the original API.
pub fn upload_vk_in_chunks(
    rpc_url: &str,
    program_id: &str,
    vk_seed: &str,
    vk_bytes: &[u8],
    _chunk_size: usize, // chunk size is now fixed at 700 bytes inside vk_uploader
) -> Result<Pubkey> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program: Pubkey = program_id.parse()?;
    let payer = keypair_loader::load_keypair()?;
    vk_uploader::upload_vk(&rpc, &program, &payer, vk_seed, vk_bytes)
}

// ── Round submission ─────────────────────────────────────────────────────────

/// Submits a ZK proof round, idempotently.
///
/// Delegates to [`round_submitter::submit_round`].
pub fn submit_round(
    rpc_url: &str,
    program_id: &str,
    round_seed: &str,
    vk_pk: Pubkey,
    proof_bytes: Vec<u8>,
    public_inputs: Vec<u8>,
    bits: Vec<bool>,
) -> Result<String> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program: Pubkey = program_id.parse()?;
    let payer = keypair_loader::load_keypair()?;
    round_submitter::submit_round(&rpc, &program, &payer, round_seed, vk_pk, proof_bytes, public_inputs, bits)
}