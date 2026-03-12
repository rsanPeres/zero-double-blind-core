//! Standalone helper for ensuring a round account exists on-chain.
//!
//! For the **full** round lifecycle (init → write chunks → submit), use
//! [`crate::round_submitter::submit_round`] instead.  This module exists for
//! callers that only need to guarantee the account is allocated before they
//! build their own transaction pipeline.

use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

/// Ensures that a seed-derived round account exists, creating it if necessary.
///
/// This is a thin convenience wrapper around `create_account_with_seed`.  It
/// does **not** send the transaction through [`crate::tx_sender`] so it also
/// works in contexts where the caller wants a simpler, synchronous send.
///
/// # Arguments
/// * `rpc`           — Solana RPC client.
/// * `payer`         — Fee-payer and base key for the seed derivation.
/// * `round_pubkey`  — Expected public key (must equal `Pubkey::create_with_seed(payer, seed, program_id)`).
/// * `round_seed`    — Seed string (≤ 32 chars).
/// * `program_id`    — On-chain ZK-verifier program ID.
/// * `space`         — Byte size to allocate; must be sufficient for the
///                     RND1 header + payload.
///
/// # Errors
/// Returns an error if the RPC call to check the existing account fails, the
/// rent query fails, or the creation transaction fails.
pub fn ensure_round_account_exists(
    rpc: &RpcClient,
    payer: &Keypair,
    round_pubkey: &Pubkey,
    round_seed: &str,
    program_id: &Pubkey,
    space: usize,
) -> Result<()> {
    // If the account already exists, nothing to do.
    if rpc.get_account(round_pubkey).is_ok() {
        return Ok(());
    }

    let lamports = rpc
        .get_minimum_balance_for_rent_exemption(space)
        .with_context(|| {
            format!(
                "failed to query rent-exempt minimum for {space} bytes"
            )
        })?;

    let ix = system_instruction::create_account_with_seed(
        &payer.pubkey(),
        round_pubkey,
        &payer.pubkey(),
        round_seed,
        lamports,
        space as u64,
        program_id,
    );

    let blockhash = rpc
        .get_latest_blockhash()
        .context("failed to fetch latest blockhash")?;

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );

    rpc.send_and_confirm_transaction(&tx)
        .with_context(|| {
            format!(
                "failed to create round account {round_pubkey} \
                 with seed='{round_seed}'"
            )
        })?;

    Ok(())
}