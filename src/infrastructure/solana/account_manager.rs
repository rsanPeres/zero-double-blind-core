//! Account lifecycle helpers — creation and validation.
//!
//! Responsibilities of this module:
//! * Verify that the on-chain program is deployed and executable.
//! * Verify that the fee-payer account is valid and funded.
//! * Query rent-exempt minimum lamports with retry + fallback.
//! * Create a seed-derived program account if it does not already exist.
//!
//! Every function that performs network I/O takes an explicit `&RpcClient`
//! and `&Keypair` so that callers control the RPC endpoint and signer.

use anyhow::{bail, ensure, Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    rent::Rent,
    signature::{Keypair, Signer},
    system_instruction, system_program,
};
use std::{thread, time::Duration};

use crate::infrastructure::solana::tx_sender;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Hard upper bound on a single account's data allocation (10 MiB).
const MAX_ACCOUNT_SPACE: usize = 10 * 1024 * 1024;

/// Number of attempts before falling back to `Rent::default()`.
const RENT_RETRY_COUNT: u32 = 5;

/// Milliseconds to wait after creating a new account before the caller sends
/// a follow-up transaction on the same account.
///
/// Without this pause the validator may still hold a write-lock on the
/// freshly-created account, causing the next transaction to fail with
/// `AccountInUse`.  300 ms is consistent with the value used in
/// `round_submitter` and `vk_uploader`.
const POST_CREATE_SLEEP_MS: u64 = 300;

// ─────────────────────────────────────────────────────────────────────────────
// Program / fee-payer guards
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that `program_id` is deployed and executable on the cluster.
pub fn ensure_program_deployed(rpc: &RpcClient, program_id: &Pubkey) -> Result<()> {
    let acc = rpc
        .get_account(program_id)
        .with_context(|| format!("program account {program_id} not found on cluster"))?;
    ensure!(
        acc.executable,
        "program {program_id} exists but is NOT executable — \
         did you deploy to the correct cluster?"
    );
    Ok(())
}

/// Verifies that `payer` is a valid fee-payer: System-owned, non-executable,
/// and has a positive lamport balance.
pub fn ensure_payer_funded(rpc: &RpcClient, payer: &Keypair) -> Result<()> {
    tx_sender::validate_fee_payer(rpc, payer)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rent query
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the rent-exempt minimum lamports for an account of `space` bytes.
///
/// Retries up to [`RENT_RETRY_COUNT`] times with exponential back-off.  On
/// persistent RPC failure, falls back to `Rent::default()` (conservative).
pub fn rent_exempt_lamports(rpc: &RpcClient, space: usize) -> u64 {
    let clamped = space.clamp(1, MAX_ACCOUNT_SPACE);
    for attempt in 0..RENT_RETRY_COUNT {
        match rpc.get_minimum_balance_for_rent_exemption(clamped) {
            Ok(v) => return v,
            Err(e) => {
                eprintln!(
                    "[account_manager] rent query attempt {}/{RENT_RETRY_COUNT} failed: {e}",
                    attempt + 1
                );
                thread::sleep(Duration::from_millis(250 * u64::from(attempt + 1)));
            }
        }
    }
    let fallback = Rent::default().minimum_balance(clamped);
    eprintln!(
        "[account_manager] WARNING: all rent RPC attempts failed; \
         using Rent::default() fallback: {fallback} lamports for {clamped} bytes"
    );
    fallback
}

// ─────────────────────────────────────────────────────────────────────────────
// Seed-derived account creation
// ─────────────────────────────────────────────────────────────────────────────

/// Ensures that a seed-derived program account exists with at least `space`
/// bytes allocated.
///
/// * Already exists and is large enough → no-op, returns pubkey immediately.
/// * Already exists but is too small → returns an error.
/// * Does not exist → creates it, **sleeps [`POST_CREATE_SLEEP_MS`] ms**, then
///   returns the pubkey.
///
/// The sleep after creation is intentional: Solana validators hold a
/// write-lock on a newly created account until the transaction is committed.
/// Sending a second transaction on the same account too quickly causes
/// `AccountInUse`.  This was the root cause of intermittent failures in the
/// original `upload_vk_in_chunks` and `submit_round`.
pub fn ensure_seeded_account(
    rpc: &RpcClient,
    payer: &Keypair,
    program_id: &Pubkey,
    seed: &str,
    space: usize,
) -> Result<Pubkey> {
    ensure_program_deployed(rpc, program_id)?;
    ensure_payer_funded(rpc, payer)?;

    let pubkey = Pubkey::create_with_seed(&payer.pubkey(), seed, program_id)
        .with_context(|| format!("failed to derive account pubkey for seed='{seed}'"))?;

    match rpc.get_account(&pubkey) {
        Ok(acc) => {
            ensure!(
                acc.data.len() >= space,
                "existing account {pubkey} is too small: \
                 {} bytes allocated but {space} bytes required — \
                 use a different seed or re-create the account",
                acc.data.len()
            );
            eprintln!(
                "[account_manager] account {pubkey} already exists ({} bytes)",
                acc.data.len()
            );
            thread::sleep(Duration::from_millis(30000));

            Ok(pubkey)
        }
        Err(_) => {
            let lamports = rent_exempt_lamports(rpc, space);
            let ix = system_instruction::create_account_with_seed(
                &payer.pubkey(),
                &pubkey,
                &payer.pubkey(),
                seed,
                lamports,
                space as u64,
                program_id,
            );
            eprintln!(
                "[account_manager] creating account {pubkey}: \
                 seed='{seed}', space={space} bytes, lamports={lamports}"
            );
            let sig = tx_sender::send_and_confirm(rpc, payer, &[ix])
                .with_context(|| format!("failed to create account with seed='{seed}'"))?;
            eprintln!("[account_manager] account created: {pubkey}  tx={sig}");

            // ── Sleep after creation ──────────────────────────────────────
            // The validator must release the write-lock on the new account
            // before any subsequent transaction can touch it.  Without this
            // pause the immediately following InitVk / InitRound fails with
            // AccountInUse on devnet.
            eprintln!(
                "[account_manager] sleeping {POST_CREATE_SLEEP_MS}ms after account creation \
                 (write-lock release)"
            );
            thread::sleep(Duration::from_millis(POST_CREATE_SLEEP_MS));

            Ok(pubkey)
        }
    }
}