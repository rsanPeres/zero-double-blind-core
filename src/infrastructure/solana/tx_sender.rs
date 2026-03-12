//! Transaction building, simulation, sending, and confirmation.
//!
//! This module is the single place responsible for all network-level
//! transaction lifecycle concerns:
//!
//! * Fee-payer guard
//! * Packet-size guard
//! * Preflight simulation with rich on-chain log hints
//! * Send with retry
//! * Confirmation polling with timeout
//!
//! # Usage
//! ```ignore
//! let sig = send_and_confirm(&rpc, &payer, &[ix])?;
//! ```

use anyhow::{bail, ensure, Context, Result};
use solana_client::{
    client_error::ClientErrorKind,
    rpc_client::RpcClient,
    rpc_config::{RpcSendTransactionConfig, RpcSimulateTransactionConfig},
};
use solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    instruction::Instruction,
    packet::PACKET_DATA_SIZE,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use solana_transaction_status::TransactionConfirmationStatus;
use std::{thread, time::{Duration, Instant}};

// ──────────────────────────────────────────────────────────────
// Configuration constants
// ──────────────────────────────────────────────────────────────

/// Maximum time to wait for a transaction to reach `Confirmed` or `Finalized`.
const CONFIRM_TIMEOUT_SECS: u64 = 30;

/// Polling interval between confirmation status checks.
const CONFIRM_POLL_MS: u64 = 500;

/// Maximum send retries forwarded to the RPC node.
const SEND_MAX_RETRIES: usize = 5;

// ──────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────

/// Build, simulate, send, and confirm a transaction containing `ixs`.
///
/// Returns the base-58 transaction signature on success.
///
/// # Errors
/// Returns an error if:
/// * The fee-payer account is invalid.
/// * The serialized transaction exceeds [`PACKET_DATA_SIZE`].
/// * Preflight simulation fails (includes a human-readable hint derived from
///   on-chain program logs).
/// * The transaction fails on-chain.
/// * Confirmation times out after [`CONFIRM_TIMEOUT_SECS`] seconds (a devnet
///   fallback returns the signature if the tx reached `Processed`).
pub fn send_and_confirm(rpc: &RpcClient, payer: &Keypair, ixs: &[Instruction]) -> Result<String> {
    // ── 1. Build and sign ──────────────────────────────────────
    let blockhash = rpc.get_latest_blockhash().context("failed to fetch latest blockhash")?;
    let mut tx = Transaction::new_with_payer(ixs, Some(&payer.pubkey()));
    tx.sign(&[payer], blockhash);

    // ── 2. Fee-payer guard ─────────────────────────────────────
    validate_fee_payer(rpc, payer)?;

    // ── 3. Packet-size guard ───────────────────────────────────
    let raw_len = tx.message_data().len();
    let ix_data_total: usize = ixs.iter().map(|ix| ix.data.len()).sum();
    eprintln!(
        "[tx] raw_len={raw_len} limit={PACKET_DATA_SIZE} ix_data_total={ix_data_total}"
    );
    ensure!(
        raw_len <= PACKET_DATA_SIZE,
        "transaction too large: {raw_len} bytes > {PACKET_DATA_SIZE} byte limit"
    );

    // ── 4. Preflight simulation with rich diagnostic ───────────
    let sim_result = rpc.simulate_transaction_with_config(
        &tx,
        RpcSimulateTransactionConfig {
            sig_verify:  true,
            commitment:  Some(CommitmentConfig::processed()),
            ..Default::default()
        },
    );

    match sim_result {
        Ok(sim) => {
            let logs = sim.value.logs.unwrap_or_default();
            for line in &logs {
                eprintln!("[sim] {line}");
            }
            if let Some(err) = sim.value.err {
                let hint = derive_error_hint(&logs);
                bail!("preflight failed: {err:?} — {hint}");
            }
        }
        Err(e) => {
            eprintln!("[sim] RPC error: {e}");
            if let ClientErrorKind::RpcError(detail) = e.kind() {
                eprintln!("[sim] detail: {detail:?}");
            }
            bail!("preflight RPC call failed: {e}");
        }
    }

    // ── 5. Send ────────────────────────────────────────────────
    let sig = match rpc.send_transaction_with_config(
        &tx,
        RpcSendTransactionConfig {
            skip_preflight:        false,
            preflight_commitment:  Some(CommitmentLevel::Processed),
            max_retries:           Some(SEND_MAX_RETRIES),
            ..Default::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[tx] send error: {e}");
            if let ClientErrorKind::RpcError(detail) = e.kind() {
                eprintln!("[tx] detail: {detail:?}");
            }
            bail!(
                "send_transaction failed — possible causes: \
                 BlockhashNotFound (blockhash expired), NodeUnhealthy / RateLimit (devnet \
                 instability). Original error: {e}"
            );
        }
    };
    eprintln!("[tx] sent: sig={sig}");

    // ── 6. Confirmation polling ────────────────────────────────
    wait_for_confirmation(rpc, &sig.to_string())
}

// ──────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────

/// Verify that `payer` is a valid System-owned, non-executable account with
/// a positive lamport balance.
pub fn validate_fee_payer(rpc: &RpcClient, payer: &Keypair) -> Result<()> {
    let acc = rpc
        .get_account(&payer.pubkey())
        .context("failed to fetch fee-payer account")?;
    ensure!(
        acc.owner == system_program::id(),
        "fee-payer {} is not System-owned (owner={})",
        payer.pubkey(),
        acc.owner
    );
    ensure!(
        !acc.executable,
        "fee-payer {} must not be executable",
        payer.pubkey()
    );
    ensure!(
        acc.lamports > 0,
        "fee-payer {} has zero lamports",
        payer.pubkey()
    );
    Ok(())
}

/// Poll for transaction confirmation, returning the signature string on success.
///
/// Returns early with the signature if the transaction reaches `Confirmed` or
/// `Finalized`.  If the timeout expires but the transaction is at `Processed`
/// (common on devnet), returns the signature with a warning rather than
/// failing hard.
fn wait_for_confirmation(rpc: &RpcClient, sig: &str) -> Result<String> {
    use solana_sdk::signature::Signature;
    let signature: Signature = sig.parse().context("failed to parse signature")?;
    let deadline = Instant::now() + Duration::from_secs(CONFIRM_TIMEOUT_SECS);
    let mut last_status: Option<TransactionConfirmationStatus> = None;

    loop {
        if Instant::now() > deadline {
            if matches!(last_status, Some(TransactionConfirmationStatus::Processed)) {
                eprintln!(
                    "[tx] confirmation timeout after {CONFIRM_TIMEOUT_SECS}s, but transaction \
                     reached 'Processed' — returning signature (devnet leniency). sig={sig}"
                );
                return Ok(sig.to_string());
            }
            bail!(
                "timed out waiting for transaction confirmation after {CONFIRM_TIMEOUT_SECS}s; \
                 sig={sig}"
            );
        }

        let statuses = rpc
            .get_signature_statuses(&[signature])
            .context("get_signature_statuses RPC call failed")?;

        if let Some(Some(status)) = statuses.value.first() {
            if let Some(on_chain_err) = &status.err {
                bail!("transaction failed on-chain: {on_chain_err:?}  sig={sig}");
            }

            if let Some(cs) = status.confirmation_status.clone() {
                if Some(cs.clone()) != last_status {
                    eprintln!("[tx] status: {cs:?}");
                    last_status = Some(cs.clone());
                }
                match cs {
                    TransactionConfirmationStatus::Confirmed
                    | TransactionConfirmationStatus::Finalized => {
                        eprintln!("[tx] confirmed: {cs:?}  sig={sig}");
                        return Ok(sig.to_string());
                    }
                    TransactionConfirmationStatus::Processed => {
                        // keep polling
                    }
                }
            } else if let Some(confirmations) = status.confirmations {
                eprintln!("[tx] confirmations (legacy): {confirmations}");
                if confirmations >= 1 {
                    return Ok(sig.to_string());
                }
            }
        }

        thread::sleep(Duration::from_millis(CONFIRM_POLL_MS));
    }
}

/// Translate on-chain program log fragments into a human-readable error hint.
fn derive_error_hint(logs: &[String]) -> String {
    if logs.iter().any(|l| l.contains("parse_proof_to_uncompressed_be falhou")
        || l.contains("parse_proof_to_uncompressed_be failed")) {
        return "proof_bytes format invalid — expected 128 bytes (compressed: A32|B64|C32) \
                or 256 bytes (uncompressed: A64|B128|C64)"
            .into();
    }
    if logs.iter().any(|l| l.contains("public_inputs tamanho inválido")
        || l.contains("public_inputs size invalid")) {
        return "public_inputs (BE32) size does not match this VK's nr_pubinputs".into();
    }
    if logs.iter().any(|l| l.contains("nr_pubinputs não suportado")
        || l.contains("nr_pubinputs not supported")) {
        return "VK expects N ∈ {1, 2, 3, 4, 8, 12, 16} public inputs".into();
    }
    if logs.iter().any(|l| l.contains("seed diverge")) {
        return "round seed mismatch — on-chain seed differs from local seed".into();
    }
    if logs.iter().any(|l| {
        l.contains("VK sem magic") || l.contains("VK não selada")
            || l.contains("VK no magic") || l.contains("VK not sealed")
    }) {
        return "VK account is invalid — missing magic header or not yet sealed".into();
    }
    if logs.iter().any(|l| l.contains("hash VK diverge") || l.contains("VK hash mismatch")) {
        return "VK hash does not match — vk_bytes differ from the on-chain account; \
                verify that you are passing the vk_pk returned by upload_vk"
            .into();
    }
    if logs.iter().any(|l| l.contains("verify=false")) {
        let nr_line = logs.iter().find(|l| l.contains("vk.nr_pubinputs")).cloned().unwrap_or_default();
        let lens    = logs.iter().find(|l| l.contains("lens:")).cloned().unwrap_or_default();
        return format!(
            "Groth16 verification returned false — the public commitment likely does not \
             match the commitment used when generating the proof.\n  {nr_line}\n  {lens}"
        );
    }
    "preflight failed (no matching on-chain log fragment found)".into()
}