//! Idempotent round submission flow.
//!
//! # Responsibility
//! This module owns the full lifecycle of submitting a ZK proof round:
//!
//! 1. **Seed namespacing** — prefixes the round seed with `"RND-"` to prevent
//!    any collision with VK seeds (which use the `"VK-"` prefix).
//! 2. **Account creation** (delegated to [`account_manager`]).
//! 3. **InitRound** — only if the account has no valid RND1 header yet.
//! 4. **WriteRoundChunk × N** — resumes from `bytes_written` on-chain.
//! 5. **VK account validation** with retry (devnet propagation delay).
//! 6. **Public-input canonicalisation** — reduces each Fr element mod q.
//! 7. **SubmitRound** — includes `ComputeBudget` instructions.
//!
//! No cryptographic logic lives here.  Proof bytes and public inputs are
//! treated as opaque byte slices and forwarded to the on-chain program.

use anyhow::{bail, ensure, Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Keypair};
use std::{thread, time::Duration};
use solana_sdk::signature::Signer;
use crate::infrastructure::solana::{account_manager, tx_sender, vk_codec, zk_instructions as ix};
use crate::infrastructure::solana::vk_uploader::VK_HDR_LEN;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum bytes per `WriteRoundChunk` instruction.
const MAX_CHUNK_BYTES: usize = 700;

/// Milliseconds to sleep after each on-chain write before the next operation.
/// Helps avoid `AccountInUse` errors and devnet rate-limit rejections.
const POST_TX_SLEEP_MS: u64 = 300;

/// Number of times to retry reading the VK account after `SubmitRound` is
/// assembled, to handle devnet propagation delay.
const VK_VALIDATION_RETRIES: u32 = 6;

/// Milliseconds between VK validation retries.
const VK_RETRY_SLEEP_MS: u64 = 150;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Submits a ZK proof round, idempotently.
///
/// # Arguments
/// * `rpc`            — Solana RPC client.
/// * `program_id`     — On-chain ZK-verifier program public key.
/// * `payer`          — Fee-payer and account owner.
/// * `round_seed`     — Base seed for the round account (automatically
///                      namespaced with `"RND-"` prefix if absent).
/// * `vk_pk`          — Public key of the sealed VK account to verify against.
/// * `proof_bytes`    — 128-byte (compressed) or 256-byte (uncompressed) proof.
/// * `public_inputs`  — `N × 32` bytes of Fr elements in big-endian form.
/// * `bits`           — Boolean flags packed into 1 byte per flag (as the
///                      on-chain program currently expects).
///
/// # Returns
/// The base-58 transaction signature of the `SubmitRound` transaction.
///
/// # Errors
/// Returns an error if any on-chain transaction fails, the VK account is
/// invalid, the round is already sealed, or if the proof is rejected.
pub fn submit_round(
    rpc: &RpcClient,
    program_id: &Pubkey,
    payer: &Keypair,
    round_seed: &str,
    vk_pk: Pubkey,
    proof_bytes: Vec<u8>,
    public_inputs: Vec<u8>,
    bits: Vec<bool>,
) -> Result<String> {
    account_manager::ensure_program_deployed(rpc, program_id)?;
    account_manager::ensure_payer_funded(rpc, payer)?;

    // ── 1. Namespace the seed ──────────────────────────────────
    let seed = namespace_round_seed(round_seed);
    eprintln!("[round_submitter] round seed: '{seed}'");

    // ── 2. Pack bits (1 byte per bool, matches on-chain expectation) ───
    // NOTE: The on-chain program currently stores 1 byte per flag, not
    // bit-packed.  If the contract is updated to bit-pack, change this line
    // and update compute_round_space() accordingly.
    let bits_payload: Vec<u8> = bits.iter().map(|&b| u8::from(b)).collect();

    // ── 3. Compute required account space ─────────────────────
    let space = compute_round_space(&seed, bits_payload.len(), public_inputs.len());
    eprintln!(
        "[round_submitter] seed_len={}, bits_len={}B, pi_len={}B, total_space={space}B",
        seed.len(),
        bits_payload.len(),
        public_inputs.len()
    );

    // ── 4. Ensure round account exists ────────────────────────
    let round_pk =
        account_manager::ensure_seeded_account(rpc, payer, program_id, &seed, space)?;
    thread::sleep(Duration::from_millis(POST_TX_SLEEP_MS));

    // ── 5. Determine resume point ─────────────────────────────
    let (start_offset, must_init) =
        read_resume_state(rpc, &round_pk, &seed, &bits_payload)?;

    // ── 6. InitRound (if needed) ──────────────────────────────
    if must_init {
        let init_ix = ix::init_round(
            *program_id,
            round_pk,
            payer.pubkey(),
            seed.clone(),
            bits_payload.len() as u32,
            public_inputs.len() as u32,
        )
            .context("failed to build InitRound instruction")?;

        eprintln!("[round_submitter] InitRound: bits_len={}B", bits_payload.len());
        tx_sender::send_and_confirm(rpc, payer, &[init_ix])
            .context("InitRound transaction failed")?;
        thread::sleep(Duration::from_millis(POST_TX_SLEEP_MS));
    }

    // ── 7. WriteRoundChunk × N ────────────────────────────────
    write_chunks(rpc, program_id, payer, &round_pk, &seed, &bits_payload, start_offset)?;

    // ── 8. Validate VK account (with retry for devnet lag) ────
    validate_vk_account(rpc, &vk_pk)?;

    // ── 9. Canonicalise public inputs ─────────────────────────
    let canonical_inputs = vk_codec::canonicalize_public_inputs_be32(&public_inputs)
        .context("failed to canonicalise public inputs")?;

    // ── 10. SubmitRound ───────────────────────────────────────
    let submit_ixs = ix::submit_round_ixs(
        *program_id,
        round_pk,
        payer.pubkey(),
        vk_pk,
        seed.clone(),
        proof_bytes,
        canonical_inputs,
    )
        .context("failed to build SubmitRound instructions")?;

    eprintln!(
        "[round_submitter] SubmitRound: ix_data={}B",
        submit_ixs.iter().map(|i| i.data.len()).sum::<usize>()
    );
    let sig = tx_sender::send_and_confirm(rpc, payer, &submit_ixs)
        .context("SubmitRound transaction failed")?;
    thread::sleep(Duration::from_millis(POST_TX_SLEEP_MS));

    eprintln!("[round_submitter] done: sig={sig}");
    Ok(sig)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed representation of the RND1 account header (variable length).
#[derive(Debug)]
struct RoundHeader {
    sealed:        bool,
    seed:          String,
    bits_len:      usize,
    bytes_written: usize,
}

/// Returns `(start_offset, must_init)` based on the current on-chain state.
///
/// * If the account has a valid `RND1` header → resume from `bytes_written`.
/// * If the account has no valid header → `must_init = true`, `start_offset = 0`.
/// * If the account is already sealed → returns an error.
fn read_resume_state(
    rpc: &RpcClient,
    round_pk: &Pubkey,
    seed: &str,
    bits_payload: &[u8],
) -> Result<(u32, bool)> {
    let acc = match rpc.get_account(round_pk) {
        Ok(a) => a,
        Err(_) => return Ok((0, true)),
    };

    let header = match parse_round_header(&acc.data) {
        Some(h) => h,
        None => return Ok((0, true)),
    };

    if header.sealed {
        bail!(
            "round account {round_pk} is already sealed; \
             use a different seed (e.g. append a timestamp suffix)"
        );
    }
    ensure!(
        header.seed == seed,
        "on-chain round seed '{}' does not match local seed '{}' — \
         was the account created with a different seed?",
        header.seed,
        seed
    );
    ensure!(
        header.bits_len == bits_payload.len(),
        "on-chain bits_len={} does not match local bits_payload len={} — \
         use a different seed if the round data has changed",
        header.bits_len,
        bits_payload.len()
    );

    eprintln!(
        "[round_submitter] resuming: written={}/{} bytes (hdr already set)",
        header.bytes_written, header.bits_len
    );
    Ok((header.bytes_written as u32, false))
}

/// Parses the variable-length RND1 header from raw account data.
///
/// Returns `None` if the data is too short, has the wrong magic, or is
/// otherwise malformed.
fn parse_round_header(data: &[u8]) -> Option<RoundHeader> {
    // Minimum: magic(4) + version(1) + sealed(1) + seed_len(4) = 10 bytes
    if data.len() < 10 || &data[0..4] != b"RND1" {
        return None;
    }
    let sealed = data[5] != 0;
    let seed_len = u32::from_le_bytes(data[6..10].try_into().ok()?) as usize;

    // seed_len + bits_len(4) + bytes_written(4) fields
    if data.len() < 10 + seed_len + 8 {
        return None;
    }
    let seed = String::from_utf8_lossy(&data[10..10 + seed_len]).to_string();
    let bits_len = u32::from_le_bytes(data[10 + seed_len..14 + seed_len].try_into().ok()?) as usize;
    let bytes_written =
        u32::from_le_bytes(data[14 + seed_len..18 + seed_len].try_into().ok()?) as usize;

    Some(RoundHeader { sealed, seed, bits_len, bytes_written })
}

/// Computes the total account space required for a round account.
///
/// Layout mirrors the on-chain `round_hdr_len` helper:
/// ```text
/// magic(4) + version(1) + sealed(1) + seed_len(4) + seed + bits_len(4)
///   + bytes_written(4)  [= header]
/// + bits_payload
/// + public_inputs_len_field(4) + public_inputs
/// ```
fn compute_round_space(seed: &str, bits_len: usize, public_inputs_len: usize) -> usize {
    let seed_len = seed.len();
    let hdr_len = 4 + 1 + 1 + 4 + seed_len + 4 + 4;
    let inputs_block = 4 + public_inputs_len; // u32 length prefix + bytes
    hdr_len + bits_len + inputs_block
}

/// Ensures the round seed starts with `"RND-"` to prevent collisions with
/// VK seeds (which use `"VK-"`) and other data.
fn namespace_round_seed(seed: &str) -> String {
    if seed.starts_with("RND-") || seed.starts_with("RD-") {
        seed.to_string()
    } else {
        format!("RND-{seed}")
    }
}

/// Sends `WriteRoundChunk` transactions for the slice
/// `bits_payload[start_offset..]`, with a short sleep between chunks to
/// avoid `AccountInUse` errors on devnet.
fn write_chunks(
    rpc: &RpcClient,
    program_id: &Pubkey,
    payer: &Keypair,
    round_pk: &Pubkey,
    seed: &str,
    bits_payload: &[u8],
    start_offset: u32,
) -> Result<()> {
    let remaining = &bits_payload[start_offset as usize..];
    if remaining.is_empty() {
        eprintln!("[round_submitter] no chunks pending (already complete)");
        return Ok(());
    }

    let mut offset = start_offset;
    for (i, chunk) in remaining.chunks(MAX_CHUNK_BYTES).enumerate() {
        let chunk_ix = ix::write_round_chunk(
            *program_id,
            *round_pk,
            payer.pubkey(),
            seed.to_string(),
            offset,
            chunk.to_vec(),
        )
            .with_context(|| format!("failed to build WriteRoundChunk #{i}"))?;

        eprintln!(
            "[round_submitter] WriteRoundChunk #{i}: offset={offset}, len={}",
            chunk.len()
        );
        tx_sender::send_and_confirm(rpc, payer, &[chunk_ix])
            .with_context(|| format!("WriteRoundChunk #{i} failed (offset={offset})"))?;

        thread::sleep(Duration::from_millis(POST_TX_SLEEP_MS));
        offset += chunk.len() as u32;
    }
    Ok(())
}

/// Validates the VK account, retrying to handle devnet propagation delays.
///
/// Checks:
/// * Account is reachable via RPC.
/// * Data is at least `VK_HDR_LEN` bytes.
/// * Magic == `"VKH1"`.
fn validate_vk_account(rpc: &RpcClient, vk_pk: &Pubkey) -> Result<()> {
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..VK_VALIDATION_RETRIES {
        match rpc.get_account_with_commitment(vk_pk, CommitmentConfig::processed()) {
            Ok(resp) => {
                if let Some(acc) = resp.value {
                    let head = acc.data.get(0..4).unwrap_or(&[]);
                    let head_str = std::str::from_utf8(head).unwrap_or("????");
                    eprintln!(
                        "[round_submitter] VK account {vk_pk}: \
                         owner={}, data_len={}, magic='{head_str}'",
                        acc.owner, acc.data.len()
                    );
                    ensure!(
                        acc.data.len() >= VK_HDR_LEN && head == b"VKH1",
                        "VK account {vk_pk} is invalid: magic='{head_str}', \
                         data_len={} — ensure you are passing the vk_pk returned \
                         by upload_vk (seed collision may have shifted the address)",
                        acc.data.len()
                    );
                    return Ok(());
                } else {
                    last_err = Some(anyhow::anyhow!(
                        "VK account {vk_pk} not found on RPC (attempt {})",
                        attempt + 1
                    ));
                }
            }
            Err(e) => {
                last_err = Some(anyhow::anyhow!(e));
            }
        }
        thread::sleep(Duration::from_millis(VK_RETRY_SLEEP_MS));
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!("VK account {vk_pk} not found after {VK_VALIDATION_RETRIES} attempts")
    }))
}