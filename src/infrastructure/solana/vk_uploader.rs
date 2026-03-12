//! Idempotent VK upload flow.
//!
//! # Responsibility
//! This module owns the full lifecycle of getting a G16V payload on-chain:
//!
//! 1. **Seed collision resolution** — if the target account already holds a
//!    *different* VK (or any non-VK data), a unique seed suffix is derived
//!    from the SHA-256 of the payload so two VKs never overwrite each other.
//! 2. **Account creation** (delegated to [`account_manager`]).
//! 3. **InitVk** — only if the account has no valid VKH1 header yet.
//! 4. **WriteVkChunk × N** — resumes from `bytes_written` on-chain.
//! 5. **SealVk** — commits the hash check on-chain.
//! 6. **Post-seal sanity** — reads back the account and verifies the magic.
//!
//! # Sleep strategy
//! Every on-chain write is followed by a [`POST_TX_SLEEP_MS`] pause.
//!
//! The original `upload_vk_in_chunks` had **no sleeps between WriteVkChunk
//! calls**, which was the root cause of intermittent `AccountInUse` failures
//! during multi-chunk VK uploads on devnet.  This module fixes that.
//!
//! Sleep placement:
//! * After `ensure_seeded_account` — handled inside `account_manager`
//!   (sleep is there so ALL callers benefit, not just this module).
//! * After `InitVk` — before the first `WriteVkChunk`.
//! * After **each** `WriteVkChunk` — before the next write or SealVk.
//! * After `SealVk` — before the post-seal sanity read.

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::{thread, time::Duration};
use solana_sdk::signature::Signer;
use crate::infrastructure::solana::{account_manager, tx_sender, zk_instructions as ix};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed byte length of the on-chain VKH1 account header.
///
/// Layout (46 bytes):
/// ```text
/// [0..4]  "VKH1"
/// [4]     version = 1
/// [5]     sealed  (0 = open, 1 = sealed)
/// [6..10] total_len    (u32 LE)
/// [10..14] bytes_written (u32 LE)
/// [14..46] sha256(vk_payload) (32 bytes)
/// ```
pub const VK_HDR_LEN: usize = 46;

/// Maximum bytes per `WriteVkChunk` instruction.
/// Kept conservative to stay inside the 1232-byte packet limit after Borsh
/// framing and envelope overhead.
const MAX_CHUNK_BYTES: usize = 700;

/// Milliseconds to sleep after every on-chain write transaction.
///
/// Prevents `AccountInUse` (write-lock not yet released by the validator)
/// and avoids devnet rate-limit rejections between consecutive transactions
/// on the same account.  Matches the value used in `round_submitter`.
const POST_TX_SLEEP_MS: u64 = 300;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Uploads `vk_bytes` on-chain under the given `base_seed`, idempotently.
///
/// Returns the public key of the VK account after it has been sealed.
///
/// Safe to call multiple times with the same arguments:
/// * Already sealed with the same hash → returns immediately (no txs sent).
/// * Partially written → resumes from `bytes_written` on-chain.
/// * Seed collides with different data → derives a new seed automatically.
pub fn upload_vk(
    rpc: &RpcClient,
    program_id: &Pubkey,
    payer: &Keypair,
    base_seed: &str,
    vk_bytes: &[u8],
) -> Result<Pubkey> {
    let want_hash: [u8; 32] = Sha256::digest(vk_bytes).into();

    // ── 1. Resolve seed (collision-safe) ──────────────────────
    let seed = resolve_seed(rpc, program_id, payer, base_seed, &want_hash)?;
    eprintln!("[vk_uploader] resolved seed: '{seed}'");

    // ── 2. Ensure account exists with enough space ─────────────
    //   account_manager::ensure_seeded_account already sleeps POST_CREATE_SLEEP_MS
    //   after creating a new account, so we don't need an extra sleep here.
    let space = VK_HDR_LEN + vk_bytes.len();
    let vk_pk = account_manager::ensure_seeded_account(rpc, payer, program_id, &seed, space)?;

    // ── 3. Read on-chain header (if any) ──────────────────────
    let header = read_vk_header(rpc, &vk_pk);

    let start_offset: u32 = match &header {
        Some(h) => {
            ensure!(
                h.hash == want_hash,
                "account '{seed}' already contains a VK with a different hash \
                 (expected={}, found={}) — was the account modified externally?",
                hex::encode(want_hash),
                hex::encode(h.hash)
            );

            if h.sealed {
                ensure!(
                    h.total_len == vk_bytes.len(),
                    "sealed account '{seed}' reports total_len={} but vk_bytes has {} bytes",
                    h.total_len,
                    vk_bytes.len()
                );
                eprintln!("[vk_uploader] VK already sealed at {vk_pk} — nothing to do");
                return Ok(vk_pk);
            }

            eprintln!(
                "[vk_uploader] resuming upload: written={}/{} bytes",
                h.written,
                vk_bytes.len()
            );
            h.written as u32
        }

        None => {
            // ── 4a. InitVk ────────────────────────────────────
            let init_ix = ix::init_vk(
                *program_id,
                vk_pk,
                payer.pubkey(),
                seed.clone(),
                vk_bytes.len() as u32,
                want_hash,
            )
                .context("failed to build InitVk instruction")?;

            tx_sender::send_and_confirm(rpc, payer, &[init_ix])
                .context("InitVk transaction failed")?;
            eprintln!("[vk_uploader] InitVk sent");

            // Sleep after InitVk — the validator must release the write-lock
            // on the account before the first WriteVkChunk can proceed.
            // Without this, the first chunk fails with AccountInUse.
            eprintln!(
                "[vk_uploader] sleeping {POST_TX_SLEEP_MS}ms after InitVk (write-lock release)"
            );
            thread::sleep(Duration::from_millis(POST_TX_SLEEP_MS));

            0u32
        }
    };

    // ── 4b. WriteVkChunk × N (sleep between each chunk) ───────
    write_chunks(rpc, program_id, payer, &vk_pk, &seed, vk_bytes, start_offset)?;

    // ── 5. SealVk ─────────────────────────────────────────────
    let seal_ix = ix::seal_vk(*program_id, vk_pk, payer.pubkey(), seed.clone())
        .context("failed to build SealVk instruction")?;
    tx_sender::send_and_confirm(rpc, payer, &[seal_ix])
        .context("SealVk transaction failed")?;
    eprintln!("[vk_uploader] SealVk sent");

    // Sleep after SealVk before the post-seal sanity read to ensure the
    // validator has committed the sealed flag to the account's state.
    eprintln!(
        "[vk_uploader] sleeping {POST_TX_SLEEP_MS}ms after SealVk (state propagation)"
    );
    thread::sleep(Duration::from_millis(POST_TX_SLEEP_MS));

    // ── 6. Post-seal sanity ────────────────────────────────────
    let acc = rpc
        .get_account(&vk_pk)
        .context("failed to read VK account after seal")?;
    ensure!(
        acc.data.get(0..4) == Some(b"VKH1"),
        "post-seal sanity failed: account {vk_pk} does not start with 'VKH1'; \
         head={:?}",
        acc.data.get(0..4)
    );
    eprintln!("[vk_uploader] VK uploaded and sealed: {vk_pk}");

    Ok(vk_pk)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed representation of the 46-byte VKH1 account header.
#[derive(Debug, Clone)]
pub struct VkHeader {
    pub sealed:    bool,
    pub total_len: usize,
    pub written:   usize,
    pub hash:      [u8; 32],
}

/// Attempts to parse the VKH1 header from an on-chain account.
/// Returns `None` if the account does not exist, has insufficient data, or
/// does not start with `"VKH1"`.
pub fn read_vk_header(rpc: &RpcClient, vk_pk: &Pubkey) -> Option<VkHeader> {
    let acc = rpc.get_account(vk_pk).ok()?;
    let d = &acc.data;
    if d.len() < VK_HDR_LEN || &d[0..4] != b"VKH1" {
        return None;
    }
    Some(VkHeader {
        sealed:    d[5] != 0,
        total_len: u32::from_le_bytes(d[6..10].try_into().ok()?) as usize,
        written:   u32::from_le_bytes(d[10..14].try_into().ok()?) as usize,
        hash:      d[14..46].try_into().ok()?,
    })
}

/// Resolves the final seed, avoiding collisions with existing accounts.
///
/// | On-chain state | Result |
/// |----------------|--------|
/// | Account absent | `base_seed` as-is |
/// | "VKH1" + same hash | `base_seed` (idempotent reuse) |
/// | "VKH1" + different hash | `"{base_seed}-{hash[..8]}"` |
/// | Other magic (e.g. "RND1") | `"{base_seed}-{hash[..8]}"` |
fn resolve_seed(
    rpc: &RpcClient,
    program_id: &Pubkey,
    payer: &Keypair,
    base_seed: &str,
    want_hash: &[u8; 32],
) -> Result<String> {
    let base_pk = Pubkey::create_with_seed(&payer.pubkey(), base_seed, program_id)
        .with_context(|| format!("invalid base_seed '{base_seed}'"))?;

    let acc = match rpc.get_account(&base_pk) {
        Ok(a) => a,
        Err(_) => return Ok(base_seed.to_string()),
    };

    let head = acc.data.get(0..4).unwrap_or(&[]);
    if head == b"VKH1" {
        if let Some(h) = read_vk_header(rpc, &base_pk) {
            if h.hash == *want_hash {
                return Ok(base_seed.to_string());
            }
        }
    }

    // Collision: derive unique suffix from the payload hash.
    let hex = hex::encode(want_hash);
    let suffix = &hex[..8]; // 8 hex chars = 4 bytes, easy to read in logs
    let candidate = format!("{base_seed}-{suffix}");
    ensure!(
        candidate.len() <= 32,
        "derived seed '{candidate}' exceeds Solana's 32-byte limit; \
         shorten base_seed (currently {} chars)",
        base_seed.len()
    );
    eprintln!("[vk_uploader] seed collision at '{base_seed}'; resolved to '{candidate}'");
    Ok(candidate)
}

/// Sends `WriteVkChunk` transactions for `vk_bytes[start_offset..]`.
///
/// Sleeps [`POST_TX_SLEEP_MS`] **after every chunk**.  This was the missing
/// piece in the original client: without inter-chunk sleeps the validator
/// returns `AccountInUse` because the previous chunk's write-lock has not
/// been released yet.
fn write_chunks(
    rpc: &RpcClient,
    program_id: &Pubkey,
    payer: &Keypair,
    vk_pk: &Pubkey,
    seed: &str,
    vk_bytes: &[u8],
    start_offset: u32,
) -> Result<()> {
    let remaining = &vk_bytes[start_offset as usize..];
    if remaining.is_empty() {
        eprintln!("[vk_uploader] no chunks to write (already complete)");
        return Ok(());
    }

    let mut offset = start_offset;
    for (i, chunk) in remaining.chunks(MAX_CHUNK_BYTES).enumerate() {
        let chunk_ix = ix::write_vk_chunk(
            *program_id,
            *vk_pk,
            payer.pubkey(),
            seed.to_string(),
            offset,
            chunk.to_vec(),
        )
            .with_context(|| format!("failed to build WriteVkChunk #{i}"))?;

        eprintln!(
            "[vk_uploader] WriteVkChunk #{i}: offset={offset}, len={}",
            chunk.len()
        );
        tx_sender::send_and_confirm(rpc, payer, &[chunk_ix])
            .with_context(|| format!("WriteVkChunk #{i} failed (offset={offset})"))?;

        // Sleep after each chunk write.  The validator holds a write-lock on
        // the account until the transaction is fully committed; without this
        // pause the next write (or SealVk) arrives while the lock is still
        // held and fails with AccountInUse.
        thread::sleep(Duration::from_millis(POST_TX_SLEEP_MS));

        offset += chunk.len() as u32;
    }
    Ok(())
}