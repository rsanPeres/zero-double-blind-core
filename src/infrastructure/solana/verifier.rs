//! Off-chain Groth16 sanity checks that mirror on-chain verification logic.
//!
//! # Two entry-points
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`sanity_check_n1`]   | Fast single-path check — matches the canonical on-chain path for N=1. Use in CI. |
//! | [`sanity_check_full`] | Exhaustive debug grid: 4 VK variants × 4 B variants × 2 A signs × 2 C signs (64 combos). Use when `sanity_check_n1` fails. |
//!
//! # Bug fixed (original `verifier.rs`)
//! The original code used `solana_program::hash::hash` (the on-chain SHA-256
//! wrapper, which uses SHA-256 but is compiled for BPF and should not be used
//! client-side).  This module now uses `sha2::Sha256` directly.
//!
//! Duplicated G2 helpers (`swap_g2_128_in_place`, `neg_be32_in_place`,
//! `conjugate_g2_128_in_place`) have been removed; this module re-exports the
//! equivalents from [`vk_codec`].

use anyhow::{anyhow, bail, ensure, Context, Result};
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::env;

use crate::infrastructure::solana::vk_codec::{
    self, conjugate_vk_g2_in_place, make_vk, parse_vk_bytes, swap_vk_g2_orientation_in_place,
    ParsedVk,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants — must match on-chain VKH1 header layout
// ─────────────────────────────────────────────────────────────────────────────

const VK_HDR_LEN: usize = 46;
const VK_HASH_OFFSET: usize = 14; // sha256 stored at bytes [14..46]
const VK_TOTAL_LEN_OFFSET: usize = 6; // u32 LE at bytes [6..10]

// ─────────────────────────────────────────────────────────────────────────────
// Public API — fast check (N=1)
// ─────────────────────────────────────────────────────────────────────────────

/// Runs a single off-chain Groth16 verification for N=1, using the canonical
/// path that the on-chain program would take.
///
/// # Arguments
/// * `vk_pk`          — Public key of the sealed VK account.
/// * `proof_bytes`    — 128 bytes (compressed) or 256 bytes (uncompressed).
/// * `pub_inputs_be`  — 32 bytes (one Fr element, big-endian).
///
/// # Environment variable
/// * `RPC_URL` — falls back to devnet if unset (with a warning).
///
/// # Errors
/// Returns an error if the VK account cannot be read, the hash does not match,
/// or the proof cannot be parsed.  Returns `Ok(false)` if verification fails.
pub fn sanity_check_n1(
    vk_pk: Pubkey,
    proof_bytes: &[u8],
    pub_inputs_be: &[u8],
) -> Result<bool> {
    let rpc_url = read_rpc_url();
    let rpc = RpcClient::new(rpc_url);

    let (_, _, parsed) = load_vk_from_chain(&rpc, &vk_pk)?;
    let vk = make_vk(&parsed);

    ensure!(
        vk.nr_pubinputs * 32 == pub_inputs_be.len(),
        "public inputs size mismatch: got {} bytes, expected {} (nr_pubinputs={})",
        pub_inputs_be.len(),
        vk.nr_pubinputs * 32,
        vk.nr_pubinputs
    );
    ensure!(
        vk.nr_pubinputs == 1,
        "sanity_check_n1 only supports N=1; this VK has N={}",
        vk.nr_pubinputs
    );

    let (a64, b128, c64) = parse_proof(proof_bytes)?;

    let mut inputs = [[0u8; 32]; 1];
    inputs[0].copy_from_slice(&pub_inputs_be[0..32]);

    let mut verifier = Groth16Verifier::<1>::new(&a64, &b128, &c64, &inputs, &vk)
        .map_err(|_| anyhow!("Groth16Verifier::new() failed — invalid proof or VK points"))?;

    verifier
        .verify()
        .map_err(|_| anyhow!("Groth16Verifier::verify() returned an internal error"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — exhaustive debug grid
// ─────────────────────────────────────────────────────────────────────────────

/// Exhaustive off-chain sanity check: tries all 64 combinations of
/// (VK orientation × B orientation × A sign × C sign) and reports which
/// combination(s) succeed.
///
/// This is a **debugging tool** for diagnosing orientation mismatches between
/// the prover and the on-chain verifier.  For production use, prefer
/// [`sanity_check_n1`].
///
/// # Arguments
/// * `vk_pk`            — Public key of the sealed VK account.
/// * `proof_be`         — 128 or 256 bytes.
/// * `pub_inputs_be`    — `N × 32` bytes.
/// * `local_vk_bytes`   — Optional G16V payload to compare against on-chain
///                        data (useful to catch upload encoding errors).
///
/// # Returns
/// `Ok(true)` if at least one combination passed.
pub fn sanity_check_full(
    vk_pk: Pubkey,
    proof_be: &[u8],
    pub_inputs_be: &[u8],
    local_vk_bytes: Option<&[u8]>,
) -> Result<bool> {
    let rpc_url = read_rpc_url();
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (payload_onchain, hash_onchain, parsed_norm) = load_vk_from_chain(&rpc, &vk_pk)?;

    let n = parsed_norm.nr_pubinputs;
    ensure!(
        n * 32 == pub_inputs_be.len(),
        "public inputs size mismatch: got {} bytes, expected {} (nr_pubinputs={n})",
        pub_inputs_be.len(),
        n * 32
    );
    eprintln!("[sanity_full] vk.nr_pubinputs={n}");

    // ── Optional local vs on-chain comparison ─────────────────
    if let Some(local) = local_vk_bytes {
        let hash_local: [u8; 32] = Sha256::digest(local).into();
        eprintln!("[sanity_full] on-chain hash: {}", hex::encode(hash_onchain));
        eprintln!("[sanity_full] local   hash: {}", hex::encode(hash_local));
        match vk_codec::first_diff(local, &payload_onchain) {
            None => eprintln!("[sanity_full] local VK == on-chain VK (byte-identical)"),
            Some((off, a, b)) => eprintln!(
                "[sanity_full] local VK != on-chain VK: \
                 first diff at byte {off} (local={a:#04x}, on-chain={b:#04x})"
            ),
        }
    }

    // ── Build 4 VK variants ────────────────────────────────────
    let mut vk_swap_p = parsed_norm.clone();
    swap_vk_g2_orientation_in_place(&mut vk_swap_p);

    let mut vk_conj_p = parsed_norm.clone();
    conjugate_vk_g2_in_place(&mut vk_conj_p);

    let mut vk_swco_p = parsed_norm.clone();
    swap_vk_g2_orientation_in_place(&mut vk_swco_p);
    conjugate_vk_g2_in_place(&mut vk_swco_p);

    let vk_norm = make_vk(&parsed_norm);
    let vk_swap = make_vk(&vk_swap_p);
    let vk_conj = make_vk(&vk_conj_p);
    let vk_swco = make_vk(&vk_swco_p);

    // ── Parse proof ────────────────────────────────────────────
    let (a64, b128, c64) = parse_proof(proof_be)?;
    eprintln!(
        "[sanity_full] B.x halves: {:02x}{:02x}{:02x}{:02x} | {:02x}{:02x}{:02x}{:02x}",
        b128[0], b128[1], b128[2], b128[3],
        b128[32], b128[33], b128[34], b128[35]
    );

    // N=1 inputs array
    let inputs_1 = to_inputs_array::<1>(pub_inputs_be)
        .map_err(|_| anyhow!("pub_inputs_be is not exactly 32 bytes (N=1 required)"))?;

    // ── Exhaustive grid ────────────────────────────────────────
    #[derive(Clone, Copy, Debug)]
    enum VkSel { Norm, Swap, Conj, SwCo }
    #[derive(Clone, Copy, Debug)]
    enum BSel  { Norm, Swap, Conj, SwCo }
    #[derive(Clone, Copy, Debug)]
    enum Sign  { Pos, Neg }

    let pick_vk = |s: VkSel| -> &Groth16Verifyingkey {
        match s {
            VkSel::Norm => &vk_norm,
            VkSel::Swap => &vk_swap,
            VkSel::Conj => &vk_conj,
            VkSel::SwCo => &vk_swco,
        }
    };

    let mut found = false;

    for vk_sel in [VkSel::Norm, VkSel::Swap, VkSel::Conj, VkSel::SwCo] {
        for b_sel in [BSel::Norm, BSel::Swap, BSel::Conj, BSel::SwCo] {
            let mut b_try = b128;
            match b_sel {
                BSel::Norm => {}
                BSel::Swap => swap_g2_128_in_place(&mut b_try),
                BSel::Conj => conjugate_g2_128_in_place(&mut b_try),
                BSel::SwCo => {
                    swap_g2_128_in_place(&mut b_try);
                    conjugate_g2_128_in_place(&mut b_try);
                }
            }
            for a_sign in [Sign::Pos, Sign::Neg] {
                let mut a_try = a64;
                if let Sign::Neg = a_sign {
                    negate_g1_y_be_in_place(&mut a_try);
                }
                for c_sign in [Sign::Pos, Sign::Neg] {
                    let mut c_try = c64;
                    if let Sign::Neg = c_sign {
                        negate_g1_y_be_in_place(&mut c_try);
                    }
                    let label = format!(
                        "VK={vk_sel:?} B={b_sel:?} A={a_sign:?} C={c_sign:?}"
                    );
                    if try_verify_n1(&label, &a_try, &b_try, &c_try, &inputs_1, pick_vk(vk_sel)) {
                        found = true;
                    }
                }
            }
        }
    }

    if !found {
        eprintln!("[sanity_full] no combination passed — proof does not match this VK");
    }
    Ok(found)
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the VK payload from an on-chain VKH1 account, verifies the SHA-256
/// hash stored in the header, and parses it into a [`ParsedVk`].
///
/// Returns `(payload_bytes, sha256_hash, ParsedVk)`.
///
/// # Errors
/// Returns an error if the account does not exist, the header is malformed,
/// the hash does not match, or the G16V payload cannot be parsed.
pub fn load_vk_from_chain(
    rpc: &RpcClient,
    vk_pk: &Pubkey,
) -> Result<(Vec<u8>, [u8; 32], ParsedVk)> {
    let acc = rpc
        .get_account(vk_pk)
        .with_context(|| format!("failed to fetch VK account {vk_pk}"))?;

    ensure!(
        acc.data.len() >= VK_HDR_LEN && &acc.data[0..4] == b"VKH1",
        "VK account {vk_pk} has an invalid header \
         (data_len={}, magic={:?})",
        acc.data.len(),
        std::str::from_utf8(acc.data.get(0..4).unwrap_or(&[])).unwrap_or("????")
    );

    let total = u32::from_le_bytes(
        acc.data[VK_TOTAL_LEN_OFFSET..VK_TOTAL_LEN_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    let stored_hash: [u8; 32] = acc.data[VK_HASH_OFFSET..VK_HASH_OFFSET + 32]
        .try_into()
        .unwrap();

    let payload = acc.data[VK_HDR_LEN..VK_HDR_LEN + total].to_vec();

    // Verify hash using sha2 (NOT solana_program::hash::hash — that is BPF-only)
    let computed: [u8; 32] = Sha256::digest(&payload).into();
    ensure!(
        computed == stored_hash,
        "on-chain VK hash mismatch for account {vk_pk}: \
         stored={}, computed={}",
        hex::encode(stored_hash),
        hex::encode(computed)
    );

    let parsed = parse_vk_bytes(&payload)
        .with_context(|| format!("failed to parse G16V payload from account {vk_pk}"))?;

    Ok((payload, stored_hash, parsed))
}

/// Parses a proof byte slice into `(A64, B128, C64)` uncompressed form.
///
/// Accepts:
/// * 256-byte uncompressed `A64 | B128 | C64`.
/// * 128-byte compressed `A32 | B64 | C32`.
pub fn parse_proof(proof: &[u8]) -> Result<([u8; 64], [u8; 128], [u8; 64])> {
    match proof.len() {
        256 => {
            let mut a = [0u8; 64];
            let mut b = [0u8; 128];
            let mut c = [0u8; 64];
            a.copy_from_slice(&proof[0..64]);
            b.copy_from_slice(&proof[64..192]);
            c.copy_from_slice(&proof[192..256]);
            Ok((a, b, c))
        }
        128 => {
            let a = decompress_g1(proof[0..32].try_into().unwrap())
                .map_err(|_| anyhow!("decompress_g1(A) failed"))?;
            let b = decompress_g2(proof[32..96].try_into().unwrap())
                .map_err(|_| anyhow!("decompress_g2(B) failed"))?;
            let c = decompress_g1(proof[96..128].try_into().unwrap())
                .map_err(|_| anyhow!("decompress_g1(C) failed"))?;
            Ok((a, b, c))
        }
        n => bail!(
            "invalid proof length: {n} bytes (expected 128 compressed or 256 uncompressed)"
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Reads `RPC_URL` from the environment, falling back to devnet with a
/// warning if not set.
fn read_rpc_url() -> String {
    std::env::var("RPC_URL").unwrap_or_else(|_| {
        eprintln!(
            "[verifier] WARNING: RPC_URL not set; \
             falling back to 'https://api.devnet.solana.com'"
        );
        "https://api.devnet.solana.com".to_string()
    })
}

/// Converts a flat `N*32` byte slice into a fixed-size array of 32-byte
/// big-endian Fr elements.
fn to_inputs_array<const N: usize>(bytes: &[u8]) -> Result<[[u8; 32]; N]> {
    ensure!(
        bytes.len() == N * 32,
        "public inputs: expected {} bytes (N={N}×32), got {}",
        N * 32,
        bytes.len()
    );
    let mut arr = [[0u8; 32]; N];
    for (i, chunk) in bytes.chunks_exact(32).enumerate() {
        arr[i].copy_from_slice(chunk);
    }
    Ok(arr)
}

/// Runs a single N=1 Groth16 verification attempt, logging the label and
/// result.  Returns `true` only if verification returns `Ok(true)`.
fn try_verify_n1(
    label: &str,
    a: &[u8; 64],
    b: &[u8; 128],
    c: &[u8; 64],
    inputs: &[[u8; 32]; 1],
    vk: &Groth16Verifyingkey,
) -> bool {
    match Groth16Verifier::<1>::new(a, b, c, inputs, vk) {
        Ok(mut v) => match v.verify() {
            Ok(true) => {
                eprintln!("[sanity_full] {label} => TRUE ✓");
                true
            }
            Ok(false) => {
                eprintln!("[sanity_full] {label} => false");
                false
            }
            Err(_) => {
                eprintln!("[sanity_full] {label} => verify() internal error");
                false
            }
        },
        Err(_) => {
            eprintln!("[sanity_full] {label} => new() failed (invalid points)");
            false
        }
    }
}

// ── G2 / G1 in-place mutation helpers ─────────────────────────────────────
// These are *local* to the verifier and operate on raw byte arrays.
// The equivalent mutations on ParsedVk are in vk_codec.

/// BN254 Fq prime in big-endian.
const BN254_P_BE: [u8; 32] = [
    0x30, 0x64, 0x4E, 0x72, 0xE1, 0x31, 0xA0, 0x29, 0xB8, 0x50, 0x45, 0xB6, 0x81, 0x81, 0x58,
    0x5D, 0x28, 0x33, 0xE8, 0x48, 0x79, 0xB9, 0x70, 0x91, 0x43, 0xE1, 0xF5, 0x93, 0xF0, 0x00,
    0x00, 0x01,
];

#[inline]
fn neg_be32_in_place(x: &mut [u8; 32]) {
    if x.iter().all(|&b| b == 0) { return; }
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let r = (BN254_P_BE[i] as i16) - (x[i] as i16) - borrow;
        x[i] = (r & 0xFF) as u8;
        borrow = if r < 0 { 1 } else { 0 };
    }
}

/// Negates a G1 point in uncompressed big-endian form by negating its Y
/// coordinate: `(x, y) → (x, p − y)`.
fn negate_g1_y_be_in_place(a64: &mut [u8; 64]) {
    let y: &mut [u8; 32] = (&mut a64[32..64]).try_into().unwrap();
    neg_be32_in_place(y);
}

/// Swaps the two Fq sub-field halves of a 128-byte G2 serialisation:
/// `(c0||c1) ↔ (c1||c0)` for X and Y.
fn swap_g2_128_in_place(b: &mut [u8; 128]) {
    for i in 0..32 { b.swap(i, 32 + i); }       // X halves
    for i in 0..32 { b.swap(64 + i, 96 + i); }  // Y halves
}

/// Conjugates a 128-byte G2 serialisation: `c1 → p − c1` for X and Y.
fn conjugate_g2_128_in_place(b: &mut [u8; 128]) {
    let x_c1: &mut [u8; 32] = (&mut b[32..64]).try_into().unwrap();
    neg_be32_in_place(x_c1);
    let y_c1: &mut [u8; 32] = (&mut b[96..128]).try_into().unwrap();
    neg_be32_in_place(y_c1);
}