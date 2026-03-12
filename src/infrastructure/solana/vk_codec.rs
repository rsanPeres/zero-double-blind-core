#![allow(unexpected_cfgs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Pure codec utilities for the G16V (Groth16 Verifying key) binary format
// and BN254 proof serialisation.
//
// This module has **zero network I/O**.  Every function either converts
// between in-memory representations or reads/writes raw bytes.
//
// # Format overview
//
// ```text
// G16V payload layout (uncompressed, flags=0):
//   [0..4]   magic "G16V"
//   [4]      version = 1
//   [5]      flags  (bit-0: 1=compressed, 0=uncompressed)
//   [6..8]   nr_pubinputs (u16 LE)
//   [8..]    α_G1 (64 B)
//            β_G2 (128 B)  — Ethereum layout: (c1||c0) for X and Y
//            γ_G2 (128 B)
//            δ_G2 (128 B)
//            IC[0..=N] × 64 B each
// ```

use alloc::vec::Vec;
use anyhow::{bail, ensure, Context, Result};
use groth16_solana::decompression::{decompress_g1, decompress_g2};

use ark_bn254::g1::G1Affine;
use ark_bn254::g2::G2Affine;
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed Groth16 verifying key in the uncompressed big-endian layout used
/// by the on-chain verifier (`groth16_solana`).
#[derive(Clone)]
pub struct ParsedVk {
    pub nr_pubinputs: usize,
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    /// IC[0..=N], one 64-byte entry per element.
    pub ic: Vec<[u8; 64]>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Private field-element helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Converts any `PrimeField` element to a 32-byte big-endian array.
fn fq_to_be32<F: PrimeField>(x: F) -> [u8; 32] {
    let le = x.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[31 - i] = le[i];
    }
    be
}

/// Serialises a G1 affine point to 64 bytes: `X_BE32 || Y_BE32`.
fn g1_to_be64(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fq_to_be32(p.x));
    out[32..64].copy_from_slice(&fq_to_be32(p.y));
    out
}

/// Serialises a G2 affine point to 128 bytes using the **Ethereum/EIP-196**
/// layout: `X=(c1||c0)`, `Y=(c1||c0)`.
fn g2_to_be128_eth(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_to_be32(p.x.c1));   // X.c1
    out[32..64].copy_from_slice(&fq_to_be32(p.x.c0));  // X.c0
    out[64..96].copy_from_slice(&fq_to_be32(p.y.c1));  // Y.c1
    out[96..128].copy_from_slice(&fq_to_be32(p.y.c0)); // Y.c0
    out
}

/// Serialises a G2 affine point to 128 bytes using the **arkworks** layout:
/// `X=(c0||c1)`, `Y=(c0||c1)`.
fn g2_to_be128(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_to_be32(p.x.c0));   // X.c0
    out[32..64].copy_from_slice(&fq_to_be32(p.x.c1));  // X.c1
    out[64..96].copy_from_slice(&fq_to_be32(p.y.c0));  // Y.c0
    out[96..128].copy_from_slice(&fq_to_be32(p.y.c1)); // Y.c1
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Public VK serialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes an arkworks `VerifyingKey<Bn254>` into the G16V binary format
/// (uncompressed, Ethereum G2 layout).
pub fn vk_to_g16v_bytes_uncompressed(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let n = (vk.gamma_abc_g1.len() - 1) as u16; // nr_pubinputs
    let mut out = Vec::with_capacity(8 + 64 + 3 * 128 + vk.gamma_abc_g1.len() * 64);

    // Header
    out.extend_from_slice(b"G16V");
    out.push(1); // version
    out.push(0); // flags: 0 = uncompressed
    out.extend_from_slice(&n.to_le_bytes());

    // α_G1, β_G2, γ_G2, δ_G2 (Ethereum G2 layout)
    out.extend_from_slice(&g1_to_be64(&vk.alpha_g1));
    out.extend_from_slice(&g2_to_be128_eth(&vk.beta_g2));
    out.extend_from_slice(&g2_to_be128_eth(&vk.gamma_g2));
    out.extend_from_slice(&g2_to_be128_eth(&vk.delta_g2));

    // IC[0..=N] in G1
    for p in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_to_be64(p));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Public Fr / public-input helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Converts an `Fr` element to a 32-byte big-endian array.
pub fn fr_to_be32(x: Fr) -> [u8; 32] {
    let le = x.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[31 - i] = le[i];
    }
    be
}

/// Packs a slice of `Fr` elements into a contiguous `N * 32` big-endian byte
/// buffer.
pub fn pack_public_inputs_be32(inputs: &[Fr]) -> Vec<u8> {
    let mut v = Vec::with_capacity(inputs.len() * 32);
    for fr in inputs {
        v.extend_from_slice(&fr_to_be32(*fr));
    }
    v
}

/// Reduces each 32-byte big-endian chunk modulo the BN254 scalar field prime
/// `r` and re-encodes it in canonical big-endian form.
///
/// This is the client-side equivalent of the on-chain canonical-input check.
pub fn canonicalize_public_inputs_be32(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        raw.len() % 32 == 0,
        "public_inputs length must be a multiple of 32, got {}",
        raw.len()
    );
    let mut out = Vec::with_capacity(raw.len());
    for chunk in raw.chunks_exact(32) {
        let arr: [u8; 32] = chunk.try_into().expect("chunk_exact guarantees 32 bytes");
        out.extend_from_slice(&fr_be32_canonical(&arr));
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public proof serialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Serialises a `Proof<Bn254>` to **128 bytes** in the compressed format
/// `A32 | B64 | C32` expected by the on-chain program.
///
/// # Errors
/// Returns an error if arkworks' compressed serialisation fails (which would
/// indicate a corrupt proof object).
pub fn proof_to_compact_128(proof: &Proof<Bn254>) -> Result<[u8; 128]> {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(
        &g1_compressed32(&proof.a).context("failed to compress proof.A (G1)")?,
    );
    out[32..96].copy_from_slice(
        &g2_compressed64(&proof.b).context("failed to compress proof.B (G2)")?,
    );
    out[96..128].copy_from_slice(
        &g1_compressed32(&proof.c).context("failed to compress proof.C (G1)")?,
    );
    Ok(out)
}

/// Serialises a `Proof<Bn254>` to **256 bytes** in the uncompressed format
/// `A64 | B128 | C64`.  The on-chain program accepts this directly without
/// decompression.
pub fn proof_to_uncompressed_256(proof: &Proof<Bn254>) -> [u8; 256] {
    let mut out = [0u8; 256];
    out[0..64].copy_from_slice(&g1_to_be64(&proof.a));
    out[64..192].copy_from_slice(&g2_to_be128(&proof.b));
    out[192..256].copy_from_slice(&g1_to_be64(&proof.c));
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Public VK parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a G16V binary payload into a [`ParsedVk`].
///
/// Handles both compressed (`flags & 1 == 1`) and uncompressed payloads.
///
/// # Errors
/// Returns a descriptive error if the payload is truncated, has an unknown
/// magic/version, or if decompression of any curve point fails.
pub fn parse_vk_bytes(vk: &[u8]) -> Result<ParsedVk> {
    ensure!(vk.len() >= 8, "VK payload too short (< 8 bytes)");
    ensure!(&vk[0..4] == b"G16V", "invalid VK magic (expected 'G16V')");
    ensure!(vk[4] == 1, "unsupported VK version {} (expected 1)", vk[4]);

    let flags = vk[5];
    let compressed = (flags & 1) == 1;
    let nr_pubinputs = u16::from_le_bytes(vk[6..8].try_into().unwrap()) as usize;

    // Cursor-based reader — avoids off-by-one errors and gives clear messages.
    let mut cur = &vk[8..];
    let mut take = |n: usize| -> Result<&[u8]> {
        ensure!(
            cur.len() >= n,
            "VK payload truncated (need {} more bytes)",
            n.saturating_sub(cur.len())
        );
        let (l, r) = cur.split_at(n);
        cur = r;
        Ok(l)
    };

    // α_G1
    let alpha_g1: [u8; 64] = if compressed {
        let c: [u8; 32] = take(32)?.try_into().unwrap();
        decompress_g1(&c).map_err(|_| anyhow::anyhow!("decompress_g1(alpha_g1) failed"))?
    } else {
        let mut a = [0u8; 64];
        a.copy_from_slice(take(64)?);
        a
    };

    // β_G2
    let beta_g2: [u8; 128] = if compressed {
        let c: [u8; 64] = take(64)?.try_into().unwrap();
        decompress_g2(&c).map_err(|_| anyhow::anyhow!("decompress_g2(beta_g2) failed"))?
    } else {
        let mut b = [0u8; 128];
        b.copy_from_slice(take(128)?);
        b
    };

    // γ_G2
    let gamma_g2: [u8; 128] = if compressed {
        let c: [u8; 64] = take(64)?.try_into().unwrap();
        decompress_g2(&c).map_err(|_| anyhow::anyhow!("decompress_g2(gamma_g2) failed"))?
    } else {
        let mut g = [0u8; 128];
        g.copy_from_slice(take(128)?);
        g
    };

    // δ_G2
    let delta_g2: [u8; 128] = if compressed {
        let c: [u8; 64] = take(64)?.try_into().unwrap();
        decompress_g2(&c).map_err(|_| anyhow::anyhow!("decompress_g2(delta_g2) failed"))?
    } else {
        let mut d = [0u8; 128];
        d.copy_from_slice(take(128)?);
        d
    };

    // IC[0..=N]
    let mut ic = Vec::with_capacity(nr_pubinputs + 1);
    for i in 0..=(nr_pubinputs) {
        let g1: [u8; 64] = if compressed {
            let c: [u8; 32] = take(32)?.try_into().unwrap();
            decompress_g1(&c).map_err(|_| anyhow::anyhow!("decompress_g1(IC[{i}]) failed"))?
        } else {
            let mut t = [0u8; 64];
            t.copy_from_slice(take(64)?);
            t
        };
        ic.push(g1);
    }

    Ok(ParsedVk {
        nr_pubinputs,
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

/// Builds a `Groth16Verifyingkey` reference from a [`ParsedVk`].
///
/// The returned value borrows from `parsed`, so `parsed` must outlive the
/// returned struct.
pub fn make_vk(parsed: &ParsedVk) -> groth16_solana::groth16::Groth16Verifyingkey<'_> {
    groth16_solana::groth16::Groth16Verifyingkey {
        nr_pubinputs: parsed.nr_pubinputs,
        vk_alpha_g1: parsed.alpha_g1,
        vk_beta_g2: parsed.beta_g2,
        vk_gamme_g2: parsed.gamma_g2, // note: field name in the crate is 'gamme'
        vk_delta_g2: parsed.delta_g2,
        vk_ic: &parsed.ic[..],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// G2 orientation helpers (in-place mutations on ParsedVk)
// ─────────────────────────────────────────────────────────────────────────────

/// Swaps the G2 coordinate orientation for β_G2, γ_G2, δ_G2 in-place:
/// `(c0, c1) ↔ (c1, c0)` for both X and Y.
///
/// Use this when the G16V payload was encoded in the arkworks layout but the
/// on-chain verifier expects the Ethereum/altbn128 layout, or vice-versa.
pub fn swap_vk_g2_orientation_in_place(parsed: &mut ParsedVk) {
    swap_g2_128_in_place(&mut parsed.beta_g2);
    swap_g2_128_in_place(&mut parsed.gamma_g2);
    swap_g2_128_in_place(&mut parsed.delta_g2);
}

/// Conjugates G2 coordinates for β_G2, γ_G2, δ_G2 in-place:
/// `(c0, c1) → (c0, −c1)` for both X and Y.
///
/// Useful when the sub-field orientation is inverted between the prover and
/// the verifier.
pub fn conjugate_vk_g2_in_place(parsed: &mut ParsedVk) {
    conjugate_g2_128_in_place(&mut parsed.beta_g2);
    conjugate_g2_128_in_place(&mut parsed.gamma_g2);
    conjugate_g2_128_in_place(&mut parsed.delta_g2);
}

/// Returns the index of the first differing byte between two slices, or
/// `None` if they are identical (including equal length).
///
/// Useful for debugging VK payload mismatches between local and on-chain.
pub fn first_diff(a: &[u8], b: &[u8]) -> Option<(usize, u8, u8)> {
    let len = a.len().min(b.len());
    for i in 0..len {
        if a[i] != b[i] {
            return Some((i, a[i], b[i]));
        }
    }
    if a.len() != b.len() {
        return Some((len, 0, 0));
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Serialises a G1 affine point to a 32-byte compressed form.
fn g1_compressed32(p: &G1Affine) -> Result<[u8; 32]> {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v)
        .context("G1 compressed serialisation failed")?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("G1 compressed: unexpected byte length (expected 32)"))
}

/// Serialises a G2 affine point to a 64-byte compressed form.
fn g2_compressed64(p: &G2Affine) -> Result<[u8; 64]> {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v)
        .context("G2 compressed serialisation failed")?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("G2 compressed: unexpected byte length (expected 64)"))
}

/// Reduces a 32-byte big-endian value modulo the BN254 scalar field prime
/// `r` and returns it in canonical big-endian form with left-zero-padding to
/// 32 bytes.
fn fr_be32_canonical(x_be32: &[u8; 32]) -> [u8; 32] {
    let fr = Fr::from_be_bytes_mod_order(x_be32);
    let bi = fr.into_bigint();
    // Convert limbs (little-endian u64 array) → byte slice → big-endian
    let mut le_bytes = alloc::vec![];
    for limb in bi.0 {
        le_bytes.extend_from_slice(&limb.to_le_bytes());
    }
    le_bytes.reverse(); // LE → BE
    let mut out = [0u8; 32];
    // Left-pad to 32 bytes (le_bytes may be shorter if leading bytes are zero)
    let start = 32usize.saturating_sub(le_bytes.len());
    out[start..].copy_from_slice(&le_bytes[..32 - start]);
    out
}

/// BN254 field prime `p` in big-endian — used for G2 negation.
const BN254_P_BE: [u8; 32] = [
    0x30, 0x64, 0x4E, 0x72, 0xE1, 0x31, 0xA0, 0x29, 0xB8, 0x50, 0x45, 0xB6, 0x81, 0x81, 0x58,
    0x5D, 0x28, 0x33, 0xE8, 0x48, 0x79, 0xB9, 0x70, 0x91, 0x43, 0xE1, 0xF5, 0x93, 0xF0, 0x00,
    0x00, 0x01,
];

/// Computes `z := p − z` in-place (big-endian, 32 bytes).  A zero input is
/// left unchanged (0 ≡ 0 mod p).
#[inline]
fn neg_be32_in_place_slice(x: &mut [u8]) {
    debug_assert_eq!(x.len(), 32);
    if x.iter().all(|&b| b == 0) {
        return;
    }
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let r = (BN254_P_BE[i] as i16) - (x[i] as i16) - borrow;
        x[i] = (r & 0xFF) as u8;
        borrow = if r < 0 { 1 } else { 0 };
    }
}

/// Swaps the two 32-byte halves of each Fq2 coordinate in a 128-byte G2
/// serialisation: `(c0||c1) ↔ (c1||c0)` for both X and Y.
#[inline]
fn swap_g2_128_in_place(b: &mut [u8; 128]) {
    for i in 0..32 {
        b.swap(i, 32 + i); // X halves
    }
    for i in 0..32 {
        b.swap(64 + i, 96 + i); // Y halves
    }
}

/// Conjugates a 128-byte G2 serialisation in-place:
/// `(c0, c1) → (c0, −c1)` for X and Y.
#[inline]
fn conjugate_g2_128_in_place(b: &mut [u8; 128]) {
    neg_be32_in_place_slice(&mut b[32..64]); // X.c1
    neg_be32_in_place_slice(&mut b[96..128]); // Y.c1
}