#![allow(unexpected_cfgs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use anyhow::ensure;
use groth16_solana::decompression::{decompress_g1, decompress_g2};

use ark_bn254::g1::G1Affine;
use ark_bn254::g2::G2Affine;
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;

/// Resultado do parse: VK em formato grande-endian não-comprimido (64/128 bytes)
#[derive(Clone)]
pub struct ParsedVk {
    pub nr_pubinputs: usize,
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: Vec<[u8; 64]>, // IC[0..=N]
}

// helpers
fn fq_to_be32<F: PrimeField>(x: F) -> [u8; 32] {
    let le = x.into_bigint().to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 { be[31 - i] = le[i]; }
    be
}

fn g1_to_be64(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fq_to_be32(p.x));
    out[32..64].copy_from_slice(&fq_to_be32(p.y));
    out
}

// ⚠️ Ethereum/EIP-196: (c1 || c0)
fn g2_to_be128_eth(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    // X = (c1, c0)
    out[  0.. 32].copy_from_slice(&fq_to_be32(p.x.c1));
    out[ 32.. 64].copy_from_slice(&fq_to_be32(p.x.c0));
    // Y = (c1, c0)
    out[ 64.. 96].copy_from_slice(&fq_to_be32(p.y.c1));
    out[ 96..128].copy_from_slice(&fq_to_be32(p.y.c0));
    out
}

pub fn vk_to_g16v_bytes_uncompressed(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let n = (vk.gamma_abc_g1.len() - 1) as u16; // nr_pubinputs
    let mut out = Vec::with_capacity(8 + 64 + 3*128 + (vk.gamma_abc_g1.len()*64));

    // header
    out.extend_from_slice(b"G16V");
    out.push(1);  // version
    out.push(0);  // flags: 0 = não-comprimido
    out.extend_from_slice(&n.to_le_bytes());

    // α_g1, β_g2, γ_g2, δ_g2
    out.extend_from_slice(&g1_to_be64(&vk.alpha_g1));
    out.extend_from_slice(&g2_to_be128_eth(&vk.beta_g2));   // ETH
    out.extend_from_slice(&g2_to_be128_eth(&vk.gamma_g2));  // ETH
    out.extend_from_slice(&g2_to_be128_eth(&vk.delta_g2));  // ETH

    // IC[0..=N] em G1
    for p in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_to_be64(p));
    }
    out
}

/////////////////////////////////////////////////////////
fn g2_to_be128(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    // X = (c0,c1), Y = (c0,c1)
    out[  0.. 32].copy_from_slice(&fq_to_be32(p.x.c0));
    out[ 32.. 64].copy_from_slice(&fq_to_be32(p.x.c1));
    out[ 64.. 96].copy_from_slice(&fq_to_be32(p.y.c0));
    out[ 96..128].copy_from_slice(&fq_to_be32(p.y.c1));
    out
}

// Converte Fr -> [u8;32] em big-endian
pub fn fr_to_be32(x: Fr) -> [u8;32] {
    let le = x.into_bigint().to_bytes_le();
    let mut be = [0u8;32];
    for i in 0..32 { be[31 - i] = le[i]; } // inverte LE->BE
    be
}

pub fn pack_public_inputs_be32(inputs: &[Fr]) -> Vec<u8> {
    let mut v = Vec::with_capacity(inputs.len() * 32);
    for fr in inputs {
        v.extend_from_slice(&fr_to_be32(*fr));
    }
    v
}

fn g1_compressed32(p: &G1Affine) -> [u8; 32] {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v).unwrap(); // 32 bytes
    v.try_into().unwrap()
}
fn g2_compressed64(p: &G2Affine) -> [u8; 64] {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v).unwrap(); // 64 bytes
    v.try_into().unwrap()
}

/// Converte `Proof<Bn254>` -> 128 bytes (A32|B64|C32), como o on-chain espera.
pub fn proof_to_compact_128(proof: &Proof<Bn254>) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&g1_compressed32(&proof.a));
    out[32..96].copy_from_slice(&g2_compressed64(&proof.b));
    out[96..128].copy_from_slice(&g1_compressed32(&proof.c));
    out
}

/// Prova NÃO-comprimida (A64|B128|C64) → 256 bytes BE.
/// Este formato é aceito diretamente pelo on-chain (sem decompress).
pub fn proof_to_uncompressed_256(proof: &Proof<Bn254>) -> [u8; 256] {
    let mut out = [0u8; 256];
    out[  0.. 64].copy_from_slice(&g1_to_be64(&proof.a));
    out[ 64..192].copy_from_slice(&g2_to_be128(&proof.b));
    out[192..256].copy_from_slice(&g1_to_be64(&proof.c));
    out
}

fn fr_be32_canonical(x_be32: &[u8;32]) -> [u8;32] {
    // reduz mod q (BN254) a partir de big-endian
    let fr = Fr::from_be_bytes_mod_order(x_be32);
    // volta para big-endian canônico (0 <= v < q) com padding até 32 bytes
    let bi = fr.into_bigint(); // 4 * u64 (little-endian por limbs)
    let mut le = Vec::new();
    // escreve em little-endian bytes
    for limb in bi.0 {
        le.extend_from_slice(&limb.to_le_bytes());
    }
    // converte para big-endian
    let mut be = le;
    be.reverse();
    // left-pad até 32
    let mut out = [0u8;32];
    let start = 32 - be.len();
    out[start..].copy_from_slice(&be);
    out
}

pub fn canonicalize_public_inputs_be32(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(raw.len() % 32 == 0, "public_inputs deve ter múltiplos de 32 bytes");
    let mut out = Vec::with_capacity(raw.len());
    for chunk in raw.chunks_exact(32) {
        let arr: [u8; 32] = <[u8; 32]>::try_from(chunk).unwrap();
        let can = fr_be32_canonical(&arr);
        out.extend_from_slice(&can);
    }
    Ok(out)
}
// === cole a partir daqui em vk_codec.rs ===

#[inline]
fn swap_g2_128_in_place(b: &mut [u8; 128]) {
    // Swap X halves: (c0,c1) <-> (c1,c0)
    for i in 0..32 {
        b.swap(i, 32 + i);
    }
    // Swap Y halves: (c0,c1) <-> (c1,c0)
    for i in 0..32 {
        b.swap(64 + i, 96 + i);
    }
}

// BN254 prime em BE (para y := p - y)
const BN254_P_BE: [u8; 32] = [
    0x30,0x64,0x4E,0x72,0xE1,0x31,0xA0,0x29,0xB8,0x50,0x45,0xB6,0x81,0x81,0x58,0x5D,
    0x28,0x33,0xE8,0x48,0x79,0xB9,0x70,0x91,0x43,0xE1,0xF5,0x93,0xF0,0x00,0x00,0x01,
];

#[inline]
fn neg_be32_in_place_slice(x: &mut [u8]) {
    // z := p - z (big-endian), assumindo x.len() == 32
    debug_assert_eq!(x.len(), 32);
    if x.iter().all(|&b| b == 0) { return; }
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let r = (BN254_P_BE[i] as i16) - (x[i] as i16) - borrow;
        x[i] = (r & 0xFF) as u8;
        borrow = if r < 0 { 1 } else { 0 };
    }
}

#[inline]
fn conjugate_g2_128_in_place(b: &mut [u8; 128]) {
    // Conjugação no Fq2: (c0, c1) -> (c0, -c1) em X e Y
    neg_be32_in_place_slice(&mut b[32..64]);   // X.c1
    neg_be32_in_place_slice(&mut b[96..128]);  // Y.c1
}

/// Troca a orientação das coordenadas de G2 em **toda a VK**:
/// (c0,c1) <-> (c1,c0) para β_g2, γ_g2, δ_g2.
/// Use quando seu payload `G16V` foi gerado no layout “ark”
/// mas o verificador espera “eth/altbn128” (ou vice-versa).
pub fn swap_vk_g2_orientation_in_place(parsed: &mut ParsedVk) {
    swap_g2_128_in_place(&mut parsed.beta_g2);
    swap_g2_128_in_place(&mut parsed.gamma_g2);
    swap_g2_128_in_place(&mut parsed.delta_g2);
}

/// Conjuga as coordenadas de G2 em **toda a VK**:
/// (c0, c1) -> (c0, -c1) em X e Y para β_g2, γ_g2, δ_g2.
/// Útil para alinhar convenções quando houver inversão de subcampo.
pub fn conjugate_vk_g2_in_place(parsed: &mut ParsedVk) {
    conjugate_g2_128_in_place(&mut parsed.beta_g2);
    conjugate_g2_128_in_place(&mut parsed.gamma_g2);
    conjugate_g2_128_in_place(&mut parsed.delta_g2);
}

// --- cole APENAS estas duas funções no seu vk_codec.rs ---

pub fn parse_vk_bytes(vk: &[u8]) -> anyhow::Result<ParsedVk> {
    use anyhow::{bail, ensure};
    use groth16_solana::decompression::{decompress_g1, decompress_g2};

    // Header mínimo
    ensure!(vk.len() >= 8, "VK muito curta (< 8)");
    ensure!(&vk[0..4] == b"G16V", "magic inválido (esperado 'G16V')");
    ensure!(vk[4] == 1, "versão inválida (esperado 1)");
    let flags = vk[5];
    let compressed = (flags & 1) == 1;

    let nr_pubinputs =
        u16::from_le_bytes(vk[6..8].try_into().unwrap()) as usize;

    // Cursor e helper local
    let mut cur = &vk[8..];
    let mut take = |n: usize| -> anyhow::Result<&[u8]> {
        if cur.len() < n {
            bail!("VK truncada (faltam {} bytes)", n - cur.len());
        }
        let (l, r) = cur.split_at(n);
        cur = r;
        Ok(l)
    };

    // α_g1
    let alpha_g1: [u8; 64] = if compressed {
        let c: [u8; 32] = take(32)?.try_into().unwrap();
        decompress_g1(&c).map_err(|_| anyhow::anyhow!("decompress_g1(alpha_g1)"))?
    } else {
        let mut a = [0u8; 64];
        a.copy_from_slice(take(64)?);
        a
    };

    // β_g2
    let beta_g2: [u8; 128] = if compressed {
        let c: [u8; 64] = take(64)?.try_into().unwrap();
        decompress_g2(&c).map_err(|_| anyhow::anyhow!("decompress_g2(beta_g2)"))?
    } else {
        let mut b = [0u8; 128];
        b.copy_from_slice(take(128)?);
        b
    };

    // γ_g2
    let gamma_g2: [u8; 128] = if compressed {
        let c: [u8; 64] = take(64)?.try_into().unwrap();
        decompress_g2(&c).map_err(|_| anyhow::anyhow!("decompress_g2(gamma_g2)"))?
    } else {
        let mut g = [0u8; 128];
        g.copy_from_slice(take(128)?);
        g
    };

    // δ_g2
    let delta_g2: [u8; 128] = if compressed {
        let c: [u8; 64] = take(64)?.try_into().unwrap();
        decompress_g2(&c).map_err(|_| anyhow::anyhow!("decompress_g2(delta_g2)"))?
    } else {
        let mut d = [0u8; 128];
        d.copy_from_slice(take(128)?);
        d
    };

    // IC[0..=N] (G1)
    let mut ic = Vec::with_capacity(nr_pubinputs + 1);
    for _ in 0..(nr_pubinputs + 1) {
        let g1: [u8; 64] = if compressed {
            let c: [u8; 32] = take(32)?.try_into().unwrap();
            decompress_g1(&c).map_err(|_| anyhow::anyhow!("decompress_g1(IC)"))?
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

pub fn make_vk<'a>(
    parsed: &'a ParsedVk,
) -> groth16_solana::groth16::Groth16Verifyingkey<'a> {
    groth16_solana::groth16::Groth16Verifyingkey {
        nr_pubinputs: parsed.nr_pubinputs,
        vk_alpha_g1: parsed.alpha_g1,
        vk_beta_g2: parsed.beta_g2,
        vk_gamme_g2: parsed.gamma_g2, // (campo da crate é 'gamme' mesmo)
        vk_delta_g2: parsed.delta_g2,
        vk_ic: &parsed.ic[..],
    }
}
