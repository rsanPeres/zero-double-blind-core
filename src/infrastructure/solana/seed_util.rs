use std::env;
use ark_bn254::Bn254;
use ark_bn254::g1::G1Affine;
use ark_bn254::g2::G2Affine;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use solana_sdk::bs58;

pub fn make_solana_seed32(label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    if let Ok(secret) = env::var("HASH_SECRET") {
        h.update(secret.as_bytes());
    }
    let bytes = &h.finalize()[..16];               // 16B -> ~22 chars em base58
    let mut s = bs58::encode(bytes).into_string();
    s.truncate(32);                                // Solana exige ≤ 32 chars
    s
}

fn g1_32(p: &G1Affine) -> [u8; 32] { let mut v=Vec::new(); p.serialize_compressed(&mut v).unwrap(); v.try_into().unwrap() }
fn g2_64(p: &G2Affine) -> [u8; 64] { let mut v=Vec::new(); p.serialize_compressed(&mut v).unwrap(); v.try_into().unwrap() }

pub(crate) fn vk_to_g16v_bytes(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let n = vk.gamma_abc_g1.len() - 1;
    let mut out = Vec::with_capacity(8 + 32 + 3*64 + (n+1)*32);
    out.extend_from_slice(b"G16V");           // magic
    out.push(1);                               // version
    out.push(1);                               // flags: 1 = pontos comprimidos
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&g1_32(&vk.alpha_g1));
    out.extend_from_slice(&g2_64(&vk.beta_g2));
    out.extend_from_slice(&g2_64(&vk.gamma_g2));
    out.extend_from_slice(&g2_64(&vk.delta_g2));
    for ic in &vk.gamma_abc_g1 { out.extend_from_slice(&g1_32(ic)); }
    out
}
