// ===== verifier.rs =====

use std::env;
use anyhow::{anyhow, bail, ensure, Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

use crate::infrastructure::solana::vk_codec::{parse_vk_bytes, make_vk, swap_vk_g2_orientation_in_place, conjugate_vk_g2_in_place, ParsedVk, vk_to_g16v_bytes_uncompressed};
use groth16_solana::decompression::{decompress_g1, decompress_g2};
use sha2::{Digest, Sha256};
use solana_sdk::commitment_config::CommitmentConfig;

// ---- carrega payload da VK (VKH1) → ParsedVk ----
fn read_parsed_vk_from_chain(rpc_url: &str, vk_pk: &Pubkey) -> Result<ParsedVk> {
    let rpc = RpcClient::new(rpc_url.to_string());
    let acc = rpc.get_account(vk_pk).context("get_account VK")?;
    ensure!(acc.data.len() >= 46 && &acc.data[0..4] == b"VKH1", "VK inválida (header)");
    let total = u32::from_le_bytes(acc.data[6..10].try_into().unwrap()) as usize;
    let payload = &acc.data[46..46+total];
    parse_vk_bytes(payload).map_err(|_| anyhow!("parse_vk_bytes falhou"))
}

// ============ SANITY ============
//-------------------------------------
fn parse_proof_to_uncompressed_be(proof: &[u8]) -> Result<([u8;64],[u8;128],[u8;64])> {
    match proof.len() {
        256 => {
            let mut a=[0u8;64]; let mut b=[0u8;128]; let mut c=[0u8;64];
            a.copy_from_slice(&proof[0..64]);
            b.copy_from_slice(&proof[64..192]);
            c.copy_from_slice(&proof[192..256]);
            Ok((a,b,c))
        }
        128 => {
            let a = decompress_g1(proof[0..32].try_into().unwrap()).map_err(|_| anyhow!("decompress A"))?;
            let b = decompress_g2(proof[32..96].try_into().unwrap()).map_err(|_| anyhow!("decompress B"))?;
            let c = decompress_g1(proof[96..128].try_into().unwrap()).map_err(|_| anyhow!("decompress C"))?;
            Ok((a,b,c))
        }
        n => bail!("prova com tamanho inválido: {n} (esperado 128 ou 256)"),
    }
}

// ---- inputs N*32 → [[u8;32];N] ----
fn to_inputs_array<const N: usize>(bytes: &[u8]) -> Result<[[u8; 32]; N]> {
    if bytes.len() != N*32 { bail!("inputs BE32 inválidos: got={}, expected={}", bytes.len(), N*32); }
    let mut arr = [[0u8;32];N];
    for (i,ch) in bytes.chunks_exact(32).enumerate() { arr[i].copy_from_slice(ch); }
    Ok(arr)
}

// ---- carrega payload da VK (VKH1) → bytes + hash + ParsedVk ----
fn load_vk_payload_from_chain(rpc_url: &str, vk_pk: Pubkey) -> Result<(Vec<u8>, [u8;32], ParsedVk)> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let acc = rpc.get_account(&vk_pk).context("get_account VK")?;
    ensure!(&acc.data[0..4] == b"VKH1", "VK head != VKH1");
    let total = u32::from_le_bytes(acc.data[6..10].try_into().unwrap()) as usize;
    let hash = <[u8;32]>::try_from(&acc.data[14..46]).unwrap();
    let payload = acc.data[46..46+total].to_vec();
    let got = solana_program::hash::hash(&payload).to_bytes();
    ensure!(got == hash, "on-chain VK hash mismatch");
    let parsed = parse_vk_bytes(&payload).map_err(|_| anyhow!("parse_vk_bytes (on-chain)"))?;
    Ok((payload, hash, parsed))
}

// Diferença amigável entre VK local (gerada do ark) e VK on-chain
fn diff_vk_payload(local: &[u8], onchain: &[u8]) -> Option<(usize, u8, u8)> {
    let len = local.len().min(onchain.len());
    for i in 0..len {
        if local[i] != onchain[i] {
            return Some((i, local[i], onchain[i]));
        }
    }
    if local.len() != onchain.len() { return Some((len, 0, 0)); }
    None
}

fn swap_g2_128_in_place(x: &mut [u8;128]) {
    for i in 0..32 { x.swap(i, 32+i); }
    for i in 0..32 { x.swap(64+i, 96+i); }
}
fn neg_be32_in_place(y: &mut [u8;32]) {
    const P: [u8;32] = [
        0x30,0x64,0x4E,0x72,0xE1,0x31,0xA0,0x29,0xB8,0x50,0x45,0xB6,0x81,0x81,0x58,0x5D,
        0x28,0x33,0xE8,0x48,0x79,0xB9,0x70,0x91,0x43,0xE1,0xF5,0x93,0xF0,0x00,0x00,0x01,
    ];
    if y.iter().all(|&b| b==0) { return; }
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let r = (P[i] as i16) - (y[i] as i16) - borrow;
        y[i] = (r & 0xFF) as u8;
        borrow = if r < 0 { 1 } else { 0 };
    }
}
fn negate_g1_y_be_in_place(a64: &mut [u8;64]) { neg_be32_in_place((&mut a64[32..64]).try_into().unwrap()); }
fn conjugate_g2_128_in_place(b: &mut [u8;128]) {
    neg_be32_in_place((&mut b[32..64]).try_into().unwrap());   // X.c1
    neg_be32_in_place((&mut b[96..128]).try_into().unwrap());  // Y.c1
}

pub fn sanity_offchain_like_onchain(
    vk_pk: Pubkey,
    proof_be: &[u8],       // 128 ou 256
    pub_inputs_be: &[u8],  // N*32
    local_vk_bytes: Option<&[u8]>, // ← opcional para comparar VK local vs on-chain
) -> Result<bool> {
    let rpc_url = env::var("RPC_URL")?;

    let (vk_payload_onchain, hash_onchain, parsed_norm) =
        load_vk_payload_from_chain(&rpc_url, vk_pk)?;
    let n = parsed_norm.nr_pubinputs;
    ensure!(
        n * 32 == pub_inputs_be.len(),
        "inputs size mismatch: got {}, want {}",
        pub_inputs_be.len(),
        n * 32
    );
    eprintln!("[sanity+] vk.nr_pubinputs={n}");

    // (Opcional) comparar VK local vs on-chain
    if let Some(local) = local_vk_bytes {
        let hash_local: [u8; 32] = Sha256::digest(local).as_slice().try_into().unwrap();
        eprintln!("[sanity+] vk.onchain.sha256 = {:02x?}", hash_onchain);
        eprintln!("[sanity+] vk.local  .sha256 = {:02x?}", hash_local);
        if local != vk_payload_onchain.as_slice() {
            eprintln!("[sanity+] VK LOCAL ≠ ON-CHAIN (payload difere)");
            if let Some((off, a, b)) = diff_vk_payload(local, &vk_payload_onchain) {
                eprintln!(
                    "[sanity+] 1º byte diferente @offset {}: local={:02x}, onchain={:02x}",
                    off, a, b
                );
            }
        } else {
            eprintln!("[sanity+] VK LOCAL == ON-CHAIN (payload idêntico)");
        }
    }

    // VK variantes (ParsedVk -> Groth16Verifyingkey)
    let mut vk_swap_p = parsed_norm.clone();  swap_vk_g2_orientation_in_place(&mut vk_swap_p);
    let mut vk_conj_p = parsed_norm.clone();  conjugate_vk_g2_in_place(&mut vk_conj_p);
    let mut vk_swco_p = parsed_norm.clone();  swap_vk_g2_orientation_in_place(&mut vk_swco_p);
    conjugate_vk_g2_in_place(&mut vk_swco_p);

    let vk_norm  = make_vk(&parsed_norm);
    let vk_swap  = make_vk(&vk_swap_p);
    let vk_conj  = make_vk(&vk_conj_p);
    let vk_swco  = make_vk(&vk_swco_p);

    // Prova → (A,B,C)
    let (mut a64, mut b128, mut c64) =
        parse_proof_to_uncompressed_be(proof_be).map_err(|_| anyhow!("parse_proof"))?;
    eprintln!(
        "[sanity+] B.x halves: {:02x}{:02x}{:02x}{:02x} | {:02x}{:02x}{:02x}{:02x}",
        b128[0], b128[1], b128[2], b128[3], b128[32], b128[33], b128[34], b128[35]
    );

    // Inputs (N=1 no seu caso)
    let inputs_1 = to_inputs_array::<1>(pub_inputs_be).map_err(|_| anyhow!("inputs N!=1"))?;

    // Grade: VK x B x A x C
    #[derive(Clone, Copy, Debug)]
    enum VKSel { Norm, Swap, Conj, SwCo }
    #[derive(Clone, Copy, Debug)]
    enum BSel  { Norm, Swap, Conj, SwCo }
    #[derive(Clone, Copy, Debug)]
    enum Sign  { Pos, Neg }

    // Devolve REFERÊNCIA para evitar mover as Vks
    let pick_vk = |s: VKSel| -> &Groth16Verifyingkey {
        match s {
            VKSel::Norm => &vk_norm,
            VKSel::Swap => &vk_swap,
            VKSel::Conj => &vk_conj,
            VKSel::SwCo => &vk_swco,
        }
    };

    // Recebe referência à VK
    let mut try_one = |label: &str,
                       a_in: &[u8; 64],
                       b_in: &[u8; 128],
                       c_in: &[u8; 64],
                       vk: &Groth16Verifyingkey| -> bool {
        if let Ok(mut v) = Groth16Verifier::<1>::new(a_in, b_in, c_in, &inputs_1, vk) {
            match v.verify() {
                Ok(true) => { eprintln!("[sanity+] {} => TRUE", label); return true; }
                Ok(false) => { eprintln!("[sanity+] {} => false", label); }
                Err(_)    => { eprintln!("[sanity+] {} => verify() erro interno", label); }
            }
        } else {
            eprintln!("[sanity+] {} => new() falhou", label);
        }
        false
    };

    let vk_opts  = [VKSel::Norm, VKSel::Swap, VKSel::Conj, VKSel::SwCo];
    let b_opts   = [BSel::Norm, BSel::Swap, BSel::Conj, BSel::SwCo];
    let a_signs  = [Sign::Pos, Sign::Neg];
    let c_signs  = [Sign::Pos, Sign::Neg];

    for vk_sel in vk_opts {
        for b_sel in b_opts {
            let mut b_try = b128;
            match b_sel {
                BSel::Norm => {}
                BSel::Swap => swap_g2_128_in_place(&mut b_try),
                BSel::Conj => conjugate_g2_128_in_place(&mut b_try),
                BSel::SwCo => { swap_g2_128_in_place(&mut b_try); conjugate_g2_128_in_place(&mut b_try); }
            }
            for asg in a_signs {
                let mut a_try = a64;
                if let Sign::Neg = asg { negate_g1_y_be_in_place(&mut a_try); }
                for csg in c_signs {
                    let mut c_try = c64;
                    if let Sign::Neg = csg { negate_g1_y_be_in_place(&mut c_try); }
                    let lab = format!("VK={:?} B={:?} A={:?} C={:?}", vk_sel, b_sel, asg, csg);
                    if try_one(&lab, &a_try, &b_try, &c_try, pick_vk(vk_sel)) {
                        return Ok(true);
                    }
                }
            }
        }
    }

    eprintln!("[sanity+] nenhuma combinação bateu");
    Ok(false)
}


pub fn sanity_offchain_like_onchain128(
    vk_pk: Pubkey,
    proof_bytes: &[u8],   // 128 (A32|B64|C32) OU 256 (A64|B128|C64)
    pub_inputs_be: &[u8], // N*32 BE
) -> anyhow::Result<bool> {
    use solana_client::rpc_client::RpcClient;
    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

    // 1) Ler VK da conta e montar Groth16Verifyingkey
    let rpc = RpcClient::new(rpc_url.to_string());
    let acc = rpc.get_account(&vk_pk).context("get_account VK")?;
    anyhow::ensure!(&acc.data[0..4] == b"VKH1", "VK head != VKH1");
    let payload = acc.data[46..].to_vec(); // pula header VKH1
    let parsed = parse_vk_bytes(&payload)?;
    let vk_norm = make_vk(&parsed);

    anyhow::ensure!(vk_norm.nr_pubinputs * 32 == pub_inputs_be.len(), "inputs size mismatch");

    // 2) Prova → (A64, B128, C64) usando o MESMO parser do on-chain
    let (a64, b128, c64) = {
        match proof_bytes.len() {
            256 => {
                let mut a = [0u8; 64]; let mut b = [0u8; 128]; let mut c = [0u8; 64];
                a.copy_from_slice(&proof_bytes[0..64]);
                b.copy_from_slice(&proof_bytes[64..192]);
                c.copy_from_slice(&proof_bytes[192..256]);
                (a, b, c)
            }
            128 => {
                use groth16_solana::decompression::{decompress_g1, decompress_g2};
                let a = decompress_g1(proof_bytes[0..32].try_into().unwrap())
                    .map_err(|_| anyhow::anyhow!("decompress_g1(A)"))?;
                let b = decompress_g2(proof_bytes[32..96].try_into().unwrap())
                    .map_err(|_| anyhow::anyhow!("decompress_g2(B)"))?;
                let c = decompress_g1(proof_bytes[96..128].try_into().unwrap())
                    .map_err(|_| anyhow::anyhow!("decompress_g1(C)"))?;
                (a, b, c)
            }
            n => anyhow::bail!("prova com tamanho inválido: {n} (esperado 128 ou 256)"),
        }
    };

    // 3) Inputs (N)
    let n = vk_norm.nr_pubinputs;
    let ok = match n {
        1 => {
            let mut arr = [[0u8; 32]; 1];
            arr[0].copy_from_slice(&pub_inputs_be[0..32]);
            let mut v = groth16_solana::groth16::Groth16Verifier::<1>::new(&a64, &b128, &c64, &arr, &vk_norm)
                .map_err(|_| anyhow::anyhow!("new() falhou"))?;
            v.verify().map_err(|_| anyhow::anyhow!("verify() erro interno"))?
        }
        _ => anyhow::bail!("N não suportado nesse sanity"),
    };

    Ok(ok)
}