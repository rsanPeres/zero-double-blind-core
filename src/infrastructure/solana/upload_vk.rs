use std::env;
use anyhow::{Context, Result};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use solana_sdk::pubkey::Pubkey;
use crate::infrastructure::solana::solana_client::upload_vk_in_chunks;
use crate::infrastructure::solana::seed_util::vk_to_g16v_bytes;
use crate::infrastructure::solana::seed_util::make_solana_seed32;

pub fn run_upload_vk(service_vk: &VerifyingKey<Bn254>) -> Result<(String, Pubkey)> {
    // 1) ENV robusto (aceita RPC_URL ou RPC)
    let rpc = env::var("RPC_URL").or_else(|_| env::var("RPC"))
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program = env::var("PROGRAM_ID").context("PROGRAM_ID não definido")?;

    // 2) Seed segura (≤32)
    let seed = make_solana_seed32("zero-trial");

    // 3) VK → bytes (layout G16V)
    let vk_bytes = vk_to_g16v_bytes(service_vk);

    eprintln!("-> rpc........: {rpc}");
    eprintln!("-> program....: {program}");
    eprintln!("-> seed(<=32).: '{}' (len={})", seed, seed.len());
    eprintln!("-> vk_bytes...: {} B", vk_bytes.len());

    // 4) Upload em chunks
    let vk_pk = upload_vk_in_chunks(&rpc, &program, &seed, &vk_bytes, 900)
        .context("falha em upload_vk_in_chunks")?;

    eprintln!("VK account: {vk_pk}");
    Ok((seed, vk_pk))
}
