use crate::infrastructure::solana::solana_client::upload_vk_in_chunks;
use crate::infrastructure::solana::vk_codec::vk_to_g16v_bytes_uncompressed;
use anyhow::{Context, Result};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;

pub fn provision_vk(service_vk: &VerifyingKey<Bn254>) -> Result<(String, Pubkey)> {
    // 1) RPC/PROGRAM_ID
    let rpc = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program = std::env::var("PROGRAM_ID").context("PROGRAM_ID não definido")?;

    // 2) VK -> bytes no formato esperado on-chain (G16V)
    let vk_bytes = vk_to_g16v_bytes_uncompressed(service_vk);

    // 3) Seed determinística e namespaced (<=32 chars) para NUNCA colidir com 'round'
    //    "VK-" + 24 hex = 27 chars (ok)
    let h = Sha256::digest(&vk_bytes);
    let hexh = hex::encode(h);
    let seed = format!("VK-{}", &hexh[..24]);

    eprintln!("-> rpc........: {rpc}");
    eprintln!("-> program....: {program}");
    eprintln!("-> seed(<=32).: '{}' (len={})", seed, seed.len());
    eprintln!("-> vk_bytes...: {} B", vk_bytes.len());

    // 4) Sobe em chunks e sela
    //    (a função já sela no final; chunk_size é capado para 700 internamente)
    let vk_pk = upload_vk_in_chunks(&rpc, &program, &seed, &vk_bytes, 700)
        .context("falha em upload_vk_in_chunks")?;

    // 5) Sanidade: conferir que a conta realmente é VK (head == "VKH1")
    let rpc_client = RpcClient::new_with_commitment(rpc.clone(), CommitmentConfig::confirmed());
    let acc = rpc_client.get_account(&vk_pk)
        .context("não consegui ler a conta da VK pós-upload")?;
    let head = acc.data.get(0..4).unwrap_or(&[]);
    let head_str = std::str::from_utf8(head).unwrap_or("????");
    anyhow::ensure!(head_str == "VKH1", "vk_pk não é VK (head={head_str}) — verifique seeds");

    Ok((seed, vk_pk))
}