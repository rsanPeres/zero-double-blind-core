use crate::infrastructure::solana::vk_codec::canonicalize_public_inputs_be32;
use anyhow::{bail, ensure, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
use shellexpand::tilde;
use solana_client::{
    client_error::ClientErrorKind,
    rpc_client::RpcClient,
    rpc_config::{RpcSendTransactionConfig, RpcSimulateTransactionConfig},
};
use solana_sdk::{commitment_config::{CommitmentConfig, CommitmentLevel}, instruction::{AccountMeta, Instruction}, packet::PACKET_DATA_SIZE, pubkey::Pubkey, rent::Rent, signature::{read_keypair_file, Keypair, Signer}, system_instruction, system_program, transaction::Transaction};
use solana_transaction_status::TransactionConfirmationStatus;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;

const MAX_SPACE: usize = 10 * 1024 * 1024; // 10 MiB
const VK_HDR_LEN: usize = 46; // deve bater com on-chain

#[derive(BorshSerialize, BorshDeserialize)]
enum ZkIx {
    InitVk { seed: String, total_len: u32, vk_hash: [u8; 32] },
    WriteVkChunk { seed: String, offset: u32, chunk: Vec<u8> },
    SealVk { seed: String },
    InitRound {
        round_seed: String,
        bits_len: u32, // tamanho em BYTES do payload que você vai escrever depois
    },
    WriteRoundChunk {
        round_seed: String,
        offset: u32,   // deve == bytes_written
        chunk: Vec<u8>,
    },
    SubmitRound {
        round_seed: String,
        proof_bytes: Vec<u8>,    // 128 (A32|B64|C32) ou 256 (A64|B128|C64)
        public_inputs: Vec<u8>,  // N*32 (Fr em BE32)
    },
}

/* =========================
   Keypair loader
   ========================= */

pub fn payer() -> Keypair {
    load_default_keypair().expect("keypair não encontrada")
}

pub fn load_default_keypair() -> Result<Keypair, Box<dyn Error>> {
    // 1) SOLANA_KEYPAIR (arquivo, JSON "[..64..]" ou base58)
    if let Ok(v) = std::env::var("SOLANA_KEYPAIR") {
        if let Some(kp) = try_from_inline_or_path(&v)? {
            return Ok(kp);
        }
    }
    // 2) default do CLI
    let id_path = Path::new("util").join("id.json");;
    if Path::new(&id_path).exists() {
        return Ok(read_keypair_file(id_path)?);
    }
    // 3) config.yml do CLI
    let cfg_path = Path::new("util").join("config.yml");;
    if Path::new(&cfg_path).exists() {
        #[derive(serde::Deserialize)]
        struct Cfg { keypair_path: Option<String> }
        let f = fs::File::open(&cfg_path)?;
        if let Some(kp_path) = serde_yaml::from_reader::<_, Cfg>(f)?.keypair_path {
            return Ok(read_keypair_file(tilde(&kp_path).into_owned())?);
        }
    }
    // 4) Windows: tentar WSL
    #[cfg(windows)]
    if let Some(kp) = try_wsl_keypair()? {
        return Ok(kp);
    }

    Err("Keypair não encontrada. Defina SOLANA_KEYPAIR (arquivo, JSON [..] ou base58), \
         ou crie ~/.config/solana/id.json".into())
}

fn try_from_inline_or_path(v: &str) -> Result<Option<Keypair>, Box<dyn Error>> {
    let s = v.trim();

    // JSON inline: [64 números]
    if s.starts_with('[') && s.ends_with(']') {
        let nums: Vec<u8> = serde_json::from_str(s)?;
        if nums.len() != 64 {
            return Err(format!("Keypair JSON precisa ter 64 bytes, veio {}", nums.len()).into());
        }
        return Ok(Some(Keypair::from_bytes(&nums)?));
    }

    // caminho
    let p = tilde(s).into_owned();
    if Path::new(&p).exists() {
        return Ok(Some(read_keypair_file(p)?));
    }

    Ok(None)
}

#[cfg(windows)]
fn try_wsl_keypair() -> Result<Option<Keypair>, Box<dyn Error>> {
    if let Ok(linux_path) = std::env::var("WSL_KEYPAIR") {
        if let Some(p) = linux_to_unc_auto(&linux_path)? {
            if p.exists() { return Ok(Some(read_keypair_file(p)?)); }
        }
    }
    let root = Path::new(r"\\wsl$");
    let entries = match fs::read_dir(root) {
        Ok(it) => it,
        Err(_) => return Ok(None),
    };
    let guesses_user: Vec<String> = [
        std::env::var("WSL_USERNAME").ok(),
        std::env::var("USERNAME").ok(),
    ].into_iter().flatten().collect();

    for de in entries.flatten() {
        let distro = de.file_name().to_string_lossy().to_string();
        let home = Path::new(r"\\wsl$").join(&distro).join("home");
        for u in &guesses_user {
            let p = home.join(u).join(".config").join("solana").join("id.json");
            if p.exists() { return Ok(Some(read_keypair_file(p)?)); }
        }
        if let Ok(users) = fs::read_dir(&home) {
            for u in users.flatten().take(10) {
                let p = u.path().join(".config").join("solana").join("id.json");
                if p.exists() { return Ok(Some(read_keypair_file(p)?)); }
            }
        }
    }
    Ok(None)
}

#[cfg(windows)]
fn linux_to_unc_auto(linux: &str) -> Result<Option<PathBuf>, Box<dyn Error>> {
    if !linux.starts_with("/home/") { return Ok(None); }
    let sub = &linux[1..].replace('/', r"\");
    if let Ok(distro) = std::env::var("WSL_DISTRO") {
        return Ok(Some(Path::new(r"\\wsl$").join(distro).join(sub)));
    }
    for d in ["Ubuntu", "Ubuntu-22.04", "Ubuntu-20.04", "Debian"] {
        let p = Path::new(r"\\wsl$").join(d).join(&sub);
        if p.exists() { return Ok(Some(p)); }
    }
    Ok(None)
}

/* =========================
   Guardas & utilitários
   ========================= */

fn ensure_payer_usable(rpc: &RpcClient, payer: &Keypair) -> Result<()> {
    let acc = rpc.get_account(&payer.pubkey())?;
    ensure!(acc.owner == system_program::id(), "fee payer não é System-owned");
    ensure!(!acc.executable, "fee payer não pode ser executable");
    ensure!(acc.lamports > 0, "fee payer sem lamports");
    Ok(())
}

fn ensure_program_executable(rpc: &RpcClient, program_id: &Pubkey) -> Result<()> {
    let prog = rpc.get_account(program_id)?;
    ensure!(prog.executable, "Program ID não é executável (deploy ausente no cluster)");
    Ok(())
}

pub fn rent_exempt_lamports(rpc: &RpcClient, space: usize) -> u64 {
    let clamped_space = space.clamp(1, MAX_SPACE);
    for attempt in 0..5 {
        match rpc.get_minimum_balance_for_rent_exemption(clamped_space) {
            Ok(v) => return v,
            Err(e) => {
                eprintln!("[rent] tentativa #{} falhou: {}", attempt + 1, e);
                thread::sleep(Duration::from_millis(250 * (attempt + 1) as u64));
            }
        }
    }
    let lamports = Rent::default().minimum_balance(clamped_space);
    eprintln!("[rent] RPC indisponível — fallback Rent::default(): {} lamports", lamports);
    lamports
}

/* =========================
   Envio de transações
   ========================= */

fn send(rpc: &RpcClient, payer: &Keypair, ixs: &[Instruction]) -> Result<String> {
    let bh = rpc.get_latest_blockhash()?;
    let mut tx = Transaction::new_with_payer(ixs, Some(&payer.pubkey()));
    tx.sign(&[payer], bh);

    // fee payer guard
    let fee_payer = tx.message().account_keys[0];
    ensure!(fee_payer == payer.pubkey(), "fee payer errado");
    let acc = rpc.get_account(&fee_payer)?;
    ensure!(acc.owner == system_program::id(), "fee payer não é System-owned");
    ensure!(!acc.executable, "fee payer não pode ser executable");

    // tamanho do pacote
    let raw_len = tx.message_data().len();
    let data_len_total: usize = ixs.iter().map(|ix| ix.data.len()).sum();
    eprintln!(
        "tx raw_len={}, limit={}, total_ix_data={}",
        raw_len, PACKET_DATA_SIZE, data_len_total
    );

    // -------- preflight com diagnóstico melhorado --------
    let sim = rpc.simulate_transaction_with_config(
        &tx,
        RpcSimulateTransactionConfig {
            sig_verify: true,
            commitment: Some(CommitmentConfig::processed()),
            ..Default::default()
        },
    );

    match sim {
        Ok(simres) => {
            // sempre despeja logs do programa
            let logs = simres.value.logs.unwrap_or_default();
            for l in &logs { eprintln!("log: {l}"); }

            if let Some(err) = simres.value.err {
                // heurísticas para explicar a falha com base nos logs on-chain
                let mut hint = String::from("falha durante preflight");

                if logs.iter().any(|l| l.contains("parse_proof_to_uncompressed_be falhou")) {
                    hint = "proof_bytes com formato inválido (esperado 128 ou 256 bytes)".into();
                } else if logs.iter().any(|l| l.contains("public_inputs tamanho inválido")) {
                    hint = "public_inputs (BE32) com tamanho incorreto para esta VK".into();
                } else if logs.iter().any(|l| l.contains("nr_pubinputs não suportado")) {
                    hint = "VK espera N ∈ {1,2,3,4,8,12,16}".into();
                } else if logs.iter().any(|l| l.contains("seed diverge")) {
                    hint = "seed/derivação da round diverge do esperado pela conta".into();
                } else if logs.iter().any(|l| l.contains("VK sem magic") || l.contains("VK não selada")) {
                    hint = "conta de VK inválida (sem magic ou não selada)".into();
                } else if logs.iter().any(|l| l.contains("hash VK diverge")) {
                    hint = "hash da VK não bate; verifique vk_bytes enviados e a conta on-chain".into();
                } else if logs.iter().any(|l| l.contains("verify=false")) {
                    // inclui alguns detalhes úteis se apareceram
                    let lens = logs.iter().find(|l| l.contains("lens:")).cloned().unwrap_or_default();
                    let nrpi = logs.iter().find(|l| l.contains("vk.nr_pubinputs")).cloned().unwrap_or_default();
                    hint = format!(
                        "verificação Groth16 falhou — provavelmente o commitment público não bate com o usado na prova.\n  {nrpi}\n  {lens}"
                    );
                }

                // erra com contexto rico
                bail!("preflight: {err:?} — {hint}");
            }
        }
        Err(e) => {
            eprintln!("simulate RPC error: {e}");
            if let ClientErrorKind::RpcError(rpc_err) = e.kind() {
                eprintln!("rpc_err detail: {rpc_err:?}");
            }
            bail!("simulate failed (RPC)");
        }
    }

    // envio + confirmação
    let sig = rpc.send_and_confirm_transaction_with_spinner_and_config(
        &tx,
        CommitmentConfig::processed(),
        RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentLevel::Processed),
            max_retries: Some(5),
            ..Default::default()
        },
    )?;
    Ok(sig.to_string())
}

fn send_tx_checked(rpc: &RpcClient, payer: &Keypair, ixs: &[Instruction]) -> Result<String> {
    use std::time::{Duration, Instant};

    // 1) Monta e assina
    let bh = rpc.get_latest_blockhash()?;
    let mut tx = Transaction::new_with_payer(ixs, Some(&payer.pubkey()));
    tx.sign(&[payer], bh);

    // 2) Sanidade do fee payer
    let fee_payer = tx.message().account_keys[0];
    ensure!(fee_payer == payer.pubkey(), "fee payer errado");
    let acc = rpc.get_account(&fee_payer)?;
    ensure!(acc.owner == system_program::id(), "fee payer não é System-owned");
    ensure!(!acc.executable, "fee payer não pode ser executable");

    // 3) Tamanho
    let raw_len = tx.message_data().len();
    ensure!(raw_len <= PACKET_DATA_SIZE, "Transaction too large: {} > {}", raw_len, PACKET_DATA_SIZE);

    // 4) Preflight com logs ricos
    let sim = rpc.simulate_transaction_with_config(
        &tx,
        RpcSimulateTransactionConfig {
            sig_verify: true,
            commitment: Some(CommitmentConfig::processed()),
            ..Default::default()
        },
    );
    match sim {
        Ok(simres) => {
            if let Some(logs) = simres.value.logs.as_ref() {
                for l in logs { eprintln!("log: {l}"); }
            }
            if let Some(err) = simres.value.err {
                let logs = simres.value.logs.unwrap_or_default();
                let mut hint = String::from("falha durante preflight");

                if logs.iter().any(|l| l.contains("parse_proof_to_uncompressed_be falhou")) {
                    hint = "proof_bytes com formato inválido (esperado 128 ou 256 bytes)".into();
                } else if logs.iter().any(|l| l.contains("public_inputs tamanho inválido")) {
                    hint = "public_inputs (BE32) com tamanho incorreto para esta VK".into();
                } else if logs.iter().any(|l| l.contains("nr_pubinputs não suportado")) {
                    hint = "VK espera N ∈ {1,2,3,4,8,12,16}".into();
                } else if logs.iter().any(|l| l.contains("seed diverge")) {
                    hint = "seed/derivação da round diverge do esperado pela conta".into();
                } else if logs.iter().any(|l| l.contains("VK sem magic") || l.contains("VK não selada")) {
                    hint = "conta de VK inválida (sem magic ou não selada)".into();
                } else if logs.iter().any(|l| l.contains("hash VK diverge")) {
                    hint = "hash da VK não bate; verifique vk_bytes enviados e a conta on-chain".into();
                } else if logs.iter().any(|l| l.contains("verify=false")) {
                    let lens = logs.iter().find(|l| l.contains("lens:")).cloned().unwrap_or_default();
                    let nrpi = logs.iter().find(|l| l.contains("vk.nr_pubinputs")).cloned().unwrap_or_default();
                    hint = format!("verificação Groth16 falhou — commitment público não bate.\n  {nrpi}\n  {lens}");
                }

                bail!("preflight: {err:?} — {hint}");
            }
        }
        Err(e) => {
            eprintln!("simulate RPC error: {e}");
            if let ClientErrorKind::RpcError(rpc_err) = e.kind() {
                eprintln!("rpc_err detail: {rpc_err:?}");
            }
            bail!("simulate failed (RPC)");
        }
    }

    // 5) Envia (sem spinner) e loga a assinatura
    let sig = match rpc.send_transaction_with_config(
        &tx,
        RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentLevel::Processed),
            max_retries: Some(5),
            ..Default::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ send_transaction error: {e}");
            if let ClientErrorKind::RpcError(rpc_err) = e.kind() {
                eprintln!("rpc_err detail: {rpc_err:?}");
            }
            // Erros comuns úteis:
            // - BlockhashNotFound => blockhash expirou antes do envio
            // - NodeUnhealthy / RateLimit => Devnet instável
            bail!("send failed");
        }
    };
    eprintln!("[tx] sent: sig={sig}");

    // 6) Poll manual por confirmação com timeout e prints
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_status: Option<TransactionConfirmationStatus> = None;

    loop {
        if Instant::now() > deadline {
            // Se pelo menos chegou a processed, devolve com aviso (útil na Devnet)
            if matches!(last_status, Some(TransactionConfirmationStatus::Processed)) {
                eprintln!("[tx] timeout aguardando 'confirmed', mas já está 'processed'. Devolvendo sig mesmo assim.");
                return Ok(sig.to_string());
            }
            bail!("timeout aguardando confirmação da transação na Devnet — sig={sig}");
        }

        let statuses = rpc.get_signature_statuses(&[sig])?;
        if let Some(Some(st)) = statuses.value.get(0) {
            if let Some(err) = &st.err {
                eprintln!("❌ tx erro on-chain: {err:?}");
                bail!("transaction failed on-chain: {err:?}");
            }

            // Loga progresso
            if let Some(cs) = st.clone().confirmation_status {
                if last_status != Some(cs.clone()) {
                    eprintln!("[tx] status: {:?}", cs.clone());
                    last_status = Some(cs.clone());
                }
                match cs {
                    TransactionConfirmationStatus::Finalized |
                    TransactionConfirmationStatus::Confirmed => {
                        eprintln!("[tx] confirmado: {cs:?}");
                        return Ok(sig.to_string());
                    }
                    TransactionConfirmationStatus::Processed => {
                        // ainda aguarda até virar confirmed/finalized
                    }
                }
            } else if let Some(conf) = st.confirmations {
                eprintln!("[tx] confirmations (legacy): {:?}", conf);
                if conf >= 1 {  // heurística: >=1 costuma ser suficiente na Devnet
                    return Ok(sig.to_string());
                }
            }
        }

        std::thread::sleep(Duration::from_millis(350));
    }
}

/* =========================
   Fluxos VK & Submit
   ========================= */

fn create_vk_account_if_needed(
    rpc: &RpcClient,
    payer: &Keypair,
    program_id: &Pubkey,
    vk_seed: &str,
    total_len: usize,
) -> Result<Pubkey> {
    ensure_program_executable(rpc, program_id)?;  // garante que o programa existe
    ensure_payer_usable(rpc, payer)?;             // garante fee payer válido

    let vk_pk = Pubkey::create_with_seed(&payer.pubkey(), vk_seed, program_id)?;
    if rpc.get_account(&vk_pk).is_ok() { return Ok(vk_pk); }

    let space = VK_HDR_LEN + total_len;
    let lamports = rent_exempt_lamports(rpc, space);
    let ix = system_instruction::create_account_with_seed(
        &payer.pubkey(), &vk_pk, &payer.pubkey(), vk_seed,
        lamports, space as u64, program_id,
    );
    let sig = send_tx_checked(rpc, payer, &[ix])?;
    eprintln!("vk account created: {vk_pk}, tx={sig}");
    Ok(vk_pk)
}

#[derive(Debug, Clone)]
struct VkHeader { sealed: bool, total_len: usize, written: usize, hash: [u8;32] }

fn read_vk_header(rpc: &RpcClient, vk_pk: &Pubkey) -> Option<VkHeader> {
    let acc = rpc.get_account(vk_pk).ok()?;
    let d = acc.data;
    if d.len() < VK_HDR_LEN || &d[0..4] != b"VKH1" { return None; }
    Some(VkHeader{
        sealed: d[5] != 0,
        total_len: u32::from_le_bytes(d[6..10].try_into().ok()?) as usize,
        written:   u32::from_le_bytes(d[10..14].try_into().ok()?) as usize,
        hash:      d[14..46].try_into().ok()?,
    })
}

pub fn upload_vk_in_chunks(
    rpc_url: &str,
    program_id: &str,
    vk_seed: &str,
    vk_bytes: &[u8],
    mut chunk_size: usize,
) -> Result<Pubkey> {
    ensure!(chunk_size > 0, "chunk_size precisa ser > 0");
    if chunk_size > 700 { chunk_size = 700; } // limite seguro de pacote

    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program: Pubkey = program_id.parse()?;
    let payer = payer();

    let want_hash: [u8; 32] = Sha256::digest(vk_bytes).into();

    // ===== 1) Escolha da seed final (evitar colisões perigosas) =====
    let base_pk = Pubkey::create_with_seed(&payer.pubkey(), vk_seed, &program)?;
    let mut seed_final = vk_seed.to_string();

    if let Ok(acc) = rpc.get_account(&base_pk) {
        // Conta já existe — verifique o "head"
        let head = acc.data.get(0..4).unwrap_or(&[]);
        let head_str = std::str::from_utf8(head).unwrap_or("");

        if head_str != "VKH1" {
            // Já tem algo que não é VK aqui (ex.: "RND1"). NÃO reusar essa seed.
            let hexh = hex::encode(want_hash);
            let mut sfx_len = 8usize;
            if seed_final.len() + 1 + sfx_len > 32 {
                sfx_len = 32usize.saturating_sub(seed_final.len() + 1);
            }
            seed_final = if sfx_len == 0 {
                hexh[..32].to_string()
            } else {
                format!("{}-{}", vk_seed, &hexh[..sfx_len])
            };
        } else if let Some(h) = read_vk_header(&rpc, &base_pk) {
            // É uma VK; se o hash divergir, derive nova seed (não sobrescreva VK diferente)
            if h.hash != want_hash {
                let hexh = hex::encode(want_hash);
                let mut sfx_len = 8usize;
                if seed_final.len() + 1 + sfx_len > 32 {
                    sfx_len = 32usize.saturating_sub(seed_final.len() + 1);
                }
                seed_final = if sfx_len == 0 {
                    hexh[..32].to_string()
                } else {
                    format!("{}-{}", vk_seed, &hexh[..sfx_len])
                };
            }
        }
    }

    // ===== 2) Garante a conta com espaço adequado =====
    let vk_pk = create_vk_account_if_needed(&rpc, &payer, &program, &seed_final, vk_bytes.len())?;
    let hdr = read_vk_header(&rpc, &vk_pk);

    match hdr {
        Some(h) => {
            ensure!(h.hash == want_hash, "Conta '{}' tem hash diferente", seed_final);
            if h.sealed {
                ensure!(h.total_len == vk_bytes.len(), "total_len divergente");
                // Sanidade: já é VK selada correta
                return Ok(vk_pk);
            }

            // Completar escrita do que falta
            let mut offset = h.written as u32;
            for chunk in vk_bytes[h.written..].chunks(chunk_size) {
                let mut data = vec![];
                ZkIx::WriteVkChunk {
                    seed: seed_final.clone(),
                    offset,
                    chunk: chunk.to_vec(),
                }.serialize(&mut data)?;

                let ix = Instruction {
                    program_id: program,
                    accounts: vec![
                        AccountMeta::new(vk_pk, false),
                        AccountMeta::new(payer.pubkey(), true),
                    ],
                    data,
                };

                eprintln!("→ write chunk: offset={}, len={}", offset, chunk.len());
                let _sig = send_tx_checked(&rpc, &payer, &[ix])?;
                offset += chunk.len() as u32;
            }

            // Seal
            let mut data = vec![];
            ZkIx::SealVk { seed: seed_final.clone() }.serialize(&mut data)?;
            let ix = Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::new(vk_pk, false),
                    AccountMeta::new(payer.pubkey(), true),
                ],
                data,
            };
            let _sig = send_tx_checked(&rpc, &payer, &[ix])?;
            // Sanidade final
            let acc = rpc.get_account(&vk_pk)?;
            anyhow::ensure!(acc.data.get(0..4) == Some(b"VKH1"), "pós-seal: header != VKH1");
            Ok(vk_pk)
        }
        None => {
            // INIT do zero (a conta pode existir mas sem VKH1; optamos por usar seed_final já “descolidida”)
            let mut data = vec![];
            ZkIx::InitVk {
                seed: seed_final.clone(),
                total_len: vk_bytes.len() as u32,
                vk_hash: want_hash,
            }.serialize(&mut data)?;
            let ix = Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::new(vk_pk, false),
                    AccountMeta::new(payer.pubkey(), true),
                ],
                data,
            };
            let _sig = send_tx_checked(&rpc, &payer, &[ix])?;

            // WRITE seq.
            let mut offset = 0u32;
            for chunk in vk_bytes.chunks(chunk_size) {
                let mut data = vec![];
                ZkIx::WriteVkChunk {
                    seed: seed_final.clone(),
                    offset,
                    chunk: chunk.to_vec(),
                }.serialize(&mut data)?;

                let ix = Instruction {
                    program_id: program,
                    accounts: vec![
                        AccountMeta::new(vk_pk, false),
                        AccountMeta::new(payer.pubkey(), true),
                    ],
                    data,
                };

                eprintln!("→ write chunk: offset={}, len={}", offset, chunk.len());
                let _sig = send_tx_checked(&rpc, &payer, &[ix])?;
                offset += chunk.len() as u32;
            }

            // SEAL
            let mut data = vec![];
            ZkIx::SealVk { seed: seed_final.clone() }.serialize(&mut data)?;
            let ix = Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::new(vk_pk, false),
                    AccountMeta::new(payer.pubkey(), true),
                ],
                data,
            };
            let _sig = send_tx_checked(&rpc, &payer, &[ix])?;

            // Sanidade final
            let acc = rpc.get_account(&vk_pk)?;
            anyhow::ensure!(acc.data.get(0..4) == Some(b"VKH1"), "pós-init: header != VKH1");
            Ok(vk_pk)
        }
    }
}

/// Compacta Vec<bool> em 1 bit por flag (8x menor) e loga tamanhos
fn pack_bits(bools: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; (bools.len() + 7) / 8];
    for (i, b) in bools.iter().enumerate() {
        if *b { out[i / 8] |= 1 << (i % 8); }
    }
    out
}

/// Parser do header RND1 no cliente (idempotência/retomada)
#[derive(Debug)]
struct RoundHeader {
    sealed: bool,
    seed: String,
    bits_len: usize,
    bytes_written: usize,
    hdr_len: usize,
}
fn u32le_at(s: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(s[i..i+4].try_into().unwrap())
}
fn parse_round_header_client(data: &[u8]) -> Option<RoundHeader> {
    if data.len() < 10 || &data[0..4] != b"RND1" { return None; }
    let sealed = data[5] != 0;
    let seed_len = u32le_at(data, 6) as usize;
    if data.len() < 10 + seed_len + 8 { return None; }
    let seed_bytes = &data[10..10+seed_len];
    let seed = String::from_utf8_lossy(seed_bytes).to_string();
    let bits_len = u32le_at(data, 10 + seed_len) as usize;
    let bytes_written = u32le_at(data, 14 + seed_len) as usize;
    let hdr_len = 4 + 1 + 1 + 4 + seed_len + 4 + 4;
    Some(RoundHeader { sealed, seed, bits_len, bytes_written, hdr_len })
}

pub fn submit_round(
    rpc_url: &str,
    program_id: &str,
    round_seed: &str,
    vk_pk: Pubkey,
    proof_bytes: Vec<u8>,
    public_inputs: Vec<u8>, // N*32 (Fr em BE32)
    bits: Vec<bool>,        // 1 byte/flag (coerente com on-chain atual)
) -> Result<String> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program: Pubkey = program_id.parse()?;
    let payer = payer();

    ensure_program_executable(&rpc, &program)?;
    ensure_payer_usable(&rpc, &payer)?;

    // Namespace da seed de round
    let round_seed_ns = if round_seed.starts_with("RND-") || round_seed.starts_with("RD-") {
        round_seed.to_string()
    } else {
        format!("RND-{}", round_seed)
    };

    // Conta derivada
    let round_pk = Pubkey::create_with_seed(&payer.pubkey(), &round_seed_ns, &program)?;

    // payload (1 byte por bool)
    let bits_packed: Vec<u8> = bits.iter().map(|&b| u8::from(b)).collect();

    // Tamanho mínimo necessário para alocação
    let seed_len = round_seed_ns.len();
    let hdr_len  = 4 + 1 + 1 + 4 + seed_len + 4 + 4;
    let need_space = hdr_len + bits_packed.len();
    eprintln!(
        "[round] seed_len={seed_len}, hdr_len={hdr_len}, bits_len={}B, need_space={need_space}B",
        bits_packed.len()
    );

    // 0) Cria a conta se não existir
    match rpc.get_account(&round_pk) {
        Ok(acc) => {
            ensure!(
                acc.data.len() >= need_space,
                "round_account pequeno: {}B < {}B", acc.data.len(), need_space
            );
        }
        Err(_) => {
            let lamports = rent_exempt_lamports(&rpc, need_space);
            let ix = system_instruction::create_account_with_seed(
                &payer.pubkey(), &round_pk, &payer.pubkey(), &round_seed_ns,
                lamports, need_space as u64, &program,
            );
            eprintln!("[round] create_account_with_seed: space={need_space}, lamports={lamports}");
            send_tx_checked(&rpc, &payer, &[ix])?;
        }
    }

    // 1) Descobre o estado atual da round para ser idempotente
    let mut start_offset: u32 = 0;
    let mut must_init = true;
    if let Ok(acc) = rpc.get_account(&round_pk) {
        if let Some(h) = parse_round_header_client(&acc.data) {
            // Já inicializada
            if h.sealed {
                bail!("round já selada; use outra seed (ex.: acrescente sufixo)");
            }
            ensure!(
                h.seed == round_seed_ns,
                "round seed diverge (on-chain='{}', local='{}')",
                h.seed, round_seed_ns
            );
            ensure!(
                h.bits_len == bits_packed.len(),
                "bits_len diverge (on-chain={}, local={}) — use outra seed",
                h.bits_len, bits_packed.len()
            );
            start_offset = h.bytes_written as u32;
            must_init = false;
            eprintln!(
                "[round] retomando upload: written={}/{} (hdr_len={})",
                h.bytes_written, h.bits_len, h.hdr_len
            );
        }
    }

    // 2) InitRound (apenas se ainda não houver header RND1)
    if must_init {
        let mut data = vec![];
        ZkIx::InitRound {
            round_seed: round_seed_ns.clone(),
            bits_len: bits_packed.len() as u32,
        }.serialize(&mut data)?;
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(round_pk, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
            data,
        };
        eprintln!("[round] InitRound: bits_len={}B", bits_packed.len());
        let _ = send_tx_checked(&rpc, &payer, &[ix])?;
        start_offset = 0;
    }

    // 3) WriteRoundChunk (continua a partir de start_offset)
    if (start_offset as usize) < bits_packed.len() {
        let mut offset = start_offset;
        for (i, chunk) in bits_packed[(offset as usize)..].chunks(700).enumerate() {
            let mut data = vec![];
            ZkIx::WriteRoundChunk {
                round_seed: round_seed_ns.clone(),
                offset,
                chunk: chunk.to_vec(),
            }.serialize(&mut data)?;
            let ix = Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::new(round_pk, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                ],
                data,
            };
            eprintln!(
                "[round] WriteRoundChunk #{}: off={}, len={}",
                i, offset, chunk.len()
            );
            let _ = send_tx_checked(&rpc, &payer, &[ix])?;
            offset += chunk.len() as u32;
        }
    } else {
        eprintln!("[round] nenhum chunk pendente (já estava completo)");
    }

    // 4) SubmitRound (pequena)
    {
        // --- VK sanity com retries e logs detalhados ---
        eprintln!("[vk] pk={}", vk_pk);

        // tente algumas vezes em 'processed' para contornar visibilidade
        let mut vk_acc_opt = None;
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..6 {
            match rpc.get_account_with_commitment(&vk_pk, CommitmentConfig::processed()) {
                Ok(res) => {
                    if let Some(acc) = res.value {
                        vk_acc_opt = Some(acc);
                        break;
                    } else {
                        last_err = Some(anyhow::anyhow!("account not found (attempt {attempt})"));
                    }
                }
                Err(e) => {
                    last_err = Some(anyhow::anyhow!(e));
                }
            }
            thread::sleep(Duration::from_millis(150));
        }

        let acc = match vk_acc_opt {
            Some(a) => a,
            None => {
                if let Some(e) = last_err { bail!("VK account não encontrada no RPC: {e}") }
                else { bail!("VK account não encontrada no RPC"); }
            }
        };

        let head = acc.data.get(0..4).unwrap_or(&[]);
        let head_str = std::str::from_utf8(head).unwrap_or("???");
        eprintln!("[vk] owner={}, len={}, head={}", acc.owner, acc.data.len(), head_str);

        ensure!(
        acc.data.len() >= VK_HDR_LEN && &acc.data[0..4] == b"VKH1",
        "vk_pk inválido: head={}, len={} — verifique se está passando o MESMO vk_pk retornado pelo upload (ou se a seed não colidiu).",
        head_str, acc.data.len()
    );

        // 3) Canonicalizar os inputs públicos (reduz mod q e padroniza BE32)
        let public_inputs: Vec<u8> = canonicalize_public_inputs_be32(&public_inputs)?;
        // --- monta ix do SubmitRound ---
        let mut data = vec![];
        ZkIx::SubmitRound {
            round_seed: round_seed_ns.clone(),
            proof_bytes,
            public_inputs,
        }.serialize(&mut data)?;

        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(round_pk, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new_readonly(vk_pk, false),
            ],
            data,
        };

        eprintln!(
            "[round] SubmitRound: ix_data={}B (proof+inputs), proof+inputs devem ser pequenos",
            ix.data.len()
        );

        let cu1 = ComputeBudgetInstruction::set_compute_unit_limit(900_000);
        let cu2 = ComputeBudgetInstruction::set_compute_unit_price(0);

        let sig = send_tx_checked(&rpc, &payer, &[cu1, cu2, ix])?;
        eprintln!("[round] done: sig={sig}");
        Ok(sig)
    }
}