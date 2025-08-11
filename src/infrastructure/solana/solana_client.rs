use anyhow::{anyhow, bail, ensure, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
use shellexpand::tilde;
use solana_client::{
    client_error::ClientErrorKind,
    rpc_client::RpcClient,
    rpc_config::{RpcSendTransactionConfig, RpcSimulateTransactionConfig},
};
use solana_sdk::{
    bs58,
    commitment_config::{CommitmentConfig, CommitmentLevel},
    instruction::{AccountMeta, Instruction},
    packet::PACKET_DATA_SIZE,
    pubkey::Pubkey,
    rent::Rent,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction, system_program,
    transaction::Transaction,
};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use solana_sdk::bs58::decode::DecodeBuilder;

const MAX_SPACE: usize = 10 * 1024 * 1024; // 10 MiB
const VK_HDR_LEN: usize = 46; // deve bater com on-chain

#[derive(BorshSerialize, BorshDeserialize)]
enum ZkIx {
    InitVk { seed: String, total_len: u32, vk_hash: [u8; 32] },
    WriteVkChunk { seed: String, offset: u32, chunk: Vec<u8> },
    SealVk { seed: String },
    SubmitRound {
        round_seed: String,
        proof_bytes: Vec<u8>,    // 128B recomendado (A32|B64|C32)
        public_inputs: Vec<u8>,  // N * 32
        bits: Vec<bool>,
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

    // base58 inline (sem / ou \)
    if !s.contains(['/', '\\']) && !s.ends_with(".json") && s.len() > 64 {
        let mut buf = [0u8; 64];
        bs58::decode(s);
        return Ok(Some(Keypair::from_bytes(&buf)?));
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
    ensure!(raw_len <= PACKET_DATA_SIZE, "Transaction too large: {} > {}", raw_len, PACKET_DATA_SIZE);

    // preflight
    let sim = rpc.simulate_transaction_with_config(&tx, RpcSimulateTransactionConfig{
        sig_verify: true,
        commitment: Some(CommitmentConfig::processed()),
        ..Default::default()
    })?;
    if let Some(logs) = sim.value.logs.as_ref() {
        for l in logs { eprintln!("log: {l}"); }
    }
    if let Some(err) = sim.value.err { anyhow::bail!("preflight: {err:?}"); }

    // envio + confirmação
    let sig = rpc.send_and_confirm_transaction_with_spinner_and_config(
        &tx,
        CommitmentConfig::confirmed(),
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
    let bh = rpc.get_latest_blockhash()?;
    let mut tx = Transaction::new_with_payer(ixs, Some(&payer.pubkey()));
    tx.sign(&[payer], bh);

    // fee payer guard (idêntico ao de send)
    let fee_payer = tx.message().account_keys[0];
    ensure!(fee_payer == payer.pubkey(), "fee payer errado");
    let acc = rpc.get_account(&fee_payer)?;
    ensure!(acc.owner == system_program::id(), "fee payer não é System-owned");
    ensure!(!acc.executable, "fee payer não pode ser executable");

    let raw_len = tx.message_data().len();
    ensure!(raw_len <= PACKET_DATA_SIZE, "Transaction too large: {} > {}", raw_len, PACKET_DATA_SIZE);

    let sim = rpc.simulate_transaction_with_config(
        &tx,
        RpcSimulateTransactionConfig {
            sig_verify: true,
            commitment: Some(CommitmentConfig::processed()),
            ..Default::default()
        },
    );
    match sim {
        Ok(sim) => {
            if let Some(err) = sim.value.err.as_ref() {
                eprintln!("❌ preflight error: {err:?}");
            }
            if let Some(logs) = sim.value.logs.as_ref() {
                for l in logs { eprintln!("log: {l}"); }
            }
            if sim.value.err.is_some() { bail!("preflight failed"); }
        }
        Err(e) => {
            eprintln!("simulate RPC error: {e}");
            if let ClientErrorKind::RpcError(rpc_err) = e.kind() {
                eprintln!("rpc_err detail: {rpc_err:?}");
            }
            bail!("simulate failed (RPC)");
        }
    }

    let sig = rpc.send_and_confirm_transaction_with_spinner_and_config(
        &tx,
        CommitmentConfig::confirmed(),
        RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentLevel::Processed),
            max_retries: Some(5),
            ..Default::default()
        },
    )?;
    Ok(sig.to_string())
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
    chunk_size: usize,
) -> Result<Pubkey> {
    ensure!(chunk_size > 0, "chunk_size precisa ser > 0");

    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program: Pubkey = program_id.parse()?;
    let payer = payer();

    // Hash esperado do payload
    let want_hash: [u8; 32] = Sha256::digest(vk_bytes).into();

    // 1) Descobre se já há conta no seed base e se o hash bate
    let base_pk = Pubkey::create_with_seed(&payer.pubkey(), vk_seed, &program)?;
    let base_hdr = read_vk_header(&rpc, &base_pk);

    // 2) Decide o seed final (talvez com sufixo do hash) respeitando limite de 32 chars
    let seed_final = match base_hdr {
        Some(ref h) if h.hash != want_hash => {
            // hash diferente -> gerar novo seed derivado do hash
            let hexh = hex::encode(want_hash); // 64 chars
            let sep_len = 1; // "-"
            let mut sfx_len = 8usize;
            if vk_seed.len() + sep_len + sfx_len > 32 {
                sfx_len = 32usize.saturating_sub(vk_seed.len() + sep_len);
            }
            if sfx_len == 0 {
                // não coube o separador + sufixo: usa só os 32 primeiros do hash
                hexh[..32].to_string()
            } else {
                format!("{}-{}", vk_seed, &hexh[..sfx_len])
            }
        }
        _ => vk_seed.to_string(),
    };

    // 3) Garante/cria a conta correspondente ao seed_final
    let vk_pk = create_vk_account_if_needed(&rpc, &payer, &program, &seed_final, vk_bytes.len())?;

    // 4) Lê o header (se existir) da conta final
    let hdr = read_vk_header(&rpc, &vk_pk);

    // 5) Flows possíveis:
    //    - Header inexistente -> INIT + WRITE(full) + SEAL
    //    - Header existente com hash == want_hash e selado -> nada a fazer
    //    - Header existente com hash == want_hash e não selado -> retomar de written
    //    - Header existente com hash != want_hash -> erro (não deveria ocorrer com seed_final amarrado ao hash)
    match hdr {
        Some(h) => {
            // Confere hash
            ensure!(
                h.hash == want_hash,
                "Conta existente em '{}' tem hash diferente (seed já usado para outra VK)",
                seed_final
            );

            if h.sealed {
                // Já finalizado: valida tamanho por segurança
                ensure!(h.total_len == vk_bytes.len(), "total_len divergente da VK selada");
                return Ok(vk_pk);
            }

            // Retoma escrita a partir de 'written'
            let mut offset = h.written as u32;
            for chunk in vk_bytes[h.written..].chunks(chunk_size) {
                let mut data = vec![];
                ZkIx::WriteVkChunk {
                    seed: seed_final.clone(),
                    offset,
                    chunk: chunk.to_vec(),
                }
                    .serialize(&mut data)?;
                let ix = Instruction {
                    program_id: program,
                    accounts: vec![
                        AccountMeta::new(vk_pk, false),
                        AccountMeta::new(payer.pubkey(), true),
                    ],
                    data,
                };
                send(&rpc, &payer, &[ix])?;
                offset += chunk.len() as u32;
            }

            // Sela
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
            send(&rpc, &payer, &[ix])?;
            Ok(vk_pk)
        }
        None => {
            // Ainda não inicializada: INIT
            let mut data = vec![];
            ZkIx::InitVk {
                seed: seed_final.clone(),
                total_len: vk_bytes.len() as u32,
                vk_hash: want_hash,
            }
                .serialize(&mut data)?;
            let ix = Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::new(vk_pk, false),
                    AccountMeta::new(payer.pubkey(), true),
                ],
                data,
            };
            send(&rpc, &payer, &[ix])?;

            // WRITE (sequencial)
            let mut offset = 0u32;
            for chunk in vk_bytes.chunks(chunk_size) {
                let mut data = vec![];
                ZkIx::WriteVkChunk {
                    seed: seed_final.clone(),
                    offset,
                    chunk: chunk.to_vec(),
                }
                    .serialize(&mut data)?;
                let ix = Instruction {
                    program_id: program,
                    accounts: vec![
                        AccountMeta::new(vk_pk, false),
                        AccountMeta::new(payer.pubkey(), true),
                    ],
                    data,
                };
                send(&rpc, &payer, &[ix])?;
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
            send(&rpc, &payer, &[ix])?;
            Ok(vk_pk)
        }
    }
}

pub fn submit_round(
    rpc_url: &str,
    program_id: &str,
    round_seed: &str,
    vk_pk: Pubkey,
    proof_bytes: Vec<u8>,
    public_inputs: Vec<u8>,
    bits: Vec<bool>,
) -> Result<String> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program: Pubkey = program_id.parse()?;
    let payer = payer();

    ensure_program_executable(&rpc, &program)?;
    ensure_payer_usable(&rpc, &payer)?;

    // Deriva a round_account exatamente como o on-chain rederiva (base=payer, seed=round_seed, owner=program)
    let round_pk = Pubkey::create_with_seed(&payer.pubkey(), round_seed, &program)?;

    // Espaço mínimo — ajuste se seu on-chain grava um estado diferente.
    // Se proof_bytes for fixo (ex.: 128B) no on-chain, troque 'proof_len' por 128 e NÃO some +4.
    let need_space = {
        let seed_len = round_seed.len();
        let bits_len = bits.len();                 // Vec<bool> → Borsh grava 4 + N*1
        let pub_inputs_len = public_inputs.len();  // Vec<u8> → 4 + N
        let proof_len = proof_bytes.len();         // ou 128 se fixo no programa
        1 /*sealed?*/ + 32 /*vk_hash?*/ + (4 + seed_len) + 32 /*round_hash?*/
            + (4 + bits_len) + (4 + pub_inputs_len) + (4 + proof_len)
    };

    match rpc.get_account(&round_pk) {
        Ok(acc) => {
            if acc.data.len() < need_space {
                bail!(
                    "round_account pequeno: tem {} B, precisa de {} B. \
                     Use um round_seed diferente ou recrie a conta.",
                    acc.data.len(), need_space
                );
            }
        }
        Err(_) => {
            let lamports = rent_exempt_lamports(&rpc, need_space);
            let ix = system_instruction::create_account_with_seed(
                &payer.pubkey(), &round_pk, &payer.pubkey(), round_seed,
                lamports, need_space as u64, &program,
            );
            send(&rpc, &payer, &[ix])?;
        }
    }

    // (Opcional) Diagnóstico da VK
    if let Ok(acc) = rpc.get_account(&vk_pk) {
        eprintln!(
            "vk_acc: owner={}, len={}, head={:?}",
            acc.owner, acc.data.len(),
            acc.data.get(0..4).map(|s| String::from_utf8_lossy(s).to_string())
        );
    } else {
        bail!("VK account não encontrado no RPC");
    }

    // Monta a instrução com a ORDEM CORRETA de contas:
    // [0] round (writable), [1] payer (signer), [2] vk (readonly)
    let mut data = vec![];
    ZkIx::SubmitRound {
        round_seed: round_seed.to_string(),
        proof_bytes: proof_bytes,
        public_inputs: public_inputs,
        bits: bits,
    }.serialize(&mut data)?;

    let ix = Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(round_pk, false),                // writable
            AccountMeta::new_readonly(payer.pubkey(), true),  // signer
            AccountMeta::new_readonly(vk_pk, false),          // readonly

        ],
        data,
    };

    let sig = send(&rpc, &payer, &[ix])?;
    Ok(sig)
}