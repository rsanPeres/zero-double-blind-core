//! Typed Solana instruction builders for the ZK-verifier on-chain program.
//!
//! Each function constructs a single [`Instruction`] that matches the
//! corresponding `ZkIx` variant defined in the on-chain program.  No network
//! I/O is performed here.
//!
//! # Account conventions (mirrors on-chain)
//! | Position | VK instructions       | Round instructions                     |
//! |----------|-----------------------|----------------------------------------|
//! | 0        | vk_account (writable) | round_account (writable)               |
//! | 1        | payer (signer)        | payer (signer, readonly for W/Submit)  |
//! | 2        | —                     | vk_account (readonly, SubmitRound only)|

use anyhow::{Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

// ─────────────────────────────────────────────────────────────────────────────
// On-chain instruction enum  (must stay byte-for-byte identical to lib.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of the `ZkIx` enum defined in the on-chain program.
/// Keep in sync with `lib.rs`.  Both sides use borsh so field order matters.
#[derive(BorshSerialize, BorshDeserialize)]
enum ZkIx {
    InitVk { seed: String, total_len: u32, vk_hash: [u8; 32] },
    WriteVkChunk { seed: String, offset: u32, chunk: Vec<u8> },
    SealVk { seed: String },
    InitRound {
        round_seed: String,
        /// Byte length of the packed-bits payload written via WriteRoundChunk.
        bits_len: u32,
        /// Byte length of the public-inputs payload (N × 32).
        public_inputs_len: u32,
    },
    WriteRoundChunk {
        round_seed: String,
        /// Must equal `bytes_written` on-chain.
        offset: u32,
        chunk: Vec<u8>,
    },
    SubmitRound {
        round_seed: String,
        /// 128 bytes (A32|B64|C32) or 256 bytes (A64|B128|C64).
        proof_bytes: Vec<u8>,
        /// N × 32 bytes, one Fr element per public input in BE32 form.
        public_inputs: Vec<u8>,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// VK instruction builders
// ─────────────────────────────────────────────────────────────────────────────

/// `InitVk` — initialises a new VK account.
/// `vk_hash` must be `sha2::Sha256::digest(vk_payload)`.
pub fn init_vk(
    program_id: Pubkey, vk_account: Pubkey, payer: Pubkey,
    seed: String, total_len: u32, vk_hash: [u8; 32],
) -> Result<Instruction> {
    let mut data = Vec::new();
    ZkIx::InitVk { seed, total_len, vk_hash }
        .serialize(&mut data).context("BorshSerialize::InitVk")?;
    Ok(Instruction {
        program_id,
        accounts: vec![AccountMeta::new(vk_account, false), AccountMeta::new(payer, true)],
        data,
    })
}

/// `WriteVkChunk` — appends one chunk of the VK payload.
pub fn write_vk_chunk(
    program_id: Pubkey, vk_account: Pubkey, payer: Pubkey,
    seed: String, offset: u32, chunk: Vec<u8>,
) -> Result<Instruction> {
    let mut data = Vec::new();
    ZkIx::WriteVkChunk { seed, offset, chunk }
        .serialize(&mut data).context("BorshSerialize::WriteVkChunk")?;
    Ok(Instruction {
        program_id,
        accounts: vec![AccountMeta::new(vk_account, false), AccountMeta::new(payer, true)],
        data,
    })
}

/// `SealVk` — seals the VK account after all chunks have been written.
pub fn seal_vk(
    program_id: Pubkey, vk_account: Pubkey, payer: Pubkey, seed: String,
) -> Result<Instruction> {
    let mut data = Vec::new();
    ZkIx::SealVk { seed }.serialize(&mut data).context("BorshSerialize::SealVk")?;
    Ok(Instruction {
        program_id,
        accounts: vec![AccountMeta::new(vk_account, false), AccountMeta::new(payer, true)],
        data,
    })
}

/// `InitRound` — initialises a new round account.
///
/// * `bits_len`          — byte size of the packed-bits payload (post `pack_bits`).
/// * `public_inputs_len` — byte size of the public-inputs payload (typically `N * 32`).
pub fn init_round(
    program_id: Pubkey, round_account: Pubkey, payer: Pubkey,
    round_seed: String, bits_len: u32, public_inputs_len: u32,
) -> Result<Instruction> {
    let mut data = Vec::new();
    ZkIx::InitRound { round_seed, bits_len, public_inputs_len }
        .serialize(&mut data).context("BorshSerialize::InitRound")?;
    Ok(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(round_account, false),
            AccountMeta::new_readonly(payer, true),
        ],
        data,
    })
}

/// `WriteRoundChunk` — appends one chunk of the packed-bits payload.
pub fn write_round_chunk(
    program_id: Pubkey, round_account: Pubkey, payer: Pubkey,
    round_seed: String, offset: u32, chunk: Vec<u8>,
) -> Result<Instruction> {
    let mut data = Vec::new();
    ZkIx::WriteRoundChunk { round_seed, offset, chunk }
        .serialize(&mut data).context("BorshSerialize::WriteRoundChunk")?;
    Ok(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(round_account, false),
            AccountMeta::new_readonly(payer, true),
        ],
        data,
    })
}

/// `SubmitRound` — submits the proof.  Returns three instructions:
/// `[SetComputeUnitLimit(900_000), SetComputeUnitPrice(0), SubmitRound]`.
pub fn submit_round_ixs(
    program_id: Pubkey, round_account: Pubkey, payer: Pubkey, vk_account: Pubkey,
    round_seed: String, proof_bytes: Vec<u8>, public_inputs: Vec<u8>,
) -> Result<Vec<Instruction>> {
    use solana_compute_budget_interface::ComputeBudgetInstruction;

    let mut data = Vec::new();
    ZkIx::SubmitRound { round_seed, proof_bytes, public_inputs }
        .serialize(&mut data).context("BorshSerialize::SubmitRound")?;

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(round_account, false),
            AccountMeta::new_readonly(payer, true),
            AccountMeta::new_readonly(vk_account, false),
        ],
        data,
    };

    Ok(vec![
        ComputeBudgetInstruction::set_compute_unit_limit(900_000),
        ComputeBudgetInstruction::set_compute_unit_price(0),
        ix,
    ])
}