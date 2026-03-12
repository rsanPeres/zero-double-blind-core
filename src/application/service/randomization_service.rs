use crate::infrastructure::solana::solana_client::submit_round;
use crate::infrastructure::solana::upload_vk::provision_vk;
use crate::infrastructure::util::hash_util::deterministic_seed_from_str;
use crate::infrastructure::zk::randomization_circuit::RandomizationCircuit;

use ark_bn254::{Bn254, Fr as Bn254Fr, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_sponge::CryptographicSponge;

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{env, fs, io::Read, path::Path};
use thiserror::Error;

use crate::infrastructure::solana::seed_util::make_solana_seed32;
use crate::infrastructure::solana::vk_codec::{pack_public_inputs_be32, proof_to_compact_128};
use anyhow::Context;
use crate::infrastructure::solana::verifier::{sanity_check_full, sanity_check_n1};
use crate::infrastructure::zk::prove::proof_to_uncompressed_be_256;

const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 31;
const ALPHA: u64 = 5;

#[derive(Error, Debug)]
pub enum RandomizationError {
    #[error("IO/serialization error")]
    SerializationError,
    #[error("Proof generation failed")]
    ProofGenerationError,
}

fn load_pk(path: &Path) -> std::result::Result<ProvingKey<Bn254>, RandomizationError> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .map_err(|_| RandomizationError::SerializationError)?
        .read_to_end(&mut buf)
        .map_err(|_| RandomizationError::SerializationError)?;
    ProvingKey::deserialize_compressed(&*buf).map_err(|_| RandomizationError::SerializationError)
}

fn load_vk(path: &Path) -> std::result::Result<VerifyingKey<Bn254>, RandomizationError> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .map_err(|_| RandomizationError::SerializationError)?
        .read_to_end(&mut buf)
        .map_err(|_| RandomizationError::SerializationError)?;
    VerifyingKey::deserialize_compressed(&*buf).map_err(|_| RandomizationError::SerializationError)
}

#[derive(Clone)]
pub struct RandomizationService {
    pk: ProvingKey<Bn254>,
    vk: VerifyingKey<Bn254>,
}

impl RandomizationService {
    pub fn new<P: AsRef<Path>>(
        pk_path: P,
        vk_path: P,
    ) -> std::result::Result<Self, RandomizationError> {
        // Validate N_PATIENT early so misconfiguration is caught at startup.
        let n_str = env::var("N_PATIENT").map_err(|_| RandomizationError::SerializationError)?;
        let _n: usize = n_str
            .parse()
            .map_err(|_| RandomizationError::SerializationError)?;

        Ok(RandomizationService {
            pk: load_pk(pk_path.as_ref())?,
            vk: load_vk(vk_path.as_ref())?,
        })
    }

    /// Generates randomization bits and a Groth16 proof for the given patient IDs.
    ///
    /// Returns `(bits, proof_128b, pi_bytes_ark, proof_struct, public_inputs_fr)`.
    /// * `proof_128b`       — 128-byte compressed proof (A32|B64|C32).
    /// * `pi_bytes_ark`     — arkworks-serialized public input (for off-chain verification).
    /// * `public_inputs_fr` — Fr elements to pass to the on-chain verifier.
    pub fn randomize_patients(
        &self,
        patient_ids: Vec<String>,
    ) -> std::result::Result<
        (Vec<bool>, Vec<u8>, Vec<u8>, Proof<Bn254>, Vec<Bn254Fr>),
        RandomizationError,
    > {
        let (n, _rng, seed, mut circuit) = Self::create_circuit(&patient_ids);

        // Build Poseidon config shared across this function.
        let cfg = poseidon_cfg();

        let mut sponge = ark_sponge::poseidon::PoseidonSponge::new(&cfg);
        sponge.absorb(&seed);

        // SHA-256(id) → Fr, mirroring the circuit witness.
        let hashes: Vec<Bn254Fr> = sha256_hashes_fr(&patient_ids);
        sponge.absorb(&hashes);

        // Extract one bit per patient from the sponge LSB, feeding back the index.
        let mut bits = Vec::with_capacity(n);
        for i in 0..n {
            let out: Vec<Bn254Fr> = sponge.squeeze_field_elements(1);
            let b = (out[0].into_bigint().as_ref()[0] & 1u64) == 1;
            bits.push(b);
            sponge.absorb(&Bn254Fr::from(i as u64));
        }

        circuit.assignments = vec![None; patient_ids.len()];

        // Single public input: Poseidon commitment over patient-ID hashes (no seed).
        let ids_commit_fr: Fr = {
            let mut s = ark_sponge::poseidon::PoseidonSponge::new(&cfg);
            s.absorb(&hashes);
            s.squeeze_field_elements(1)[0]
        };

        circuit.ids_commitment = Some(ids_commit_fr.clone());

        let proof =
            crate::infrastructure::zk::prove::provar_com_diagnostico(circuit, &self.pk)
                .map_err(|e| {
                    eprintln!("proof diagnostic: {e}");
                    RandomizationError::ProofGenerationError
                })?;

        let proof_128: Vec<u8> = proof_to_compact_128(&proof)
            .map_err(|_| RandomizationError::ProofGenerationError)?
            .to_vec();

        let mut pi_bytes = Vec::new();
        ids_commit_fr
            .serialize_compressed(&mut pi_bytes)
            .map_err(|_| RandomizationError::SerializationError)?;

        let public_inputs_fr: Vec<Bn254Fr> = vec![ids_commit_fr];

        Ok((bits, proof_128, pi_bytes, proof, public_inputs_fr))
    }

    /// Verifies a proof locally using the arkworks Groth16 verifier.
    ///
    /// `proof_bytes`   — arkworks-compressed proof bytes.
    /// `public_inputs` — arkworks-compressed Fr elements.
    pub fn off_chain_verify_randomization_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, String> {
        let proof =
            Proof::<Bn254>::deserialize_compressed(&mut std::io::Cursor::new(proof_bytes))
                .map_err(|e| format!("failed to deserialize proof: {e}"))?;

        let mut inputs = Vec::new();
        let mut cursor = std::io::Cursor::new(public_inputs);
        while (cursor.position() as usize) < public_inputs.len() {
            let input = Bn254Fr::deserialize_compressed(&mut cursor)
                .map_err(|e| format!("failed to deserialize public input: {e}"))?;
            inputs.push(input);
        }

        eprintln!("public inputs len: {}", inputs.len());
        eprintln!(
            "expected inputs in circuit: {}",
            self.vk.gamma_abc_g1.len() - 1
        );

        Groth16::<Bn254>::verify(&self.vk, &*inputs, &proof)
            .map_err(|e| format!("verification error: {e}"))
    }

    /// Submits a round on-chain using the 256-byte uncompressed proof format.
    ///
    /// Calls `sanity_check_full` before sending to surface orientation
    /// mismatches early.  All sleep/retry logic is handled by the delegates
    /// (`provision_vk`, `submit_round`).
    pub fn on_chain_verify_randomization_proof(
        &self,
        proof: &Proof<Bn254>,
        public_inputs_fr: &[Bn254Fr],
        values: Vec<bool>,
    ) -> anyhow::Result<String> {
        use crate::infrastructure::solana::vk_codec::vk_to_g16v_bytes_uncompressed;

        let rpc = rpc_url();
        let program =
            env::var("PROGRAM_ID").context("PROGRAM_ID environment variable is not set")?;

        let (vk_seed, vk_pk) = provision_vk(&self.vk)?;
        let round_seed = unique_round_seed(&vk_seed);

        // Verify the account is a sealed VK before proceeding.
        let rpc_client = solana_client::rpc_client::RpcClient::new(rpc.clone());
        let acc = rpc_client.get_account(&vk_pk)?;
        let head_str = std::str::from_utf8(acc.data.get(0..4).unwrap_or(&[])).unwrap_or("????");
        anyhow::ensure!(head_str == "VKH1", "vk_pk is not a VK account: head={head_str}");

        let proof_bytes = proof_to_uncompressed_be_256(proof).to_vec();
        let public_inputs_be = pack_public_inputs_be32(public_inputs_fr);
        let local_vk_bytes = vk_to_g16v_bytes_uncompressed(&self.vk);

        // Exhaustive orientation grid — useful for diagnosing on-chain failures.
        match sanity_check_full(vk_pk, &proof_bytes, &public_inputs_be, Some(&local_vk_bytes)) {
            Ok(ok) => eprintln!("[sanity_check_full] result={ok}"),
            Err(e) => eprintln!("[sanity_check_full] failed: {e}"),
        }

        submit_round(
            &rpc,
            &program,
            &round_seed,
            vk_pk,
            proof_bytes,
            public_inputs_be,
            values,
        )
            .context("SubmitRound failed")
    }

    /// Submits a round on-chain using the 128-byte compressed proof format (A32|B64|C32).
    ///
    /// Preferred over `on_chain_verify_randomization_proof` because the
    /// compact format avoids G2-orientation ambiguity in the on-chain verifier.
    pub fn on_chain_verify_randomization_proof2(
        &self,
        proof: &Proof<Bn254>,
        public_inputs_fr: &[Bn254Fr],
        values: Vec<bool>,
    ) -> anyhow::Result<String> {
        let rpc = rpc_url();
        let program =
            env::var("PROGRAM_ID").context("PROGRAM_ID environment variable is not set")?;

        let (vk_seed, vk_pk) = provision_vk(&self.vk)?;
        let round_seed = unique_round_seed(&vk_seed);

        let rpc_client = solana_client::rpc_client::RpcClient::new(rpc.clone());
        let acc = rpc_client.get_account(&vk_pk)?;
        let head_str = std::str::from_utf8(acc.data.get(0..4).unwrap_or(&[])).unwrap_or("????");
        anyhow::ensure!(head_str == "VKH1", "vk_pk is not a VK account: head={head_str}");

        let public_inputs_be = pack_public_inputs_be32(public_inputs_fr);
        eprintln!(
            "pi0_be32 prefix={:02x}{:02x}{:02x}{:02x}",
            public_inputs_be[0],
            public_inputs_be[1],
            public_inputs_be[2],
            public_inputs_be[3]
        );

        let proof_bytes = proof_to_compact_128(proof)
            .map_err(|_| RandomizationError::ProofGenerationError)?
            .to_vec();

        // Guard: confirm the proof passes the local arkworks verifier before
        // spending lamports on an on-chain transaction.
        assert!(
            Groth16::<Bn254>::verify(&self.vk, public_inputs_fr, proof)?,
            "local Groth16 verification failed — proof or public inputs are inconsistent"
        );

        // Fast single-path check matching the canonical on-chain path (N=1).
        match sanity_check_n1(vk_pk, &proof_bytes, &public_inputs_be) {
            Ok(ok) => eprintln!("[sanity_check_n1] result={ok}"),
            Err(e) => eprintln!("[sanity_check_n1] failed: {e}"),
        }

        submit_round(
            &rpc,
            &program,
            &round_seed,
            vk_pk,
            proof_bytes,
            public_inputs_be,
            values,
        )
            .context("SubmitRound failed")
    }

    fn create_circuit(
        patient_ids: &[String],
    ) -> (usize, OsRng, Vec<Fr>, RandomizationCircuit) {
        let n = patient_ids.len();
        let rng = OsRng;

        let seed = deterministic_seed_from_str(
            env::var("HASH_SECRET")
                .expect("HASH_SECRET is not set")
                .as_str(),
            32,
        );

        let cfg = poseidon_cfg();
        let hashes = sha256_hashes_fr(patient_ids);

        let ids_commit_fr = {
            let mut s = ark_sponge::poseidon::PoseidonSponge::new(&cfg);
            s.absorb(&hashes);
            s.squeeze_field_elements(1)[0]
        };

        let circuit = RandomizationCircuit {
            seed: seed.clone(),
            patient_ids: patient_ids.to_vec(),
            assignments: vec![None; patient_ids.len()],
            ids_commitment: Some(ids_commit_fr),
        };

        (n, rng, seed, circuit)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the Poseidon config used throughout this service.
fn poseidon_cfg() -> ark_sponge::poseidon::PoseidonConfig<Bn254Fr> {
    use ark_sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
    let prime_bits = <Bn254Fr as PrimeField>::MODULUS.num_bits() as u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<Bn254Fr>(
        prime_bits,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
}

/// Maps each patient ID to `SHA-256(id) mod q` as an `Fr` element.
fn sha256_hashes_fr(ids: &[String]) -> Vec<Bn254Fr> {
    ids.iter()
        .map(|id| {
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            Bn254Fr::from_le_bytes_mod_order(&h.finalize())
        })
        .collect()
}

/// Returns the RPC endpoint, preferring `RPC_URL` then `RPC`, defaulting to devnet.
fn rpc_url() -> String {
    env::var("RPC_URL")
        .or_else(|_| env::var("RPC"))
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string())
}

/// Returns a round seed guaranteed to differ from `vk_seed`.
///
/// `make_solana_seed32` is deterministic for a given `HASH_SECRET`, so two
/// calls would return the same value.  Appending a suffix is intentional:
/// the round account must live at a different address from the VK account.
fn unique_round_seed(vk_seed: &str) -> String {
    let seed = make_solana_seed32();
    if seed != vk_seed {
        return seed;
    }
    // Extremely unlikely (would require a SHA-256 collision on the VK bytes),
    // but handled defensively.
    format!("{seed}-r")
}