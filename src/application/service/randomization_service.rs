use crate::infrastructure::error::error_handler::AppError;
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
use crate::infrastructure::solana::vk_codec::{
    pack_public_inputs_be32, proof_to_compact_128,
};
use anyhow::Context;
use crate::infrastructure::solana::verifier::{sanity_offchain_like_onchain, sanity_offchain_like_onchain128};
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
        .expect("error reading PK file");
    ProvingKey::deserialize_compressed(&*buf).map_err(|_| RandomizationError::SerializationError)
}

fn load_vk(path: &Path) -> std::result::Result<VerifyingKey<Bn254>, RandomizationError> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .map_err(|_| RandomizationError::SerializationError)?
        .read_to_end(&mut buf)
        .expect("error reading VK file");
    VerifyingKey::deserialize_compressed(&*buf).map_err(|_| RandomizationError::SerializationError)
}

#[derive(Clone)]
pub struct RandomizationService {
    pk: ProvingKey<Bn254>,
    vk: VerifyingKey<Bn254>,
}

impl RandomizationService {
    pub fn new<P: AsRef<Path>>(pk_path: P, vk_path: P) -> std::result::Result<Self, RandomizationError> {
        let pk_path = pk_path.as_ref();
        let vk_path = vk_path.as_ref();

        // Mantido: validação externa de N_PATIENT (se houver)
        let s = env::var("N_PATIENT")
            .map_err(|_| AppError::Config("env var N_PATIENT error".into()));
        let _n = s.unwrap().parse::<usize>()
            .map_err(|_| AppError::Config("N_PATIENT needs to be integer".into()));

        Ok(RandomizationService {
            pk: load_pk(pk_path)?,
            vk: load_vk(vk_path)?,
        })
    }

    pub fn randomize_patients(
        &self,
        patient_ids: Vec<String>,
    ) -> Result<(Vec<bool>, Vec<u8>, Vec<u8>, Proof<Bn254>, Vec<Bn254Fr>), RandomizationError> {
        // monta circuito com seed, ids etc. (usa os mesmos parâmetros do circuito)
        let (n, _rng, seed, mut circuit) = Self::create_circuit(&patient_ids);

        // === bits off-chain (seed + hashes -> LSB; absorve idx) ===
        let cfg = {
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
        };
        let mut sponge = ark_sponge::poseidon::PoseidonSponge::new(&cfg);

        // seed
        sponge.absorb(&seed);

        // SHA256(id) -> Fr (igual ao circuito)
        let hashes: Vec<Bn254Fr> = patient_ids
            .iter()
            .map(|id| {
                let mut h = Sha256::new();
                h.update(id.as_bytes());
                Bn254Fr::from_le_bytes_mod_order(&h.finalize())
            })
            .collect();

        // ids em Fr
        sponge.absorb(&hashes);

        // extrai bits
        let mut bits = Vec::with_capacity(n);
        for i in 0..n {
            let out: Vec<Bn254Fr> = sponge.squeeze_field_elements(1);
            let bi = out[0].into_bigint();
            let b = (bi.as_ref()[0] & 1u64) == 1;
            bits.push(b);
            sponge.absorb(&Bn254Fr::from(i as u64));
        }

        // o circuito só checa o compromisso público
        circuit.asserted_assignments = vec![None; patient_ids.len()];

        // 1) ÚNICO input público: Poseidon dos hashes (SEM seed)
        let ids_commit_fr = {
            use ark_sponge::{poseidon::{find_poseidon_ark_and_mds, PoseidonConfig}, CryptographicSponge};
            let prime_bits = <Bn254Fr as PrimeField>::MODULUS.num_bits() as u64;
            let (ark, mds) = find_poseidon_ark_and_mds::<Bn254Fr>(
                prime_bits,
                RATE,
                FULL_ROUNDS as u64,
                PARTIAL_ROUNDS as u64,
                0,
            );
            let cfg = PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY);
            let mut sponge = ark_sponge::poseidon::PoseidonSponge::new(&cfg);
            sponge.absorb(&hashes);
            sponge.squeeze_field_elements(1)[0]
        };

        circuit.participant_roster_commitment = Some(ids_commit_fr);

        // Prova (com diagnóstico)
        let proof = crate::infrastructure::zk::prove::provar_com_diagnostico(circuit, &self.pk)
            .map_err(|e| {
                eprintln!("diagnóstico da prova: {e}");
                RandomizationError::ProofGenerationError
            })?;

        // 2) Prova compacta 128 B (A32|B64|C32) — útil para off-chain
        let proof_128: Vec<u8> = proof_to_compact_128(&proof).to_vec();

        // 3a) Input público em formato ark (para verificação OFF-CHAIN, se quiser)
        let mut pi_bytes = Vec::new();
        ids_commit_fr
            .serialize_compressed(&mut pi_bytes)
            .map_err(|_| RandomizationError::SerializationError)?;

        // 3b) Inputs públicos como Fr (para a chamada on-chain)
        let public_inputs_fr: Vec<Bn254Fr> = vec![ids_commit_fr];

        // (bits, prova_128B, pi_bytes(ark), prova_struct, inputs_fr)
        Ok((bits, proof_128, pi_bytes, proof, public_inputs_fr))
    }

    pub fn off_chain_verify_randomization_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, String> {
        let proof = Proof::<Bn254>::deserialize_compressed(&mut std::io::Cursor::new(proof_bytes))
            .map_err(|e| format!("Erro ao desserializar prova: {}", e))?;

        let mut inputs = Vec::new();
        let mut cursor = std::io::Cursor::new(public_inputs);
        while (cursor.position() as usize) < public_inputs.len() {
            let input = Bn254Fr::deserialize_compressed(&mut cursor)
                .map_err(|e| format!("Erro ao desserializar input público: {}", e))?;
            inputs.push(input);
        }

        println!("Public inputs len: {}", inputs.len());
        println!("Expected inputs in circuit: {}", self.vk.gamma_abc_g1.len() - 1);

        let result = Groth16::<Bn254>::verify(&self.vk, &*inputs, &proof)
            .map_err(|e| format!("Erro ao verificar prova: {}", e))?;

        Ok(result)
    }

    pub fn on_chain_verify_randomization_proof(
        &self,
        proof: &Proof<Bn254>,
        public_inputs_fr: &[Bn254Fr],
        values: Vec<bool>,
    ) -> anyhow::Result<String> {
        use anyhow::Context;
        use solana_client::rpc_client::RpcClient;
        use crate::infrastructure::solana::vk_codec::{pack_public_inputs_be32, vk_to_g16v_bytes_uncompressed};
        use crate::infrastructure::solana::verifier::sanity_offchain_like_onchain;
        use crate::infrastructure::zk::prove::proof_to_uncompressed_be_256;

        // 1) RPC/Program
        let rpc = std::env::var("RPC_URL")
            .or_else(|_| std::env::var("RPC"))
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
        let program = std::env::var("PROGRAM_ID").context("PROGRAM_ID não definido no ambiente")?;

        // 2) Conta da VK on-chain
        let (vk_seed, vk_pk) = provision_vk(&self.vk)?;
        let mut round_seed = make_solana_seed32();
        if round_seed == vk_seed { round_seed = make_solana_seed32(); }

        let rpc_client = RpcClient::new(rpc.clone());
        let acc = rpc_client.get_account(&vk_pk)?;
        let head = acc.data.get(0..4).unwrap_or(&[]);
        let head_str = std::str::from_utf8(head).unwrap_or("????");
        anyhow::ensure!(head_str == "VKH1", "vk_pk não é VK: head={head_str}");

        // 3) Prova 256B (A64|B128|C64) e inputs BE32
        let proof_bytes = proof_to_uncompressed_be_256(proof).to_vec();
        let public_inputs_be = pack_public_inputs_be32(public_inputs_fr);

        // 4) VK local serializada (para comparação na sanity)
        let local_vk_bytes = vk_to_g16v_bytes_uncompressed(&self.vk);

        // 5) Diagnóstico “like on-chain” (agora com VK local)
        match sanity_offchain_like_onchain(vk_pk, &proof_bytes, &public_inputs_be, Some(&local_vk_bytes)) {
            Ok(ok) => eprintln!("sanity (like on-chain): {}", ok),
            Err(e) => eprintln!("sanity falhou: {e}"),
        }

        // 6) (restante do envio da rodada)
        submit_round(
            &rpc,
            &program,
            &round_seed,
            vk_pk,
            proof_bytes,
            public_inputs_be,
            values,
        ).context("falha ao enviar SubmitRound")
    }

    fn create_circuit(patient_ids: &Vec<String>) -> (usize, OsRng, Vec<Fr>, RandomizationCircuit) {
        let n = patient_ids.len();
        let mut rng = OsRng;

        let seed = deterministic_seed_from_str(
            env::var("HASH_SECRET").unwrap().as_str(), 32);

        // Poseidon cfg
        let cfg = {
            use ark_sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
            let prime_bits = <Bn254Fr as PrimeField>::MODULUS.num_bits() as u64;
            let (ark, mds) = find_poseidon_ark_and_mds::<Bn254Fr>(
                prime_bits, RATE, FULL_ROUNDS as u64, PARTIAL_ROUNDS as u64, 0);
            PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
        };

        // SHA256(id) -> Fr (witness no circuito, igual ao off-chain)
        let hashes: Vec<Bn254Fr> = patient_ids.iter().map(|id| {
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            Bn254Fr::from_le_bytes_mod_order(&h.finalize())
        }).collect();

        // compromisso Poseidon dos hashes (SEM seed) — único input público
        let ids_commit_fr = {
            let mut sponge_ids = ark_sponge::poseidon::PoseidonSponge::new(&cfg);
            sponge_ids.absorb(&hashes);
            sponge_ids.squeeze_field_elements(1)[0]
        };

        let circuit = RandomizationCircuit {
            allocation_seed: seed.clone(),
            participant_ids: patient_ids.clone(),
            asserted_assignments: vec![None; patient_ids.len()],
            participant_roster_commitment: Some(ids_commit_fr),
        };
        (n, rng, seed, circuit)
    }
}