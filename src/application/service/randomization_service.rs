use crate::infrastructure::error::error_handler::AppError;
use crate::infrastructure::zk::randomization_circuit::RandomizationCircuit;
use crate::infrastructure::zk::trusted_setup::generate_pk_vk_to_files;
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_sponge::CryptographicSponge;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{env, fs, io::Read, path::Path};
use thiserror::Error;

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

fn load_pk(path: &Path) -> Result<ProvingKey<Bn254>, RandomizationError> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .map_err(|_| RandomizationError::SerializationError)?
        .read_to_end(&mut buf).expect("error reading PK file");
    ProvingKey::deserialize_compressed(&*buf).map_err(|_| RandomizationError::SerializationError)
}

fn load_vk(path: &Path) -> Result<VerifyingKey<Bn254>, RandomizationError> {
    let mut buf = Vec::new();
    fs::File::open(path)
        .map_err(|_| RandomizationError::SerializationError)?
        .read_to_end(&mut buf).expect("error reading VK file");
    VerifyingKey::deserialize_compressed(&*buf).map_err(|_| RandomizationError::SerializationError)
}

#[derive(Clone)]
pub struct RandomizationService {
    pk: ProvingKey<Bn254>,
    vk: VerifyingKey<Bn254>,
}

impl RandomizationService {
    pub fn new<P: AsRef<Path>>(pk_path: P, vk_path: P) -> Result<Self, RandomizationError> {
        let pk_path = pk_path.as_ref();
        let vk_path = vk_path.as_ref();
        let s = env::var("N_PATIENT")
            .map_err(|_| AppError::Config("env var N_PATIENT error".into()));
        let n = s.unwrap().parse::<usize>()
            .map_err(|_| AppError::Config("N_PATIENT needs to be integer".into()));

        if !pk_path.exists() || !vk_path.exists() {
            generate_pk_vk_to_files(n.unwrap(), pk_path, vk_path)?;
        }
        Ok(RandomizationService {
            pk: load_pk(pk_path)?,
            vk: load_vk(vk_path)?,
        })
    }

    pub fn randomize_patients(
        &self,
        patient_ids: Vec<String>,
    ) -> Result<(Vec<bool>, Vec<u8>, Vec<u8>), RandomizationError> {
        let n = patient_ids.len();
        let mut rng = OsRng;

        let seed: Vec<Bn254Fr> = (0..32).map(|_| Bn254Fr::rand(&mut rng)).collect();

        let mut circuit = RandomizationCircuit {
            seed: seed.clone(),
            patient_ids: patient_ids.clone(),
            assignments: vec![None; n],
        };

        let mut sponge = {
            let cfg = {
                use ark_sponge::poseidon::find_poseidon_ark_and_mds;
                use ark_sponge::poseidon::PoseidonConfig;
                let prime_bits = <Bn254Fr as PrimeField>::MODULUS.num_bits() as u64;

                let (ark, mds) = find_poseidon_ark_and_mds::<Bn254Fr>(
                    prime_bits, RATE, FULL_ROUNDS as u64, PARTIAL_ROUNDS as u64, 0
                );
                PoseidonConfig::new(
                    FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY
                )
            };
            ark_sponge::poseidon::PoseidonSponge::new(&cfg)
        };
        sponge.absorb(&seed);
        let hashes: Vec<Bn254Fr> = patient_ids
            .iter()
            .map(|id| {
                let mut h = Sha256::new();
                h.update(id.as_bytes());
                Bn254Fr::from_le_bytes_mod_order(&h.finalize())
            })
            .collect();
        sponge.absorb(&hashes);

        let mut bits = Vec::with_capacity(n);
        for i in 0..n {
            let out: Vec<Bn254Fr> = sponge.squeeze_field_elements(1);
            let bi = out[0].into_bigint();
            let b = bi.as_ref()[0] & 1u64 == 1;
            bits.push(b);
            sponge.absorb(&Bn254Fr::from(i as u64));
        }

        circuit.assignments = bits.iter().copied().map(Some).collect();

        let proof = Groth16::<Bn254>::prove(&self.pk, circuit, &mut rng)
            .map_err(|_| RandomizationError::ProofGenerationError)?;

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes)
            .map_err(|_| RandomizationError::SerializationError)?;

        let mut pi_bytes = Vec::new();
        for h in hashes {
            h.serialize_compressed(&mut pi_bytes)
                .map_err(|_| RandomizationError::SerializationError)?;
        }

        Ok((bits, proof_bytes, pi_bytes))
    }
}
