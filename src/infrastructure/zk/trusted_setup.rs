use crate::application::service::randomization_service::RandomizationError;
use crate::infrastructure::util::hash_util::deterministic_seed_from_str;
use crate::infrastructure::zk::randomization_circuit::RandomizationCircuit;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::CircuitSpecificSetupSNARK;
use ark_sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{env, fs::File, path::Path};
use crate::infrastructure::zk::poseidon::poseidon_cfg;

/// SHA256(participant_identifier) -> Fr for each participant in the roster
fn participant_ids_to_hashes_fr(participant_roster: &[String]) -> Vec<Bn254Fr> {
    participant_roster
        .iter()
        .map(|id| {
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            Bn254Fr::from_le_bytes_mod_order(&h.finalize())
        })
        .collect()
}

/// Poseidon commitment of the participant roster (does NOT include the allocation seed)
fn compute_roster_commitment(participant_roster: &[String]) -> Bn254Fr {
    let hashes = participant_ids_to_hashes_fr(participant_roster);
    let cfg = poseidon_cfg();
    let mut sponge = PoseidonSponge::new(&cfg);
    sponge.absorb(&hashes);
    sponge.squeeze_field_elements(1)[0]
}

/// Generate and persist SNARK keys (pk/vk) — trusted setup phase for the double-blind study
pub fn generate_snark_keys_to_files(
    proving_key_path: impl AsRef<Path>,
    verifying_key_path: impl AsRef<Path>,
    participant_roster: Vec<String>,
) -> Result<(), RandomizationError> {
    // Witness: cryptographic seed used for allocation (same format/length as the circuit expects)
    let allocation_seed_elements: Vec<Bn254Fr> =
        deterministic_seed_from_str(env::var("HASH_SECRET").unwrap().as_str(), 32);

    // The ONLY public input of the circuit: commitment to the participant roster
    let roster_commitment = compute_roster_commitment(&participant_roster);

    // During setup we don't bind any assignments/bits → None
    let circuit = RandomizationCircuit {
        allocation_seed: allocation_seed_elements.clone(),
        participant_ids: participant_roster.clone(),
        asserted_assignments: vec![None; participant_roster.len()],
        participant_roster_commitment: Some(roster_commitment),
    };

    // Trusted setup (Groth16): generate proving key (pk) and verifying key (vk)
    let (proving_key, verifying_key) = Groth16::<Bn254>::setup(circuit, &mut OsRng)
        .map_err(|_| RandomizationError::ProofGenerationError)?;

    // Ensure output directories exist
    if let Some(dir) = proving_key_path.as_ref().parent() {
        std::fs::create_dir_all(dir).expect("Error creating key directory");
    }
    if let Some(dir) = verifying_key_path.as_ref().parent() {
        std::fs::create_dir_all(dir).expect("Error creating key directory");
    }

    // Persist pk
    let mut pk_file = File::create(proving_key_path).expect("Error creating pk file");
    proving_key
        .serialize_compressed(&mut pk_file)
        .expect("Pk serialization error");

    // Persist vk
    let mut vk_file = File::create(verifying_key_path).expect("Error creating vk file");
    verifying_key
        .serialize_compressed(&mut vk_file)
        .expect("Vk serialization error");

    Ok(())
}
