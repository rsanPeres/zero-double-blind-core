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

/// SHA256(id) -> Fr para cada ID
fn ids_to_hashes_fr(ids: &[String]) -> Vec<Bn254Fr> {
    ids.iter()
        .map(|id| {
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            Bn254Fr::from_le_bytes_mod_order(&h.finalize())
        })
        .collect()
}

/// Poseidon commitment dos hashes (NÃO inclui a seed)
fn compute_ids_commitment(ids: &[String]) -> Bn254Fr {
    let hashes = ids_to_hashes_fr(ids);
    let cfg = poseidon_cfg();
    let mut sponge = PoseidonSponge::new(&cfg);
    sponge.absorb(&hashes);
    sponge.squeeze_field_elements(1)[0]
}

pub fn generate_pk_vk_to_files(
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
    ids: Vec<String>,
) -> Result<(), RandomizationError> {
    // Witness de seed (mesmo formato/quantidade usado no circuito)
    let seed: Vec<Bn254Fr> =
        deterministic_seed_from_str(env::var("HASH_SECRET").unwrap().as_str(), 32);

    // ÚNICO input público do circuito
    let ids_commitment = compute_ids_commitment(&ids);

    // Durante o setup não precisamos amarrar os bits → None
    let circ = RandomizationCircuit {
        seed,
        patient_ids: ids.clone(),
        assignments: vec![None; ids.len()],
        ids_commitment: Some(ids_commitment),
    };

    let (pk, vk) = Groth16::<Bn254>::setup(circ, &mut OsRng)
        .map_err(|_| RandomizationError::ProofGenerationError)?;

    if let Some(dir) = pk_path.as_ref().parent() {
        std::fs::create_dir_all(dir).expect("Error creating key directory");
    }
    if let Some(dir) = vk_path.as_ref().parent() {
        std::fs::create_dir_all(dir).expect("Error creating key directory");
    }

    let mut f_pk = File::create(pk_path).expect("Error creating pk file");
    pk.serialize_compressed(&mut f_pk).expect("Pk serialization error");

    let mut f_vk = File::create(vk_path).expect("Error creating vk file");
    vk.serialize_compressed(&mut f_vk).expect("Vk serialization error");

    Ok(())
}
