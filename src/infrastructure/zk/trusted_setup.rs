use crate::application::service::randomization_service::RandomizationError;
use crate::infrastructure::zk::randomization_circuit::RandomizationCircuit;
use ark_bn254::Fr as Bn254Fr;
use ark_bn254::Bn254;
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::CircuitSpecificSetupSNARK;
use rand::rngs::OsRng;
use std::{fs::File, path::Path};

pub fn generate_pk_vk_to_files(
    max_patients: usize,
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) -> Result<(), RandomizationError> {
    let seed: Vec<Bn254Fr> = (0..32)
        .map(|_| Bn254Fr::rand(&mut OsRng))
        .collect();

    let ids: Vec<String> = (0..max_patients)
        .map(|i| format!("_{}", i))
        .collect();

    let circ = RandomizationCircuit {
        seed,
        patient_ids: ids,
        assignments: vec![None; max_patients],
    };

    let (pk, vk) = Groth16::<Bn254>::setup(circ, &mut OsRng)
        .map_err(|_| RandomizationError::ProofGenerationError)?;

    std::fs::create_dir_all(pk_path.as_ref().parent().unwrap()).expect("Error creating key directory");
    let mut f_pk = File::create(pk_path);
    pk.serialize_compressed(&mut f_pk.unwrap()).expect("Pk serialization error");
    let f_vk = File::create(vk_path);
    vk.serialize_compressed(&mut f_vk.unwrap()).expect("Vk serialization error");
    Ok(())
}
