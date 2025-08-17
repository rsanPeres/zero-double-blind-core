use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig},
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use ark_r1cs_std::fields::FieldVar;

// mesmos parâmetros usados off-chain
const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 31;
const ALPHA: u64 = 5;

/// Poseidon cfg singleton
fn poseidon_cfg() -> &'static PoseidonConfig<Bn254Fr> {
    static CFG: OnceLock<PoseidonConfig<Bn254Fr>> = OnceLock::new();
    CFG.get_or_init(|| {
        let prime_bits = <Bn254Fr as PrimeField>::MODULUS.num_bits() as u64;
        let (ark, mds) = find_poseidon_ark_and_mds::<Bn254Fr>(
            prime_bits,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

#[derive(Clone)]
pub struct RandomizationCircuit {
    pub seed: Vec<Bn254Fr>,          // witness
    pub patient_ids: Vec<String>,    // viram witness (hash->Fr) dentro do circuito
    pub assignments: Vec<Option<bool>>, // se Some, checa o bit gerado
    pub ids_commitment: Option<Bn254Fr>, // ÚNICO input público (Poseidon dos hashes)
}

impl ConstraintSynthesizer<Bn254Fr> for RandomizationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
        // 1) Seed como witness
        let seed_vars = self
            .seed
            .iter()
            .map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)))
            .collect::<Result<Vec<_>, _>>()?;

        // 2) patient_ids -> SHA256 -> Fr (fora do R1CS) e aloca como WITNESS
        let id_hash_vars = self
            .patient_ids
            .iter()
            .map(|id| {
                let mut h = Sha256::new();
                h.update(id.as_bytes());
                let fr = Bn254Fr::from_le_bytes_mod_order(&h.finalize());
                FpVar::new_witness(cs.clone(), || Ok(fr))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let cfg = poseidon_cfg();

        // 3) Commitment interno (witness -> Poseidon) e vincula ao ÚNICO input público
        let mut sponge_commit = PoseidonSpongeVar::new(cs.clone(), cfg);
        sponge_commit.absorb(&id_hash_vars)?;
        let commit_var = sponge_commit.squeeze_field_elements(1)?[0].clone();

        let public_commit =
            FpVar::new_input(cs.clone(), || self.ids_commitment.ok_or(SynthesisError::AssignmentMissing))?;
        commit_var.enforce_equal(&public_commit)?;

        // 4) Fluxo original de geração de bits: seed + ids (hashes) → squeeze LSB
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), cfg);
        sponge.absorb(&seed_vars)?;
        sponge.absorb(&id_hash_vars)?;

        for (i, claim_opt) in self.assignments.into_iter().enumerate() {
            let out = sponge.squeeze_field_elements(1)?[0].clone();
            let bit = out.to_bits_le()?[0].clone(); // LSB

            if let Some(claim) = claim_opt {
                let claimed = Boolean::new_witness(cs.clone(), || Ok(claim))?;
                bit.enforce_equal(&claimed)?;
            }

            // absorve índice para o próximo passo (igual ao seu desenho original)
            let idx = FpVar::constant(Bn254Fr::from(i as u64));
            sponge.absorb(&idx)?;
        }

        Ok(())
    }
}
