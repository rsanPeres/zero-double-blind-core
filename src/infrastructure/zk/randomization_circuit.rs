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

const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 31;
const ALPHA: u64 = 5;

/// Shared Poseidon configuration (singleton).
/// the roster commitment and the per-participant allocation sponge.
fn poseidon_config_shared() -> &'static PoseidonConfig<Bn254Fr> {
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

/// Trial randomization circuit (clinical domain + zk-SNARK construction).
/// - allocation_seed: secret randomness that drives assignment bits (witness)
/// - participant_ids: external identifiers, pre-hashed off-circuit to Fr (witness)
/// - asserted_assignments: optional claimed arm per participant to audit (witness)
/// - participant_roster_commitment: the ONLY public input (Poseidon over ID hashes)
#[derive(Clone)]
pub struct RandomizationCircuit {
    pub allocation_seed: Vec<Bn254Fr>,              // was `seed` (witness)
    pub participant_ids: Vec<String>,               // was `patient_ids` (hashed→Fr off-circuit, then witness)
    pub asserted_assignments: Vec<Option<bool>>,    // was `assignments` (if Some, enforce equality)
    pub participant_roster_commitment: Option<Bn254Fr>, // was `ids_commitment` (single public input)
}

impl ConstraintSynthesizer<Bn254Fr> for RandomizationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
        // --------------------------------------------------------------------
        // 1) Allocate the allocation seed as private witnesses.
        //    ZK rationale: keep the randomization entropy hidden from the verifier.
        // --------------------------------------------------------------------
        let allocation_seed_vars = self
            .allocation_seed
            .iter()
            .map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)))
            .collect::<Result<Vec<_>, _>>()?;

        // --------------------------------------------------------------------
        // 2) For each participant ID: SHA-256(ID) → Fr (done off-circuit),
        //    then allocate the resulting field elements as private witnesses.
        //    Clinical rationale: prove consistency with the roster without
        //    revealing IDs; ZK rationale: cheaper than in-circuit SHA-256.
        // --------------------------------------------------------------------
        let participant_id_hash_vars = self
            .participant_ids
            .iter()
            .map(|pid| {
                let mut h = Sha256::new();
                h.update(pid.as_bytes());
                let fr = Bn254Fr::from_le_bytes_mod_order(&h.finalize());
                FpVar::new_witness(cs.clone(), || Ok(fr))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Shared Poseidon configuration
        let poseidon_cfg = poseidon_config_shared();

        // --------------------------------------------------------------------
        // 3) In-circuit roster commitment:
        //    Poseidon(participant_id_hashes) must equal the SINGLE public input.
        //    This binds the proof to the exact participant roster.
        // --------------------------------------------------------------------
        let mut commitment_sponge = PoseidonSpongeVar::new(cs.clone(), poseidon_cfg);
        commitment_sponge.absorb(&participant_id_hash_vars)?;
        let recomputed_roster_commitment = commitment_sponge.squeeze_field_elements(1)?[0].clone();

        let public_roster_commitment =
            FpVar::new_input(cs.clone(), || {
                self.participant_roster_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Enforce binding between private roster and the public commitment
        recomputed_roster_commitment.enforce_equal(&public_roster_commitment)?;

        // --------------------------------------------------------------------
        // 4) Per-participant allocation flow:
        //    Build a Poseidon sponge absorbing (allocation_seed || roster_hashes),
        //    then for each participant:
        //      - squeeze a field element,
        //      - take its LSB as the assignment bit,
        //      - optionally check against an asserted assignment,
        //      - absorb the participant index to evolve the sponge state.
        // --------------------------------------------------------------------
        let mut allocation_sponge = PoseidonSpongeVar::new(cs.clone(), poseidon_cfg);
        allocation_sponge.absorb(&allocation_seed_vars)?;
        allocation_sponge.absorb(&participant_id_hash_vars)?;

        for (participant_index, asserted_assignment_opt) in
            self.asserted_assignments.into_iter().enumerate()
        {
            // Squeeze pseudorandom field element for this participant
            let allocation_draw = allocation_sponge.squeeze_field_elements(1)?[0].clone();

            // Convert to bits (LE) and use the LSB as the assigned arm bit
            // Convention: 0 → control, 1 → treatment (or as defined externally)
            let assigned_arm_bit = allocation_draw.to_bits_le()?[0].clone();

            // If an asserted assignment exists, enforce equality (audit mode)
            if let Some(claimed) = asserted_assignment_opt {
                let claimed_bit = Boolean::new_witness(cs.clone(), || Ok(claimed))?;
                assigned_arm_bit.enforce_equal(&claimed_bit)?;
            }

            // Absorb the participant index to decorrelate subsequent squeezes
            let participant_index_var = FpVar::constant(Bn254Fr::from(participant_index as u64));
            allocation_sponge.absorb(&participant_index_var)?;
        }

        Ok(())
    }
}
