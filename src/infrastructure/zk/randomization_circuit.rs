use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::{
    poseidon::{constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig},
    CryptographicSponge,
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use ark_sponge::constraints::CryptographicSpongeVar;

const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 31;
const ALPHA: u64 = 5;

#[derive(Clone)]
pub struct RandomizationCircuit {
    pub seed: Vec<Bn254Fr>,
    pub patient_ids: Vec<String>,
    pub assignments: Vec<Option<bool>>,
}

impl ConstraintSynthesizer<Bn254Fr> for RandomizationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
        let seed_vars = self.seed
            .iter()
            .map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)))
            .collect::<Result<Vec<_>, _>>()?;

        let id_vars = self.patient_ids
            .iter()
            .map(|id| {
                let mut h = Sha256::new();
                h.update(id.as_bytes());
                let bytes = h.finalize();
                let fr = Bn254Fr::from_le_bytes_mod_order(&bytes);
                FpVar::new_input(cs.clone(), || Ok(fr))
            })
            .collect::<Result<Vec<_>, _>>()?;

        static POSEIDON_CFG: OnceLock<PoseidonConfig<Bn254Fr>> = OnceLock::new();
        let cfg = POSEIDON_CFG.get_or_init(|| {

            let prime_bits = <Bn254Fr as PrimeField>::MODULUS.num_bits() as u64;

            let (ark, mds) = find_poseidon_ark_and_mds::<Bn254Fr>(
                prime_bits, RATE, FULL_ROUNDS as u64, PARTIAL_ROUNDS as u64, 0
            );
            PoseidonConfig::new(
                FULL_ROUNDS,               // full rounds
                PARTIAL_ROUNDS,            // partial rounds
                ALPHA,                     // alpha
                mds,                       // MDS matrix
                ark,                       // ARK constants
                RATE,                      // rate
                CAPACITY,                  // capacity
            )
        });

        let mut sponge = PoseidonSpongeVar::new(cs.clone(), cfg);
        sponge.absorb(&seed_vars)?;
        sponge.absorb(&id_vars)?;

        for (i, claim_opt) in self.assignments.into_iter().enumerate() {
            let out = sponge.squeeze_field_elements(1)?[0].clone();
            let bi_var = out.to_bits_le()?;
            let bit = bi_var[0].clone();

            if let Some(claim) = claim_opt {
                let claimed_var = Boolean::new_witness(cs.clone(), || Ok(claim))?;
                bit.enforce_equal(&claimed_var)?;
            }

            let idx = FpVar::constant(Bn254Fr::from(i as u64));
            sponge.absorb(&idx)?;
        }

        Ok(())
    }
}
