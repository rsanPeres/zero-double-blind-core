use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig},
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::prelude::CondSelectGadget;

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
        println!("[ZK] --- generate_constraints: begin ---");
        println!("[ZK] seed len = {}", self.seed.len());
        let seed_vars = self
            .seed
            .iter()
            .enumerate()
            .map(|(j, &s)| {
                println!("[ZK] seed[{}] (Fr witness) = {}", j, s);
                FpVar::new_witness(cs.clone(), || Ok(s))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 2) patient_ids -> SHA256 -> Fr (fora do R1CS) e aloca como WITNESS
        println!("[ZK] patient_ids len = {}", self.patient_ids.len());
        let id_hash_vars = self
            .patient_ids
            .iter()
            .enumerate()
            .map(|(idx, id)| {
                let mut h = Sha256::new();
                h.update(id.as_bytes());
                let digest = h.finalize(); // bytes
                let fr = Bn254Fr::from_le_bytes_mod_order(&digest);

                println!("[ZK] patient_ids[{}] = {}", idx, id);
                println!("[ZK]   SHA256(id) = {:02x?}", digest);
                println!("[ZK]   fr(hash)   = {}", fr);

                FpVar::new_witness(cs.clone(), || Ok(fr))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let cfg = poseidon_cfg();

        // 3) Commitment interno (witness -> Poseidon) e vincula ao ÚNICO input público
        println!("[ZK] building commitment sponge (ids_commitment)...");
        let mut sponge_commit = PoseidonSpongeVar::new(cs.clone(), &cfg.clone());
        sponge_commit.absorb(&id_hash_vars)?;
        let commit_var = sponge_commit.squeeze_field_elements(1)?[0].clone();

        // (debug) tenta extrair o valor real do commitment (quando houver assignment)
        match commit_var.value() {
            Ok(v) => println!("[ZK][VALUE] ids_commitment (Poseidon output in-circuit) = {}", v),
            Err(_) => println!("[ZK][VALUE] ids_commitment (Poseidon output) not available at synthesis time"),
        }

        match self.ids_commitment {
            Some(c) => println!("[ZK] ids_commitment (expected public input) = {}", c),
            None => println!("[ZK] ids_commitment is MISSING (will error if required)"),
        }

        let public_commit =
            FpVar::new_input(cs.clone(), || self.ids_commitment.ok_or(SynthesisError::AssignmentMissing))?;

        println!("[ZK] enforce: commit_var == public_commit (constraint added)");
        commit_var.enforce_equal(&public_commit)?;

        // 4) Geração de bits (Poseidon sponge) + contagem para impor 50/50
        println!("[ZK] building bit-generation sponge...");
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), cfg);
        sponge.absorb(&seed_vars)?;
        sponge.absorb(&id_hash_vars)?;

        // Contador de 1s (em Fr) para impor 50/50
        let mut ones = FpVar::<Bn254Fr>::constant(Bn254Fr::from(0u64));

        let n = self.patient_ids.len();
        println!("[ZK] n (participants) = {}", n);

        if n % 2 != 0 {
            println!("[ZK][ERROR] 50/50 impossível: n é ímpar");
            return Err(SynthesisError::Unsatisfiable);
        }

        // Segurança do mapeamento: assignments deve cobrir todos os participantes
        if self.assignments.len() != n {
            println!(
                "[ZK][ERROR] assignments.len()={} != patient_ids.len()={}",
                self.assignments.len(),
                n
            );
            return Err(SynthesisError::Unsatisfiable);
        }

        for (i, claim_opt) in self.assignments.into_iter().enumerate() {
            let out = sponge.squeeze_field_elements(1)?[0].clone();
            let bit = out.to_bits_le()?[0].clone(); // Boolean (LSB)

            println!("[ZK] --- patient index i = {} ---", i);

            if let Some(id) = self.patient_ids.get(i) {
                println!("[ZK] patient_id = {}", id);

                // out (Fr) em geral só tem value() quando há assignment
                match out.value() {
                    Ok(v) => println!("[ZK][VALUE] out_i (Poseidon field element) = {}", v),
                    Err(_) => println!("[ZK][VALUE] out_i not available at synthesis time"),
                }

                match bit.value() {
                    Ok(v) => println!("[ZK][bit] boolean = {}", v),
                    Err(_) => println!("[ZK][bit] bit not available at synthesis time"),
                }
            } else {
                println!("[ZK] patient_id = <no patient_ids[i] (index out of range)>");
            }

            // Soma: bit (0/1) no campo
            let bit_fp = FpVar::<Bn254Fr>::conditionally_select(
                &bit,
                &FpVar::constant(Bn254Fr::from(1u64)),
                &FpVar::constant(Bn254Fr::from(0u64)),
            )?;
            ones += bit_fp;

            // (debug) tenta imprimir o acumulado quando houver assignment
            match ones.value() {
                Ok(v) => println!("[ZK][COUNT] ones_so_far (Fr) = {}", v),
                Err(_) => println!("[ZK][COUNT] ones_so_far not available at synthesis time"),
            }

            match claim_opt {
                Some(claim) => {
                    println!("[ZK] claim (witness) = {}", claim);
                    let claimed = Boolean::new_witness(cs.clone(), || Ok(claim))?;
                    println!("[ZK] enforce: bit == claimed (constraint added)");
                    bit.enforce_equal(&claimed)?;
                }
                None => {
                    println!("[ZK] claim = None (no constraint enforced for this bit)");
                }
            }

            // A absorção do índice é parte do fluxo e muda o estado para o próximo squeeze.
            println!("[ZK] absorb idx = {} into sponge (advance state)", i);
            let idx = FpVar::constant(Bn254Fr::from(i as u64));
            sponge.absorb(&idx)?;
        }

        // Impõe 50/50: soma dos bits deve ser N/2
        let half = FpVar::constant(Bn254Fr::from((n / 2) as u64));
        println!("[ZK] enforce: ones == n/2 ({} == {})", n, n / 2);
        ones.enforce_equal(&half)?;

        // (debug) tenta imprimir o total quando houver assignment
        match ones.value() {
            Ok(v) => println!("[ZK][COUNT] total ones (Fr) = {}", v),
            Err(_) => println!("[ZK][COUNT] total ones not available at synthesis time"),
        }

        println!("[ZK] --- generate_constraints: end ---");
        Ok(())
    }
}
