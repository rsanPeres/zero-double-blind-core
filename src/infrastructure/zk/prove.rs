use std::ops::Neg;
// src/infrastructure/zk/prover.rs
use anyhow::{anyhow, bail, Result};
use ark_bn254::{Bn254, Fq, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;

/// Gera uma prova Groth16 só se o circuito estiver satisfeito,
/// emitindo diagnóstico legível quando não estiver.
pub fn provar_com_diagnostico<C>(
    circuito: C,                       // seu circuito (ex.: RandomizationCircuit)
    chave_de_prova: &ProvingKey<Bn254> // proving key (PK)
) -> Result<Proof<Bn254>>
where
    C: ConstraintSynthesizer<Fr> + Clone,
{
    // 1) Monta o sistema de restrições (R1CS) para checagem local
    let sistema_de_restricoes = ConstraintSystem::<Fr>::new_ref();
    circuito.clone().generate_constraints(sistema_de_restricoes.clone())?;

    // 2) Diagnóstico de satisfatibilidade
    let circuito_satisfeito = sistema_de_restricoes
        .is_satisfied()
        .map_err(|e| anyhow!("erro ao verificar R1CS: {e}"))?;

    if !circuito_satisfeito {
        let primeira_restricao_nao_satisfeita =
            sistema_de_restricoes.which_is_unsatisfied().unwrap_or_default();
        let total_variaveis             = sistema_de_restricoes.num_instance_variables();
        let total_restricoes           = sistema_de_restricoes.num_constraints();
        let total_variaveis_publicas   = sistema_de_restricoes.num_instance_variables();
        let total_variaveis_testemunha = sistema_de_restricoes.num_witness_variables();

        bail!(
            "Circuito NÃO satisfeito: primeira_falha={:?}; \
             variaveis={total_variaveis}, restricoes={total_restricoes}, \
             publicas={total_variaveis_publicas}, testemunha={total_variaveis_testemunha}",
            primeira_restricao_nao_satisfeita
        );
    }

    // 3) Prova apenas se estiver tudo OK
    let mut gerador_aleatorio = rand_core::OsRng;
    let prova = Groth16::<Bn254>::prove(chave_de_prova, circuito, &mut gerador_aleatorio)?;
    Ok(prova)
}

// Fq -> 32B big-endian
fn fq_to_be32(x: &Fq) -> [u8; 32] {
    let bi = x.into_bigint(); // 4 * u64 (LE por limbs)
    let mut le = [0u8; 32];
    let mut off = 0usize;
    for limb in bi.0 {
        le[off..off + 8].copy_from_slice(&limb.to_le_bytes());
        off += 8;
    }
    let mut out = [0u8; 32];
    for i in 0..32 { out[i] = le[31 - i]; } // LE -> BE
    out
}

/// Prova NÃO-comprimida (A64|B128|C64) **em ARK**: G2 como (c0‖c1).
/// Este é o formato aceito diretamente pelo on-chain (sem decompress).
/// Prova NÃO-comprimida (A64|B128|C64) → 256 bytes BE.
/// Usa orientação G2 = (c0, c1) tanto em X quanto em Y.
pub fn proof_to_uncompressed_be_256(proof: &Proof<Bn254>) -> [u8; 256] {
    fn fq_to_be32(x: &ark_bn254::Fq) -> [u8; 32] {
        let bi = x.into_bigint();
        let mut le = [0u8; 32];
        let mut off = 0usize;
        for limb in bi.0 { le[off..off+8].copy_from_slice(&limb.to_le_bytes()); off += 8; }
        let mut be = [0u8; 32];
        for i in 0..32 { be[i] = le[31 - i]; }
        be
    }

    // ⚠️ Groth16Verifier espera A NEGADO
    let a_neg = proof.a.neg();

    // G1 (A=-A, C como está)
    let ax = fq_to_be32(&a_neg.x);
    let ay = fq_to_be32(&a_neg.y);

    let cx = fq_to_be32(&proof.c.x);
    let cy = fq_to_be32(&proof.c.y);

    // G2 (ETH: c1||c0)
    let bx_c1 = fq_to_be32(&proof.b.x.c1);
    let bx_c0 = fq_to_be32(&proof.b.x.c0);
    let by_c1 = fq_to_be32(&proof.b.y.c1);
    let by_c0 = fq_to_be32(&proof.b.y.c0);

    let mut out = [0u8; 256];
    out[  0.. 32].copy_from_slice(&ax);
    out[ 32.. 64].copy_from_slice(&ay);
    out[ 64.. 96].copy_from_slice(&bx_c1); // ETH
    out[ 96..128].copy_from_slice(&bx_c0); // ETH
    out[128..160].copy_from_slice(&by_c1); // ETH
    out[160..192].copy_from_slice(&by_c0); // ETH
    out[192..224].copy_from_slice(&cx);
    out[224..256].copy_from_slice(&cy);
    out
}