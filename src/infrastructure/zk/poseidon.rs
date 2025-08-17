use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_sponge::{poseidon::{find_poseidon_ark_and_mds, PoseidonConfig}, CryptographicSponge, poseidon::PoseidonSponge};
use sha2::{Digest, Sha256};

const RATE: usize = 2;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 31;
const ALPHA: u64 = 5;

pub fn poseidon_cfg() -> PoseidonConfig<Bn254Fr> {
    let prime_bits = <Bn254Fr as PrimeField>::MODULUS.num_bits() as u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<Bn254Fr>(prime_bits, RATE, FULL_ROUNDS as u64, PARTIAL_ROUNDS as u64, 0);
    PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
}

pub fn compute_ids_commitment(ids: &[String]) -> Bn254Fr {
    // ID -> SHA256 -> Fr
    let hashes: Vec<Bn254Fr> = ids.iter().map(|id| {
        let mut h = Sha256::new();
        h.update(id.as_bytes());
        Bn254Fr::from_le_bytes_mod_order(&h.finalize())
    }).collect();

    let cfg = poseidon_cfg();
    let mut sponge = PoseidonSponge::new(&cfg);
    sponge.absorb(&hashes);
    sponge.squeeze_field_elements(1)[0]
}
