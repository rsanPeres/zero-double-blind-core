# zero_double_blind_core

Núcleo (Rust) para **randomização com privacidade** usando **zk-SNARK Groth16 (BN254)** e verificação **on-chain em Solana**.

Inclui:
- API com autenticação utilizando JWT que faz gerenciamento de estudo clínicos. 
- **Postman Collection**: [zero_double_blind_core.postman_collection.json](postman/double_blind.postman_collection.json)
- Serviço **off-chain** para **gerar e verificar provas** (Arkworks).
- **Cliente Solana** para subir a **Verifying Key (VK)** em **chunks** e **submeter rounds** sem estourar o limite de tamanho de transação.
- **Programa on-chain** que **valida Groth16** via syscalls (`groth16_solana`) e **persiste estado**.

> Objetivo: permitir sorteio/aleatorização (ex.: pacientes) com prova criptográfica verificável em cadeia, preservando privacidade.

---

## Arquitetura da API (DDD)

A API segue **Domain-Driven Design (DDD)** com separação clara entre camadas, _bounded contexts_ e contratos estáveis. O objetivo é manter o domínio de **randomização com provas zk-SNARK** isolado de detalhes de infraestrutura (Solana, Arkworks, HTTP, DB).

### Visão Geral

## Visão geral da arquitetura

### Account da VK (`vk_account`)
Armazena a VK em **payload selado**, com cabeçalho fixo:

[0..4] "VKH1" (magic)
[4] 1 (version)
[5] sealed (0/1)
[6..10] total_len (u32 LE)
[10..14] bytes_written (u32 LE)
[14..46] sha256(payload) (32B)
[46.. ] payload (VK no layout G16V)

É derivada por `create_with_seed(base = payer, seed, owner = program_id)`.

### Instruções on-chain

- `InitVk { seed, total_len, vk_hash }`
- `WriteVkChunk { seed, offset, chunk }` *(escrita sequencial)*
- `SealVk { seed }` *(confere tamanho + hash e sela)*
- `SubmitRound { round_seed, proof_bytes, public_inputs, bits }`  
  Lê `vk_account` **readonly**, faz a verificação **Groth16** e grava estado (ex.: `RoundState`).

### Limites de tamanho (Solana)

- Tamanho **bruto** da transação ≤ **1232 bytes**.
- Por isso, **NÃO** enviamos a VK em `ix_data`; usamos **account + chunks (~900 B)** e **selamos**.

---

## Formatos criptográficos suportados

### VK – layout **G16V (comprimido)**

"G16V" | version=1 | flags=1 (comprimido) | nr_pubinputs (u16 LE)
α_g1(32B) | β_g2(64B) | γ_g2(64B) | δ_g2(64B) | IC[0..N] (N+1 pontos G1, 32B cada)

**Tamanho:** `232 + 32*(N+1)`.

### Prova Groth16 – **128 bytes** (recomendado)

A(32) | B(64) | C(32) // big-endian por coordenada

> Se vier em **256B**, **converta para 128B** antes de enviar.

### Public Inputs – `N * 32` bytes
Vetor concatenado de elementos do campo (BN254) em **32B big-endian**.

---

## Pré-requisitos

- **Rust** `1.75+` (stable).
- **Solana** `2.2.x` (SDK/CLI) — mantenha **todos** os crates `solana-*` no **mesmo patch** (ex.: `=2.2.3`).
- **Windows (MSVC)** — dependência de OpenSSL (devido a `solana-secp256r1-program`):
    - **Opção A: vcpkg**
      ```bat
      git clone https://github.com/microsoft/vcpkg %USERPROFILE%\vcpkg
      %USERPROFILE%\vcpkg\bootstrap-vcpkg.bat
      %USERPROFILE%\vcpkg\vcpkg.exe install openssl:x64-windows
      setx VCPKG_ROOT %USERPROFILE%\vcpkg
      ```
    - **Opção B: vendored** (compila OpenSSL) → instale **Strawberry Perl** + **NASM**.
- **Linux/WSL**: `libssl-dev`, `pkg-config`.

---

## Variáveis de ambiente úteis

Crie um `.env` (opcional):

```env
RPC_URL=https://api.devnet.solana.com
PROGRAM_ID=<Pubkey do seu programa>
SOLANA_KEYPAIR=~/.config/solana/id.json       # caminho, ou JSON [64 bytes], ou base58
HASH_SECRET=algum-segredo-estavel             # p/ seed determinística off-chain
N_PATIENT=32
```


Windows + WSL: se sua keypair está na WSL, você pode usar
WSL_KEYPAIR=/home/ubuntu/.config/solana/id.json.

## Como gerar vk_bytes no layout G16V

### Off-chain (Arkworks → bytes):

### On-chain (Chunks):
```
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;

fn g1_32(p: &ark_bn254::G1Affine) -> [u8; 32] {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v).unwrap();
    v.try_into().unwrap()
}
fn g2_64(p: &ark_bn254::G2Affine) -> [u8; 64] {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v).unwrap();
    v.try_into().unwrap()
}

pub fn vk_to_g16v_bytes(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let n = vk.gamma_abc_g1.len() - 1;
    let mut out = Vec::with_capacity(8 + 32 + 3*64 + (n+1)*32);
    out.extend_from_slice(b"G16V"); // magic
    out.push(1);                    // version
    out.push(1);                    // flags=1 (comprimido)
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&g1_32(&vk.alpha_g1));
    out.extend_from_slice(&g2_64(&vk.beta_g2));
    out.extend_from_slice(&g2_64(&vk.gamma_g2));
    out.extend_from_slice(&g2_64(&vk.delta_g2));
    for ic in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_32(ic));
    }
    out
}
```

### Fluxo de uso (cliente)
1) Upload da VK em chunks (uma vez por VK)
```
let vk_bytes = vk_to_g16v_bytes(&vk);
let vk_pk = upload_vk_in_chunks(
    &std::env::var("RPC_URL")?,     // ex.: https://api.devnet.solana.com
    &std::env::var("PROGRAM_ID")?,  // Pubkey do programa
    "vk-seed-minha-vk",             // ≤ 32 chars
    &vk_bytes,
    900,                            // chunk_size (folga)
)?;
```
2) Submit do round com prova / inputs / bits
```
let sig = submit_round(
    &std::env::var("RPC_URL")?,
    &std::env::var("PROGRAM_ID")?,
    "round-seed-rodada1", // ≤ 32 chars
    vk_pk,                // da etapa anterior
    proof_128_bytes,      // A32|B64|C32
    public_inputs_bytes,  // N*32
    bits_vec,             // payload de negócio
)?;
println!("tx: {sig}");
```

> Se os public_inputs também ficarem grandes, suba-os em outra account readonly com fluxo idêntico (Init/Write/Seal) e referencie no SubmitRound.