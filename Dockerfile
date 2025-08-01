# Etapa 1: builder
FROM rust:1.88 AS builder

WORKDIR /usr/src/app

# Copia todo o contexto de build (inclui .env, Cargo.toml, src/, keys/, etc)
COPY . .

# Compila em modo release, cacheando dependências
RUN cargo build --release

# Etapa 2: runtime minimalista
FROM debian:bookworm-slim

# Instalações mínimas (certificados TLS e AWS CLI para pegar secrets)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      awscli \
 && rm -rf /var/lib/apt/lists/*

# (Opcional) Cria diretório para chaves/configurações
RUN mkdir -p /usr/local/share/zero-double-blind-core/keys

# Copia o binário compilado do builder
COPY --from=builder /usr/src/app/target/release/zero-double-blind-core /usr/local/bin/app

# Define diretório de trabalho
WORKDIR /usr/local/share/zero-double-blind-core

# Expõe a porta que o Warp usa
EXPOSE 3030

# Comando padrão
ENTRYPOINT ["/usr/local/bin/app"]
