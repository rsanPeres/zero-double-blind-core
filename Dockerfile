# Etapa 1: builder
FROM rust:1.88 as builder

WORKDIR /usr/src/app

# Copia o .env
COPY .env /usr/src/app/.env

# Copia todo o projeto de uma vez (inclui Cargo.toml, Cargo.lock, src/, keys/, etc)
COPY . .

ENV MONGO_URI=$MONGO_URI
ENV JWT_SECRET=$JWT_SECRET
ENV HASH_SECRET=$HASH_SECRET

# Compila em modo release
RUN cargo build --release

# Etapa 2: runtime minimalista
FROM debian:bookworm-slim

# Instalações mínimas (certificados TLS)
RUN apt-get update \
 && apt-get install -y ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Cria diretório para chaves e configurações, caso você queira montar volumes
RUN mkdir -p /usr/local/share/zero-double-blind-core/keys

# Copia o binário compilado
COPY --from=builder /usr/src/app/target/release/zero-double-blind-core /usr/local/bin/app

# Exponha a porta que o Warp vai usar
EXPOSE 3030

# Comando padrão
CMD ["app"]
