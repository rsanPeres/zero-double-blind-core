# Etapa 1: builder
FROM rust:1.88 as builder

WORKDIR /usr/src/app

# Copia e compila dependências primeiro (melhora cache)
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copia o restante do código
COPY . .

# Compila binário final
RUN cargo build --release

# Etapa 2: runtime minimalista
FROM debian:bullseye-slim

# Instalações mínimas (certificados TLS)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copia binário
COPY --from=builder /usr/src/app/target/release/zero-double-blind-core /usr/local/bin/app

# Porta que o warp usa
EXPOSE 3030

CMD ["app"]
