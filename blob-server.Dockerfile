FROM rust:1.73
ENV CONFIG="blob-server/dev/config/Binary.toml"

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/blob-server
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/blob-server/target \
    cargo install --locked --path ./blob-server/blob-server-cli

VOLUME /app

CMD ["sh", "-c", "blob-server-cli ${CONFIG}"]
