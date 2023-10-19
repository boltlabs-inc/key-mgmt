FROM rust:1.65
ENV CONFIG="dev/config/docker/Binary.toml"

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/lock-keeper-key-server
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/lock-keeper-key-server/target \
    cargo install --locked --path ./bin/key-server-cli

VOLUME /app

CMD ["sh", "-c", "key-server-cli ${CONFIG}"]