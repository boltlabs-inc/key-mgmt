FROM rust:1.65

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/lock-keeper-key-server
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/lock-keeper-key-server/target \
    cargo install --path ./lock-keeper-key-server

CMD ["key-server-cli", "./dev/docker/Server.toml"]
