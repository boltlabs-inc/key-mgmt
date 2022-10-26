# Lock Keeper

## Overview

Lock Keeper helps people store, retrieve and use the private keys associated with their digital assets. We're building a security-first system with layers of cryptography, hardware protection, and a misuse-resistant design to prevent theft and misuse of keys. 

Lock Keeper aims to provide a flexible system of components for managing digital assets and composed of the following:

* A **client library**: The *client* allows a user to generate and store a secret key in a distributed way, across multiple servers, and provides generic functionality for requesting a signature under the stored key, and reconstructs a full signature from a set of partial signatures. <br/>
The client also includes the cryptographic functionality for:
  * authentication,
  * networking with servers,
  * integration as a self-contained library.

* A **key server** is responsible for the generation, the secure storage for secret keys and distributed operations on those keys with cryptographic-based guarantees. The server has the following properties:

    * The server may be run by either an external cloud provider, e.g, Microsoft Azure, AWS, or directly by the service provider. This allows for a flexible distribution of trust; in particular, the compromise of a single server (or some group of servers below a designated threshold) does not allow for theft or misuse of the given secret key.

    * Integrates with an extensible **external policy engine client API** for approval & rejection of requested signing operations by asset fiduciaries with a stake in the use and sale of the underlying digital asset.

    * Leverages enclaves for increased security against key theft and misuse; in this model, a server is unable to participate in signing without authorization by the user. That is, the key share is held by the enclave and is not accessible outside of the enclave environment; the enclave authenticates the client before any partial signatures are produced. Similarly, the enclave may enforce transaction approval by a designated party as well, thereby enforcing the policy restrictions on signing.

    * This server either returns a partial signature, if the signature request meets the designated policy, or returns an appropriate rejection message. 

Refer to the [current design specification](https://github.com/boltlabs-inc/key-mgmt-spec) for Lock Keeper.

## Install & Setup

### Dependencies:

- A recent version of [stable Rust](https://www.rust-lang.org/) to build the Lock Keeper project. Version 1.64 is the minimum required version.
- OpenSSL. You should be able to install this using your package manager of choice.
- `protoc` is required to build .proto files. It can be installed using `brew` for MacOS or `apt install` for Linux. Further instructions [here](https://grpc.io/docs/protoc-installation/).
- [cargo-make](https://github.com/sagiegurari/cargo-make) can be installed with `cargo install cargo-make`.
- [Docker](https://www.docker.com/). 
- On Linux, you may need to install [Docker Compose](https://docs.docker.com/compose/install/) separately.

In order to use the `cargo make` tasks on Linux, you need to be able to run Docker without `sudo`. You can find instructions for this [here](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user).

If you need to run the server outside of Docker, [MongoDB](https://www.mongodb.com/try/download/community) is also required.


Once the required dependencies are installed, build the project as follows:

```bash
cargo build --all-features --all-targets
```

## Running unit and doc tests

We follow test-driven development practices and the test suite should be a close mapping to the functionality we currently implement at any given stage of development.


To run unit tests:
```bash
cargo test --all-features
```

To run the doctests:

```bash
cargo test --all-features --doc
```

## Integration tests

Integration tests are separated into two categories, end-to-end tests and general integration tests. Both categories require the key server to be running.

Start the server running in the background. This will compile the project from scratch the first time you run it so it will take a while. It should be faster for future runs.
```bash
cargo make start
```

To run the end-to-end tests:
```bash
cargo make e2e
```

To run the integration tests:
```bash
cargo make integration
```

To run all tests including unit tests with a single command:
```bash
cargo make all-tests
```

The server will be running in the background so you can continue to run integration tests without starting the server again. To stop the server, run:
```bash
cargo make stop
```

If you want to watch server output in real-time, you can run the server in the foreground with:
```bash
cargo make start-server
```

Running the test binary directly offers some extra command line options.

To only run tests whose name contains certain words, use the `--filter` option
```bash
cargo run --bin lock-keeper-tests -- --filter generate --filter retrieve
```

## Running the server locally

To run the server locally, first make sure MongoDB is running. You can run MongoDB [in Docker](https://www.mongodb.com/compatibility/docker) or [locally with a config file](https://www.mongodb.com/docs/manual/reference/configuration-options/).

Then run:
```bash
cargo make start-server-local
```

Tests can be run against a local server with:
```bash
cargo make e2e
```

## Running the interactive client

Lock Keeper comes with an interactive client CLI that can be used to interact with a key server for basic testing and troubleshooting.
See the `lock-keeper-client-cli` crate for more information.

First start the key server:
```bash
cargo make start
```

Then run the client CLI:
```bash
cargo make cli
```

## Troubleshooting

If you get a `no space left on device` error from Docker, try running:
```bash
docker image prune -a
docker volume prune
```

If this doesn't help, you can do a full system prune. This will delete your cache and your next build will take a long time.
```bash
docker system prune -a --volumes
```

## Build documentation

To build the API documentation for the project:

```bash
RUSTDOCFLAGS="-Dwarnings" cargo doc --all-features --no-deps --open
```

You can find the API docs in the source of the [client](lock-keeper-client/src/api.rs) and [policy engine](lock-keeper-key-server/src/policy_engine.rs).

## Published Documentation

Documentation from the `main` and `develop` branches is automatically deployed to GitHub Pages any time code is merged. There is a very basic index page for published documentation [here](https://boltlabs-inc.github.io/key-mgmt/).

### `develop` docs

[lock-keeper](https://boltlabs-inc.github.io/key-mgmt/develop/lock_keeper)  
[lock-keeper-client](https://boltlabs-inc.github.io/key-mgmt/develop/lock_keeper_client)  
[lock-keeper-key-server](https://boltlabs-inc.github.io/key-mgmt/develop/lock_keeper_key_server)  

### `main` docs
[dams](https://boltlabs-inc.github.io/key-mgmt/main/dams)  
[dams-client](https://boltlabs-inc.github.io/key-mgmt/main/dams_client)  
[dams-key-server](https://boltlabs-inc.github.io/key-mgmt/main/dams_key_server) 
