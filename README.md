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

## Breaking Changes
- LockKeeperKeyServer v0.3 introduces a breaking change with respect to a database that was generated using LockKeeperKeyServer v0.2. Remotely generated signing keys are now encrypted using a remote storage key.
- LockKeeperClient v0.3 introduces a breaking change with respect to v0.2. Storage keys are encrypted inside the database using a different key, therefore, old storage keys in the database cannot be used anymore.
- LockKeeperClient v0.3 is backwards **incompatible** with LockKeeperServer v0.2, given that authenticated traffic will now use an extra layer of encryption using the session key.

## Install & Setup

### Dependencies:

- A recent version of [stable Rust](https://www.rust-lang.org/) to build the Lock Keeper project. Version 1.65 is the minimum required version.
- OpenSSL. You should be able to install this using your package manager of choice.
- `protoc` is required to build .proto files. It can be installed using `brew` for MacOS or `apt install` for Linux. Further instructions [here](https://grpc.io/docs/protoc-installation/).
- [cargo-make](https://github.com/sagiegurari/cargo-make) can be installed with `cargo install cargo-make`.
- [Docker](https://www.docker.com/). 
- On Linux, you may need to install [Docker Compose](https://docs.docker.com/compose/install/) separately.

In order to use the `cargo make` tasks on Linux, you need to be able to run Docker without `sudo`. You can find instructions for this [here](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user).

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
cargo make run
```

Running the test binary directly offers some extra command line options.

To only run tests whose name contains certain words, use the `--filter` option
```bash
cargo run --bin lock-keeper-tests -- --filter generate --filter retrieve
```

## Running the server locally

Then run:
```bash
cargo run --bin key-server-cli ./dev/config/local/Binary.toml
```

## TLS client authentication

Client authentication can be enabled in server and client configs. See the config files in `dev/config/docker-client-auth` or `dev/config/local-client-auth`
for examples.

# Private key security
The key server always requires a private key. 
The private key can optionally be provided via a file path in the server config.
Alternatively, the raw bytes for a private key can be passed to the `lock_keeper_key_server::Config` constructors.
This alternative allows the server to secure its private key however it chooses.

The `key-server-cli` binary included with the `lock-keeper-key-server` crate provides a command-line argument to accept a private
key as a base64 string.

Example:

```bash
cargo run --bin key-server-cli dev/config/local-client-auth/Binary.toml --private-key "$(cat dev/test-pki/gen/certs/server.key | base64)"
```

`LockKeeperClient` requires a private key if client authentication is enabled. 
The private key can optionally be provided via a file path in the client config.
Alternatively, the raw bytes for a private key can be passed to the `lock_keeper_client::Config` constructors.
This alternative allows the client to secure its private key however it chooses.

# Remote storage key security
The key server always requires a remote storage key.
The remote storage key can be provided in a similar fashion as the private key (see above).

The command line argument for the `key-server-cli` binary included with the `lock-keeper-key-server` is `remote-storage-key`.

Example:

```bash
cargo run --bin key-server-cli dev/config/local-client-auth/Binary.toml --remote_storage_key "$(cat dev/remote-storage-key/gen/remote_storage.key | base64)"
```

Important to note is that this key encrypts all signing keys on the server, therefore, loss of this key would mean loss of all signing keys.
Therefore, we recommend to store this key in a secure fashion, e.g. by using an HSM. Access to this key should be well guarded to obtain very high security.
Ultimately, the key server will provide a different way to keep signing keys secure using an enclave.

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

There are a few `cargo make` tasks that run specific CLI scripts for quick testing. Check the CLI section of  `Makefile.toml` for available tasks.

## Troubleshooting
### Logging
The server writes logs to a few locations:
- **Standard Output**: `INFO` level logs get written out to standard output for any events originating from any lock-keeper crates.
- **Sever-only logs**: `INFO` level logs written to a file based on user config (see below) for any events originating from any lock-keeper crates.
- **All logs**: `TRACE` or higher level logs written to a file based on user config (see below) for any event from any crate including dependencies.

The following may be configured via the server configuration file:
- The log directory may be specified via the `log_directory` field in the server config file.
- The sever-only log file may be specified via the `lock_keeper_logs_file_name` field.
- The all log file may be specified via the `all_logs_file_name` field.

### No Space Left

If you get a `no space left on device` error from Docker, try running:
```bash
docker image prune -a
docker volume prune
```

If this doesn't help, you can do a full system prune. This will delete your cache and your next build will take a long time.
```bash
docker system prune -a --volumes
```

## About the use of Zeroize

In our client and server we make use of the [zeroize](https://docs.rs/zeroize/latest/zeroize/) library to make sure secrets get properly removed from memory after dropping. This library will make sure that the memory is set to zero after the secret is of no use anymore. 
Most of the secrets are annotated with the trait [ZeroizeOnDrop](https://docs.rs/zeroize/latest/zeroize/trait.ZeroizeOnDrop.html) which assures the allocated memory gets set to zero as soon as the object gets dropped.

The zeroize crate guarantees the following:
1. The zeroing operation can’t be “optimized away” by the compiler.
2. All subsequent reads to memory will see “zeroized” values.

For more information about this carte and its usage, we refer the reader to the [zeroize documentation.](https://docs.rs/zeroize/latest/zeroize/)

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
