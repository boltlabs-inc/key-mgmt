# Digital asset management system (DAMS)

## Overview

The DAMS helps people store, retrieve and use the private keys associated with their digital assets. We're building a security-first system with layers of cryptography, hardware protection, and a misuse-resistant design to prevent theft and misuse of keys. 

The DAMS aims to provide a flexible system of components for managing digital assets and composed of the following:

* A **local** and **remote client library**: This client allows a user to generate and store a secret key in a distributed way, across multiple servers, and provides generic functionality for requesting a signature under the stored key, and reconstructs a full signature from a set of partial signatures. This client also includes the cryptographic functionality for:
    * user authentication,
    * networking with servers.
    * integration either as a self-contained library or a binary.

* A **key server** which includes a flexible program that can be deployed at multiple providers. The server has the following properties:

    * The server may be run by either an external cloud provider, e.g, Microsoft Azure, AWS, or directly by Forte. This allows for a flexible distribution of trust; in particular, the compromise of a single server (or some group of servers below a designated threshold) does not allow for theft or misuse of the given private key.

    * Integrates with an **external policy engine client** for approval/rejection of requested signing operations via a well-defined API.

    * Leverages enclaves for increased security against key theft and misuse; in this model, a server is unable to participate in signing without authorization by the user. That is, the key share is held by the enclave and is not accessible outside of the enclave environment; the enclave authenticates the client before any partial signatures are produced. Similarly, the enclave may enforce transaction approval by a designated party as well, thereby enforcing the policy restrictions on signing.

    * This server either returns a partial signature, if the signature request meets the designated policy, or returns an appropriate rejection message. 


## Install & Setup

To build the DAMS project, you will need: 

  - A recent version of nightly Rust. This project has been tested with 1.57.0-nightly. You can set this with:
  ```
  $ rustup override set nightly-2021-11-29
  ```

Then, build the project as follows:

```bash
cargo build --all-features --all-targets
```

## Running local tests

To run the doctests locally:

```bash
cargo test --all-features --doc --verbose
```

To run all unit and integration tests:

```bash
cargo test --all-features --all-targets
```

The current set of tests comprise the following components:
* local client
* remote client
* policy server
* key server [TODO]
* cryptographic library [TODO]

## Build documentation

To build the API documentation for the project:

```bash
RUSTDOCFLAGS="-Dwarnings" cargo doc --all-features --no-deps
```

The generated html docs are in the local `target/doc` directory. In addition, you can find the API docs in the source of the [local client](https://github.com/boltlabs-inc/key-mgmt/blob/main/src/local_client.rs), [remote client](https://github.com/boltlabs-inc/key-mgmt/blob/main/src/remote_client.rs) and [policy engine](https://github.com/boltlabs-inc/key-mgmt/blob/main/src/policy_engine.rs).