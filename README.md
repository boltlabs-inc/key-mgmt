# Digital asset management system (DAMS)

## Overview

The DAMS helps people store, retrieve and use the private keys associated with their digital assets. We're building a security-first system with layers of cryptography, hardware protection, and a misuse-resistant design to prevent theft and misuse of keys. 

The DAMS aims to provide a flexible system of components for managing digital assets and composed of the following:

* A **local** and **remote client library**: The *local client* allows a user to generate and store a secret key in a distributed way, across multiple servers, and provides generic functionality for requesting a signature under the stored key, and reconstructs a full signature from a set of partial signatures. The *remote client* provides functionality to support key delegation for automated key use flows whereby users do not actively participate in transaction signing. <br/>
Both clients also include the cryptographic functionality for:
  * authentication,
  * networking with servers,
  * integration as a self-contained library.

* A **key server** is responsible for the generation, the secure storage for secret keys and distributed operations on those keys with cryptographic-based guarantees. The server has the following properties:

    * The server may be run by either an external cloud provider, e.g, Microsoft Azure, AWS, or directly by the service provider. This allows for a flexible distribution of trust; in particular, the compromise of a single server (or some group of servers below a designated threshold) does not allow for theft or misuse of the given secret key.

    * Integrates with an extensible **external policy engine client API** for approval & rejection of requested signing operations by asset fiduciaries with a stake in the use and sale of the underlying digital asset.

    * Leverages enclaves for increased security against key theft and misuse; in this model, a server is unable to participate in signing without authorization by the user. That is, the key share is held by the enclave and is not accessible outside of the enclave environment; the enclave authenticates the client before any partial signatures are produced. Similarly, the enclave may enforce transaction approval by a designated party as well, thereby enforcing the policy restrictions on signing.

    * This server either returns a partial signature, if the signature request meets the designated policy, or returns an appropriate rejection message. 


## Install & Setup

You will need a recent version of [stable Rust](https://www.rust-lang.org/) to build the DAMS project. We have tested with 1.59.0.

Once Rust is installed, build the project as follows:

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

We practice test-driven development and the test suite should be a close mapping to the functionality we currently implement at any given stage of development.

## Build documentation

To build the API documentation for the project:

```bash
RUSTDOCFLAGS="-Dwarnings" cargo doc --all-features --no-deps --open
```

You can find the API docs in the source of the [local client](https://github.com/boltlabs-inc/key-mgmt/blob/main/src/local_client.rs), [remote client](https://github.com/boltlabs-inc/key-mgmt/blob/main/src/remote_client.rs) and [policy engine](https://github.com/boltlabs-inc/key-mgmt/blob/main/src/policy_engine.rs).