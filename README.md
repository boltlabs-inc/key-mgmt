# Digital asset management system (DAMS)

## Overview

The DAMS helps people store, retrieve and use the private keys associated with their digital assets. We're building a security-first system with layers of cryptography, hardware protection, and a misuse-resistant design to prevent theft and misuse of keys. 

The DAMS aims to provide a flexible system of components for managing digital assets and composed of the following:

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

Refer to the [current design specification](https://github.com/boltlabs-inc/key-mgmt-spec) for the DAMS.

## Install & Setup

### Dependencies:

- A recent version of [stable Rust](https://www.rust-lang.org/) to build the DAMS project. We have tested with 1.59.0.
- OpenSSL. You should be able to install this using your package manager of choice.
- [MongoDB](https://www.mongodb.com/try/download/community) is required to run `dams-key-server`. This includes running the integration tests.
- `protoc` is required to build .proto files. It can be installed using `brew` for MacOS or `apt install` for Linux. Further instructions [here](https://grpc.io/docs/protoc-installation/).

Once the required dependencies are installed, build the project as follows:

```bash
cargo build --all-features --all-targets
```

## Running local tests

To run the doctests locally:

```bash
cargo test --all-features --doc --verbose
```

To run all unit and integration tests (make sure MongoDB is running first):

```bash
cargo test --all-features --all-targets
```

We follow test-driven development practices and the test suite should be a close mapping to the functionality we currently implement at any given stage of development.

## Build documentation

To build the API documentation for the project:

```bash
RUSTDOCFLAGS="-Dwarnings" cargo doc --all-features --no-deps --open
```

You can find the API docs in the source of the [client](dams-client/src/api.rs) and [policy engine](dams-key-server/src/policy_engine.rs).
