window.SIDEBAR_ITEMS = {"constant":[["_DERIVE_Drop_FOR_Export",""],["_DERIVE_Drop_FOR_MasterKey",""],["_DERIVE_Drop_FOR_OpaqueSessionKey",""],["_DERIVE_Drop_FOR_StorageKey",""]],"enum":[["CryptoError","Errors that arise in the cryptography module."]],"mod":[["arbitrary_secret",""],["generic",""],["signing_key",""]],"struct":[["Encrypted","A ciphertext representing an object of type `T`, encrypted under the ChaCha20Poly1305 scheme for authenticated encryption with associated data (AEAD)."],["Export","Raw material for an exported signing key."],["Import","Raw material for an imported signing key."],["KeyId","Universally unique identifier for a stored secret or signing key."],["MasterKey","The master key is a default-length symmetric encryption key for an AEAD scheme."],["OpaqueSessionKey","A session key is produced as shared output for client and server from OPAQUE."],["PlaceholderEncryptedSigningKeyPair","Temporary type to represent a remotely generated encrypted [`SigningKeyPair`]."],["Secret","An arbitrary secret."],["SignableBytes","Wrapper used to declare arbitrary bytes as [`Signable`]."],["Signature","A signature on an object encrypted under the ECDSA signature scheme."],["SigningKeyPair","An ECDSA signing key pair, including a public component for verifying signatures, a private component for creating them, and context about the key pair."],["SigningPublicKey","The public component of an ECDSA signing key, and context about the key."],["StorageKey","A storage key is a default-length symmetric encryption key for an AEAD scheme. The storage key is used to encrypt stored secrets and signing keys."]],"trait":[["Signable","Provides the methods necessary to sign and verify a piece of data with a [`SigningKeyPair`]. This trait should be explicitly implemented on types that are intended to be signed."]]};