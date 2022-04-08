mod create;
mod retrieve;

/// The object that the client sends to the server when creating a secret
#[derive(Debug)]
pub struct CreateSecretRequest;
/// The object containing info about a secret
#[derive(Debug)]
pub struct SecretInfo;
/// The object that the client sends to the server when retrieving a secret
#[derive(Debug)]
pub struct SecretRetrieveRequest;
