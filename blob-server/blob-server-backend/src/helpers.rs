use argon2::{password_hash::{SaltString, rand_core::OsRng}, Argon2, PasswordHash, PasswordVerifier, PasswordHasher};

use crate::BlobServerError;


pub fn hash_api_secret(api_secret: &str) -> Result<String, BlobServerError> {
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default parameters
    let argon2 = Argon2::default();

    let secret_hash = argon2
        .hash_password(api_secret.as_bytes(), &salt)
        .map_err(|_| BlobServerError::Argon2HashError)?
        .to_string();

    Ok(secret_hash)
}

pub fn verify_hashed_secret(
    passed_secret: &str,
    stored_hashed_secret: &str,
) -> Result<(), BlobServerError> {
    let parsed_hash = PasswordHash::new(&stored_hashed_secret).map_err(|_| BlobServerError::Argon2HashError)?;
    Argon2::default()
        .verify_password(passed_secret.as_bytes(), &parsed_hash)
        .map_err(|_| BlobServerError::Argon2HashVerificationFailed)?;
    Ok(())
}
