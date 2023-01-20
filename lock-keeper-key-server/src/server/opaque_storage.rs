use lock_keeper::config::opaque::OpaqueCipherSuite;
use opaque_ke::{keypair::PrivateKey, Ristretto255, ServerSetup};
use rand::rngs::StdRng;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use crate::LockKeeperServerError;

/// Retrieves the [`ServerSetup`] used for OPAQUE authentication, creating it if
/// it doesn't already exist.
///
/// TODO: replace with decent and secure storage for server keys #56
pub fn create_or_retrieve_server_key_opaque(
    rng: &mut StdRng,
    opaque_server_key_path: impl AsRef<Path>,
) -> Result<ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>, LockKeeperServerError> {
    let server_key_file = File::open(opaque_server_key_path.as_ref());
    match server_key_file {
        // Server key file doesn't exist yet, create new
        Err(_) => {
            let server_setup = ServerSetup::<OpaqueCipherSuite>::new(rng);
            let dir = opaque_server_key_path
                .as_ref()
                .parent()
                .ok_or(LockKeeperServerError::InvalidOpaqueDirectory)?;

            std::fs::create_dir_all(dir)
                .map_err(|e| LockKeeperServerError::FileIo(e, dir.to_path_buf()))?;

            let mut file = File::create(&opaque_server_key_path).map_err(|e| {
                LockKeeperServerError::FileIo(e, opaque_server_key_path.as_ref().to_path_buf())
            })?;

            file.write_all(bincode::serialize(&server_setup)?.as_slice())?;
            Ok(server_setup)
        }

        // Server key file does exist!
        Ok(mut file) => {
            let mut contents = vec![];
            let _ = file.read_to_end(&mut contents)?;
            let server_setup: ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>> =
                bincode::deserialize(contents.as_slice())?;
            Ok(server_setup)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use std::{env::temp_dir, path::Path};

    #[tokio::test]
    async fn opaque_server_key_is_retrievable() {
        let mut rng = StdRng::from_entropy();
        let key_path = temp_dir().join("opaque/server_setup");

        // Delete file from previous run if it exists
        let _ = std::fs::remove_file(&key_path);

        // First, the storage key doesn't exist
        assert!(!Path::new(&key_path).is_file());

        let server_setup = create_or_retrieve_server_key_opaque(&mut rng, &key_path).unwrap();

        // Then, it does exist
        assert!(Path::new(&key_path).exists());

        let retrieved_server_setup =
            create_or_retrieve_server_key_opaque(&mut rng, &key_path).unwrap();

        // Re-retrieving gets the same thing back
        assert_eq!(server_setup, retrieved_server_setup);

        // Clean up
        assert!(std::fs::remove_file(&key_path).is_ok());
    }
}
