use lock_keeper::config::opaque::OpaqueCipherSuite;
use opaque_ke::{keypair::PrivateKey, Ristretto255, ServerSetup};
use rand::rngs::StdRng;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use tracing::log::warn;

use crate::LockKeeperServerError;

/// Retrieves the [`ServerSetup`] used for OPAQUE authentication,
/// On a test environment it can be stored in a file or created upon startup.
pub fn create_or_retrieve_server_setup_opaque(
    rng: &mut StdRng,
    opaque_server_setup_path: Option<impl AsRef<Path>>,
    opaque_server_setup_bytes: Option<Vec<u8>>,
) -> Result<ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>, LockKeeperServerError> {
    match opaque_server_setup_bytes {
        None => {
            warn!("Opaque setup not defined in cli. Ensure you are not running in production!");
            match opaque_server_setup_path {
                None => Err(LockKeeperServerError::OpaqueServerSetupNotDefined),
                Some(opaque_server_setup_path) => {
                    let server_setup_file = File::open(opaque_server_setup_path.as_ref());
                    match server_setup_file {
                        // Server key file doesn't exist yet, create new
                        Err(_) => {
                            let server_setup = ServerSetup::<OpaqueCipherSuite>::new(rng);
                            let dir = opaque_server_setup_path
                                .as_ref()
                                .parent()
                                .ok_or(LockKeeperServerError::InvalidOpaqueDirectory)?;

                            std::fs::create_dir_all(dir)
                                .map_err(|e| LockKeeperServerError::FileIo(e, dir.to_path_buf()))?;

                            let mut file =
                                File::create(&opaque_server_setup_path).map_err(|e| {
                                    LockKeeperServerError::FileIo(
                                        e,
                                        opaque_server_setup_path.as_ref().to_path_buf(),
                                    )
                                })?;

                            file.write_all(bincode::serialize(&server_setup)?.as_slice())?;
                            Ok(server_setup)
                        }

                        // Server key file does exist!
                        Ok(mut file) => {
                            let mut contents = vec![];
                            let _ = file.read_to_end(&mut contents)?;
                            let server_setup: ServerSetup<
                                OpaqueCipherSuite,
                                PrivateKey<Ristretto255>,
                            > = bincode::deserialize(contents.as_slice())?;
                            Ok(server_setup)
                        }
                    }
                }
            }
        }
        Some(bytes) => {
            let server_setup: ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>> =
                bincode::deserialize(bytes.as_ref())?;
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

        let server_setup =
            create_or_retrieve_server_setup_opaque(&mut rng, Some(&key_path), None).unwrap();

        // Then, it does exist
        assert!(Path::new(&key_path).exists());

        let retrieved_server_setup =
            create_or_retrieve_server_setup_opaque(&mut rng, Some(&key_path), None).unwrap();

        // Re-retrieving gets the same thing back
        assert_eq!(server_setup, retrieved_server_setup);

        const SAMPLE_OPAQUE_SERVER_SETUP: &str = "5OYJzN1yWT2GZ7ThPeK3jtQXHjuIj7id6gSirS5Y+/iaAXC5w/nTVzzKHOjx0vZMYMI/IX/t/jyxZAM94U4wgcylgHMV3NxQkA+yI6J4XNqc6xq4oSXOpErA/3bIZuAiwuRqQieTBFYKWHd10mLu7yOWNKyY5aTfiVMQ1GwX8wAaQ+IZA7+MAm73B3NkceIq0bA2bB6v57cbMQJphzkhHy1D8ihI7HO+G2DlYvhGeZzZY2MX3Wwmhw3Agpq3/HYG";
        let opaque_server_setup_bytes = base64::decode(SAMPLE_OPAQUE_SERVER_SETUP).unwrap();
        let cli_server_setup = create_or_retrieve_server_setup_opaque(
            &mut rng,
            Some(&key_path),
            Some(opaque_server_setup_bytes),
        );

        assert!(
            cli_server_setup.is_ok(),
            "{}",
            cli_server_setup.unwrap_err()
        );
        assert_eq!(
            base64::encode(bincode::serialize(&cli_server_setup.unwrap()).unwrap()),
            SAMPLE_OPAQUE_SERVER_SETUP
        );

        // Clean up
        assert!(std::fs::remove_file(&key_path).is_ok());
    }
}
