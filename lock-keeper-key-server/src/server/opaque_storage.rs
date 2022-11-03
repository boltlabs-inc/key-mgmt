use lock_keeper::config::{opaque::OpaqueCipherSuite, server::Service};
use opaque_ke::{keypair::PrivateKey, Ristretto255, ServerSetup};
use rand::rngs::StdRng;
use std::{
    fs::File,
    io::{Read, Write},
};

use crate::LockKeeperServerError;

/// Retrieves the [`ServerSetup`] used for OPAQUE authentication, creating it if
/// it doesn't already exist.
///
/// TODO: replace with decent and secure storage for server keys #56
pub fn create_or_retrieve_server_key_opaque(
    rng: &mut StdRng,
    service: &Service,
) -> Result<ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>, LockKeeperServerError> {
    let server_key_file = File::open(&service.opaque_server_key);
    match server_key_file {
        // Server key file doesn't exist yet, create new
        Err(_) => {
            let server_setup = ServerSetup::<OpaqueCipherSuite>::new(rng);
            std::fs::create_dir_all(
                service
                    .opaque_server_key
                    .parent()
                    .ok_or(LockKeeperServerError::InvalidOpaqueDirectory)?,
            )?;
            let mut file = File::create(&service.opaque_server_key)?;
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
    use lock_keeper::config::server::Service;
    use rand::SeedableRng;
    use std::{
        env::temp_dir,
        net::{IpAddr, Ipv4Addr},
        path::Path,
    };

    #[tokio::test]
    async fn opaque_server_key_is_retrievable() {
        let mut rng = StdRng::from_entropy();
        let service = &Service {
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 0,
            private_key: Default::default(),
            certificate: Default::default(),
            opaque_path: temp_dir().join("opaque"),
            opaque_server_key: temp_dir().join("opaque/server_setup"),
        };

        // Delete file from previous run if it exists
        let _ = std::fs::remove_file(&service.opaque_server_key);

        // First, the storage key doesn't exist
        assert!(!Path::new(&service.opaque_server_key).is_file());

        let server_setup = create_or_retrieve_server_key_opaque(&mut rng, service).unwrap();

        // Then, it does exist
        assert!(Path::new(&service.opaque_server_key).exists());

        let retrieved_server_setup =
            create_or_retrieve_server_key_opaque(&mut rng, service).unwrap();

        // Re-retrieving gets the same thing back
        assert_eq!(server_setup, retrieved_server_setup);

        // Clean up
        assert!(std::fs::remove_file(&service.opaque_server_key).is_ok());
    }
}
