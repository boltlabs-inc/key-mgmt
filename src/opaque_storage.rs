use crate::config::opaque::OpaqueCipherSuite;
use crate::keys::UserId;
use crate::server::config::Service;
use anyhow::{anyhow, Context, Error};
use generic_array::GenericArray;
use opaque_ke::keypair::PrivateKey;
use opaque_ke::{Ristretto255, ServerRegistration, ServerRegistrationLen, ServerSetup};
use rand::rngs::StdRng;
use std::fs::File;
use std::io::{Read, Write};

// TODO: replace with decent key-value storage #52.

/// Abstraction of the storage for the OPAQUE authentication information.
///
/// `user_id` is the key under which the [`ServerRegistration`] is stored.
pub(crate) fn store_opaque(
    service: &Service,
    user_id: &UserId,
    server_registration: &ServerRegistration<OpaqueCipherSuite>,
) -> Result<(), Error> {
    std::fs::create_dir_all(
        &service
            .opaque_path
            .parent()
            .context("could not create opaque path directory")?,
    )?;
    let mut file = File::create(service.opaque_path.join(user_id.to_string()))
        .context("could not create file")?;
    file.write_all(server_registration.serialize().as_slice())
        .context("could not write file")?;
    Ok(())
}

/// Abstraction to retrieve the OPAQUE authentication information from storage.
///
/// `user_id` is the key under which the [`ServerRegistration`] is stored.
pub(crate) fn retrieve_opaque(
    service: &Service,
    user_id: &UserId,
) -> Result<ServerRegistration<OpaqueCipherSuite>, Error> {
    let mut file = File::open(service.opaque_path.join(user_id.to_string()))?;
    let mut contents: GenericArray<u8, ServerRegistrationLen<OpaqueCipherSuite>> =
        GenericArray::default();
    let _ = file.read(&mut contents);
    ServerRegistration::<OpaqueCipherSuite>::deserialize(contents.as_slice())
        .map_err(|_| anyhow!("couldn't deserialize file"))
}

/// Retrieves the [`ServerSetup`] used for OPAQUE authentication, creating it if
/// it doesn't already exist.
///
/// TODO: replace with decent and secure storage for server keys #56
pub(crate) fn create_or_retrieve_server_key_opaque(
    rng: &mut StdRng,
    service: &Service,
) -> Result<ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>, Error> {
    let server_key_file = File::open(&service.opaque_server_key);
    match server_key_file {
        // Server key file doesn't exist yet, create new
        Err(_) => {
            let server_setup = ServerSetup::<OpaqueCipherSuite>::new(rng);
            std::fs::create_dir_all(
                &service
                    .opaque_server_key
                    .parent()
                    .context("could not create server key file location path")?,
            )?;
            let mut file = File::create(&service.opaque_server_key)
                .context("could not create server key file")?;
            file.write_all(
                bincode::serialize(&server_setup)
                    .context("could not serialize server setup")?
                    .as_slice(),
            )
            .context("could not write file")?;
            Ok(server_setup)
        }

        // Server key file does exist!
        Ok(mut file) => {
            let mut contents = vec![];
            let _ = file.read_to_end(&mut contents)?;
            let server_setup: ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>> =
                match bincode::deserialize(contents.as_slice()) {
                    Ok(server_setup) => server_setup,
                    Err(_) => return Err(anyhow!("could not deserialize server key file")),
                };
            Ok(server_setup)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::Service;
    use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters};
    use rand::SeedableRng;
    use std::env::temp_dir;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_store_and_retrieve() -> Result<(), Error> {
        let mut rng = StdRng::from_entropy();
        let service = &Service {
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 0,
            connection_timeout: None,
            max_pending_connection_retries: 0,
            message_timeout: Default::default(),
            max_message_length: 0,
            private_key: Default::default(),
            certificate: Default::default(),
            opaque_path: temp_dir().join("opaque"),
            opaque_server_key: temp_dir().join("opaque/server_setup"),
        };
        let server_setup = create_or_retrieve_server_key_opaque(&mut rng, service).unwrap();

        let mut rng = StdRng::from_entropy();
        let user_id = "testUserId";
        let password = "testPassword";
        let client_registration_start_result =
            ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, password.as_bytes()).unwrap();
        let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &server_setup,
            client_registration_start_result.message,
            user_id.as_bytes(),
        )
        .unwrap();
        let client_finish_registration_result = client_registration_start_result
            .state
            .finish(
                &mut rng,
                password.as_bytes(),
                server_registration_start_result.message,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let server_registration =
            ServerRegistration::finish(client_finish_registration_result.message);
        assert!(ServerRegistration::<OpaqueCipherSuite>::deserialize(
            server_registration.serialize().as_slice()
        )
        .is_ok());
        assert!(store_opaque(service, &UserId::from_str(user_id)?, &server_registration).is_ok());

        let retrieved_result = retrieve_opaque(service, &UserId::from_str(user_id)?);
        assert!(
            retrieved_result.is_ok(),
            "{:?}",
            retrieved_result.err().unwrap()
        );
        assert_eq!(retrieved_result.unwrap(), server_registration);
        Ok(())
    }
}
