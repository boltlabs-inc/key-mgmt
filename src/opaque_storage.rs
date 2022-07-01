use crate::config::opaque::OpaqueCipherSuite;
use crate::server::config::Service;
use anyhow::{Context, Error};
use generic_array::GenericArray;
use opaque_ke::keypair::PrivateKey;
use opaque_ke::{Ristretto255, ServerRegistrationLen, ServerSetup};
use rand::rngs::StdRng;
use std::fs::File;
use std::io::{Read, Write};

// TODO: replace with decent key-value storage #52

pub fn store_opaque(
    service: &Service,
    key: String,
    value: GenericArray<u8, ServerRegistrationLen<OpaqueCipherSuite>>,
) -> Result<(), Error> {
    std::fs::create_dir_all(&service.opaque_path).unwrap();
    let mut file = File::create(service.opaque_path.join(key)).context("could not create file")?;
    file.write_all(value.as_slice())
        .context("could not write file")?;
    Ok(())
}

pub fn retrieve_opaque(
    service: &Service,
    key: String,
) -> Result<GenericArray<u8, ServerRegistrationLen<OpaqueCipherSuite>>, Error> {
    let mut file = File::open(service.opaque_path.join(key))?;
    let mut contents: GenericArray<u8, ServerRegistrationLen<OpaqueCipherSuite>> =
        GenericArray::default();
    let _ = file.read(&mut contents)?;
    Ok(contents)
}

//TODO: replace with decent and secure storage for server keys #56
pub fn create_or_retrieve_server_key_opaque(
    mut rng: StdRng,
    service: &Service,
) -> Result<ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>, Error> {
    let server_key_file = File::open(service.opaque_server_key.clone());
    if server_key_file.is_err() {
        let server_setup = ServerSetup::<OpaqueCipherSuite>::new(&mut rng);
        std::fs::create_dir_all(&service.opaque_server_key.parent().unwrap()).unwrap();
        let mut file =
            File::create(service.opaque_server_key.clone()).context("could not create file")?;
        file.write_all(bincode::serialize(&server_setup).unwrap().as_slice())
            .context("could not write file")?;
        return Ok(server_setup);
    }
    let mut contents = vec![];
    let _ = server_key_file.unwrap().read_to_end(&mut contents)?;
    let server_setup: ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>> =
        bincode::deserialize(contents.as_slice()).unwrap();
    Ok(server_setup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::Service;
    use generic_array::GenericArray;
    use std::env::temp_dir;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_store_and_retrieve() -> Result<(), Error> {
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
        store_opaque(service, "test".to_string(), GenericArray::default())?;

        let file = retrieve_opaque(service, "test".to_string())?;
        assert_eq!(file, GenericArray::default());
        Ok(())
    }
}
