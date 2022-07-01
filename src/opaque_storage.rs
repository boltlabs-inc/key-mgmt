use crate::config::opaque::OpaqueCipherSuite;
use crate::server::config::Service;
use anyhow::{Context, Error};
use generic_array::GenericArray;
use opaque_ke::ServerRegistrationLen;
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

#[allow(unused)]
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
        };
        store_opaque(service, "test".to_string(), GenericArray::default())?;

        let file = retrieve_opaque(service, "test".to_string())?;
        assert_eq!(file, GenericArray::default());
        Ok(())
    }
}
