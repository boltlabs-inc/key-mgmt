use http::{uri::InvalidUri, Uri};
use std::{fmt, fmt::Display, str::FromStr};
use thiserror::Error;
use webpki::{DnsName, DnsNameRef, InvalidDnsNameError};

use crate::client;
use tclient::Address;
use transport::client as tclient;

/// The address of a keymgmt server: a URI of the form `keymgmt://some.domain.com:1113` with
/// an optional port number.
#[derive(Debug, Clone, serde_with::SerializeDisplay, serde_with::DeserializeFromStr)]
pub struct KeyMgmtAddress {
    host: DnsName,
    port: Option<u16>,
}

impl Address for KeyMgmtAddress {
    fn get_host(&self) -> &DnsName {
        &self.host
    }

    fn get_port(&self) -> u16 {
        self.port.unwrap_or_else(client::defaults::port)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InvalidKeyMgmtAddress {
    #[error("Incorrect URI scheme: expecting `keymgmt://`")]
    IncorrectScheme,
    #[error("Unexpected non-root path in `keymgmt://` address")]
    UnsupportedPath,
    #[error("Unexpected query string in `keymgmt://` address")]
    UnsupportedQuery,
    #[error("Missing hostname in `keymgmt://` address")]
    MissingHost,
    #[error("Invalid DNS hostname in `keymgmt://` address: {0}")]
    InvalidDnsName(InvalidDnsNameError),
    #[error("Invalid `keymgmt://` address: {0}")]
    InvalidUri(InvalidUri),
}

impl FromStr for KeyMgmtAddress {
    type Err = InvalidKeyMgmtAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri: Uri = s.parse().map_err(InvalidKeyMgmtAddress::InvalidUri)?;
        if uri.scheme_str() != Some("keymgmt") {
            Err(InvalidKeyMgmtAddress::IncorrectScheme)
        } else if uri.path() != "" && uri.path() != "/" {
            Err(InvalidKeyMgmtAddress::UnsupportedPath)
        } else if uri.query().is_some() {
            Err(InvalidKeyMgmtAddress::UnsupportedQuery)
        } else if let Some(host) = uri.host() {
            Ok(KeyMgmtAddress {
                host: DnsNameRef::try_from_ascii_str(host)
                    .map_err(InvalidKeyMgmtAddress::InvalidDnsName)?
                    .to_owned(),
                port: uri.port_u16(),
            })
        } else {
            Err(InvalidKeyMgmtAddress::MissingHost)
        }
    }
}

impl Display for KeyMgmtAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let host: &str = self.host.as_ref().into();
        write!(f, "keymgmt://{}", host)?;
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}
