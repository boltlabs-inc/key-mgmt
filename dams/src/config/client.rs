use crate::error::DamsError;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use tonic::transport::Uri;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct Config {
    pub server_location: String,
    #[serde(default)]
    pub trust_certificate: Option<PathBuf>,
}

impl Config {
    pub async fn load(config_path: impl AsRef<Path>) -> Result<Config, DamsError> {
        let config_string = tokio::fs::read_to_string(&config_path).await?;
        let mut config = Self::from_str(&config_string)?;

        // Directory containing the configuration path
        let config_dir = config_path
            .as_ref()
            .parent()
            .expect("Client configuration path must exist in some parent directory");

        // Adjust contained paths to be relative to the config path
        config.trust_certificate = config
            .trust_certificate
            .map(|ref cert_path| config_dir.join(cert_path));

        Ok(config)
    }

    pub fn server_location(&self) -> Result<Uri, DamsError> {
        Ok(Uri::from_str(self.server_location.as_str())?)
    }
}

impl FromStr for Config {
    type Err = DamsError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        let config: Config = toml::from_str(config_string)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_location: "https://127.0.0.1:1113".to_string(),
            trust_certificate: Some(PathBuf::from("tests/gen/localhost.crt")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_str() {
        let config_str = r#"
            server_location = "https://127.0.0.1:1113"
        "#;

        // Destructure so the test breaks when fields are added
        let Config {
            server_location,
            trust_certificate,
        } = Config::from_str(config_str).unwrap();

        assert_eq!(server_location, "https://127.0.0.1:1113");
        assert_eq!(trust_certificate, None);
    }
}
