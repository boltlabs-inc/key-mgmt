//! Config file tests that depend on files to exist at specific paths.
//! If the paths listed in these tests change, the tests will fail.

use std::str::FromStr;

use colored::Colorize;
use lock_keeper_client::LockKeeperClientError;
use lock_keeper_key_server::LockKeeperServerError;

use crate::{
    config::Config,
    error::Result,
    run_parallel,
    test_suites::database::TestDatabase,
    utils::{report_test_results, TestResult},
};

pub async fn run_tests(config: &Config) -> Result<Vec<TestResult>> {
    println!("{}", "Running config file tests".cyan());

    let db = TestDatabase::new("config_file_tests").await?;
    let results = run_parallel!(
        config.clone(),
        client_config_with_file_private_key_works(),
        client_config_with_manual_private_key_works(),
        client_config_without_private_key_fails(),
        server_config_with_file_private_key_works(),
        server_config_with_manual_private_key_works(),
        server_config_without_private_key_fails(),
    )?;

    db.drop().await?;

    println!("config file tests: {}", report_test_results(&results));

    Ok(results)
}

async fn client_config_with_file_private_key_works() -> Result<()> {
    use lock_keeper_client::config::{Config as ClientConfig, ConfigFile};

    let config_file = ConfigFile::from_str(CLIENT_CONFIG_WITH_KEY)?;
    let config = ClientConfig::from_config_file(config_file, None);
    assert!(config.is_ok());

    Ok(())
}

async fn client_config_with_manual_private_key_works() -> Result<()> {
    use lock_keeper_client::config::{Config as ClientConfig, ConfigFile};

    let config_file = ConfigFile::from_str(CLIENT_CONFIG_NO_KEY)?;
    let private_key_bytes = SAMPLE_PRIVATE_KEY.to_string().into_bytes();
    let config = ClientConfig::from_config_file(config_file, Some(private_key_bytes));
    assert!(config.is_ok());

    Ok(())
}

async fn client_config_without_private_key_fails() -> Result<()> {
    use lock_keeper_client::config::{Config as ClientConfig, ConfigFile};

    let config_file = ConfigFile::from_str(CLIENT_CONFIG_NO_KEY)?;
    let config = ClientConfig::from_config_file(config_file, None);
    assert!(matches!(
        config,
        Err(LockKeeperClientError::PrivateKeyMissing)
    ));

    Ok(())
}

async fn server_config_with_file_private_key_works() -> Result<()> {
    use lock_keeper_key_server::config::{Config as ServerConfig, ConfigFile};

    let config_file = ConfigFile::from_str(SERVER_CONFIG_WITH_KEY)?;
    let config = ServerConfig::from_config_file(config_file, None);
    assert!(config.is_ok());

    Ok(())
}

async fn server_config_with_manual_private_key_works() -> Result<()> {
    use lock_keeper_key_server::config::{Config as ServerConfig, ConfigFile};

    let config_file = ConfigFile::from_str(SERVER_CONFIG_NO_KEY)?;
    let private_key_bytes = SAMPLE_PRIVATE_KEY.to_string().into_bytes();
    let config = ServerConfig::from_config_file(config_file, Some(private_key_bytes));
    assert!(config.is_ok());

    Ok(())
}

async fn server_config_without_private_key_fails() -> Result<()> {
    use lock_keeper_key_server::config::{Config as ServerConfig, ConfigFile};

    let config_file = ConfigFile::from_str(SERVER_CONFIG_NO_KEY)?;
    let config = ServerConfig::from_config_file(config_file, None);
    assert!(matches!(
        config,
        Err(LockKeeperServerError::PrivateKeyMissing)
    ));

    Ok(())
}

const CLIENT_CONFIG_NO_KEY: &str = r#"
server_uri = "https://localhost:1114"
ca_chain = "dev/test-pki/gen/ca/signing-ca.chain"

[client_auth]
certificate_chain = "dev/test-pki/gen/certs/client.chain"
"#;

const CLIENT_CONFIG_WITH_KEY: &str = r#"
server_uri = "https://localhost:1114"
ca_chain = "dev/test-pki/gen/ca/signing-ca.chain"

[client_auth]
certificate_chain = "dev/test-pki/gen/certs/client.chain"
private_key = "dev/test-pki/gen/certs/client.key"
"#;

const SERVER_CONFIG_NO_KEY: &str = r#"
address = "127.0.0.1"
port = 1114
certificate_chain = "dev/test-pki/gen/certs/server.chain"
client_auth = true
opaque_path = "dev/opaque"
opaque_server_key = "dev/opaque/server_setup"

[database]
mongodb_uri = 'mongodb://localhost:27017'
db_name = 'lock-keeper-test-db'
"#;

const SERVER_CONFIG_WITH_KEY: &str = r#"
address = "127.0.0.1"
port = 1114
certificate_chain = "dev/test-pki/gen/certs/server.chain"
private_key = "dev/test-pki/gen/certs/server.key"
client_auth = true
opaque_path = "dev/opaque"
opaque_server_key = "dev/opaque/server_setup"

[database]
mongodb_uri = 'mongodb://localhost:27017'
db_name = 'lock-keeper-test-db'
"#;

const SAMPLE_PRIVATE_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHcJ1EdkWCtFpN
QTbMP5D4oBV0XtpbRPxV2Z+sCHyrHknyi54ZSM2A3vNoWZKsSavD/2lIAyRn14GL
1UJmJHbafmcbZb2tWH8oTB717lnnJ72cKlpZtbB1C6GUU9rgsBlnnwi7rB8mYcU5
5iMJ3eH5LrWKv9n6oSXiB2z/V+iWBVrlXacQrgwKgpcdogZC7pHkUpqbyLjHt6JM
Y3mC7TVkP+mL4W4rHSRYyuj9NwOos7B5zmMTYL9gHYi9yIS8+n2aK5pc+IU8Q2WR
gemGwMU/QhPi/3kT5Wi8/88uopjANlpFuVsluSc29GKt0gZcuYpVJBnfgJJT6jEG
v/+aLOzNAgMBAAECggEAdvBmGeoe0jAUmnYF5BEUt/FgWiInPr8JbXl3i/UTxEkv
+IHjK1kLlYtgxh6FJlJZKW4sr1GQaI1RKL9p9dhROUSg4OnwEGzyiGm9HRWkcAJ3
RabMcyuzrFnfZsILimv6+p0RbDrd6Nnt8PWad8vnc9+zTKfVq25nVUDwc+dNQgmp
9MgvT3z85CbwuPJlx3MD+Wyj6mwTw5GleVRp8rfeN9WGNzZ0f0WkokAtNkFk2kS1
1+F1nxqei893lWrtwZx9M4KO6gYH9NtFzq3NC4632oQl3z9B6Lr3S1bH35rwPTS2
hjAEUKtqZR0CRIgAhnDMi1yRfxcZFzsM9TMEP/bZgQKBgQDm6P+ZsYnpSCJCgQGA
+wEVUOTCuS10v99eJ7z/aQw+W9xOQtkP5yMO9xnQEfb9A5M1JricCyGQNh/Dat4h
fEdCK1boWg/OfrLpEzfYY4cFiNCCm2BWO+DK3I0U8wtrmsJB5T//lQhWhU5mAWCI
8bTcPdrLrQ6bBDJRezrjmloiiQKBgQDdHD0eRdR8QD36A1YzGxFv0EmgS4LirICe
0/fb2+CyZAnOSrSBBYc/56WgEZb9Ue6EhFHD/UR3QB35e3Tpk5UIB1D44OUwqAHB
78pKnIh1HP2GdpCI/2QQJV3goFZVGa735WVnMYi8QSZK2CFI7GlLa7i6dSV8tNlo
cDGMU0a3JQKBgQCSeCth72b+jd4Fd1Vf3lfikIx7JAE8dFUYoXZWQOkeSSCml+qe
Fsx7Oqyp+itEdNcUuPoTKVBh7KMbTxeWAAIna9xVyIMMRfvwslsTLJbCIPW6Uxq5
uIOvylTHfB+7YtBkAiolUgCW+TowpCD63O8PYUD/P0frdq8AVn2VUBxqmQKBgA8L
O9FSePmXOWBIV9YUUmRkLI4+dQJNMFceHvATjr80dUJW7N8WbDRZ43f3mmlT6MGV
aybFlaHzd9agory9sNciAE1ep9lepPf4A7B94/7r4QgECyN3FOzQTgnZfuY9YB03
u2WBBkeguyU+fU1D4IokIyZ0j/9jIqOrdoOQqvANAoGBANcHkQfda6mPq2aFZIv9
tbZ2ky1GRvAxuVcCjS1vn5ZF5VvnqLn5DktdbSp9LbnrdF9B9PR3XPC2AoZLvdAg
XrqXH4XVk0PdxqQL0Ntny3OZT0QCnAFMIzs5Tb1hZy6mwOgXcOSOo+qs0l0ckvX3
3jgHukmZ0w0rPwXJn8PRIa0b
-----END PRIVATE KEY-----
"#;
