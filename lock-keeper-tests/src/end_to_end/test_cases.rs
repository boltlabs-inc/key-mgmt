use std::str::FromStr;

use lock_keeper_client::{client::Password, LockKeeperClientError};

use crate::{
    config::Config,
    end_to_end::{Operation, Outcome},
};

use super::Test;

/// Get a list of tests to execute.
/// Assumption: none of these will cause a fatal error to the long-running
/// processes (server).
pub async fn tests(config: &Config) -> Vec<Test> {
    use Operation::*;

    vec![
        Test::new(
            "Register the same user twice user",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Register,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::AccountAlreadyRegistered),
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Register and open multiple sessions as a client to the server",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(None),
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(None),
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Register and authenticate with wrong password fails as a client to the server",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(Some(Password::from_str("wrongPassword").unwrap())),
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidLogin),
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Authenticate with unregistered user fails",
            vec![(
                Authenticate(None),
                Outcome {
                    expected_error: Some(LockKeeperClientError::InvalidAccount),
                },
            )],
            config.client_config.clone(),
        ),
        Test::new(
            "Generate a secret",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Retrieve a secret",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Retrieve,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Retrieving a non-existent secret fails",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    SetFakeKeyId,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Retrieve,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidAccount),
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Export a secret",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Export,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Exporting a non-existent secret fails",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    SetFakeKeyId,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Export,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidAccount),
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Remote generate a signing key",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    RemoteGenerate,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Import a signing key",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    ImportSigningKey,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Export an imported signing key",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    ImportSigningKey,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    ExportSigningKey,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Exporting a secret using 'export_signing_key' fails",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    ExportSigningKey,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidAccount),
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Exporting a non-existent signing key fails",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    SetFakeKeyId,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    ExportSigningKey,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidAccount),
                    },
                ),
            ],
            config.client_config.clone(),
        ),
        Test::new(
            "Sign data with a remotely generated key",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    RemoteGenerate,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    RemoteSignBytes,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
            config.client_config.clone(),
        ),
    ]
}
