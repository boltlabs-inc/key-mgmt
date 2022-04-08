pub(crate) mod common;

use keymgmt::{client, server};

#[tokio::test]
pub async fn integration_tests() {
    let server_future = common::setup().await;
    let _client_config = client::Config::load(common::CLIENT_CONFIG)
        .await
        .expect("Failed to load client config");
    let _server_config = server::Config::load(common::SERVER_CONFIG)
        .await
        .expect("Failed to load server config");

    // Run every test, printing out details if it fails
    let tests = tests();
    println!("Executing {} tests", tests.len());
    for test in tests {
        eprintln!("\n\ntest integration_tests::{} ... ", test.name);
    }

    common::teardown(server_future).await;
}

/// Get a list of tests to execute.
/// Assumption: none of these will cause a fatal error to the long-running processes (server).
fn tests() -> Vec<Test> {
    vec![
        Test {
            name: "Channel establishes correctly".to_string(),
        },
        Test {
            name: "Channels cannot share names".to_string(),
        },
    ]
}

#[derive(Debug)]
struct Test {
    pub name: String,
}
