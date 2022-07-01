# key-mgmt


Generate certificates for local testing:

```./dev/generate-certificates```

Run server:

```./target/debug/key-mgmt server --config "./dev/Server.toml" run```

Client commands:

1. ```./target/debug/key-mgmt client --config "./dev/Client.toml" register "keymgmt://localhost" --username "testUsername" --password "testSecretPassword"```
2. ```./target/debug/key-mgmt client --config "./dev/Client.toml" authenticate "keymgmt://localhost" --username "testUsername" --password "testSecretPassword"```
