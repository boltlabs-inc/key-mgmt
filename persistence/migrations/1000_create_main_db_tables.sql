-- Maps client actions to unique ID
CREATE TABLE IF NOT EXISTS ClientActionsTypes (
    client_action_id BIGINT PRIMARY KEY UNIQUE NOT NULL,
    client_action VARCHAR(50) UNIQUE NOT NULL
);

-- These can be found in lock-keeper/src/types/operations.rs
INSERT INTO ClientActionsTypes (client_action_id, client_action)
VALUES
    (0, 'Authenticate'),
    (1, 'CreateStorageKey'),
    (2, 'ExportSecret'),
    (3, 'ExportSigningKey'),
    (4, 'GenerateSecret'),
    (5, 'GetUserId'),
    (6, 'ImportSigningKey'),
    (7, 'Logout'),
    (8, 'Register'),
    (9, 'RemoteGenerateSigningKey'),
    (10, 'RemoteSignBytes'),
    (11, 'RetrieveSecret'),
    (12, 'RetrieveAuditEvents'),
    (13, 'RetrieveSigningKey'),
    (14, 'RetrieveStorageKey')
ON CONFLICT (client_action_id) DO NOTHING;

-- Maps secret types to unique ID
CREATE TABLE IF NOT EXISTS SecretTypes (
    secret_type_id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    secret_type VARCHAR(50) UNIQUE NOT NULL
);

-- These can be found in /lock-keeper/src/types/database/secrets.rs
INSERT INTO SecretTypes (secret_type)
VALUES
    ('arbitrary_secret'),
    ('remote_signing_key'),
    ('signing_key_pair')
ON CONFLICT (secret_type) DO NOTHING;

CREATE TABLE IF NOT EXISTS Accounts
(
    account_id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id BYTEA UNIQUE NOT NULL,
    account_name VARCHAR(50) UNIQUE NOT NULL,
    storage_key BYTEA,
    server_registration BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS Secrets
(
    secret_id BIGINT GENERATED ALWAYS AS IDENTITY,

    key_id BYTEA UNIQUE NOT NULL,
    account_id BIGINT NOT NULL,
    secret BYTEA NOT NULL,
    secret_type_id BIGINT NOT NULL,
    retrieved BOOL NOT NULL,
    PRIMARY KEY (secret_id),
    FOREIGN KEY (account_id) REFERENCES Accounts(account_id)
);

CREATE TABLE IF NOT EXISTS AuditEvents
(
    audit_event_id BIGINT GENERATED ALWAYS AS IDENTITY,
    account_id BIGINT NOT NULL,
    key_id BYTEA,
    request_id UUID NOT NULL,
    client_action_id BIGINT NOT NULL,
    event_status TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (audit_event_id),
    FOREIGN KEY (account_id) REFERENCES Accounts(account_id)
    -- FOREIGN KEY (key_id) REFERENCES Secrets(key_id)
);
