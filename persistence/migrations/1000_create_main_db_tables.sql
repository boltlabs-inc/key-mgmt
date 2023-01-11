CREATE TABLE IF NOT EXISTS Accounts
(
    account_id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id BYTEA UNIQUE NOT NULL,
    -- TODO: Introduce auxiliary table for mapping account_name <-> unique integer.
    account_name VARCHAR(30) UNIQUE NOT NULL,
    storage_key BYTEA,
    server_registration BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS Secrets
(
    secret_id BIGINT GENERATED ALWAYS AS IDENTITY,
    key_id BYTEA UNIQUE NOT NULL,
    user_id BYTEA NOT NULL,
    -- TODO: Use account_id from Accounts table instead of user_id.
    -- account_id BIGINT NOT NULL,
    secret BYTEA NOT NULL,
    secret_type TEXT NOT NULL,
    -- TODO: Utilize this field.
    retrieved BOOL NOT NULL,
    PRIMARY KEY (secret_id),
    FOREIGN KEY (user_id) REFERENCES Accounts(user_id)
    -- FOREIGN KEY (account_id) REFERENCES Accounts(account_id)
);

CREATE TABLE IF NOT EXISTS AuditEvents
(
    audit_event_id BIGINT GENERATED ALWAYS AS IDENTITY,
    -- TODO: Use account_id from Accounts table instead of account_name.
    -- account_id BIGSERIAL NOT NULL,
    account_name VARCHAR(30) NOT NULL,
    key_id BYTEA,
    request_id UUID NOT NULL,
    action TEXT NOT NULL,
    event_status TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (audit_event_id)
    -- FOREIGN KEY (account_id) REFERENCES Accounts(account_id),
    -- FOREIGN KEY (key_id) REFERENCES Secrets(key_id)
);