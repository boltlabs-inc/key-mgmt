CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS Session
(
    session_id uuid DEFAULT uuid_generate_v4 (),
    user_id BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT Now(),
    session_key BYTEA NOT NULL,
    PRIMARY KEY (session_id)
);
