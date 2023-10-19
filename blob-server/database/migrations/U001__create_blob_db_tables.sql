-- Create tables
CREATE TABLE IF NOT EXISTS blob_account
(
    blob_account_id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name VARCHAR(50) UNIQUE NOT NULL,
    api_secret VARCHAR(64) NOT NULL,
    time_created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    time_modified TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blob
(
    blob_id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    blob_account_id BIGINT NOT NULL,
    data BYTEA NOT NULL,
    time_created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    time_modified TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (blob_account_id) REFERENCES blob_account(blob_account_id)
);

CREATE TABLE IF NOT EXISTS blob_session
(
    blob_session_id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    blob_account_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    token VARCHAR(188) NOT NULL,
    expiration TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (blob_account_id) REFERENCES blob_account(blob_account_id)
);

-- Create indices
CREATE INDEX IF NOT EXISTS idx_blobs_blob_account
    ON blob USING btree
    (blob_id ASC NULLS LAST, blob_account_id ASC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_blob_sessions_blob_account
    ON blob_session USING btree
    (blob_session_id ASC NULLS LAST, blob_account_id ASC NULLS LAST);

-- Create modify triggers
CREATE OR REPLACE FUNCTION update_time_modified()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.time_modified = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_blob_account_time_modified BEFORE UPDATE
    ON blob_account FOR EACH ROW EXECUTE PROCEDURE
    update_time_modified();

CREATE TRIGGER update_blob_time_modified BEFORE UPDATE
    ON blob FOR EACH ROW EXECUTE PROCEDURE
    update_time_modified();
