CREATE INDEX IF NOT EXISTS idx_secrets_key_account
    ON Secrets USING btree
    (key_id ASC NULLS LAST, account_id ASC NULLS LAST);