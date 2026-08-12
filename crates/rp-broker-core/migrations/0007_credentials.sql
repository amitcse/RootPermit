CREATE TABLE credentials (
    credential_id BLOB PRIMARY KEY CHECK (length(credential_id) BETWEEN 1 AND 1024),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    cose_algorithm INTEGER NOT NULL,
    public_key_cose BLOB NOT NULL CHECK (length(public_key_cose) BETWEEN 1 AND 4096),
    sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    quarantined INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0, 1))
);
