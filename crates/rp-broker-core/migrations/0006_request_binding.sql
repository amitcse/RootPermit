ALTER TABLE requests ADD COLUMN request_digest BLOB
    CHECK (request_digest IS NULL OR length(request_digest) = 32);
ALTER TABLE requests ADD COLUMN request_cose BLOB;
ALTER TABLE requests ADD COLUMN request_nonce BLOB
    CHECK (request_nonce IS NULL OR length(request_nonce) = 32);
ALTER TABLE requests ADD COLUMN request_boot_id BLOB
    CHECK (request_boot_id IS NULL OR length(request_boot_id) = 16);
ALTER TABLE requests ADD COLUMN request_policy_id BLOB
    CHECK (request_policy_id IS NULL OR length(request_policy_id) = 16);
ALTER TABLE requests ADD COLUMN request_policy_digest BLOB
    CHECK (request_policy_digest IS NULL OR length(request_policy_digest) = 32);
ALTER TABLE requests ADD COLUMN request_frozen_plan BLOB;
ALTER TABLE requests ADD COLUMN request_expires_utc INTEGER;
