ALTER TABLE broker_identity ADD COLUMN device_id BLOB
    CHECK (device_id IS NULL OR length(device_id) = 16);
