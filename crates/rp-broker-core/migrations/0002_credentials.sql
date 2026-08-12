CREATE TABLE broker_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    boot_epoch INTEGER NOT NULL CHECK (boot_epoch >= 0),
    credential_generation INTEGER NOT NULL CHECK (credential_generation >= 0)
);
INSERT INTO broker_metadata(singleton, schema_version, boot_epoch, credential_generation)
VALUES (1, 2, 0, 0);
