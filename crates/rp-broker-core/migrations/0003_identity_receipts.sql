CREATE TABLE broker_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    key_kid BLOB NOT NULL CHECK (length(key_kid) BETWEEN 8 AND 32),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    broker_epoch INTEGER NOT NULL CHECK (broker_epoch >= 0)
);

CREATE TABLE receipts (
    receipt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES requests (request_id) ON DELETE RESTRICT,
    requester_uid INTEGER NOT NULL CHECK (requester_uid >= 0),
    terminal_state TEXT NOT NULL,
    cose_bytes BLOB NOT NULL,
    created_utc INTEGER NOT NULL,
    completed_utc INTEGER NOT NULL
);

CREATE TRIGGER requests_terminal_receipt_immutable
BEFORE UPDATE OF receipt_bytes ON requests
WHEN OLD.receipt_bytes IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'terminal receipt is immutable');
END;
