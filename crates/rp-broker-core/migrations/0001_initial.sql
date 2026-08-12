CREATE TABLE requests (
    request_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    requester_uid INTEGER NOT NULL CHECK (requester_uid >= 0),
    operation_key TEXT NOT NULL,
    input_digest BLOB NOT NULL CHECK (length(input_digest) = 32),
    package_name TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL CHECK (state IN (
        'planning', 'pending', 'approved', 'executing', 'no_change', 'invalid',
        'denied', 'expired', 'cancelled', 'stale', 'succeeded', 'failed', 'recovery_required'
    )),
    boot_epoch INTEGER NOT NULL DEFAULT 0 CHECK (boot_epoch >= 0),
    deadline_mono_ns INTEGER CHECK (deadline_mono_ns IS NULL OR deadline_mono_ns >= 0),
    plan_digest BLOB CHECK (plan_digest IS NULL OR length(plan_digest) = 32),
    approval_context_digest BLOB CHECK (approval_context_digest IS NULL OR length(approval_context_digest) = 32),
    created_utc INTEGER NOT NULL DEFAULT 0,
    updated_utc INTEGER NOT NULL DEFAULT 0,
    receipt_bytes BLOB,
    recovery_evidence BLOB
);
CREATE UNIQUE INDEX requests_idempotency ON requests (requester_uid, operation_key);
CREATE UNIQUE INDEX requests_one_active_per_device ON requests (device_id)
    WHERE state IN ('planning', 'pending', 'approved', 'executing', 'recovery_required');
CREATE TABLE request_events (
    request_id TEXT NOT NULL REFERENCES requests (request_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    state TEXT NOT NULL,
    reason INTEGER NOT NULL CHECK (reason > 0),
    previous_event_digest BLOB CHECK (previous_event_digest IS NULL OR length(previous_event_digest) = 32),
    event_digest BLOB NOT NULL CHECK (length(event_digest) = 32),
    occurred_mono_ns INTEGER NOT NULL DEFAULT 0 CHECK (occurred_mono_ns >= 0),
    occurred_utc INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (request_id, sequence)
);
