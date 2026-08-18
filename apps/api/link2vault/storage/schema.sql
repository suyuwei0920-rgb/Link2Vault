CREATE TABLE IF NOT EXISTS capture_tasks (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL CHECK (source IN ('douyin', 'recording')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    stage TEXT NOT NULL CHECK (
        stage IN ('validating', 'fetching', 'asr', 'cleaning', 'writing', 'notifying')
    ),
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    media_seconds REAL,
    artifacts_json TEXT NOT NULL,
    error_json TEXT NOT NULL,
    worker_id TEXT,
    input_ref TEXT
);

CREATE INDEX IF NOT EXISTS capture_tasks_queue
    ON capture_tasks(status, created_at, id);

CREATE INDEX IF NOT EXISTS capture_tasks_fingerprint
    ON capture_tasks(fingerprint, status, updated_at);

CREATE TABLE IF NOT EXISTS enrollment_codes (
    code_digest TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS devices_active_token
    ON devices(token_digest, revoked_at);

CREATE TABLE IF NOT EXISTS quota_reservations (
    task_id TEXT PRIMARY KEY,
    month TEXT NOT NULL,
    seconds REAL NOT NULL CHECK (seconds > 0),
    status TEXT NOT NULL CHECK (status IN ('reserved', 'released')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS quota_reservations_month
    ON quota_reservations(month, status);
