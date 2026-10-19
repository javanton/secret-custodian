pub const SCHEMA_VERSION: i64 = 1;

pub const SCHEMA: &str = r#"
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    value_enc BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER
);
CREATE TABLE roles (
    name TEXT PRIMARY KEY,
    unmatched_policy TEXT NOT NULL CHECK (unmatched_policy IN ('passthrough','deny'))
);
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    host_pattern TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    methods TEXT NOT NULL,
    injection_kind TEXT NOT NULL CHECK (injection_kind IN ('header','query')),
    target_name TEXT NOT NULL,
    template TEXT NOT NULL,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE RESTRICT
);
CREATE TABLE tokens (
    jti TEXT PRIMARY KEY,
    machine TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    token_hash TEXT NOT NULL
);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    jti TEXT, machine TEXT, role TEXT,
    host TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
    rule_id INTEGER, decision TEXT NOT NULL, status INTEGER
);
CREATE INDEX audit_ts ON audit(ts);
CREATE TABLE ca (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    cert_pem TEXT NOT NULL,
    key_enc BLOB NOT NULL,
    domains TEXT NOT NULL
);
"#;
