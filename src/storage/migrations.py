"""Database schema migrations for local identity, runtime control, and audit."""

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            jti TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id),
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            revoked_at REAL
        );
        CREATE INDEX IF NOT EXISTS ix_auth_sessions_user ON auth_sessions(user_id);
        CREATE INDEX IF NOT EXISTS ix_auth_sessions_expiry ON auth_sessions(expires_at);

        CREATE TABLE IF NOT EXISTS runtime_response_control (
            singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
            mode TEXT NOT NULL CHECK (mode IN ('monitor', 'enforce')),
            auto_block_enabled INTEGER NOT NULL CHECK (auto_block_enabled IN (0, 1)),
            kill_switch INTEGER NOT NULL CHECK (kill_switch IN (0, 1)),
            updated_by TEXT,
            updated_at REAL NOT NULL,
            reason TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            occurred_at REAL NOT NULL,
            actor_user_id TEXT,
            actor_role TEXT,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT,
            reason TEXT,
            outcome TEXT NOT NULL,
            request_id TEXT,
            details_json TEXT NOT NULL,
            previous_hash TEXT,
            event_hash TEXT NOT NULL UNIQUE
        );
        CREATE INDEX IF NOT EXISTS ix_audit_events_occurred_at ON audit_events(occurred_at DESC);
        CREATE INDEX IF NOT EXISTS ix_audit_events_action ON audit_events(action);

        CREATE TRIGGER IF NOT EXISTS audit_events_no_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events are append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events are append-only');
        END;
        """,
    ),
)
