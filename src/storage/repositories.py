"""Repositories for users, sessions, and persistent response control."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from src.storage.database import Database


@dataclass(frozen=True)
class UserRecord:
    user_id: str
    username: str
    password_hash: str
    role: str
    is_active: bool
    created_at: float


@dataclass(frozen=True)
class RuntimeResponseRecord:
    mode: str
    auto_block_enabled: bool
    kill_switch: bool
    updated_by: str | None
    updated_at: float
    reason: str


class UserRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _from_row(row: object) -> UserRecord:
        return UserRecord(
            user_id=row["user_id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=row["role"],
            is_active=bool(row["is_active"]),
            created_at=float(row["created_at"]),
        )

    def create(self, username: str, password_hash: str, role: str) -> UserRecord:
        record = UserRecord(
            user_id=str(uuid.uuid4()),
            username=username.strip(),
            password_hash=password_hash,
            role=role,
            is_active=True,
            created_at=time.time(),
        )
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO users(user_id, username, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.user_id,
                    record.username,
                    record.password_hash,
                    record.role,
                    int(record.is_active),
                    record.created_at,
                ),
            )
        return record

    def get_by_username(self, username: str) -> UserRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username.strip(),),
            ).fetchone()
        return self._from_row(row) if row else None

    def get_by_id(self, user_id: str) -> UserRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        return self._from_row(row) if row else None

    def active_admin_exists(self) -> bool:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM users WHERE role = 'admin' AND is_active = 1 LIMIT 1"
            ).fetchone()
        return row is not None


class SessionRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, jti: str, user_id: str, created_at: float, expires_at: float) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_sessions(jti, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (jti, user_id, created_at, expires_at),
            )

    def is_active(self, jti: str, now: float | None = None) -> bool:
        checked_at = now or time.time()
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM auth_sessions
                WHERE jti = ? AND revoked_at IS NULL AND expires_at > ?
                """,
                (jti, checked_at),
            ).fetchone()
        return row is not None

    def revoke(self, jti: str) -> None:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE auth_sessions SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL",
                (time.time(), jti),
            )


class RuntimeControlRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _from_row(row: object) -> RuntimeResponseRecord:
        return RuntimeResponseRecord(
            mode=row["mode"],
            auto_block_enabled=bool(row["auto_block_enabled"]),
            kill_switch=bool(row["kill_switch"]),
            updated_by=row["updated_by"],
            updated_at=float(row["updated_at"]),
            reason=row["reason"],
        )

    def ensure_safe_default(self) -> RuntimeResponseRecord:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO runtime_response_control(
                    singleton_id, mode, auto_block_enabled, kill_switch,
                    updated_by, updated_at, reason
                ) VALUES (1, 'monitor', 0, 1, NULL, ?, ?)
                """,
                (time.time(), "Release 1 fail-safe default"),
            )
            row = connection.execute(
                "SELECT * FROM runtime_response_control WHERE singleton_id = 1"
            ).fetchone()
        return self._from_row(row)

    def get(self) -> RuntimeResponseRecord:
        return self.ensure_safe_default()

    def update(
        self,
        *,
        mode: str,
        auto_block_enabled: bool,
        kill_switch: bool,
        updated_by: str | None,
        reason: str,
    ) -> RuntimeResponseRecord:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE runtime_response_control
                SET mode = ?, auto_block_enabled = ?, kill_switch = ?,
                    updated_by = ?, updated_at = ?, reason = ?
                WHERE singleton_id = 1
                """,
                (
                    mode,
                    int(auto_block_enabled),
                    int(kill_switch),
                    updated_by,
                    time.time(),
                    reason,
                ),
            )
            row = connection.execute(
                "SELECT * FROM runtime_response_control WHERE singleton_id = 1"
            ).fetchone()
        return self._from_row(row)
