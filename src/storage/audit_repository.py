"""Append-only security audit event repository with a verifiable hash chain."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from src.storage.database import Database


class AuditRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _hash_payload(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append(
        self,
        *,
        action: str,
        target_type: str,
        outcome: str,
        actor_user_id: str | None = None,
        actor_role: str | None = None,
        target_id: str | None = None,
        reason: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {
            "event_id": str(uuid.uuid4()),
            "occurred_at": time.time(),
            "actor_user_id": actor_user_id,
            "actor_role": actor_role,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "reason": reason,
            "outcome": outcome,
            "request_id": request_id,
            "details_json": json.dumps(details or {}, sort_keys=True, separators=(",", ":")),
        }
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            event["previous_hash"] = previous["event_hash"] if previous else None
            event["event_hash"] = self._hash_payload(event)
            connection.execute(
                """
                INSERT INTO audit_events(
                    event_id, occurred_at, actor_user_id, actor_role, action, target_type,
                    target_id, reason, outcome, request_id, details_json, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(event[key] for key in (
                    "event_id", "occurred_at", "actor_user_id", "actor_role", "action",
                    "target_type", "target_id", "reason", "outcome", "request_id",
                    "details_json", "previous_hash", "event_hash",
                )),
            )
        return event

    def list(
        self,
        *,
        limit: int = 100,
        action: str | None = None,
        since: float | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if action:
            clauses.append("action = ?")
            values.append(action)
        if since is not None:
            clauses.append("occurred_at >= ?")
            values.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(max(1, min(limit, 500)))
        with self.database.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM audit_events {where} ORDER BY occurred_at DESC LIMIT ?",
                values,
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_chain(self) -> bool:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY rowid ASC"
            ).fetchall()
        previous_hash: str | None = None
        for row in rows:
            payload = {
                key: row[key]
                for key in (
                    "event_id", "occurred_at", "actor_user_id", "actor_role", "action",
                    "target_type", "target_id", "reason", "outcome", "request_id", "details_json",
                )
            }
            payload["previous_hash"] = previous_hash
            if row["previous_hash"] != previous_hash or row["event_hash"] != self._hash_payload(payload):
                return False
            previous_hash = row["event_hash"]
        return True
