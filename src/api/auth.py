"""Local JWT session authentication and role checks."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

import bcrypt
from jose import JWTError, jwt

from src.storage.repositories import SessionRepository, UserRecord, UserRepository

SESSION_COOKIE_NAME = "ddos_session"


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


ROLE_RANK = {
    Role.VIEWER: 1,
    Role.ANALYST: 2,
    Role.ADMIN: 3,
}


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: str
    username: str
    role: Role
    jti: str

    def to_dict(self) -> dict[str, str]:
        return {"user_id": self.user_id, "username": self.username, "role": self.role.value}


class AuthService:
    def __init__(
        self,
        users: UserRepository,
        sessions: SessionRepository,
        *,
        secret_key: str,
        algorithm: str,
        expiration_minutes: int,
    ) -> None:
        self.users = users
        self.sessions = sessions
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.expiration_minutes = expiration_minutes
    def hash_password(self, password: str) -> str:
        encoded = password.encode("utf-8")
        if len(encoded) > 72:
            raise ValueError("bcrypt passwords must not exceed 72 bytes")
        return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        encoded = password.encode("utf-8")
        if len(encoded) > 72:
            return False
        try:
            return bcrypt.checkpw(encoded, password_hash.encode("utf-8"))
        except ValueError:
            return False

    def create_user(self, username: str, password: str, role: Role) -> UserRecord:
        return self.users.create(username, self.hash_password(password), role.value)

    def login(self, username: str, password: str) -> tuple[str, AuthenticatedUser, float] | None:
        record = self.users.get_by_username(username)
        if record is None or not record.is_active or not self._verify_password(password, record.password_hash):
            return None
        created_at = time.time()
        expires_at = created_at + self.expiration_minutes * 60
        jti = str(uuid.uuid4())
        self.sessions.create(jti, record.user_id, created_at, expires_at)
        token = jwt.encode(
            {
                "sub": record.user_id,
                "role": record.role,
                "jti": jti,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=self.expiration_minutes),
            },
            self.secret_key,
            algorithm=self.algorithm,
        )
        return (
            token,
            AuthenticatedUser(record.user_id, record.username, Role(record.role), jti),
            expires_at,
        )

    def authenticate_token(self, token: str | None) -> AuthenticatedUser | None:
        if not token:
            return None
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id = str(payload["sub"])
            jti = str(payload["jti"])
        except (JWTError, KeyError, ValueError):
            return None
        record = self.users.get_by_id(user_id)
        if record is None or not record.is_active or not self.sessions.is_active(jti):
            return None
        try:
            role = Role(record.role)
        except ValueError:
            return None
        return AuthenticatedUser(record.user_id, record.username, role, jti)

    def logout(self, token: str | None) -> AuthenticatedUser | None:
        user = self.authenticate_token(token)
        if user is not None:
            self.sessions.revoke(user.jti)
        return user

    @staticmethod
    def has_role(user: AuthenticatedUser, required: Role) -> bool:
        return ROLE_RANK[user.role] >= ROLE_RANK[required]
