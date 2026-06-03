"""Bootstrap the first local administrator account."""

from __future__ import annotations

import getpass

from src.api.auth import AuthService, Role
from src.config.settings import get_settings
from src.storage.database import Database
from src.storage.repositories import SessionRepository, UserRepository


def main() -> int:
    settings = get_settings()
    database = Database(settings.database.database_url)
    database.initialize()
    users = UserRepository(database)
    if users.active_admin_exists():
        print("An active Admin account already exists; bootstrap is disabled.")
        return 1
    username = input("Admin username: ").strip()
    if not username:
        print("Username is required.")
        return 1
    password = getpass.getpass("Admin password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        print("Password must be at least 12 characters.")
        return 1
    if len(password.encode("utf-8")) > 72:
        print("Password must not exceed 72 bytes for bcrypt storage.")
        return 1
    if password != confirmation:
        print("Passwords do not match.")
        return 1
    auth = AuthService(
        users,
        SessionRepository(database),
        secret_key=settings.jwt.jwt_secret_key,
        algorithm=settings.jwt.jwt_algorithm,
        expiration_minutes=settings.jwt.jwt_expiration_minutes,
    )
    auth.create_user(username, password, Role.ADMIN)
    print("Initial Admin account created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
