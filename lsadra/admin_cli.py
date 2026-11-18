"""Create or promote LSADRA dashboard admins from the command line.

Self-registration through the dashboard always creates ANALYST accounts. An
admin is made by someone with shell access to the server, which is the only
party that should be able to grant that role on a fresh install:

    python -m lsadra.admin_cli create-admin --username alice
    python -m lsadra.admin_cli promote --username bob

``create-admin`` prompts for the password (or reads one line from stdin with
``--password-stdin``, for scripts and containers). ``promote`` turns an existing
account into an admin. Both work on the same database the server uses
(``data/sentinel_v3.db``), and create it if it doesn't exist yet. Once one admin
exists, further role changes can also be made from the dashboard's Admin page.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import uuid
from typing import List, Optional

MIN_PASSWORD_LENGTH = 12


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise SystemExit("error: passwords do not match")
    return first


def create_admin(username: str, password: str) -> str:
    """Create an ADMIN account and return its user id. Raises ValueError on bad input."""
    from lsadra.auth import hash_password
    from lsadra.storage.database import create_user, get_user_by_username, init_db

    username = username.strip()
    if not username:
        raise ValueError("username must not be empty")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    init_db()
    if get_user_by_username(username):
        raise ValueError(f"user '{username}' already exists; use `promote` instead")
    user_id = str(uuid.uuid4())
    create_user(user_id, username, hash_password(password), "ADMIN")
    return user_id


def promote(username: str) -> str:
    """Give an existing account the ADMIN role and return its user id."""
    from lsadra.storage.database import get_user_by_username, init_db, update_user_role

    init_db()
    user = get_user_by_username(username.strip())
    if not user:
        raise ValueError(f"no user named '{username}'")
    update_user_role(user["id"], "ADMIN")
    return user["id"]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lsadra.admin_cli", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create-admin", help="create a new admin account")
    p_create.add_argument("--username", required=True)
    p_create.add_argument("--password-stdin", action="store_true",
                          help="read the password from the first line of stdin instead of prompting")

    p_promote = sub.add_parser("promote", help="make an existing account an admin")
    p_promote.add_argument("--username", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "create-admin":
            create_admin(args.username, _read_password(args.password_stdin))
            print(f"Created admin '{args.username.strip()}'.")
        else:
            promote(args.username)
            print(f"'{args.username.strip()}' is now an admin. Existing sessions keep their old role until they log in again.")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
