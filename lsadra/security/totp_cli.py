"""Enrol or remove an authenticator from the server's command line (G-33).

    python -m lsadra.security.totp_cli enroll <username>
    python -m lsadra.security.totp_cli remove <username>
    python -m lsadra.security.totp_cli status

``enroll`` prints a secret and an otpauth:// URI to add to any authenticator
app, then asks for one code to confirm before turning TOTP on. Runs against the
local database, so only someone with shell access to the server can use it;
this is how an admin enrols when LSADRA_ADMIN_TOTP=required blocks a login
without a code. Every change is written to the audit trail.
"""

import argparse
import logging
import sys

from lsadra import config

logger = logging.getLogger(__name__)


def warn_if_admin_without_totp() -> int:
    """Log a warning when the API listens beyond loopback and an admin has no TOTP."""
    from lsadra.security.tls import is_loopback
    from lsadra.storage.database import list_users

    if is_loopback(config.API_HOST):
        return 0
    try:
        bare = [u["username"] for u in list_users()
                if u.get("role") == "ADMIN" and not u.get("totp_enabled") and not u.get("disabled")]
    except Exception:
        logger.exception("Could not check admin TOTP enrolment")
        return 0
    if bare:
        logger.warning(
            "LSADRA listens on %s and %d admin account(s) have no authenticator: %s. "
            "Enrol with: python -m lsadra.security.totp_cli enroll <username>, "
            "and consider LSADRA_ADMIN_TOTP=required.",
            config.API_HOST, len(bare), ", ".join(sorted(bare)),
        )
    return len(bare)


def main(argv=None) -> int:
    from lsadra.security import audit, totp
    from lsadra.storage.database import (
        bump_token_version,
        get_user_by_username,
        init_db,
        list_users,
        set_user_totp,
    )

    parser = argparse.ArgumentParser(prog="python -m lsadra.security.totp_cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("enroll", "remove"):
        p = sub.add_parser(name)
        p.add_argument("username")
    sub.add_parser("status")
    args = parser.parse_args(argv)

    init_db()
    actor = {"user_id": None, "username": "server-cli"}
    if args.cmd == "status":
        for u in list_users():
            print(f"{u['username']:<24} {u['role']:<8} totp={'on' if u.get('totp_enabled') else 'off'}")
        return 0

    user = get_user_by_username(args.username)
    if user is None:
        print(f"No such user: {args.username}", file=sys.stderr)
        return 1

    if args.cmd == "remove":
        set_user_totp(user["id"], None, enabled=False)
        bump_token_version(user["id"])
        audit.record("user.totp.disable", actor=actor, target=user["username"],
                     details={"via": "server-cli"})
        print(f"Authenticator removed for {user['username']}; their sessions were ended.")
        return 0

    secret = totp.generate_secret()
    print(f"Secret:  {secret}")
    print(f"URI:     {totp.provisioning_uri(secret, user['username'])}")
    code = input("Enter the 6-digit code your app shows now: ").strip()
    if totp.verify(secret, code) is None:
        print("That code did not match. Nothing was changed.", file=sys.stderr)
        return 1
    set_user_totp(user["id"], secret, enabled=True)
    audit.record("user.totp.enable", actor=actor, target=user["username"],
                 details={"via": "server-cli"})
    print(f"Authenticator enrolled for {user['username']}; their earlier sessions were ended.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
