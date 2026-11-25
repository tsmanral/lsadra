"""
Command line for LSADRA threat intel.

    python -m lsadra.intel status          # what is loaded, verified, enabled
    python -m lsadra.intel verify [DIR]    # verify a bundle directory (default: packaged)
    python -m lsadra.intel update-feeds    # fetch the feeds in LSADRA_INTEL_FEEDS
    python -m lsadra.intel geo-update      # download a local geolocation database

Maintainer commands (the refresh workflow runs these):

    python -m lsadra.intel build --out DIR [--if-changed]
    python -m lsadra.intel sign DIR        # key from env LSADRA_INTEL_SIGNING_KEY
    python -m lsadra.intel keygen          # new pair; private half to stdout only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m lsadra.intel")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    v = sub.add_parser("verify")
    v.add_argument("dir", nargs="?")
    sub.add_parser("update-feeds")
    sub.add_parser("geo-update")
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    b.add_argument(
        "--if-changed",
        action="store_true",
        help="exit 3 without writing when upstream data is unchanged",
    )
    s = sub.add_parser("sign")
    s.add_argument("dir")
    sub.add_parser("keygen")
    args = p.parse_args(argv)

    if args.cmd == "status":
        from lsadra import intel

        _print(intel.status())
        return 0

    if args.cmd == "verify":
        from lsadra.intel import bundle

        d = Path(args.dir) if args.dir else bundle.PACKAGED_DIR
        try:
            vb = bundle.verify_dir(d)
        except bundle.BundleError as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            return 1
        print(f"OK: {vb.sqlite_path.name} signed by {vb.key_id}")
        return 0

    if args.cmd == "update-feeds":
        from lsadra.intel import feeds

        results = feeds.update_feeds()
        if not results:
            print("No feeds enabled. Set LSADRA_INTEL_FEEDS, e.g. feodo,spamhaus_drop,tor_exits")
            return 0
        _print(results)
        return 1 if any(r["status"] == "error" for r in results) else 0

    if args.cmd == "geo-update":
        from lsadra.intel import geo

        path = geo.download()
        print(f"Wrote {path}")
        _print(geo.status())
        return 0

    if args.cmd == "build":
        import tempfile
        import shutil
        from lsadra.intel import build, bundle

        out = Path(args.out)
        old = out / bundle.MANIFEST_NAME
        old_text = old.read_text(encoding="utf-8") if old.is_file() else ""
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build.build(Path(tmp))
            if args.if_changed and old_text and build.upstream_unchanged(manifest, old_text):
                print("Upstream sources unchanged; nothing to do.")
                return 3
            out.mkdir(parents=True, exist_ok=True)
            for f in out.glob("intel-*.sqlite"):
                f.unlink()
            for name in (bundle.SIGNATURE_NAME,):
                if (out / name).exists():
                    (out / name).unlink()
            for f in Path(tmp).iterdir():
                shutil.copy2(f, out / f.name)
        _print({k: manifest[k] for k in ("file", "sha256", "size", "built_at")})
        return 0

    if args.cmd == "sign":
        from lsadra.intel import build

        key = os.environ.get("LSADRA_INTEL_SIGNING_KEY", "")
        if not key:
            print("LSADRA_INTEL_SIGNING_KEY is not set", file=sys.stderr)
            return 2
        print(f"Signed with {build.sign_dir(Path(args.dir), key)}")
        return 0

    if args.cmd == "keygen":
        from lsadra.intel import signing

        key_id, priv, pub = signing.generate_keypair()
        print(f"key_id:      {key_id}", file=sys.stderr)
        print(f"public_key:  {pub}", file=sys.stderr)
        print(
            "Add the public key to lsadra/intel/trusted_keys.json; store the private key "
            "(stdout) as the LSADRA_INTEL_SIGNING_KEY secret. Never commit it.",
            file=sys.stderr,
        )
        print(priv)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
