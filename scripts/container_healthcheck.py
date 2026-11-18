"""Container health probe for the API (Dockerfile HEALTHCHECK).

The launcher (`python -m lsadra.serve`) serves plain HTTP when it is allowed
to (e.g. docker compose), otherwise TLS, by default with a self-signed
certificate. Try HTTP first, then HTTPS on loopback without verifying the
certificate: the probe only asks whether this container's own server answers.
"""

import ssl
import sys
import urllib.request

URL = "127.0.0.1:8000/api/health"


def main() -> int:
    try:
        urllib.request.urlopen(f"http://{URL}", timeout=4)  # noqa: S310 - fixed loopback URL
        return 0
    except Exception:  # noqa: BLE001, S110 - fall through to TLS
        pass
    ctx = ssl._create_unverified_context()  # noqa: S323 - loopback self-check of our own listener
    try:
        urllib.request.urlopen(f"https://{URL}", timeout=4, context=ctx)  # noqa: S310
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
