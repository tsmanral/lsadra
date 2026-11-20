"""Start the LSADRA API with the listener policy applied (G-8).

    lsadra-server                     # 127.0.0.1:8000, or as configured
    python -m lsadra.serve            # the same, from a checkout

Use this instead of calling uvicorn directly: it binds loopback by default,
refuses plain HTTP on any other address unless TLS is configured, generated,
or deliberately waived, and prints the certificate fingerprint agents pin.
"""

import sys

from lsadra.security.tls import ListenerPolicyError, activate, plan_listener


def main() -> int:
    import uvicorn

    try:
        plan = plan_listener()
    except ListenerPolicyError as exc:
        print(f"Refusing to start: {exc}", file=sys.stderr)
        return 2
    activate(plan)
    from lsadra.app import app

    kwargs = {"host": plan.host, "port": plan.port}
    if plan.tls:
        kwargs.update(ssl_certfile=plan.certfile, ssl_keyfile=plan.keyfile)
    uvicorn.run(app, **kwargs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
