"""Client IP for throttling and audit rows.

``X-Forwarded-For`` is honoured only when the direct peer is a configured
trusted proxy (LSADRA_TRUSTED_PROXY_IPS), and then only its last entry, the
address that proxy itself saw. Anything else would let a caller pick the IP
its failed logins are counted against.
"""

from starlette.requests import HTTPConnection

from lsadra import config


def client_ip(conn: HTTPConnection) -> str:
    peer = conn.client.host if conn.client else "unknown"
    if peer in config.TRUSTED_PROXY_IPS:
        forwarded = conn.headers.get("x-forwarded-for", "")
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        if hops:
            return hops[-1]
    return peer
