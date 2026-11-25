"""
LSADRA V2 — Optional TCP syslog receiver.

Listens on a TCP port for RFC-5424-ish syslog messages from remote agents
or rsyslog forwarders.  Each line is handed to the Linux parser and inserted
into the database.

This is an *alternative* to the HTTPS ``api_ingestion`` route, kept for
environments where agents push logs via traditional syslog transport.
"""

import logging
import socketserver
from typing import Optional

from lsadra.ingestion.parsers_linux import LinuxSSHParser
from lsadra.storage.database import insert_event

logger = logging.getLogger(__name__)

DEFAULT_PORT = 5514


class _SyslogHandler(socketserver.StreamRequestHandler):
    """Handle one TCP connection, reading lines until the client disconnects."""

    def handle(self) -> None:
        client_ip = self.client_address[0]
        logger.info("Syslog connection from %s", client_ip)
        for raw_line in self.rfile:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            parsed = LinuxSSHParser.parse(line)
            if parsed:
                parsed["source_ip"] = parsed.get("source_ip") or client_ip
                insert_event(parsed)


class SyslogReceiver:
    """
    Threaded TCP syslog receiver.

    Usage::

        receiver = SyslogReceiver(port=5514)
        receiver.start()   # blocks until interrupted
    """

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self._server: Optional[socketserver.TCPServer] = None

    def start(self) -> None:
        """Start listening (blocking)."""
        self._server = socketserver.ThreadingTCPServer((self.host, self.port), _SyslogHandler)
        logger.info("Syslog receiver listening on %s:%d", self.host, self.port)
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Syslog receiver stopped.")
        finally:
            self._server.server_close()

    def stop(self) -> None:
        """Gracefully shut down the receiver."""
        if self._server:
            self._server.shutdown()
