"""Compatibility entry point: the application lives in :mod:`lsadra.app`.

``import server`` returns the very same module object as ``import lsadra.app``,
so ``uvicorn server:app``, ``server.app`` and ``unittest.mock.patch("server.X")``
keep working. ``python server.py`` starts the server with the same listener
policy as ``lsadra-server`` (loopback by default, G-8).
"""

import sys

if __name__ == "__main__":
    from lsadra.serve import main

    sys.exit(main())

import lsadra.app as _app  # noqa: E402

sys.modules[__name__] = _app
