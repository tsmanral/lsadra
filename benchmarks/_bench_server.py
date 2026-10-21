"""
Launch the real LSADRA core against a throwaway data directory.

Used only by ``run_ingest_bench.py``, which starts it as a subprocess. It runs
the unmodified ``server:app`` under uvicorn's defaults (as the Dockerfile CMD
does) — the only difference is that the database and model directory point at
``--data-dir`` instead of ``<repo>/data``, done the same way the test suite
does it (patch ``lsadra.config`` before ``lsadra.storage.database`` is
imported), so a benchmark can never touch a developer's real database.

With ``--trace-file`` it also installs ``_bench_trace.py`` (per-request
timings, detection runs, garbage collections), wrapping the core from outside.

Requires ``LSADRA_DEV_MODE=true`` in the environment (the harness sets it).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--trace-file", default=None,
                        help="write per-request timing records here (_bench_trace.py)")
    args = parser.parse_args()

    if os.environ.get("LSADRA_DEV_MODE", "").lower() != "true":
        raise SystemExit("benchmark server refuses to run outside LSADRA_DEV_MODE=true")

    data_dir = Path(args.data_dir).resolve()
    (data_dir / "models").mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(REPO_ROOT))
    # server.py's lifespan creates ./data/models relative to the cwd; keep that
    # inside the throwaway directory too.
    os.chdir(data_dir)

    import lsadra.config as config

    config.DATA_DIR = data_dir
    config.DB_PATH = data_dir / "bench.db"
    config.MODEL_DIR = data_dir / "models"

    import uvicorn

    import server  # noqa: E402 — must follow the config patch

    app = server.app
    if args.trace_file:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import _bench_trace

        app = _bench_trace.install(args.trace_file, server)
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
