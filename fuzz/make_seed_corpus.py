"""Write the Atheris seed corpus from fuzz/seeds.py into a zip.

Each entry is one selector byte (which parser) followed by a synthetic line.
Usage: python fuzz/make_seed_corpus.py <out.zip>
"""

import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fuzz.seeds import (  # noqa: E402
    ALL_SEEDS,
    ENDPOINT_SEEDS,
    NETWORK_SEEDS,
    SSH_SEEDS,
    SYSLOG_SEEDS,
    WINDOWS_SEEDS,
)

# Selector bytes match the parser order in fuzz_parsers.py.
GROUPS = [
    (0, SYSLOG_SEEDS),
    (1, WINDOWS_SEEDS),
    (2, NETWORK_SEEDS),
    (3, ENDPOINT_SEEDS),
    (4, SSH_SEEDS),
    (5, SSH_SEEDS + SYSLOG_SEEDS),
    (6, WINDOWS_SEEDS),
    (7, ALL_SEEDS),
]


def main(out_path: str) -> None:
    with zipfile.ZipFile(out_path, "w") as zf:
        n = 0
        for selector, seeds in GROUPS:
            for seed in seeds:
                zf.writestr(f"seed-{n:03d}", bytes([selector]) + seed.encode("utf-8"))
                n += 1
    print(f"wrote {n} seeds to {out_path}")


if __name__ == "__main__":
    main(sys.argv[1])
