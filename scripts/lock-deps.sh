#!/usr/bin/env bash
# Regenerate the hash-locked requirement files from requirements/*.in.
#
#   scripts/lock-deps.sh            # re-resolve keeping current pins where possible
#   scripts/lock-deps.sh --upgrade  # move every pin to the newest allowed version
#
# Needs uv (https://docs.astral.sh/uv/). Locks are universal: one file serves
# Linux, Windows and macOS on Python 3.12+, with a hash for every wheel.
set -euo pipefail
cd "$(dirname "$0")/../requirements"

compile() {
  local in="$1"; shift
  uv pip compile "$in" -o "${in%.in}.txt" \
    --universal --python-version 3.12 --generate-hashes \
    "$@"
}

extra=()
[[ "${1:-}" == "--upgrade" ]] && extra+=(--upgrade)

# base.txt first: ml/ui/dev are constrained to its pins (-c base.txt).
compile base.in "${extra[@]}"
compile ml.in "${extra[@]}"
compile ui.in "${extra[@]}"
compile dev.in "${extra[@]}"
compile ci-tools.in "${extra[@]}"
# torch comes from the CPU wheel index only. --emit-index-url writes that
# index into torch.txt so pip never looks at PyPI for it. --no-deps: its
# dependencies are locked in ml.in from PyPI; install torch.txt with
# `pip install --no-deps --require-hashes -r requirements/torch.txt`.
compile torch.in "${extra[@]}" --no-deps \
  --index-url https://download.pytorch.org/whl/cpu --emit-index-url
