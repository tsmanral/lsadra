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

# base.txt and ci-tools.txt first: ml/ui/dev are constrained to base's pins
# (-c base.txt), and dev takes ruff at CI's version (-c ci-tools.txt).
compile base.in "${extra[@]}"
compile ci-tools.in "${extra[@]}"
compile ml.in "${extra[@]}"
compile ui.in "${extra[@]}"
compile dev.in "${extra[@]}"
