#!/bin/bash -eu
# Build every Atheris target under fuzz/ (gap G-24). The parsers use only the
# standard library, so no project dependencies are installed.
export PYTHONPATH="$SRC/lsadra"
for fuzzer in $(find "$SRC/lsadra/fuzz" -name 'fuzz_*.py'); do
  name=$(basename -s .py "$fuzzer")
  compile_python_fuzzer "$fuzzer"
  python3 "$SRC/lsadra/fuzz/make_seed_corpus.py" "$OUT/${name}_seed_corpus.zip"
done
