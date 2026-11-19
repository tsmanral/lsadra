# Python dependencies

Every Python dependency is pinned to one version and checked by hash. pip
refuses a file whose hash is not in the lock, so a tampered or swapped
package on the index cannot be installed.

| Source (`.in`) | Lock (`.txt`) | What it is for |
| --- | --- | --- |
| `base.in` | `base.txt` | The API server (`uvicorn server:app`). A Lite install needs only this. |
| `ml.in` | `ml.txt` | Optional SHAP explanations, plus the dependencies of torch. |
| `ui.in` | `ui.txt` | The legacy Streamlit dashboard and its charts. |
| `dev.in` | `dev.txt` | Tests and the benchmark harness. |
| `torch.in` | `torch.txt` | Optional autoencoder: CPU torch from the PyTorch index only. |
| `ci-tools.in` | `ci-tools.txt` | Tools CI runs: ruff, pip-audit, zizmor. |

`ml`, `ui` and `dev` are constrained to `base.txt` (`-c base.txt`), so shared
packages have one version everywhere. The root `requirements.txt` pulls in
base, ml, ui and dev.

## Install

```bash
pip install -r requirements.txt                    # everything except torch
pip install --no-deps -r requirements/torch.txt    # optional, after the line above
pip install -r requirements/base.txt               # API server only
```

torch installs in its own run because `torch.txt` points pip at the PyTorch
CPU index alone (`--index-url`). It uses `--no-deps` because its dependencies
are already locked in `ml.txt` from PyPI.

## Change a dependency

1. Edit the `.in` file. Never edit a `.txt` lock by hand.
2. Run `scripts/lock-deps.sh` (needs [uv](https://docs.astral.sh/uv/)).
   `--upgrade` moves every pin to the newest allowed version.
3. Commit the `.in` and `.txt` changes together.

The locks are universal: one file serves Linux, Windows and macOS on Python
3.12 and newer, with environment markers where a package differs by platform.
Dependabot proposes updates weekly, and CI runs `pip-audit` on every lock.
