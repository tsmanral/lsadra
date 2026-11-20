"""Entry point of the self-contained lsadra-server the desktop app bundles.

PyInstaller freezes this file, the lsadra package and its dependencies into
one folder, so the desktop installer needs no Python. It runs exactly what
``lsadra-server`` runs (``lsadra.serve.main``), with one extra rule: inside
the bundle the package sits in a read-only install folder, so the server
refuses to start unless LSADRA_DATA_DIR names a data folder. The desktop app
always sets it.

``lsadra-server --self-test`` checks the frozen bundle instead of serving:
the app imports, the Sigma rules and signed intel bundle load, and a model
trained on the shipped demo corpus passes the canary. CI runs it on every
build, because a module or data file PyInstaller missed only shows up at
run time.
"""

import multiprocessing
import os
import sys


def self_test() -> int:
    import tempfile

    os.environ["LSADRA_DEV_MODE"] = "true"
    os.environ["LSADRA_DATA_DIR"] = tempfile.mkdtemp(prefix="lsadra-self-test-")
    os.environ["LSADRA_SCHEDULER_ENABLED"] = "false"

    import lsadra.app  # noqa: F401  every router and its imports
    from lsadra import __version__
    from lsadra.detection import model_lifecycle
    from lsadra.detection.sigma_engine import SigmaEngine
    from lsadra.intel import bundle
    from lsadra.models.autoencoder_model import AutoencoderModel
    from lsadra.models.ensemble_model import EnsembleModel

    problems = []
    rules = len(SigmaEngine().rules)
    if rules == 0:
        problems.append("no Sigma rules loaded")
    if bundle.load() is None:
        problems.append(f"intel bundle did not verify: {bundle.status()}")
    frame = model_lifecycle._canary_frame("benign_background")
    if frame is None:
        problems.append("canary corpus missing")
    else:
        ensemble, autoencoder = EnsembleModel(), AutoencoderModel()
        ensemble.train(frame[0])
        autoencoder.train(frame[0])
        canary = model_lifecycle.run_canary(ensemble, autoencoder)
        if not canary["passed"]:
            problems.append(f"canary failed: {canary}")
    for problem in problems:
        print(f"self-test: {problem}", file=sys.stderr)
    print(f"lsadra-server {__version__} self-test: {rules} Sigma rules, "
          f"{'FAILED' if problems else 'ok'}")
    return 1 if problems else 0


def main() -> int:
    multiprocessing.freeze_support()
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if not os.environ.get("LSADRA_DATA_DIR", "").strip():
        print(
            "Refusing to start: set LSADRA_DATA_DIR to the folder for the database "
            "and models. The LSADRA desktop app sets it for you.",
            file=sys.stderr,
        )
        return 2
    from lsadra.serve import main as serve

    return serve()


if __name__ == "__main__":
    sys.exit(main())
