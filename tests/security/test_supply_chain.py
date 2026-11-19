"""Supply-chain guards (audit gaps G-20, G-21, G-22).

These pin the properties that make an install or a release reproducible and
tamper-evident, so a later edit cannot quietly drop them:

* every Python dependency is pinned to one version and checked by hash;
* the container runs as a non-root user on a digest-pinned base image;
* every third-party GitHub Action is pinned to a full commit SHA;
* a release publishes only after the full CI suite passes, with an SBOM,
  provenance and a signature.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
REQ_DIR = ROOT / "requirements"
WORKFLOWS = ROOT / ".github" / "workflows"


def _lock_entries(path: Path) -> list[str]:
    """Return each requirement entry, with its --hash continuation lines joined."""
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "-")):
            entries.append(line)
    return entries


def test_root_requirements_only_includes_locks():
    lines = [
        ln.strip()
        for ln in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert lines, "requirements.txt is empty"
    for ln in lines:
        assert ln.startswith("-r requirements/") and ln.endswith(".txt"), ln


def test_every_lock_pins_exact_versions_with_hashes():
    locks = sorted(REQ_DIR.glob("*.txt"))
    names = {p.stem for p in locks}
    assert {"base", "ml", "dev", "ci-tools"} <= names
    for lock in locks:
        assert (REQ_DIR / f"{lock.stem}.in").exists(), f"{lock.name} has no .in source"
        entries = _lock_entries(lock)
        assert entries, f"{lock.name} pins nothing"
        for entry in entries:
            assert re.match(r"^[A-Za-z0-9_.\-\[\],]+==\S+", entry), f"{lock.name}: not pinned: {entry}"
            assert "--hash=sha256:" in entry, f"{lock.name}: no hash: {entry.split()[0]}"


def test_no_lock_installs_torch_or_uses_another_index():
    """PyTorch is not a dependency (the autoencoder is a scikit-learn MLP).

    Importing torch cost ~900 MB of server RSS on Linux, so a lock that pulls
    it back in would break the M1 600 MB limit. Every lock resolves from PyPI
    only: no file may point pip at a different or extra index.
    """
    for lock in sorted(REQ_DIR.glob("*.txt")):
        text = lock.read_text(encoding="utf-8")
        names = [e.split("==")[0].lower() for e in _lock_entries(lock)]
        assert "torch" not in names, f"{lock.name} pins torch"
        index_lines = [
            ln for ln in text.splitlines() if ln.startswith(("--index-url", "--extra-index-url"))
        ]
        assert index_lines == [], f"{lock.name} sets a package index: {index_lines}"


def test_dockerfile_is_digest_pinned_and_non_root():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    froms = re.findall(r"^FROM\s+(\S+)", text, flags=re.MULTILINE)
    assert len(froms) >= 2, "expected a two-stage build"
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"base image not digest-pinned: {image}"
    users = re.findall(r"^USER\s+(\S+)", text, flags=re.MULTILINE)
    assert users, "no USER instruction: the container would run as root"
    assert users[-1].split(":")[0] not in {"0", "root"}
    assert "HEALTHCHECK" in text
    # The runtime stage installs no OS packages (no compilers, no curl).
    runtime = text.split("AS runtime", 1)[1]
    assert "apt-get" not in runtime


def test_frontend_image_is_digest_pinned():
    text = (ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    froms = re.findall(r"^FROM\s+(\S+)", text, flags=re.MULTILINE)
    assert froms
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"base image not digest-pinned: {image}"


def test_actions_are_pinned_to_commit_shas():
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        for ref in re.findall(r"^\s*-?\s*uses:\s*(\S+)", wf.read_text(encoding="utf-8"), flags=re.MULTILINE):
            if ref.startswith("./"):
                continue
            assert re.search(r"@[0-9a-f]{40}$", ref), f"{wf.name}: action not SHA-pinned: {ref}"


def test_release_is_gated_signed_and_attested():
    wf = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    assert wf.get("permissions") == {}, "release.yml must grant nothing at the top level"
    jobs = wf["jobs"]
    assert jobs["verify"]["uses"] == "./.github/workflows/ci.yml"
    image = jobs["docker-image"]
    assert image["needs"] == "verify"
    assert image["environment"] == "release"
    assert image["permissions"]["id-token"] == "write"
    steps = image["steps"]
    build = next(s for s in steps if "docker/build-push-action" in s.get("uses", ""))
    assert build["with"]["sbom"] is True
    assert build["with"]["provenance"] == "mode=max"
    assert any("actions/attest-build-provenance" in s.get("uses", "") for s in steps)
    assert any("cosign sign" in s.get("run", "") for s in steps)
    assert "docker-image" in str(jobs["github-release"]["needs"])


def test_ci_installs_dependencies_by_hash():
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    dev = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert [ln for ln in dev.splitlines() if ln.strip() and not ln.startswith("#")] == ["-r requirements/dev.txt"]
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        for cmd in re.findall(r"pip install[^\n]*", wf.read_text(encoding="utf-8")):
            assert "--require-hashes" in cmd, f"{wf.name}: unhashed install: {cmd}"
    assert "workflow_call" in ci
