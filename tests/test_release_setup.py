"""Release machinery: one version source, release-please and the release workflow.

These pin the release process so a later edit cannot quietly break it:

* the version lives only in ``lsadra/__init__.py`` and every copy agrees;
* release-please bumps that file, signs off its commits (the DCO check is
  required) and creates only draft releases, so nothing is public before
  release.yml has verified, signed and attested the image;
* release.yml publishes only from a ``v*`` tag, and the release-please
  workflow hands the tag to it explicitly.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCRIPT = ROOT / "scripts" / "release_notes.py"

sys.path.insert(0, str(ROOT / "scripts"))
import release_notes  # noqa: E402


def _on(workflow: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True.
    return workflow.get("on", workflow.get(True))


def test_version_sources_agree():
    assert release_notes.check() == []


def test_version_is_not_hard_coded_elsewhere():
    from lsadra import __version__

    pattern = re.compile(rf"['\"]v?{re.escape(__version__)}['\"]")
    for path in [ROOT / "server.py", *sorted((ROOT / "lsadra").rglob("*.py"))]:
        if path == ROOT / "lsadra" / "__init__.py":
            continue
        assert not pattern.search(path.read_text(encoding="utf-8")), (
            f"{path.relative_to(ROOT)} hard-codes the version; import lsadra.__version__"
        )


def test_release_please_config():
    config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    package = config["packages"]["."]
    assert config["release-type"] == "python"
    assert package["package-name"] == "lsadra"  # bumps lsadra/__init__.py
    assert {"type": "generic", "path": "README.md"} in package["extra-files"]
    # Release-please commits must pass the required DCO check.
    assert re.match(r"^.+ <.+@.+>$", config["signoff"])
    # Draft until release.yml publishes; the tag must still exist for the next run.
    assert config["draft"] is True
    assert config["force-tag-creation"] is True
    assert config["include-v-in-tag"] is True
    # Release PR title must be a Conventional Commit for commitlint.
    assert config["pull-request-title-pattern"].startswith("chore(release): ")


def test_pinned_release_as_is_ahead_of_the_manifest():
    """A leftover release-as would make every later release PR reuse one version."""
    config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    pinned = config["packages"]["."].get("release-as")
    if pinned:
        released = tuple(int(x) for x in release_notes.manifest_version().split("."))
        assert tuple(int(x) for x in pinned.split(".")) > released, (
            f"release-as {pinned} is already released; remove it from release-please-config.json"
        )


def test_release_please_workflow_dispatches_release_on_the_tag():
    wf = yaml.safe_load((WORKFLOWS / "release-please.yml").read_text(encoding="utf-8"))
    assert wf["permissions"] == {}
    assert _on(wf)["push"]["branches"] == ["main"]
    jobs = wf["jobs"]
    step = jobs["release-please"]["steps"][0]
    assert step["uses"].startswith("googleapis/release-please-action@")
    assert step["with"]["config-file"] == "release-please-config.json"
    publish = jobs["publish"]
    assert publish["permissions"] == {"actions": "write"}
    assert "release_created" in publish["if"]
    run = publish["steps"][0]["run"]
    assert "gh workflow run release.yml" in run and '--ref "$TAG"' in run


def test_release_publishes_only_from_a_tag():
    wf = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    on = _on(wf)
    assert on["push"]["tags"] == ["v*"]
    assert "workflow_dispatch" in on
    # Every publishing job hangs off verify, which only runs for a v* tag.
    assert wf["jobs"]["verify"]["if"] == "startsWith(github.ref, 'refs/tags/v')"
    assert wf["jobs"]["docker-image"]["needs"] == "verify"
    assert wf["jobs"]["github-release"]["needs"] == "docker-image"
    assert wf["jobs"]["github-release"]["environment"] == "release"


def test_release_dry_run_never_publishes():
    text = (WORKFLOWS / "release-dry-run.yml").read_text(encoding="utf-8")
    wf = yaml.safe_load(text)
    assert wf["permissions"] == {"contents": "read"}
    for job in wf["jobs"].values():
        for key, value in job.get("permissions", {}).items():
            assert value in ("read", "none"), f"dry run asks for {key}: {value}"
    build = next(
        s for s in wf["jobs"]["image"]["steps"] if "build-push-action" in s.get("uses", "")
    )
    assert build["with"]["push"] is False
    assert "--dry-run" in text
    for forbidden in ("gh release", "git tag", "git push", "cosign sign"):
        assert forbidden not in text


def test_notes_include_hand_written_notes_and_verification(tmp_path):
    out = tmp_path / "notes.md"
    digest = "sha256:" + "0" * 64
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            str(SCRIPT),
            "--tag",
            "v6.0.0",
            "--owner",
            "example",
            "--digest",
            digest,
            "--out",
            str(out),
        ],
        check=True,
    )
    notes = out.read_text(encoding="utf-8")
    assert notes.startswith("## LSADRA v6.0.0")
    assert f"gh attestation verify oci://ghcr.io/example/lsadra@{digest} --owner example" in notes


def test_notes_refuse_a_non_release_tag(tmp_path):
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            str(SCRIPT),
            "--tag",
            "main",
            "--owner",
            "x",
            "--digest",
            "d",
            "--out",
            str(tmp_path / "n.md"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "not a release tag" in proc.stderr


def test_next_release_has_notes():
    nxt = release_notes.next_version()
    assert (
        ROOT / "docs" / "releases" / f"v{nxt}.md"
    ).exists() or nxt == release_notes.package_version()
