#!/usr/bin/env python3
"""Verify and stage a release in a NEW directory, without activating services.

The policy must be provisioned through a trusted administrative channel. Neither
the downloaded archive nor an API request can change the repository, source
allowlist, platform or monotonic release floor. Requires Python 3.10+ and gh.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile

import release_security as security
import release_sequence as sequence

MAX_ARCHIVE = 2 * 1024**3
MAX_EXPANDED = 4 * 1024**3
MAX_FILES = 10000


def file_identity(info):
    # Windows stat/fstat legacy ctime values may differ; Linux retains ctime.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns if os.name == 'posix' else None)


def copy_candidate(artifact: Path, candidate: Path) -> None:
    """Bounded private copy; no symlinks, hard links, special files or read races."""
    before = artifact.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_ARCHIVE:
        raise ValueError('candidate must be a regular, single-link file within the size limit')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(artifact, flags), 'rb') as src, candidate.open('xb') as out:
        if file_identity(before) != file_identity(os.fstat(src.fileno())):
            raise ValueError('candidate changed before private copy')
        size = 0
        while block := src.read(1024 * 1024):
            size += len(block)
            if size > MAX_ARCHIVE:
                raise ValueError('candidate exceeds size limit')
            out.write(block)
        if (size != before.st_size or file_identity(before) != file_identity(os.fstat(src.fileno()))
                or file_identity(before) != file_identity(artifact.lstat())):
            raise ValueError('candidate changed during private copy')
    candidate.chmod(0o600)


def load_policy(path: Path, commit: str | None = None) -> dict:
    sequence.trusted_path(path)
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("trusted release policy exceeds size limit")
    policy = json.loads(raw)
    if (not isinstance(policy, dict) or type(policy.get('schema_version')) is not int
            or policy.get("schema_version") != 1
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", policy.get("repository", ""))
            or policy.get("platform") not in ("linux-amd64", "linux-arm64")
            or type(policy.get("minimum_sequence")) is not int or policy["minimum_sequence"] < 1
            or not isinstance(policy.get("allowed_commits"), list)
            or not policy["allowed_commits"]
            or any(not isinstance(c, str) or not re.fullmatch(r"[0-9a-f]{40}", c)
                   for c in policy["allowed_commits"])):
        raise ValueError("invalid trusted release policy")
    if commit is not None and commit not in policy["allowed_commits"]:
        raise ValueError("source commit is not authorized by trusted policy")
    policy["_sha256"] = hashlib.sha256(raw).hexdigest()
    return policy


def extract_checked(archive: Path, destination: Path) -> None:
    """No links, devices, path escapes, duplicate names or unbounded extraction."""
    seen, total = set(), 0
    with tarfile.open(archive, "r:gz") as source:
        for count, member in enumerate(source, 1):
            if count > MAX_FILES:
                raise ValueError("too many archive entries")
            name = PurePosixPath(member.name)
            if member.name in (".", "./") and member.isdir():
                continue
            if (name.is_absolute() or ".." in name.parts or not name.parts
                    or "\\" in member.name or ":" in member.name
                    or any(p.rstrip(". ") != p for p in name.parts)):
                raise ValueError("unsafe archive path")
            key = name.as_posix().casefold()
            if key in seen:
                raise ValueError("duplicate archive path")
            seen.add(key)
            target = destination.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.size < 0:
                raise ValueError("archive links and special files are forbidden")
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError("expanded archive exceeds size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as src, target.open("xb") as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)
            # Never accept setuid/setgid or world-writable archive permissions.
            target.chmod(0o755 if name.parts[0] == "bin" else 0o644)
    # mkdir(parents=True) applies the caller's umask to intermediate directories.
    # They must not become group-writable when the private tree is published.
    for path in destination.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)


def validate_payload(stage: Path, policy: dict, commit: str) -> dict:
    manifest = security.read_json(stage / "release.json")
    if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
            or manifest.get("schema_version") != 1 or manifest.get("source_commit") != commit
            or manifest.get("platform") != policy["platform"]
            or manifest.get("repository") != policy["repository"]
            or type(manifest.get("release_sequence")) is not int
            or manifest["release_sequence"] < policy["minimum_sequence"]):
        raise ValueError("release identity, platform or downgrade policy mismatch")
    if (stage / "SOURCE_COMMIT").read_text(encoding="utf-8").strip() != commit:
        raise ValueError("source commit mismatch")
    expected = {}
    for line in (stage / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
        if not match or match[2] in expected:
            raise ValueError("invalid checksum manifest")
        expected[match[2]] = match[1]
    actual = {p.relative_to(stage).as_posix(): security.digest(p)
              for p in stage.rglob("*") if p.is_file() and p != stage / "SHA256SUMS"}
    if expected != actual:
        raise ValueError("payload checksum mismatch or unlisted files")
    if "admission.json" in actual:
        raise ValueError("archive cannot supply its own admission receipt")
    report = security.check(stage / "security", require_clean=True)
    if report["status"] != "passed":
        raise ValueError("candidate evidence blocked: " + "; ".join(report["blockers"]))
    evidence = security.read_json(stage / "security/evidence.json")
    if evidence["source"]["commit"] != commit:
        raise ValueError("scan evidence source commit mismatch")
    return {"manifest": manifest, "payload_sha256": {**actual, "SHA256SUMS": security.digest(stage / "SHA256SUMS")}}


def admit(artifact: Path, policy_path: Path, commit: str, destination: Path, state_dir: Path) -> dict:
    policy = load_policy(policy_path, commit)
    # Normalize lexical '..' components before enforcing disjoint directories.
    # Do not resolve symlinks: trusted_path must still reject them explicitly.
    destination = Path(os.path.abspath(destination))
    state_dir = Path(os.path.abspath(state_dir))
    if (state_dir == destination or state_dir in destination.parents or destination in state_dir.parents):
        raise ValueError("release sequence state must be outside the release destination")
    with sequence.locked_state(state_dir, policy) as state:
        return _admit_locked(artifact, policy_path, commit, destination, state_dir, policy, state)


def _admit_locked(artifact: Path, policy_path: Path, commit: str, destination: Path,
                  state_dir: Path, policy: dict, state: dict) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError("release destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    sequence.trusted_path(destination.parent)
    # Private copy prevents a download being replaced between verification and
    # extraction. No unverified file is ever written into the release directory.
    with tempfile.TemporaryDirectory(prefix=".aegis-admission-", dir=destination.parent) as tmp:
        workspace = Path(tmp)
        candidate = workspace / "candidate.tar.gz"
        copy_candidate(artifact, candidate)
        security.verify_artifact(candidate, policy["repository"], commit)
        stage = workspace / "payload"
        stage.mkdir(mode=0o700)
        extract_checked(candidate, stage)
        result = validate_payload(stage, policy, commit)
        receipt = {"schema_version": 1, "feature_id": "NAS-0116", "status": "admitted",
                   "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                   "artifact_sha256": security.digest(candidate),
                   "policy_sha256": policy["_sha256"],
                   "signature_verified_at_admission": True,
                   "predicates": ["https://slsa.dev/provenance/v1", "https://cyclonedx.org/bom"],
                   "sequence_guard": {"state_id": state["state_id"],
                                      "highest_verified_sequence": result["manifest"]["release_sequence"],
                                      "artifact_sha256": security.digest(candidate)},
                   **result}
        security.write_json(stage / "admission.json", receipt)
        (stage / 'admission.json').chmod(0o644)
        stage.chmod(0o755)
        sequence.sync_payload(stage)
        if load_policy(policy_path, commit)['_sha256'] != policy["_sha256"]:
            raise ValueError("trusted policy changed during admission")
        if destination.exists() or destination.is_symlink():
            raise ValueError("release destination appeared during verification")
        sequence.reserve(state_dir, state, policy, result["manifest"], receipt["artifact_sha256"])
        os.rename(stage, destination)
        sequence.sync_directory(destination.parent)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, nargs="?")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--initialize-state", action="store_true",
                        help="Explicit one-time provisioning; never resets existing state")
    parser.add_argument("--commit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.initialize_state and (args.artifact or args.commit or args.output):
        parser.error("state initialization cannot also admit an artifact")
    if not args.initialize_state and not (args.artifact and args.commit and args.output):
        parser.error("admission requires artifact, --commit and --output")
    try:
        if args.initialize_state:
            state = sequence.initialize(args.state_dir, load_policy(args.policy))
            print(json.dumps(state, indent=2))
            return 0
        receipt = admit(args.artifact, args.policy, args.commit, args.output, args.state_dir)
        print(json.dumps({k: v for k, v in receipt.items() if k != "payload_sha256"}, indent=2))
        return 0
    except Exception as exc:
        print(f"release admission blocked: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
