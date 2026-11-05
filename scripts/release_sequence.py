#!/usr/bin/env python3
"""Persistent, fail-closed sequence reservation for verified release admission.

This is administrative state, not a signature or activation record. Production
use requires a root-owned local Linux filesystem and the same state directory
for every admission of a repository/platform. Never restore an older copy.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid


def trusted_path(path: Path, *, private: bool = False) -> None:
    """Reject links and paths writable by another account on production Linux."""
    path = path.absolute()
    for current in (path, *path.parents):
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("trusted admission path contains a symbolic link")
        if current == path and not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError("trusted admission path is not a regular file or directory")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("trusted admission file has multiple hard links")
        if os.name == "posix":
            sticky_root_parent = (current != path and info.st_uid == 0
                                  and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not sticky_root_parent)):
                raise ValueError("trusted admission path has unsafe ownership or permissions")
            if current == path and private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise ValueError("release sequence state must be private to its administrative owner")


def sync_directory(path: Path) -> None:
    # Windows exercises logic/locking only; production durability is Linux-only.
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def sync_payload(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            # Windows _commit requires a write-capable descriptor as well.
            with path.open("r+b") as stream:
                os.fsync(stream.fileno())
    directories = [p for p in root.rglob("*") if p.is_dir()]
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        sync_directory(path)
    sync_directory(root)


def _write_state(directory: Path, state: dict) -> None:
    fd, name = tempfile.mkstemp(prefix=".sequence-", dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(state, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "sequence.json")
        sync_directory(directory)
    finally:
        temporary.unlink(missing_ok=True)


def initialize(directory: Path, policy: dict) -> dict:
    """Explicit first provisioning only; an existing or damaged store is never reset."""
    directory = directory.absolute()
    trusted_path(directory.parent)
    directory.mkdir(mode=0o700, exist_ok=False)
    trusted_path(directory, private=True)
    state = {"schema_version": 1, "state_id": uuid.uuid4().hex,
             "repository": policy["repository"], "platform": policy["platform"],
             "highest_verified_sequence": policy["minimum_sequence"] - 1,
             "artifact_sha256": None, "source_commit": None, "policy_sha256": None}
    fd = os.open(directory / "sequence.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, b"0")
        os.fsync(fd)
    finally:
        os.close(fd)
    _write_state(directory, state)
    sync_directory(directory.parent)
    return state


def read_state(directory: Path, policy: dict) -> dict:
    path = directory / "sequence.json"
    trusted_path(path, private=True)
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("release sequence state exceeds size limit")
    state = json.loads(raw)
    if (not isinstance(state, dict) or type(state.get("schema_version")) is not int or state["schema_version"] != 1
            or not {"artifact_sha256", "source_commit", "policy_sha256"}.issubset(state)
            or not isinstance(state.get("state_id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", state["state_id"])
            or state.get("repository") != policy["repository"]
            or state.get("platform") != policy["platform"]
            or type(state.get("highest_verified_sequence")) is not int
            or state["highest_verified_sequence"] < 0):
        raise ValueError("invalid release sequence state or repository/platform mismatch")
    identities = (state.get("artifact_sha256"), state.get("source_commit"), state.get("policy_sha256"))
    if identities != (None, None, None) and any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value)
            for value, length in zip(identities, (64, 40, 64))):
        raise ValueError("invalid release sequence artifact identity")
    return state


@contextmanager
def locked_state(directory: Path, policy: dict):
    """OS lock is released on process death; its inode is never replaced/deleted."""
    directory = directory.absolute()
    trusted_path(directory, private=True)
    lock_path = directory / "sequence.lock"
    trusted_path(lock_path, private=True)
    with lock_path.open("r+b", buffering=0) as lock:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ValueError("release admission is busy or its lock is unavailable") from exc
        try:
            yield read_state(directory, policy)
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def reserve(directory: Path, state: dict, policy: dict, manifest: dict, artifact_sha256: str) -> dict:
    """Called under locked_state, after complete signature/evidence validation.

    Persist BEFORE publishing payload. An interrupted publication consumes the
    sequence; retrying the identical artifact is permitted, lowering it is not.
    """
    number = manifest["release_sequence"]
    if number < max(policy["minimum_sequence"], state["highest_verified_sequence"]):
        raise ValueError("release sequence downgrade rejected by durable state")
    if number == state["highest_verified_sequence"] and (
            state["artifact_sha256"] != artifact_sha256 or state["source_commit"] != manifest["source_commit"]):
        raise ValueError("release sequence is already bound to another artifact")
    updated = {**state, "highest_verified_sequence": number,
               "artifact_sha256": artifact_sha256, "source_commit": manifest["source_commit"],
               "policy_sha256": policy["_sha256"],
               "reserved_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    _write_state(directory, updated)
    return {"state_id": updated["state_id"], "highest_verified_sequence": number,
            "artifact_sha256": artifact_sha256}
