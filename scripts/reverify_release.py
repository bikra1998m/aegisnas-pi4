#!/usr/bin/env python3
"""Reverify a staged release against its signed archive and current trusted policy.

This is a point-in-time prerequisite for activation, not an activation command.
It does not update admission/sequence state, install, restart, or restore data.
Requires Python 3.10+ and the GitHub CLI used by the admission verifier.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

import admit_release as admission
import release_security as security
import release_sequence as sequence

MAX_RECEIPT = 4 * 1024**2
PREDICATES = ['https://slsa.dev/provenance/v1', 'https://cyclonedx.org/bom']


def _read_file(path: Path, limit: int, *, retain: bool = False):
    sequence.trusted_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('staged file is not regular or exceeds its size limit')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    digest, parts, size = hashlib.sha256(), [], 0
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        if admission.file_identity(before) != admission.file_identity(os.fstat(stream.fileno())):
            raise ValueError('staged file changed before verification')
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > limit:
                raise ValueError('staged file exceeds its size limit')
            digest.update(block)
            if retain:
                parts.append(block)
        if (size != before.st_size or admission.file_identity(before) != admission.file_identity(os.fstat(stream.fileno()))
                or admission.file_identity(before) != admission.file_identity(path.lstat())):
            raise ValueError('staged file changed during verification')
    return digest.hexdigest(), size, admission.file_identity(before), b''.join(parts)


def _inspect_tree(directory: Path):
    """Bounded enumeration without following links; snapshot ordinary mutations."""
    sequence.trusted_path(directory)
    if not directory.is_dir():
        raise ValueError('release directory must be an existing directory')
    files, directories, states, pending = {}, set(), [], [directory]
    count, total = 0, 0
    while pending:
        parent = pending.pop()
        sequence.trusted_path(parent)
        before = parent.lstat()
        members = set()
        with os.scandir(parent) as entries:
            for item in entries:
                count += 1
                if count > admission.MAX_FILES + 1:
                    raise ValueError('staged tree exceeds entry limit')
                members.add(item.name)
                path = Path(item.path)
                name = path.relative_to(directory).as_posix()
                info = path.lstat()
                sequence.trusted_path(path)
                if stat.S_ISDIR(info.st_mode):
                    directories.add(name)
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    limit = MAX_RECEIPT if name == 'admission.json' else admission.MAX_EXPANDED
                    if total + info.st_size > admission.MAX_EXPANDED + MAX_RECEIPT:
                        raise ValueError('staged tree exceeds byte limit')
                    hashed, size, identity, _ = _read_file(path, limit)
                    total += size
                    files[name] = hashed
                    states.append((path, identity, None))
                else:
                    raise ValueError('staged tree contains a link or special file')
                if os.name == 'posix':
                    expected_mode = 0o755 if stat.S_ISDIR(info.st_mode) or name.startswith('bin/') else 0o644
                    if stat.S_IMODE(info.st_mode) != expected_mode:
                        raise ValueError('staged entry has unexpected permissions: ' + name)
        states.append((parent, admission.file_identity(before), members))
    return files, directories, states, total


def _unchanged(states) -> None:
    for path, before, members in states:
        sequence.trusted_path(path)
        if admission.file_identity(path.lstat()) != before:
            raise ValueError('staged tree changed during reverification')
        if members is not None:
            remaining = set(members)
            with os.scandir(path) as current:
                for item in current:
                    if item.name not in remaining:
                        raise ValueError('staged tree membership changed during reverification')
                    remaining.remove(item.name)
            if remaining:
                raise ValueError('staged tree membership changed during reverification')


def _receipt(path: Path) -> tuple[dict, str]:
    hashed, _, _, raw = _read_file(path, MAX_RECEIPT, retain=True)
    receipt = json.loads(raw)
    if (not isinstance(receipt, dict) or type(receipt.get('schema_version')) is not int
            or receipt['schema_version'] != 1 or receipt.get('feature_id') != 'NAS-0116'
            or receipt.get('status') != 'admitted' or receipt.get('signature_verified_at_admission') is not True
            or receipt.get('predicates') != PREDICATES):
        raise ValueError('invalid admission receipt')
    try:
        verified = dt.datetime.fromisoformat(receipt['verified_at'])
        if verified.tzinfo is None or verified > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            raise ValueError('invalid admission verification time')
    except (KeyError, TypeError) as exc:
        raise ValueError('invalid admission verification time') from exc
    return receipt, hashed


def reverify(artifact: Path, policy_path: Path, commit: str, directory: Path, state_dir: Path) -> dict:
    policy = admission.load_policy(policy_path, commit)
    directory, state_dir = Path(os.path.abspath(directory)), Path(os.path.abspath(state_dir))
    if directory == state_dir or directory in state_dir.parents or state_dir in directory.parents:
        raise ValueError('sequence state and staged release must be disjoint')
    sequence.trusted_path(directory)
    with sequence.locked_state(state_dir, policy) as state:
        if state['highest_verified_sequence'] < policy['minimum_sequence']:
            raise ValueError('reserved release is below the current policy floor')
        receipt, receipt_hash = _receipt(directory / 'admission.json')
        with tempfile.TemporaryDirectory(prefix='.aegis-reverification-', dir=directory.parent) as temporary:
            work = Path(temporary)
            candidate = work / 'candidate.tar.gz'
            admission.copy_candidate(artifact, candidate)
            artifact_hash = security.digest(candidate)
            if (state['source_commit'] != commit or state['artifact_sha256'] != artifact_hash
                    or receipt.get('artifact_sha256') != artifact_hash
                    or receipt.get('policy_sha256') != state['policy_sha256']
                    or receipt.get('sequence_guard') != {'state_id': state['state_id'],
                       'highest_verified_sequence': state['highest_verified_sequence'], 'artifact_sha256': artifact_hash}):
                raise ValueError('receipt, artifact and current sequence reservation do not match')
            # A receipt never substitutes for fresh cryptographic verification.
            security.verify_artifact(candidate, policy['repository'], commit)
            clean = work / 'payload'; clean.mkdir(mode=0o700)
            admission.extract_checked(candidate, clean)
            verified = admission.validate_payload(clean, policy, commit)
            if (verified['manifest']['release_sequence'] != state['highest_verified_sequence']
                    or receipt.get('manifest') != verified['manifest']
                    or receipt.get('payload_sha256') != verified['payload_sha256']):
                raise ValueError('receipt or signed manifest differs from the reserved release')
            files, directories, states, total = _inspect_tree(directory)
            expected_directories = {p.relative_to(clean).as_posix() for p in clean.rglob('*') if p.is_dir()}
            if (files != {**verified['payload_sha256'], 'admission.json': receipt_hash}
                    or directories != expected_directories):
                raise ValueError('staged payload differs from the signed archive')
            _unchanged(states)
            if admission.load_policy(policy_path, commit)['_sha256'] != policy['_sha256']:
                raise ValueError('trusted policy changed during reverification')
            if sequence.read_state(state_dir, policy) != state:
                raise ValueError('sequence state changed during reverification')
        return {'schema_version': 1, 'feature_id': 'NAS-0116', 'status': 'reverified',
                'verified_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                'signature_reverified': True, 'predicates': PREDICATES,
                'artifact_sha256': artifact_hash, 'receipt_sha256': receipt_hash,
                'current_policy_sha256': policy['_sha256'], 'state_id': state['state_id'],
                'manifest': verified['manifest'], 'payload_files_verified': len(files) - 1,
                'bytes_verified': total, 'production_activation_authorized': False,
                'scope': 'Point-in-time staged payload verification; no service, database or activation changes'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--release-dir', required=True, type=Path)
    parser.add_argument('--state-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = reverify(args.artifact, args.policy, args.commit, args.release_dir, args.state_dir)
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print('Release reverification blocked: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
