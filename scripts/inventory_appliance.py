#!/usr/bin/env python3
"""Read-only snap, firmware and boot inventory; never a release admission.

Use an immutable Linux rootfs snapshot for release evidence. A live-host run
detects ordinary concurrent changes but cannot establish snapshot atomicity.
No firmware is executed, no snap mounted, and no service or package is changed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys
import time

SCOPES = {'snaps': 'var/lib/snapd/snaps', 'firmware': 'lib/firmware', 'boot': 'boot'}
MAX_ENTRIES = 100000
MAX_FILE_BYTES = 8 * 1024**3
MAX_TOTAL_BYTES = 32 * 1024**3
MAX_MANIFEST_BYTES = 64 * 1024**2
MAX_LINK_BYTES = 4096
HEX = re.compile(r'[0-9a-f]{64}')


def check_budget(budget: dict) -> None:
    if budget.get('cancelled', lambda: False)():
        raise ValueError('inventory cancelled; partial evidence is not complete')
    if 'deadline' in budget and time.monotonic() >= budget['deadline']:
        raise ValueError('inventory time limit exceeded; partial evidence is not complete')


def fingerprint(info):
    # Windows Python stat/lstat and fstat can expose different legacy ctime
    # values (creation vs change time). Linux change-time checks remain strict.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns if os.name == 'posix' else None)


def rooted_path(root: Path, relative: str) -> Path:
    """Resolve Linux snapshot links inside the snapshot, including absolute links."""
    pending = list(PurePosixPath(relative).parts)
    parts, links = [], 0
    while pending:
        piece = pending.pop(0)
        if piece in ('', '.', '/'):
            continue
        if piece == '..':
            if not parts:
                raise ValueError('link escapes the rootfs')
            parts.pop()
            continue
        if '\\' in piece or ':' in piece:
            raise ValueError('non-Linux path in rootfs')
        path = root.joinpath(*parts, piece)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 40:
                raise ValueError('symbolic link loop or excessive depth')
            target = os.readlink(path)
            if len(target.encode('utf-8')) > MAX_LINK_BYTES:
                raise ValueError('symbolic link exceeds size limit')
            if fingerprint(info) != fingerprint(path.lstat()):
                raise ValueError('symbolic link changed during resolution')
            if target.startswith('/'):
                parts = []
            pending = list(PurePosixPath(target).parts) + pending
        else:
            parts.append(piece)
    return root.joinpath(*parts)


def regular_digest(path: Path, budget: dict) -> tuple[str, int]:
    """Bounded streaming read; reject special files and mutation/replacement."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('inventory input is not a regular file')
    if before.st_size > MAX_FILE_BYTES or budget['bytes'] + before.st_size > MAX_TOTAL_BYTES:
        raise ValueError('inventory byte limit exceeded')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    hashed, size = hashlib.sha256(), 0
    with os.fdopen(fd, 'rb') as source:
        if fingerprint(before) != fingerprint(os.fstat(source.fileno())):
            raise ValueError('inventory input changed before read')
        while True:
            check_budget(budget)
            block = source.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            budget['bytes'] += len(block)
            if size > MAX_FILE_BYTES or budget['bytes'] > MAX_TOTAL_BYTES:
                raise ValueError('inventory byte limit exceeded during read')
            hashed.update(block)
        if (fingerprint(before) != fingerprint(os.fstat(source.fileno()))
                or fingerprint(before) != fingerprint(path.lstat()) or size != before.st_size):
            raise ValueError('inventory input changed during read')
    return hashed.hexdigest(), size


def _under(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def inventory_scope(root: Path, name: str, relative: str, budget: dict) -> dict:
    result = {'path': relative, 'status': 'BLOCKED', 'entries': [], 'errors': []}
    try:
        directory = rooted_path(root, relative)
    except FileNotFoundError:
        result.update(status='ABSENT', errors=['Required inventory directory is absent or has a broken alias'])
        return result
    except (OSError, ValueError) as exc:
        result['errors'].append(str(exc))
        return result
    result['resolved_path'] = directory.relative_to(root).as_posix()
    if not directory.is_dir():
        result['errors'].append('Inventory root is not a directory')
        return result
    directory_states, file_states = [], []
    pending = [directory]
    try:
        while pending:
            check_budget(budget)
            current = pending.pop()
            before = current.lstat()
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('inventory directory changed type')
            members = set()
            # Bound directory enumeration too; do not first materialize an unbounded list.
            with os.scandir(current) as children:
                for child in children:
                    check_budget(budget)
                    members.add(child.name)
                    budget['entries'] += 1
                    if budget['entries'] > MAX_ENTRIES:
                        raise ValueError('inventory entry limit exceeded')
                    path = Path(child.path)
                    info = path.lstat()
                    row = {'path': path.relative_to(directory).as_posix()}
                    if stat.S_ISDIR(info.st_mode):
                        row['kind'] = 'directory'
                        pending.append(path)
                    elif stat.S_ISLNK(info.st_mode):
                        target = os.readlink(path)
                        resolved = rooted_path(root, path.relative_to(root).as_posix())
                        if not _under(resolved, directory):
                            raise ValueError('inventory link leaves its component scope: ' + row['path'])
                        if name == 'snaps':
                            raise ValueError('snap blob store must not contain symbolic links')
                        if fingerprint(info) != fingerprint(path.lstat()):
                            raise ValueError('inventory link changed: ' + row['path'])
                        row.update(kind='symlink', target=target,
                                   resolved_path=resolved.relative_to(directory).as_posix())
                    elif stat.S_ISREG(info.st_mode):
                        # Revalidate parents before reading; ordinary replacement races fail closed.
                        if rooted_path(root, path.relative_to(root).as_posix()) != path:
                            raise ValueError('inventory parent changed to a symbolic link')
                        digest, size = regular_digest(path, budget)
                        file_states.append((path, fingerprint(info)))
                        row.update(kind='file', size=size, sha256=digest)
                        if name == 'snaps' and path.suffix == '.snap':
                            row['artifact_kind'] = 'snap-squashfs'
                        elif name == 'snaps':
                            row['artifact_kind'] = 'snap-store-support-file'
                    else:
                        raise ValueError('special file in inventory: ' + row['path'])
                    result['entries'].append(row)
            directory_states.append((current, fingerprint(before), members))
            if fingerprint(before) != fingerprint(current.lstat()):
                raise ValueError('inventory directory changed during enumeration')
        for path, state, members in directory_states:
            check_budget(budget)
            if state != fingerprint(path.lstat()):
                raise ValueError('inventory directory changed during collection')
            observed = set()
            with os.scandir(path) as children:
                for child in children:
                    check_budget(budget)
                    if child.name not in members:
                        raise ValueError('inventory directory membership changed')
                    observed.add(child.name)
            if observed != members:
                raise ValueError('inventory directory membership changed')
        for path, state in file_states:
            check_budget(budget)
            if fingerprint(path.lstat()) != state:
                raise ValueError('inventory file changed during collection')
        if rooted_path(root, relative) != directory:
            raise ValueError('inventory root alias changed during collection')
        result['status'] = 'PASS'
    except (OSError, ValueError) as exc:
        result['errors'].append(str(exc))
    result['entries'].sort(key=lambda row: row['path'])
    result['file_count'] = sum(row['kind'] == 'file' for row in result['entries'])
    result['file_bytes'] = sum(row.get('size', 0) for row in result['entries'])
    return result


def payload_digest(scopes: dict) -> str:
    return hashlib.sha256(json.dumps(scopes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def collect(root: Path, timeout_seconds: int = 300, cancelled=lambda: False) -> dict:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
        raise ValueError('timeout must be an integer between 1 and 3600 seconds')
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('rootfs must be a directory')
    start = time.monotonic()
    budget = {'bytes': 0, 'entries': 0, 'deadline': start + timeout_seconds, 'cancelled': cancelled}
    scopes = {name: inventory_scope(root, name, relative, budget) for name, relative in SCOPES.items()}
    complete = all(scope['status'] == 'PASS' for scope in scopes.values())
    return {'schema_version': 1, 'feature_id': 'NAS-0116', 'kind': 'appliance-file-inventory',
            'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'status': 'PASS' if complete else 'BLOCKED',
            'scope': 'Files present in snap blob store, firmware directory and boot directory only',
            'rootfs': str(root), 'scopes': scopes, 'payload_sha256': payload_digest(scopes),
            'file_bytes_hashed': sum(scope.get('file_bytes', 0) for scope in scopes.values()),
            'bytes_read': budget['bytes'], 'entries_observed': budget['entries'],
            'timeout_seconds': timeout_seconds,
            'seconds': time.monotonic() - start,
            'release_gate': {'status': 'BLOCKED', 'signature_verified': False,
                'blockers': ['Inventory is not a vulnerability assessment or signature verification',
                    'Nested snap package scans and artifact-to-image binding require separate evidence',
                    'Firmware vendor/version/advisory mapping and device EEPROM are not covered',
                    'Live filesystem enumeration is not an atomic or trusted full-image snapshot']}}


def verify(root: Path, inventory: Path, expected_sha256: str, timeout_seconds: int = 300, cancelled=lambda: False) -> dict:
    if not HEX.fullmatch(expected_sha256):
        raise ValueError('expected inventory SHA-256 must be 64 lowercase hexadecimal digits')
    # Do not accept a manifest's own digest as its trust anchor.
    before = inventory.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('inventory manifest must be a regular file, not a link or special file')
    if before.st_size > MAX_MANIFEST_BYTES:
        raise ValueError('inventory manifest exceeds size limit')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(inventory, flags), 'rb') as source:
        if fingerprint(before) != fingerprint(os.fstat(source.fileno())):
            raise ValueError('inventory manifest changed before read')
        raw = source.read(MAX_MANIFEST_BYTES + 1)
        if (fingerprint(before) != fingerprint(os.fstat(source.fileno()))
                or fingerprint(before) != fingerprint(inventory.lstat())):
            raise ValueError('inventory manifest changed during read')
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('inventory manifest exceeds size limit')
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('inventory manifest does not match independently recorded digest')
    original = json.loads(raw)
    if (not isinstance(original, dict) or type(original.get('schema_version')) is not int
            or original['schema_version'] != 1 or original.get('kind') != 'appliance-file-inventory'
            or original.get('status') != 'PASS' or not isinstance(original.get('scopes'), dict)
            or set(original['scopes']) != set(SCOPES)):
        raise ValueError('invalid or incomplete appliance inventory')
    current = collect(root, timeout_seconds, cancelled)
    unchanged = (current['status'] == 'PASS' and current['scopes'] == original['scopes']
                 and current['payload_sha256'] == original.get('payload_sha256'))
    return {'schema_version': 1, 'feature_id': 'NAS-0116', 'kind': 'appliance-inventory-comparison',
            'status': 'PASS' if unchanged else 'FAIL', 'inventory_sha256': expected_sha256,
            'unchanged': unchanged, 'current': current, 'release_gate': current['release_gate']}


def write_new(path: Path, report: dict) -> None:
    # Output is outside the collected directories; never overwrite prior evidence.
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['collect', 'verify'])
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--timeout-seconds', type=int, default=300,
                        help='Collection time budget, 1..3600 seconds; exhaustion retains partial evidence')
    args = parser.parse_args()
    if args.action == 'verify' and not (args.inventory and args.expected_sha256):
        parser.error('verify requires --inventory and its independently recorded --expected-sha256')
    if args.action == 'collect' and (args.inventory or args.expected_sha256):
        parser.error('collect does not accept verification inputs')
    try:
        root = args.root.resolve(strict=True)
        output = args.output.resolve()
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('output already exists; preserve prior evidence')
        for relative in SCOPES.values():
            try:
                scope = rooted_path(root, relative)
            except FileNotFoundError:
                scope = root / relative
            if _under(output, scope):
                raise ValueError('output must be outside collected directories')
        cancellation = []
        def cancel(signum, frame):
            cancellation.append(signum)
        signal.signal(signal.SIGINT, cancel)
        signal.signal(signal.SIGTERM, cancel)
        report = (collect(root, args.timeout_seconds, lambda: bool(cancellation)) if args.action == 'collect'
                  else verify(root, args.inventory, args.expected_sha256, args.timeout_seconds, lambda: bool(cancellation)))
        write_new(output, report)
        print(json.dumps({'status': report['status'], 'output': str(output),
                          'release_gate': report['release_gate']}))
        return 0 if report['status'] == 'PASS' else 1
    except (OSError, ValueError) as exc:
        print('Appliance inventory blocked: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
