#!/usr/bin/env python3
"""Exercise the built recovery CLI with a NEW isolated SQLite database.

Never starts/stops appliance services or restores a deployed database. Test keys
are generated locally and removed when the fixture finishes; reports contain no
key material. --output must not exist. Requires only Python's standard library.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-bin', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--config-template', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'configs/config.example.yaml')
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = output / 'state'
    state.mkdir(mode=0o700)
    config = args.config_template.read_text(encoding='utf-8').replace('/var/lib/aegisnas', state.as_posix())
    config_path = state / 'config.yaml'
    config_path.write_text(config, encoding='utf-8')
    config_path.chmod(0o600)
    checks = []
    result = {'status': 'FAIL', 'checks': checks,
              'scope': 'Actual CLI + isolated populated SQLite recovery; no production activation or signed release.'}
    started = time.perf_counter()
    admin = str(args.admin_bin.resolve(strict=True))

    def check(name, condition):
        checks.append({'check': name, 'status': 'PASS' if condition else 'FAIL'})
        if not condition:
            raise RuntimeError(name)

    def command(label, argv, success=True):
        start = time.perf_counter()
        proc = subprocess.run([admin, *argv], capture_output=True, timeout=180)
        (output / (label + '.stdout')).write_bytes(proc.stdout)
        (output / (label + '.stderr')).write_bytes(proc.stderr)
        passed = proc.returncode == 0 if success else proc.returncode != 0
        checks.append({'check': label, 'status': 'PASS' if passed else 'FAIL',
                       'exit_code': proc.returncode, 'expected_success': success,
                       'seconds': time.perf_counter() - start})
        if not passed:
            raise RuntimeError(label)
        return json.loads(proc.stdout) if success and label.startswith(('create-', 'extract-')) else None

    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    try:
        command('validate', ['validate-config', '--config', str(config_path)])
        command('migrate', ['migrate', '--config', str(config_path)])
        database = state / 'data.db'
        with sqlite3.connect(database) as connection:
            connection.execute('CREATE TABLE recovery_fixture (id INTEGER PRIMARY KEY, value TEXT)')
            connection.execute("INSERT INTO recovery_fixture VALUES (1, 'before snapshot')")
        config_hash = digest(config_path)
        with tempfile.TemporaryDirectory(prefix='aegis-recovery-key-') as key_dir:
            key_path = Path(key_dir) / 'key'
            wrong_key = Path(key_dir) / 'wrong-key'
            for path in (key_path, wrong_key):
                with path.open('xb') as stream:
                    stream.write(secrets.token_bytes(32))
                path.chmod(0o600)
            context = 'isolated-cli/appliance-42/recovery-1'
            sealed = output / 'snapshot.aegis-recovery'
            create_args = ['create-sealed-upgrade-rollback-package', '--config', str(config_path),
                           '--key-file', str(key_path), '--recovery-context', context, '--output', str(sealed)]
            receipt = command('create-snapshot', create_args)
            check('sealed-digest-matches', receipt['sealed_sha256'] == digest(sealed))
            check('does-not-authorize-activation', receipt['production_activation_authorized'] is False)
            command('reject-overwrite', create_args, success=False)
            check('original-encrypted-snapshot-preserved', receipt['sealed_sha256'] == digest(sealed))
            with sqlite3.connect(database) as connection:
                connection.execute("UPDATE recovery_fixture SET value = 'after snapshot'")
            live_hash = digest(database)

            def extract_args(source, dest, key=key_path, scope=context, sha=receipt['sealed_sha256']):
                return ['extract-sealed-upgrade-rollback-package', '--input', str(source),
                        '--key-file', str(key), '--recovery-context', scope,
                        '--expected-sha256', sha, '--output-dir', str(dest)]

            altered = output / 'tampered.aegis-recovery'
            value = bytearray(sealed.read_bytes())
            value[-1] ^= 1
            altered.write_bytes(value)
            for name, source, key, scope, sha in (
                ('wrong-key', sealed, wrong_key, context, receipt['sealed_sha256']),
                ('wrong-context', sealed, key_path, 'different-appliance', receipt['sealed_sha256']),
                ('wrong-digest', sealed, key_path, context, '0' * 64),
                ('tampered', altered, key_path, context, digest(altered)),
            ):
                dest = output / ('reject-' + name)
                command('reject-' + name, extract_args(source, dest, key, scope, sha), success=False)
                check('no-output-' + name, not dest.exists())
            staged = output / 'staged'
            extracted = command('extract-snapshot', extract_args(sealed, staged))
            check('authenticated-staging-receipt', extracted['receipt']['status'] == 'authenticated_for_staging')
            with sqlite3.connect(staged / 'database/data.db') as connection:
                value = connection.execute('SELECT value FROM recovery_fixture WHERE id=1').fetchone()[0]
                check('snapshot-data-restored-in-isolation', value == 'before snapshot')
                check('snapshot-sqlite-integrity', connection.execute('PRAGMA integrity_check').fetchone() == ('ok',))
            check('config-snapshot-identical', digest(staged / 'config/config.yaml') == config_hash)
            command('reject-extraction-overwrite', extract_args(sealed, staged), success=False)
            check('live-database-untouched', digest(database) == live_hash)
            check('live-config-untouched', digest(config_path) == config_hash)
            if os.name == 'posix':
                check('private-staging-permissions', all(p.stat().st_mode & 0o077 == 0
                      for p in (staged, staged / 'config', staged / 'database', *[p for p in staged.rglob('*') if p.is_file()])))
            else:
                checks.append({'check': 'linux-staging-permissions', 'status': 'SKIPPED', 'reason': 'Windows ACLs are not certified'})
        result['status'] = 'PASS'
        result['recovery_receipt'] = receipt
    except Exception as exc:
        result['error'] = str(exc)
    finally:
        result['seconds'] = time.perf_counter() - started
        result['counts'] = {status: sum(c['status'] == status for c in checks) for status in ('PASS', 'FAIL', 'SKIPPED')}
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
