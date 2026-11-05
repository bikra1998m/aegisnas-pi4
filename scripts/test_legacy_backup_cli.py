#!/usr/bin/env python3
"""Exercise legacy backup/restore only against a newly created SQLite fixture.

No deployed database, config or services are accessed. Existing output is refused.
Archive checksums are not authentication; these checks do not certify production
activation, power-loss recovery or live-client quiescing.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--config-template', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'configs/config.example.yaml')
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = output / 'state'
    state.mkdir(mode=0o700)
    config_text = args.config_template.read_text(encoding='utf-8').replace('/var/lib/aegisnas', state.as_posix())
    config_path = state / 'config.yaml'
    config_path.write_text(config_text, encoding='utf-8')
    config_path.chmod(0o600)
    database = state / 'data.db'
    admin = str(args.admin_bin.resolve(strict=True))
    checks = []
    result = {'status': 'FAIL', 'checks': checks,
              'scope': 'Actual legacy CLI, committed WAL snapshot and offline restore of a disposable SQLite fixture; no production deployment.'}
    started = time.perf_counter()
    connection = None

    def check(name, condition):
        checks.append({'check': name, 'status': 'PASS' if condition else 'FAIL'})
        if not condition:
            raise RuntimeError(name)

    def command(name, argv, success=True, stdin=None):
        start = time.perf_counter()
        proc = subprocess.run([admin, *argv], cwd=state, input=stdin, capture_output=True, timeout=180)
        (output / (name + '.stdout')).write_bytes(proc.stdout)
        (output / (name + '.stderr')).write_bytes(proc.stderr)
        passed = proc.returncode == 0 if success else proc.returncode != 0
        checks.append({'check': name, 'status': 'PASS' if passed else 'FAIL', 'exit_code': proc.returncode,
                       'expected_success': success, 'seconds': time.perf_counter() - start})
        if not passed:
            raise RuntimeError(name)
        return proc

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def make_archive(name, entries, manifest=None):
        path = output / (name + '.tar.gz')
        if manifest is None:
            manifest = {key: hashlib.sha256(value).hexdigest() for key, value in entries.items()}
        with tarfile.open(path, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for key, value in {**entries, 'manifest.json': json.dumps(manifest).encode()}.items():
                header = tarfile.TarInfo(key)
                header.size = len(value)
                header.mode = 0o600
                archive.addfile(header, io.BytesIO(value))
        return path

    try:
        command('validate', ['validate-config', '--config', str(config_path)])
        connection = sqlite3.connect(database)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA wal_autocheckpoint=0')
        connection.execute('CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT)')
        connection.execute("INSERT INTO fixture VALUES (1, 'committed WAL value')")
        connection.commit()
        wal = Path(str(database) + '-wal')
        check('wal-fixture-is-populated', wal.is_file() and wal.stat().st_size > 32)
        original_inputs = {str(path): digest(path) for path in (database, wal, config_path)}
        backup = output / 'snapshot.tar.gz'
        # No --config: this must capture the actual ./config.yaml selected by Load.
        command('backup-default-selected-config', ['backup', str(backup)])
        with tarfile.open(backup, 'r:gz') as archive:
            check('archive-exact-members', set(archive.getnames()) == {'data.db', 'config.yaml', 'manifest.json'})
            members = {name: archive.extractfile(name).read() for name in archive.getnames()}
        manifest = json.loads(members['manifest.json'])
        check('manifest-covers-entire-payload', set(manifest) == {'data.db', 'config.yaml'} and all(
            hashlib.sha256(members[name]).hexdigest() == value for name, value in manifest.items()))
        check('selected-config-is-included', members['config.yaml'] == config_path.read_bytes())
        snapshot = output / 'inspect.db'
        snapshot.write_bytes(members['data.db'])
        with sqlite3.connect(snapshot) as inspected:
            check('snapshot-includes-committed-wal-row', inspected.execute('SELECT value FROM fixture').fetchone() == ('committed WAL value',))
            check('snapshot-integrity', inspected.execute('PRAGMA integrity_check').fetchone() == ('ok',))
        check('backup-did-not-change-source', all(digest(Path(path)) == value for path, value in original_inputs.items()))
        backup_hash = digest(backup)
        command('reject-backup-overwrite', ['backup', str(backup)], success=False)
        check('existing-backup-preserved', digest(backup) == backup_hash)
        command('reject-live-wal-restore', ['restore', str(backup)], success=False, stdin=b'yes\n')
        check('wal-rejection-preserved-source', all(digest(Path(path)) == value for path, value in original_inputs.items()))
        connection.execute("UPDATE fixture SET value = 'after snapshot'")
        connection.commit()
        connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        connection.close()
        connection = None
        check('fixture-clients-closed', all(not Path(str(database) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')))
        before_restore = {str(path): digest(path) for path in (database, config_path)}

        def unchanged(name):
            check(name, all(digest(Path(path)) == value for path, value in before_restore.items()))

        command('reject-user-declined-restore', ['restore', str(backup)], success=False, stdin=b'no\n')
        unchanged('declined-restore-preserves-files')
        empty_manifest = make_archive('empty-manifest', {'data.db': members['data.db']}, manifest={})
        command('reject-incomplete-manifest', ['restore', str(empty_manifest)], success=False, stdin=b'yes\n')
        unchanged('invalid-manifest-preserves-files')
        invalid_db = make_archive('invalid-database', {'data.db': b'not a SQLite database'})
        command('reject-invalid-database', ['restore', str(invalid_db)], success=False, stdin=b'yes\n')
        unchanged('invalid-database-preserves-files')
        redirected = config_text.replace(str(database.as_posix()), str((state / 'different.db').as_posix()))
        check('redirected-config-fixture-differs', redirected != config_text)
        redirect_archive = make_archive('redirected-config', {'data.db': members['data.db'], 'config.yaml': redirected.encode()})
        command('reject-database-path-change', ['restore', str(redirect_archive)], success=False, stdin=b'yes\n')
        unchanged('redirected-config-preserves-files')
        check('redirect-target-not-created', not (state / 'different.db').exists())

        # A fake secret reference is sufficient: the backend guard must run
        # before trying to resolve it or opening any database connection.
        postgres_text = config_text.replace('backend: sqlite', 'backend: postgres', 1).replace(
            '# dsn_ref: "env:AEGIS_SECRET_POSTGRES_DSN"', 'dsn_ref: "env:AEGIS_LEGACY_BACKUP_UNSET_DSN"', 1)
        check('postgres-config-fixture-created', postgres_text != config_text and 'dsn_ref: "env:AEGIS_LEGACY_BACKUP_UNSET_DSN"' in postgres_text)
        postgres_config = state / 'postgres.yaml'
        postgres_config.write_text(postgres_text, encoding='utf-8')
        rejected_output = output / 'postgres-backup.tar.gz'
        for name, argv in [('reject-postgres-backup', ['backup', str(rejected_output)]),
                           ('reject-postgres-restore', ['restore', str(backup)])]:
            proc = command(name, [*argv, '--config', str(postgres_config)], success=False, stdin=b'yes\n')
            check(name + '-backend-guard', b'requires SQLite' in proc.stderr)
        check('postgres-rejection-created-no-archive', not rejected_output.exists())
        unchanged('postgres-rejection-preserves-local-files')

        command('restore-offline-fixture', ['restore', str(backup)], stdin=b'yes\n')
        with sqlite3.connect(database) as restored:
            check('restored-committed-value', restored.execute('SELECT value FROM fixture').fetchone() == ('committed WAL value',))
            check('restored-database-integrity', restored.execute('PRAGMA integrity_check').fetchone() == ('ok',))
        check('restored-config-identical', config_path.read_bytes() == members['config.yaml'])
        safety = list(state.glob('.aegis-restore-before-*'))
        check('safety-copies-retained', len(safety) == 2)
        if os.name == 'posix':
            check('private-backup-restore-permissions', all(path.stat().st_mode & 0o077 == 0
                  for path in (backup, database, config_path, *safety)))
        else:
            checks.append({'check': 'linux-private-file-permissions', 'status': 'SKIPPED', 'reason': 'Windows ACLs are not certified'})
        result['status'] = 'PASS'
    except Exception as exc:
        result['error'] = str(exc)
    finally:
        if connection is not None:
            connection.close()
        result['seconds'] = time.perf_counter() - started
        result['counts'] = {status: sum(check['status'] == status for check in checks) for status in ('PASS', 'FAIL', 'SKIPPED')}
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
