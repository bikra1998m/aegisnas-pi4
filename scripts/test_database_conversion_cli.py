#!/usr/bin/env python3
"""Run actual conversion commands using a NEW SQLite fixture and disposable PostgreSQL.

Requires AEGIS_TEST_POSTGRES_DSN. Creates uniquely named private schemas and retains
them for inspection; use an isolated PostgreSQL cluster/container. Never activates
services, changes existing schemas or prints the DSN. Output contains test logs and
receipts; private fixture database/config files must not be published as artifacts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--config-template', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'configs/config.example.yaml')
    args = parser.parse_args()
    assert os.environ.get('AEGIS_TEST_POSTGRES_DSN'), 'A disposable PostgreSQL DSN is required'
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = output / 'state'
    state.mkdir(mode=0o700)
    source_config = state / 'sqlite.yaml'
    target_config = state / 'postgres.yaml'
    text = args.config_template.read_text(encoding='utf-8').replace('/var/lib/aegisnas', state.as_posix())
    source_config.write_text(text, encoding='utf-8')
    target_config.write_text(text.replace('backend: sqlite', 'backend: postgres', 1).replace(
        '# dsn_ref: "env:AEGIS_SECRET_POSTGRES_DSN"', 'dsn_ref: "env:AEGIS_TEST_POSTGRES_DSN"', 1).replace(
        '# sslmode: verify-full', 'sslmode: disable', 1).replace(
        'allow_unsafe_postgresql_sslmode: false', 'allow_unsafe_postgresql_sslmode: true', 1), encoding='utf-8')
    source_config.chmod(0o600)
    target_config.chmod(0o600)
    admin = str(args.admin_bin.resolve(strict=True))
    checks = []
    result = {'status': 'FAIL', 'scope': 'Actual CLI; isolated SQLite and disposable PostgreSQL, no production activation', 'checks': checks}
    start = time.monotonic()
    connection = None

    def check(name, condition):
        checks.append({'check': name, 'status': 'PASS' if condition else 'FAIL'})
        if not condition:
            raise RuntimeError(name)

    def command(name, arguments, success):
        began = time.monotonic()
        proc = subprocess.run([admin, *arguments], capture_output=True, timeout=300, cwd=state)
        secret = os.environ['AEGIS_TEST_POSTGRES_DSN'].encode()
        assert secret not in proc.stdout and secret not in proc.stderr, 'DSN leaked into command output'
        (output / (name + '.stdout')).write_bytes(proc.stdout)
        (output / (name + '.stderr')).write_bytes(proc.stderr)
        passed = proc.returncode == 0 if success else proc.returncode != 0
        checks.append({'check': name, 'status': 'PASS' if passed else 'FAIL', 'exit_code': proc.returncode, 'seconds': time.monotonic() - began})
        if not passed:
            raise RuntimeError(name)
        return proc

    try:
        command('migrate-source', ['migrate', '--config', str(source_config)], True)
        source = state / 'data.db'
        connection = sqlite3.connect(source)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA wal_autocheckpoint=0')
        connection.executescript("""
            INSERT INTO roles(id,name,priority,created_at) VALUES
              (600,'conversion-role',1099511627776,'2026-01-01T00:00:00.123456789Z'),
              (800,'conversion-deleted',0,'2026-01-01 00:00:00');
            DELETE FROM roles WHERE id=800;
            INSERT INTO local_users(username,password_hash,role) VALUES
              ('conversion-user','fixture-hash-not-for-deployment','conversion-role');
            INSERT INTO ai_recommendations(severity,source,confidence,title) VALUES
              ('info','conversion-fixture',0.1,'Conversion REAL precision fixture');
        """)
        connection.commit()
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND substr(name,1,7)<>'sqlite_'")]
        counts = {table: connection.execute('SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"').fetchone()[0] for table in tables}
        tracked = [source, Path(str(source) + '-wal'), source_config, target_config]
        before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
        schema = 'aegis_conversion_cli_' + uuid.uuid4().hex[:20]
        base = ['rehearse-sqlite-to-postgres', '--source-sqlite', str(source), '--config', str(target_config)]
        strict = command('reject-implicit-precision-loss', [*base, '--target-schema', schema + '_strict'], False)
        strict_receipt = json.loads(strict.stdout)
        check('failed-receipt-never-authorizes-activation', strict_receipt['status'] == 'failed' and not strict_receipt['production_activation_authorized'])
        proc = command('convert-private-schema', [*base, '--target-schema', schema, '--allow-precision-loss'], True)
        receipt = json.loads(proc.stdout)
        check('verified-rehearsal-only', receipt['status'] == 'verified_rehearsal' and not receipt['production_activation_authorized'])
        check('every-table-covered', {table['name'] for table in receipt['tables']} == set(tables))
        check('every-row-count-matches', all(table['rows'] == counts[table['name']] for table in receipt['tables']))
        check('every-content-digest-matches', all(table['source_sha256'] == table['target_sha256'] for table in receipt['tables']))
        check('deleted-id-high-water-preserved', receipt['sequence_next_values']['roles.id'] == 801)
        check('precision-loss-reported', receipt['timestamp_values_truncated'] >= 1)
        check('real-rounding-reported', receipt['real_values_rounded'] >= 1)
        collision = command('reject-existing-schema', [*base, '--target-schema', schema, '--allow-precision-loss'], False)
        check('collision-did-not-claim-creation', not json.loads(collision.stdout)['target_schema_created'])
        command('reject-public-schema', [*base, '--target-schema', 'public'], False)
        command('reject-sqlite-target', ['rehearse-sqlite-to-postgres', '--source-sqlite', str(source), '--config', str(source_config), '--target-schema', schema + '_wrong'], False)
        check('source-and-config-bytes-unchanged', all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in before.items()))
        result['receipt'] = receipt
        result['status'] = 'PASS'
    finally:
        if connection is not None:
            connection.close()
        result['seconds'] = time.monotonic() - start
        result['counts'] = {status: sum(check['status'] == status for check in checks) for status in ('PASS', 'FAIL')}
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': result['status'], 'counts': result['counts'], 'seconds': result['seconds']}))


if __name__ == '__main__':
    main()
