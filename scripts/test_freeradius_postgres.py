#!/usr/bin/env python3
"""Opt-in Linux integration fixture. Never touches system services or databases.

Requires an extracted PostgreSQL installation, matching FreeRADIUS SQL driver,
and a Linux radius.test built from this tree. Uses a NEW private root and random
loopback ports. All certificates and credentials are disposable fixture data.
"""
import argparse
import datetime
import json
import os
import pathlib
import socket
import subprocess
import time
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'pg-root', 'module-root', 'generator-test-binary'):
        parser.add_argument('--' + name, required=True, type=pathlib.Path)
    parser.add_argument('--accounting', action='store_true', help='Exercise generated accounting queries and Go session reconciliation')
    parser.add_argument('--accounting-policy', type=pathlib.Path, help='Readable stock FreeRADIUS policy.d/accounting for the installed version')
    parser.add_argument('--database-test-binary', type=pathlib.Path, help='Optionally run the shared PostgreSQL runtime matrix in isolated schemas')
    args = parser.parse_args()
    if args.accounting and (not args.accounting_policy or not args.accounting_policy.is_file()):
        parser.error('--accounting requires a readable --accounting-policy file')
    root = args.root.resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    pg = args.pg_root.resolve() / 'usr/lib/postgresql/14/bin'
    env = {**os.environ, 'LD_LIBRARY_PATH': str(args.pg_root.resolve() / 'usr/lib/x86_64-linux-gnu')}
    checks = []
    result = {'started': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'scope': 'Isolated generated SQL module, TLS, real RADIUS packet/query, and PostgreSQL reconnect; not production accounting certification', 'checks': checks, 'status': 'FAIL'}
    cluster = root / 'pgdata'
    process = None
    running = False

    def check(name, ok, **details):
        checks.append({'name': name, 'status': 'PASS' if ok else 'FAIL', **details})
        if not ok:
            raise RuntimeError(name)

    def command(name, argv, extra=None, expected=0, data=None):
        start = time.monotonic()
        try:
            p = subprocess.run([str(a) for a in argv], env={**env, **(extra or {})}, input=data, text=True, capture_output=True, timeout=1500 if name == 'postgres-runtime-matrix' else 90)
        except subprocess.TimeoutExpired as exc:
            def decoded(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            (root / (name + '.log')).write_text(decoded(exc.stdout) + decoded(exc.stderr))
            check(name, False, exit_code=124, seconds=time.monotonic() - start, error='process timeout; partial output preserved')
        (root / (name + '.log')).write_text(p.stdout + p.stderr)
        check(name, p.returncode == expected, exit_code=p.returncode, seconds=time.monotonic() - start)
        return p.stdout

    def port(kind=socket.SOCK_STREAM):
        with socket.socket(type=kind) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    pgport, radiusport, acctport = port(), port(socket.SOCK_DGRAM), port(socket.SOCK_DGRAM)
    result.update(postgres_port=pgport, radius_port=radiusport)
    sql_dsn = f'postgres://fixture@127.0.0.1:{pgport}/postgres?sslmode=disable'
    admin_tls = f'postgres://fixture@localhost:{pgport}/postgres?' + urllib.parse.urlencode({'sslmode': 'verify-full', 'sslrootcert': str(root / 'root ca.crt')})
    options = f'-h 127.0.0.1,127.0.0.2 -p {pgport} -k {root} -c ssl=on -c ssl_cert_file={root}/server.crt -c ssl_key_file={root}/server.key -c max_wal_size=64MB -c min_wal_size=32MB'

    def start_pg(name):
        command(name, [pg / 'pg_ctl', '-D', cluster, '-l', root / 'postgres.log', '-o', options, '-w', 'start'])

    def stop_pg(name):
        command(name, [pg / 'pg_ctl', '-D', cluster, '-m', 'fast', '-w', 'stop'])

    # Exercises both URI encoding and real SCRAM authentication. This is not a
    # deployment secret and must never be replaced with production credentials.
    password = "fixture'\"\\ ${must_not_expand} $ENV{must_not_expand} +%&"

    def generate(name, host='localhost', cert='root ca.crt'):
        uri = f'postgres://radius:{urllib.parse.quote(password, safe="")}@{host}:{pgport}/postgres?'
        uri += urllib.parse.urlencode({'sslmode': 'disable', 'sslrootcert': str(root / cert), 'options': '-c TimeZone=Asia/Colombo -c statement_timeout=0'})
        fixture = 'TestPostgreSQLAccountingLiveFixture' if args.accounting else 'TestPostgreSQLModuleLiveFixture'
        command(name + '-generate', [args.generator_test_binary.resolve(), '-test.run=^' + fixture + '$', '-test.v'], {
            'AEGIS_RADIUS_PG_FIXTURE_DSN': uri, 'AEGIS_RADIUS_PG_MODULE_OUTPUT': str(root / 'sql'),
            'AEGIS_RADIUS_SQL_FIXTURE_ROOT': str(root), 'AEGIS_RADIUS_SQL_FIXTURE_ADMIN_DSN': admin_tls,
            'AEGIS_RADIUS_SQL_FIXTURE_ACTION': 'prepare'})
        module = (root / 'sql').read_text()
        # Only pool sizing is fixture-specific. The URI and TLS policy are the
        # unchanged output of the production generator.
        module = module.rsplit('}', 1)[0] + '\n pool {\n start = 1\n min = 1\n max = 2\n spare = 1\n retry_delay = 1\n idle_timeout = 0\n }\n}\n'
        (root / 'sql').write_text(module)

    def start_radius(name):
        nonlocal process
        log = root / (name + '.log')
        with log.open('wb') as stream:
            process = subprocess.Popen(['freeradius', '-X', '-d', str(root)], env=env, stdout=stream, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and process.poll() is None:
            if 'Ready to process requests' in log.read_text(errors='replace'):
                return True
            time.sleep(0.1)
        return False

    def stop_radius():
        nonlocal process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)
        process = None

    def packet(name, accept, username='fixture'):
        p = subprocess.run(['radclient', '-x', '-t', '3', '-r', '1', f'127.0.0.1:{radiusport}', 'auth', 'fixture-only-radius-secret'], input=f'User-Name = "{username}"\nUser-Password = "fixture"\n', text=True, capture_output=True, timeout=10)
        output = p.stdout + p.stderr
        (root / (name + '.log')).write_text(output)
        expected = 'Received Access-Accept' if accept else 'Received Access-Reject'
        check(name, expected in output, exit_code=p.returncode, response=expected)
        if accept:
            check(name + '-sql-policy', 'UTC|1500ms|true' in output)

    def reconcile(name):
        command(name, [args.generator_test_binary.resolve(), '-test.run=^TestPostgreSQLAccountingLiveFixture$', '-test.v'], {
            'AEGIS_RADIUS_SQL_FIXTURE_ROOT': str(root), 'AEGIS_RADIUS_SQL_FIXTURE_ADMIN_DSN': admin_tls,
            'AEGIS_RADIUS_SQL_FIXTURE_ACTION': 'reconcile'})

    try:
        command('initdb', [pg / 'initdb', '-D', cluster, '-U', 'fixture', '-A', 'trust', '--no-locale', '-E', 'UTF8'])
        for prefix in ('server', 'untrusted'):
            command(prefix + '-certificate', ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root / (prefix + '.key'), '-out', root / (prefix + '.crt'), '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'])
            (root / (prefix + '.key')).chmod(0o600)
        (root / 'root ca.crt').write_bytes((root / 'server.crt').read_bytes())
        start_pg('postgres-start'); running = True
        quoted = password.replace("'", "''")
        command('fixture-role', [pg / 'psql', sql_dsn, '-X', '-v', 'ON_ERROR_STOP=1'], data=f"SET password_encryption='scram-sha-256'; CREATE ROLE radius LOGIN PASSWORD '{quoted}';\n")
        hba = cluster / 'pg_hba.conf'
        hba.write_text('hostssl all radius 127.0.0.0/8 scram-sha-256\nhostnossl all radius 127.0.0.0/8 reject\n' + hba.read_text())
        command('postgres-reload-auth', [pg / 'pg_ctl', '-D', cluster, 'reload'])
        (root / 'dictionary').write_text('$INCLUDE /usr/share/freeradius/dictionary\n')
        acct_policy = 'policy {\n $INCLUDE ' + str(args.accounting_policy.resolve()) + '\n}' if args.accounting else ''
        acct_site = f'''listen {{
 type = acct
 ipaddr = 127.0.0.1
 port = {acctport}
}}
preacct {{
 acct_unique
}}
accounting {{
 $INCLUDE {root}/accounting.inc
}}
post-auth {{
 $INCLUDE {root}/postauth.inc
}}
''' if args.accounting else ''
        (root / 'radiusd.conf').write_text(f'''prefix = /usr
name = aegis-isolated-postgres
raddbdir = {root}
logdir = {root}
run_dir = {root}
libdir = {args.module_root.resolve()}
pidfile = {root}/radius.pid
log {{
 destination = files
 file = {root}/radius.log
}}
security {{
 max_attributes = 200
}}
client fixture {{
 ipaddr = 127.0.0.1
 secret = fixture-only-radius-secret
}}
{acct_policy}
modules {{
 always reject {{
  rcode = reject
 }}
 always ok {{
  rcode = ok
 }}
 expr {{
 }}
 $INCLUDE {root}/sql
}}
server fixture {{
 {acct_site}
 listen {{
  type = auth
  ipaddr = 127.0.0.1
  port = {radiusport}
 }}
 authorize {{
  update reply {{
   Reply-Message := "%{{sql:SELECT current_setting('TimeZone') || '|' || current_setting('statement_timeout') || '|' || ssl::text FROM pg_stat_ssl WHERE pid=pg_backend_pid()}}"
  }}
  if (&reply:Reply-Message != "UTC|1500ms|true" || &User-Name == "reject-fixture") {{
   update control {{
    Auth-Type := Reject
   }}
  }}
  else {{
   update control {{
    Auth-Type := Accept
   }}
  }}
 }}
}}
''')
        generate('valid')
        check('radius-start-valid-tls', start_radius('radius-valid'))
        packet('valid-tls-packet', True)
        if args.accounting:
            from sql_accounting_fixture import exercise_accounting, accounting_packet
            result['scope'] = 'Isolated generated PostgreSQL accounting/postauth queries, real RADIUS packets and Go session reconciliation; production installation and hardware certification are excluded'
            result['accounting_port'] = acctport
            exercise_accounting(root, pg, sql_dsn, acctport, env, command, check, reconcile)
            packet('postauth-reject-packet', False, 'reject-fixture')
            rejected = command('postauth-reject-read', [pg / 'psql', sql_dsn, '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', "SELECT COUNT(*) FROM radpostauth WHERE username='reject-fixture' AND reply='Access-Reject' AND COALESCE(pass,'')=''"])
            check('postauth-reject-recorded', rejected.strip() == '1')
        if args.database_test_binary:
            command('postgres-runtime-matrix', [args.database_test_binary.resolve(), '-test.v', '-test.count=1', '-test.timeout=25m', '-test.skip=^TestMigrate|^TestSeed|^TestVendorIdentity'], {'AEGIS_TEST_POSTGRES_DSN': admin_tls, 'AEGIS_TEST_RUNTIME_POSTGRES_DSN': admin_tls, 'GOMAXPROCS': '2'})
        stop_pg('postgres-outage'); running = False
        packet('database-outage-reject', False)
        if args.accounting:
            accounting_packet(root, acctport, 'outage-not-acknowledged', 'Start', 'outage-session', int(time.time()), check, expect_response=False)
        start_pg('postgres-recovery'); running = True
        time.sleep(2)
        packet('database-reconnected', True)
        if args.accounting:
            accounting_packet(root, acctport, 'outage-retry-persisted', 'Start', 'outage-session', int(time.time()), check)
            reconcile('outage-retry-reconciled')
            persisted = command('outage-retry-read', [pg / 'psql', sql_dsn, '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', "SELECT COUNT(*) FROM sessions s JOIN radacct r ON r.aegis_session_id=s.id WHERE r.acctsessionid='outage-session' AND r.aegis_reconcile_status='reconciled'"])
            check('outage-retry-session-exists', persisted.strip() == '1')
        stop_radius()
        for name, host, cert, reason in [('wrong-root', 'localhost', 'untrusted.crt', 'certificate verify failed'), ('wrong-host', '127.0.0.2', 'root ca.crt', 'does not match host name')]:
            generate(name, host, cert)
            started = start_radius('radius-' + name)
            check(name + '-startup-rejected', not started and process.poll() is not None)
            check(name + '-reason', reason in (root / ('radius-' + name + '.log')).read_text(errors='replace'))
            stop_radius()
        result['status'] = 'PASS'
    except Exception as exc:
        result['error'] = str(exc)
    finally:
        stop_radius()
        if running:
            try:
                stop_pg('postgres-stop')
            except Exception as exc:
                result.update(status='FAIL', cleanup_error=str(exc))
        result['ended'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (root / 'result.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
