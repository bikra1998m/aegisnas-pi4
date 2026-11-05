#!/usr/bin/env python3
"""Run a real API process against a new isolated test database; never deploy.

Build aegis-admin and aegis-admin-api first, then supply their --bin-dir and a
NEW --output directory. Only processes started by this harness are terminated.
"""
import argparse
import io
import json
import os
from pathlib import Path
import secrets
import socket
import statistics
import subprocess
import time
import urllib.parse
import urllib.error
import urllib.request
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--postgres', action='store_true', help='Use AEGIS_LIVE_TEST_POSTGRES_DSN for an isolated loopback aegis_smoke_* database')
    parser.add_argument('--all-system-reads', action='store_true', help='Exercise parameter-free system GET endpoints from the actual OpenAPI document')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    state = output / 'state'
    state.mkdir(mode=0o700)
    token = secrets.token_urlsafe(40)
    env = {**os.environ, 'AEGIS_ADMIN_BOOTSTRAP_TOKEN': token,
           'AEGIS_ADMIN_UI_DIR': str(root / 'web/admin-ui/dist'), 'AEGIS_RELEASE_DIR': str(state / 'release')}
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    config = (root / 'configs/config.example.yaml').read_text(encoding='utf-8')
    config = config.replace('/var/lib/aegisnas', state.as_posix()).replace('admin_port: 8083', f'admin_port: {port}')
    if args.postgres:
        target = urllib.parse.urlparse(os.environ.get('AEGIS_LIVE_TEST_POSTGRES_DSN', ''))
        if target.scheme not in ('postgres', 'postgresql') or target.hostname not in ('127.0.0.1', 'localhost', '::1') or not target.path.startswith('/aegis_smoke_'):
            raise ValueError('PostgreSQL smoke tests require a dedicated loopback aegis_smoke_* database')
        config = config.replace('  backend: sqlite # sqlite for lite/lab, postgres for enterprise production',
                                '  backend: postgres\n  dsn_ref: "env:AEGIS_LIVE_TEST_POSTGRES_DSN"\n  sslmode: disable')
        config = config.replace('  allow_unsafe_postgresql_sslmode: false', '  allow_unsafe_postgresql_sslmode: true')
    config_path = state / 'config.yaml'
    config_path.write_text(config, encoding='utf-8')
    checks, latencies = [], []
    suffix = '.exe' if os.name == 'nt' else ''
    binaries = args.bin_dir.resolve()

    def command(label, argv):
        start = time.perf_counter()
        proc = subprocess.run(argv, cwd=root, env=env, capture_output=True, timeout=180)
        text = (proc.stdout + proc.stderr).decode(errors='replace').replace(token, '[REDACTED]')
        (output / (label + '.log')).write_text(text, encoding='utf-8')
        checks.append({'check': label, 'exit_code': proc.returncode, 'seconds': time.perf_counter() - start})
        if proc.returncode:
            raise RuntimeError(label + ' failed')

    def request(label, route, expected=200, auth=True, method=None, body=None, record=True):
        headers = {'Authorization': 'Bearer ' + token} if auth else {}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(f'http://127.0.0.1:{port}' + route, method=method,
                                     data=json.dumps(body).encode() if body is not None else None, headers=headers)
        start = time.perf_counter()
        try:
            response = urllib.request.urlopen(req, timeout=120)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            data, status = response.read(), response.status
        elapsed = time.perf_counter() - start
        if record:
            checks.append({'check': label, 'status': status, 'expected': expected, 'seconds': elapsed, 'bytes': len(data)})
        if status != expected:
            raise RuntimeError(f'{label}: HTTP {status}, expected {expected}: ' + data.decode(errors='replace')[:600].replace(token, '[REDACTED]'))
        if 'json' in response.headers.get('Content-Type', ''):
            return json.loads(data), elapsed
        return data, elapsed

    process = None
    result = {'status': 'FAIL', 'scope': f'Real isolated API + {"PostgreSQL" if args.postgres else "SQLite"} + built UI; no external NAS or production deployment.',
              'checks': checks}
    try:
        admin = str(binaries / ('aegis-admin' + suffix))
        for action in ('validate-config', 'migrate', 'seed'):
            command(action, [admin, action, '--config', str(config_path)])
        with (output / 'api.log').open('wb') as log:
            process = subprocess.Popen([str(binaries / ('aegis-admin-api' + suffix)), 'run', '--config', str(config_path)],
                                       cwd=root, env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 90
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('API failed to start')
                    time.sleep(0.25)
            request('health', '/health', auth=False)
            request('authentication-required', '/api/v1/system/release-security', expected=401, auth=False)
            report, _ = request('release-security', '/api/v1/system/release-security')
            if report['status'] != 'not_admitted' or report['signature_reverified']:
                raise RuntimeError('unsigned development build incorrectly claims verified admission')
            (output / 'release-security.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
            for name in ('database', 'docsis-policy', 'upgrade-readiness', 'support-bundle/summary'):
                value, _ = request(name, '/api/v1/system/' + name)
                if args.postgres and name == 'upgrade-readiness':
                    rehearsal = value.get('rehearsal', {})
                    if rehearsal.get('ran') or rehearsal.get('succeeded') or 'PostgreSQL' not in rehearsal.get('error', ''):
                        raise RuntimeError('PostgreSQL incorrectly claims a supported SQLite upgrade rehearsal')
            request('roles', '/api/v1/roles')
            request('docsis-preview', '/api/v1/system/docsis-policy/preview', method='POST')
            request('built-ui', '/', auth=False)
            spec, _ = request('openapi', '/api/v1/openapi.json')
            if '/api/v1/system/release-security' not in spec['paths']:
                raise RuntimeError('release-security endpoint missing from OpenAPI')
            if args.all_system_reads:
                failures = []
                omitted = []
                for route, methods in sorted(spec['paths'].items()):
                    if not route.startswith('/api/v1/system/') or 'get' not in methods:
                        continue
                    # Export/download routes require specific persisted artifacts;
                    # the support bundle has its own validation below.
                    if '{' in route or any(word in route for word in ('/export', '/download', '/support-bundle')):
                        omitted.append(route)
                        continue
                    try:
                        if route == '/api/v1/system/controller-sync/preview':
                            # Disabled example integrations reject preview requests;
                            # this is an asserted negative check, not live controller coverage.
                            request('system-read:' + route, route + '?operation=pull', expected=400)
                        elif args.postgres and route == '/api/v1/system/ha/replication-package':
                            request('unsupported-sqlite-replication-on-postgres', route, expected=409)
                        elif args.postgres and route == '/api/v1/system/upgrade-rollback-package':
                            request('unsupported-sqlite-rollback-on-postgres', route, expected=409)
                        else:
                            request('system-read:' + route, route)
                    except Exception as exc:
                        failures.append({'route': route, 'error': str(exc)})
                result['system_read_failures'] = failures
                result['omitted_system_routes'] = omitted
                if failures:
                    raise RuntimeError(f'{len(failures)} system GET endpoints failed')
            bundle, _ = request('support-bundle', '/api/v1/system/support-bundle')
            with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
                capture = json.loads(archive.read('api/release-security.json'))
                if capture['status'] != 'not_admitted':
                    raise RuntimeError('support bundle omitted current release state')
                # Retain names and checked result, not private host journals.
                (output / 'support-bundle-members.json').write_text(json.dumps(archive.namelist(), indent=2), encoding='utf-8')
            for _ in range(100):
                _, elapsed = request('latency', '/api/v1/system/release-security', record=False)
                latencies.append(elapsed * 1000)
        result['status'] = 'PASS'
        result['performance'] = {'endpoint': '/api/v1/system/release-security', 'requests': len(latencies),
                                 'concurrency': 1, 'unit': 'ms', 'median': statistics.median(latencies),
                                 'p95': sorted(latencies)[94], 'max': max(latencies),
                                 'scope': 'Loopback HTTP latency for missing admission; not NAS forwarding throughput.'}
    except Exception as exc:
        checks.append({'error': str(exc).replace(token, '[REDACTED]')})
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        log = output / 'api.log'
        if log.exists():
            log.write_text(log.read_text(encoding='utf-8', errors='replace').replace(token, '[REDACTED]'), encoding='utf-8')
        (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
