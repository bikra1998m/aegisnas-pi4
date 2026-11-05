"""Real packet assertions used only by test_freeradius_postgres.py --accounting.

Every query uses the disposable cluster supplied by that harness. No service,
deployment configuration, production account or production database is modified.
"""
import json
import subprocess
import time


def accounting_packet(root, port, name, status, session, timestamp, check,
                      expect_response=True, user='sql-fixture', nas='192.0.2.10',
                      duration=0, incoming=0, outgoing=0, extra=None):
    attrs = {'User-Name': user, 'NAS-IP-Address': nas, 'NAS-Port': 7,
             'Calling-Station-Id': '02-00-00-00-00-01',
             'Acct-Status-Type': status, 'Event-Timestamp': timestamp,
             'Acct-Session-Time': duration, 'Acct-Input-Octets': incoming & 0xffffffff,
             'Acct-Input-Gigawords': incoming >> 32,
             'Acct-Output-Octets': outgoing & 0xffffffff,
             'Acct-Output-Gigawords': outgoing >> 32}
    if session is not None:
        attrs['Acct-Session-Id'] = session
    attrs.update(extra or {})
    def radius_value(value):
        if isinstance(value, int):
            return str(value)
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    data = ''.join(f'{key} = {radius_value(value)}\n' for key, value in attrs.items() if value is not None)
    started = time.monotonic()
    p = subprocess.run(['radclient', '-x', '-t', '2', '-r', '1',
                        f'127.0.0.1:{port}', 'acct', 'fixture-only-radius-secret'],
                       input=data, text=True, capture_output=True, timeout=10)
    output = p.stdout + p.stderr
    (root / (name + '.log')).write_text(output)
    received = 'Received Accounting-Response' in output
    check(name, 'Sent Accounting-Request' in output and received == expect_response and (not expect_response or p.returncode == 0),
          response=received, exit_code=p.returncode, seconds=time.monotonic() - started)


def exercise_accounting(root, pg, dsn, port, env, command, check, reconcile):
    def query(name, sql):
        output = command(name, [pg / 'psql', dsn, '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', sql])
        return json.loads(output.strip())

    def snapshot(name, session):
        # Session identifiers below are fixed test constants, not network input.
        return query(name, "SELECT row_to_json(r) FROM radacct r WHERE acctsessionid = '" + session + "'")

    def session_state(name, session):
        return query(name, "SELECT row_to_json(s) FROM sessions s JOIN radacct r ON r.aegis_session_id=s.id WHERE r.acctsessionid='" + session + "'")

    def ledger_count(name):
        return query(name, 'SELECT COUNT(*) FROM radius_accounting_events')

    send = lambda name, status, sid, ts, **kw: accounting_packet(root, port, name, status, sid, ts, check, **kw)
    base = int(time.time()) - 3600
    check('postauth-accept-recorded', query('postauth-accept-read', "SELECT COUNT(*) FROM radpostauth WHERE reply='Access-Accept'") >= 1)
    send('start-packet', 'Start', 'lifecycle', base, extra={'Framed-IP-Address': '192.0.2.51'})
    reconcile('start-reconcile')
    start = snapshot('start-snapshot', 'lifecycle')
    check('start-session-created', start['aegis_reconcile_status'] == 'reconciled' and start['aegis_session_id'].startswith('sql-') and start['aegis_packet_source'] == '127.0.0.1')
    session_state('start-session-read', 'lifecycle')
    big = 2**32 + 123
    send('interim-packet', 'Interim-Update', 'lifecycle', base + 60, duration=60, incoming=big, outgoing=456)
    reconcile('interim-reconcile')
    current = session_state('interim-session-read', 'lifecycle')
    check('gigawords-reconciled', current['bytes_in'] == big and current['bytes_out'] == 456)
    count = ledger_count('ledger-before-duplicate')
    send('duplicate-interim', 'Interim-Update', 'lifecycle', base + 60, duration=60, incoming=big, outgoing=456)
    reconcile('duplicate-reconcile')
    check('duplicate-ledger-idempotent', ledger_count('ledger-after-duplicate') == count)
    send('reordered-interim', 'Interim-Update', 'lifecycle', base + 30, duration=30, incoming=50)
    row = snapshot('reordered-snapshot', 'lifecycle')
    check('reordered-counter-preserved', row['aegis_input_octets_64'] == str(big) and row['aegis_reconcile_status'] == 'reconciled')
    send('stop-packet', 'Stop', 'lifecycle', base + 120, duration=120, incoming=big + 77, outgoing=800, extra={'Acct-Terminate-Cause': 'User-Request'})
    reconcile('stop-reconcile')
    closed = session_state('stop-session-read', 'lifecycle')
    check('stop-session-closed', closed['end_time'] is not None and closed['bytes_in'] == big + 77 and closed['stop_reason'] == 'User-Request')
    count = ledger_count('ledger-before-terminal-duplicates')
    send('late-interim-after-stop', 'Interim-Update', 'lifecycle', base + 180, duration=180, incoming=big + 999)
    send('late-start-after-stop', 'Start', 'lifecycle', base)
    send('duplicate-stop', 'Stop', 'lifecycle', base + 120, duration=120, incoming=big + 77, outgoing=800, extra={'Acct-Terminate-Cause': 'User-Request'})
    reconcile('terminal-duplicates-reconcile')
    terminal = snapshot('terminal-snapshot', 'lifecycle')
    check('terminal-state-preserved', terminal['acctstoptime'] is not None and terminal['aegis_input_octets_64'] == str(big + 77))
    check('terminal-ledger-idempotent', ledger_count('ledger-after-terminal-duplicates') == count)

    send('interim-without-start', 'Interim-Update', 'missing-start', base + 60, duration=60, incoming=700)
    send('older-stop-after-interim', 'Stop', 'missing-start', base + 30, duration=30, incoming=50)
    reconcile('older-stop-reconcile')
    row = snapshot('older-stop-snapshot', 'missing-start')
    check('older-stop-closes-preserves-counters', row['acctstoptime'] is not None and row['aegis_input_octets_64'] == '700' and row['acctsessiontime'] == 60)
    send('stop-without-start', 'Stop', 'missing-all', base + 60, duration=60, incoming=42)
    reconcile('missing-all-reconcile')
    check('stop-without-start-closed', session_state('missing-all-session', 'missing-all')['end_time'] is not None)

    maximum = 2**64 - 1
    send('unsigned-maximum', 'Stop', 'uint64', base + 60, duration=60, incoming=maximum, outgoing=maximum)
    reconcile('unsigned-reconcile')
    row = snapshot('unsigned-snapshot', 'uint64')
    check('unsigned-raw-preserved', row['aegis_input_octets_64'] == str(maximum) and row['aegis_output_octets_64'] == str(maximum) and row['acctinputoctets'] == 4294967295 and row['acctinputgigawords'] == 4294967295)
    check('unsigned-session-no-negative-overflow', session_state('unsigned-session', 'uint64')['bytes_in'] >= 0)

    unusual = "o'reilly\\subscriber; DROP TABLE radacct; --"
    send('escaped-username', 'Start', 'escaping', base, user=unusual)
    check('network-text-escaped', snapshot('escaping-snapshot', 'escaping')['username'] == unusual)
    send('same-session-first-nas', 'Start', 'shared-session', base)
    send('same-session-second-nas', 'Start', 'shared-session', base, nas='192.0.2.11')
    reconcile('namespace-reconcile')
    check('nas-session-namespace-separated', query('namespace-read', "SELECT COUNT(DISTINCT s.id) FROM sessions s JOIN radacct r ON s.id=r.aegis_session_id WHERE r.acctsessionid='shared-session'") == 2)
    shared_class = {'Class': 'ai:' + 'a' * 32}
    send('class-session-first-nas', 'Start', 'shared-class-session', base, extra=shared_class)
    send('class-session-second-nas', 'Start', 'shared-class-session', base, nas='192.0.2.11', extra=shared_class)
    reconcile('class-namespace-reconcile')
    check('class-session-namespace-separated', query('class-namespace-read', "SELECT COUNT(DISTINCT s.id) FROM sessions s JOIN radacct r ON s.id=r.aegis_session_id WHERE r.acctsessionid='shared-class-session'") == 2)
    send('future-session', 'Start', 'future-session', base + 600)
    send('accounting-off', 'Accounting-Off', None, base + 300)
    reconcile('accounting-off-reconcile')
    check('nas-off-is-scoped', query('nas-off-read', "SELECT COUNT(*) FROM radacct WHERE acctsessionid='shared-session' AND nasipaddress='192.0.2.11' AND acctstoptime IS NULL") == 1)
    check('nas-off-preserves-newer-session', snapshot('future-session-read', 'future-session')['acctstoptime'] is None)
    check('nas-off-closes-older-session', snapshot('escaping-after-off', 'escaping')['acctterminatecause'] == 'NAS-Reboot')
    send('accounting-on', 'Accounting-On', None, base + 700)
    reconcile('accounting-on-reconcile')
    check('nas-on-closes-session', snapshot('future-after-on', 'future-session')['acctstoptime'] is not None)
    send('missing-session-dropped', 'Start', None, base, expect_response=False)
    send('unsupported-status-dropped', 99, None, base, expect_response=False)
    send('missing-status-dropped', None, 'missing-status', base, expect_response=False)
    wall = int(time.time())
    send('timestamp-fallback', 'Start', 'timestamp-fallback', None, extra={'Acct-Delay-Time': 5})
    fallback = query('timestamp-fallback-read', "SELECT EXTRACT(EPOCH FROM acctstarttime)::BIGINT FROM radacct WHERE acctsessionid='timestamp-fallback'")
    check('timestamp-fallback-honors-delay', wall - 6 <= fallback <= int(time.time()) - 4)
    send('ipv6-assignment', 'Start', 'ipv6-assignment', base, extra={'Framed-IPv6-Address': '2001:db8::2', 'Framed-IPv6-Prefix': '2001:db8:1::/64', 'Delegated-IPv6-Prefix': '2001:db8:2::/64'})
    reconcile('ipv6-reconcile')
    row = snapshot('ipv6-read', 'ipv6-assignment')
    check('ipv6-metadata-persisted', row['framedipv6address'] == '2001:db8::2' and row['framedipv6prefix'] == '2001:db8:1::/64' and row['delegatedipv6prefix'] == '2001:db8:2::/64' and row['aegis_reconcile_status'] == 'reconciled')
    check('postauth-no-passwords', query('postauth-password-read', "SELECT COUNT(*) FROM radpostauth WHERE COALESCE(pass, '') <> ''") == 0)
    check('sql-role-least-privilege', query('role-privilege-read', "SELECT to_json(has_table_privilege('radius','radacct','INSERT') AND NOT has_table_privilege('radius','sessions','INSERT') AND NOT has_schema_privilege('radius','public','CREATE'))") is True)
