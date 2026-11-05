import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import inventory_appliance as inventory


class ApplianceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / 'root'
        for path in inventory.SCOPES.values():
            (self.root / path).mkdir(parents=True)
        self.snap = self.root / 'var/lib/snapd/snaps/example_10.snap'
        self.firmware = self.root / 'lib/firmware/device.bin'
        self.kernel = self.root / 'boot/vmlinuz-1'
        self.snap.write_bytes(b'synthetic squashfs fixture, not a real snap')
        self.firmware.write_bytes(b'firmware-fixture')
        self.kernel.write_bytes(b'kernel-fixture')

    def save(self):
        result = inventory.collect(self.root)
        path = self.base / 'inventory.json'
        inventory.write_new(path, result)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def cli(self, *arguments):
        return subprocess.run([sys.executable, str(Path(inventory.__file__).resolve()),
                               *map(str, arguments)], capture_output=True, text=True, timeout=20)

    def test_inventory_hashes_every_file_without_claiming_security_pass(self):
        value = inventory.collect(self.root)
        self.assertEqual(value['status'], 'PASS')
        self.assertEqual(value['file_bytes_hashed'], sum(p.stat().st_size for p in (self.snap, self.firmware, self.kernel)))
        for scope, path in (('snaps', self.snap), ('firmware', self.firmware), ('boot', self.kernel)):
            row = value['scopes'][scope]['entries'][0]
            self.assertEqual(row['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(value['scopes']['snaps']['entries'][0]['artifact_kind'], 'snap-squashfs')
        self.assertEqual(value['release_gate']['status'], 'BLOCKED')
        self.assertFalse(value['release_gate']['signature_verified'])

    def test_unchanged_rootfs_matches_independently_recorded_manifest(self):
        path, digest = self.save()
        result = inventory.verify(self.root, path, digest)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['release_gate']['status'], 'BLOCKED')

    def test_file_change_detected_even_if_size_unchanged(self):
        path, digest = self.save()
        self.firmware.write_bytes(b'F' * self.firmware.stat().st_size)
        self.assertEqual(inventory.verify(self.root, path, digest)['status'], 'FAIL')

    def test_addition_and_removal_detected(self):
        path, digest = self.save()
        extra = self.root / 'boot/new-kernel'
        extra.write_bytes(b'new')
        self.assertEqual(inventory.verify(self.root, path, digest)['status'], 'FAIL')
        extra.unlink()
        self.kernel.unlink()
        self.assertEqual(inventory.verify(self.root, path, digest)['status'], 'FAIL')

    def test_manifest_tamper_and_invalid_expected_digest_rejected(self):
        path, digest = self.save()
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'independently recorded'):
            inventory.verify(self.root, path, digest)
        for invalid in ('', digest.upper(), 'a' * 63, 'g' * 64):
            with self.assertRaises(ValueError):
                inventory.verify(self.root, path, invalid)

    def test_oversized_manifest_is_bounded(self):
        path, digest = self.save()
        with patch.object(inventory, 'MAX_MANIFEST_BYTES', 16):
            with self.assertRaisesRegex(ValueError, 'manifest exceeds'):
                inventory.verify(self.root, path, digest)

    def test_malformed_and_incomplete_inventory_rejected(self):
        path = self.base / 'bad.json'
        for value in ([], {}, {'schema_version': True}, {'schema_version': 1,
                      'kind': 'appliance-file-inventory', 'status': 'BLOCKED', 'scopes': {}}):
            with self.subTest(value=value):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    inventory.verify(self.root, path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_missing_scope_blocks_collection_and_verification(self):
        self.kernel.unlink()
        (self.root / 'boot').rmdir()
        path, digest = self.save()
        self.assertEqual(json.loads(path.read_text())['status'], 'BLOCKED')
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            inventory.verify(self.root, path, digest)

    def test_entry_and_byte_limits_fail_closed(self):
        for key, limit in (('MAX_ENTRIES', 1), ('MAX_FILE_BYTES', 1), ('MAX_TOTAL_BYTES', 1)):
            with self.subTest(limit=key), patch.object(inventory, key, limit):
                result = inventory.collect(self.root)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertTrue(any('limit' in error for scope in result['scopes'].values() for error in scope['errors']))

    def test_permission_error_is_not_empty_inventory_success(self):
        with patch.object(inventory.os, 'scandir', side_effect=PermissionError('not readable')):
            self.assertEqual(inventory.collect(self.root)['status'], 'BLOCKED')

    def test_time_limit_retains_partial_inventory_and_blocks(self):
        with patch.object(inventory.time, 'monotonic', side_effect=[0] + [2] * 100):
            result = inventory.collect(self.root, timeout_seconds=1)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertTrue(all('time limit' in s['errors'][0] for s in result['scopes'].values()))

    def test_cancellation_retains_blocked_evidence_and_invalid_timeout_rejected(self):
        result = inventory.collect(self.root, cancelled=lambda: True)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertTrue(all('cancelled' in s['errors'][0] for s in result['scopes'].values()))
        for value in (0, 3601, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                inventory.collect(self.root, timeout_seconds=value)

    def test_changed_input_during_read_rejected(self):
        actual = inventory.os.fstat
        def changed(fd):
            info = actual(fd)
            self.firmware.write_bytes(b'changed during read')
            return info
        with patch.object(inventory.os, 'fstat', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed during read'):
                inventory.regular_digest(self.firmware, {'bytes': 0})

    def test_changed_directory_during_enumeration_rejected(self):
        actual = inventory.regular_digest
        def changed(path, budget):
            value = actual(path, budget)
            if path == self.firmware:
                (path.parent / 'new-file').write_bytes(b'new')
            return value
        with patch.object(inventory, 'regular_digest', side_effect=changed):
            self.assertEqual(inventory.collect(self.root)['scopes']['firmware']['status'], 'BLOCKED')

    def test_support_files_not_mislabeled_as_snap_packages(self):
        (self.snap.parent / 'README').write_bytes(b'support-file')
        rows = inventory.collect(self.root)['scopes']['snaps']['entries']
        row = next(r for r in rows if r['path'] == 'README')
        self.assertEqual(row['artifact_kind'], 'snap-store-support-file')

    def test_cli_roundtrip_and_overwrite_refusal(self):
        path = self.base / 'collected.json'
        proc = self.cli('collect', '--root', self.root, '--output', path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        before = path.read_bytes()
        proc = self.cli('collect', '--root', self.root, '--output', path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(before, path.read_bytes())
        proc = self.cli('verify', '--root', self.root, '--output', self.base / 'compared.json',
                        '--inventory', path, '--expected-sha256', hashlib.sha256(before).hexdigest())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['release_gate']['status'], 'BLOCKED')

    def test_output_cannot_contaminate_scope(self):
        output = self.kernel.parent / 'inventory.json'
        proc = self.cli('collect', '--root', self.root, '--output', output)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(output.exists())

    def test_verification_requires_external_digest(self):
        path, _ = self.save()
        proc = self.cli('verify', '--root', self.root, '--inventory', path, '--output', self.base / 'verify.json')
        self.assertEqual(proc.returncode, 2)

    @unittest.skipUnless(os.name == 'posix', 'Linux rootfs link and special-file semantics')
    def test_merged_usr_and_absolute_links_are_resolved_inside_snapshot(self):
        (self.root / 'usr').mkdir()
        (self.root / 'lib').rename(self.root / 'usr/lib')
        (self.root / 'lib').symlink_to('usr/lib', target_is_directory=True)
        (self.root / 'usr/lib/firmware/alias.bin').symlink_to('/lib/firmware/device.bin')
        result = inventory.collect(self.root)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['scopes']['firmware']['resolved_path'], 'usr/lib/firmware')
        row = next(r for r in result['scopes']['firmware']['entries'] if r['path'] == 'alias.bin')
        self.assertEqual(row['resolved_path'], 'device.bin')
        path, digest = self.save()
        self.assertEqual(inventory.verify(self.root, path, digest)['status'], 'PASS')

    @unittest.skipUnless(os.name == 'posix', 'Linux rootfs link and special-file semantics')
    def test_verification_rejects_fifo_and_symlink_before_reading(self):
        path, digest = self.save()
        link = self.base / 'manifest-link'
        link.symlink_to(path.name)
        fifo = self.base / 'manifest-pipe'
        os.mkfifo(fifo)
        for value in (link, fifo):
            with self.subTest(path=value), self.assertRaisesRegex(ValueError, 'regular file'):
                inventory.verify(self.root, value, digest)

    @unittest.skipUnless(os.name == 'posix', 'Linux rootfs link and special-file semantics')
    def test_scope_escape_broken_cycle_and_blob_symlinks_fail_closed(self):
        link = self.firmware.parent / 'link'
        for target in ('../../../outside', '/boot/vmlinuz-1', 'missing', 'link'):
            with self.subTest(target=target):
                link.symlink_to(target)
                self.assertEqual(inventory.collect(self.root)['status'], 'BLOCKED')
                link.unlink()
        (self.snap.parent / 'alias.snap').symlink_to(self.snap.name)
        self.assertEqual(inventory.collect(self.root)['status'], 'BLOCKED')

    @unittest.skipUnless(os.name == 'posix', 'Linux rootfs link and special-file semantics')
    def test_fifo_rejected_without_blocking_and_directory_links_not_followed(self):
        fifo = self.firmware.parent / 'pipe'
        os.mkfifo(fifo)
        self.assertEqual(inventory.collect(self.root)['status'], 'BLOCKED')
        fifo.unlink()
        (self.firmware.parent / 'directory-alias').symlink_to('.', target_is_directory=True)
        result = inventory.collect(self.root)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['scopes']['firmware']['file_count'], 1)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process signals and procfs')
    def test_cli_sigterm_saves_blocked_partial_report(self):
        large = self.snap.parent / 'large.snap'
        with large.open('wb') as stream:
            stream.truncate(1024**3)  # Sparse fixture: no 1 GiB allocation or write.
        output = self.base / 'cancelled.json'
        process = subprocess.Popen([sys.executable, str(Path(inventory.__file__).resolve()),
            'collect', '--root', str(self.root), '--output', str(output)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            started = False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    started = any(os.readlink(p) == str(large) for p in Path('/proc', str(process.pid), 'fd').iterdir())
                except (FileNotFoundError, ProcessLookupError):
                    pass
                if started:
                    break
                time.sleep(0.005)
            self.assertTrue(started, 'collector must be reading the fixture before SIGTERM')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 1, (stdout, stderr))
            result = json.loads(output.read_text())
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertTrue(any('cancelled' in error for s in result['scopes'].values() for error in s['errors']))
            self.assertEqual(large.stat().st_size, 1024**3)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


if __name__ == '__main__':
    unittest.main()
