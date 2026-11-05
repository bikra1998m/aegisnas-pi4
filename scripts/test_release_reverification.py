import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_admit_release as fixtures
import test_release_security as evidence_fixtures
import admit_release as admission
import release_security as security
import release_sequence as sequence
import reverify_release as verifier


class ReleaseReverificationTests(unittest.TestCase):
    setUp = fixtures.AdmissionTests.setUp
    archive = fixtures.AdmissionTests.archive
    run_admission = fixtures.AdmissionTests.run_admission

    def stage(self):
        self.archive()
        return self.run_admission()

    def reverify(self):
        with patch.object(security, 'verify_artifact') as verify, patch.object(
                security, 'check', return_value={'status': 'passed'}) as check:
            result = verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
            verify.assert_called_once()
            check.assert_called_once()
            return result

    def mutate_receipt(self, **values):
        path = self.output / 'admission.json'
        receipt = security.read_json(path)
        receipt.update(values)
        security.write_json(path, receipt)

    def test_all_files_reverified_without_changing_receipt_or_state(self):
        self.stage()
        before = {p: p.read_bytes() for p in (self.output / 'admission.json', self.state_dir / 'sequence.json')}
        result = self.reverify()
        self.assertEqual(result['status'], 'reverified')
        self.assertTrue(result['signature_reverified'])
        self.assertFalse(result['production_activation_authorized'])
        self.assertEqual(result['payload_files_verified'], len(self.files) + 1)
        for path, value in before.items():
            self.assertEqual(path.read_bytes(), value)

    def test_bad_signature_blocks_even_with_valid_receipt(self):
        self.stage()
        with patch.object(security, 'verify_artifact', side_effect=subprocess.CalledProcessError(1, 'gh')):
            with self.assertRaises(subprocess.CalledProcessError):
                verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        self.assertEqual(self.reverify()['status'], 'reverified')  # lock released after failure

    def test_missing_verifier_blocks_real_verification_path(self):
        self.stage()
        with patch.object(security.shutil, 'which', return_value=None), self.assertRaisesRegex(ValueError, 'GitHub CLI'):
            verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)

    def test_changed_file_and_forged_receipt_cannot_replace_signed_contents(self):
        self.stage()
        payload = self.output / 'bin/aegis-admin'
        payload.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.reverify()
        receipt = security.read_json(self.output / 'admission.json')
        receipt['payload_sha256']['bin/aegis-admin'] = security.digest(payload)
        self.mutate_receipt(payload_sha256=receipt['payload_sha256'])
        with self.assertRaisesRegex(ValueError, 'receipt or signed manifest'):
            self.reverify()

    def test_missing_file_extra_file_and_empty_directory_block(self):
        self.stage()
        extra = self.output / 'extra'
        extra.write_bytes(b'unlisted')
        extra.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.reverify()
        extra.unlink(); extra.mkdir()
        extra.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.reverify()
        extra.rmdir()
        (self.output / 'bin/aegis-admin').unlink()
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.reverify()

    def test_altered_artifact_and_wrong_scope_do_not_pass(self):
        self.stage()
        original = self.artifact.read_bytes()
        self.artifact.write_bytes(original + b'changed')
        with self.assertRaisesRegex(ValueError, 'reservation'):
            self.reverify()
        self.artifact.write_bytes(original)
        self.policy['platform'] = 'linux-amd64'
        security.write_json(self.policy_path, self.policy)
        with self.assertRaisesRegex(ValueError, 'repository/platform'):
            self.reverify()

    def test_newer_reservation_and_current_floor_block_old_release(self):
        self.stage()
        self.policy['minimum_sequence'] = 13
        security.write_json(self.policy_path, self.policy)
        with self.assertRaisesRegex(ValueError, 'floor'):
            self.reverify()
        self.policy['minimum_sequence'] = 12
        security.write_json(self.policy_path, self.policy)
        policy = admission.load_policy(self.policy_path)
        with sequence.locked_state(self.state_dir, policy) as state:
            sequence.reserve(self.state_dir, state, policy, {'release_sequence': 13, 'source_commit': self.commit}, 'b' * 64)
        with self.assertRaisesRegex(ValueError, 'reservation'):
            self.reverify()

    def test_updated_policy_is_rechecked_without_rewriting_old_receipt(self):
        receipt = self.stage()
        self.policy['allowed_commits'].append('b' * 40)
        security.write_json(self.policy_path, self.policy)
        result = self.reverify()
        self.assertNotEqual(result['current_policy_sha256'], receipt['policy_sha256'])
        self.assertEqual(security.read_json(self.output / 'admission.json'), receipt)
        self.policy['allowed_commits'] = ['b' * 40]
        security.write_json(self.policy_path, self.policy)
        with self.assertRaisesRegex(ValueError, 'not authorized'):
            self.reverify()

    def test_boolean_policy_schema_is_not_version_one(self):
        self.policy['schema_version'] = True
        security.write_json(self.policy_path, self.policy)
        with self.assertRaises(ValueError):
            admission.load_policy(self.policy_path)

    def test_boolean_release_schema_cannot_be_admitted(self):
        value = json.loads(self.files['release.json']); value['schema_version'] = True
        self.files['release.json'] = json.dumps(value).encode(); self.archive()
        with self.assertRaises(ValueError):
            self.run_admission()

    def test_failed_or_stale_security_evidence_still_blocks(self):
        self.stage()
        with patch.object(security, 'verify_artifact'), patch.object(security, 'check', return_value={
                'status': 'blocked', 'blockers': ['scan evidence older than 24 hours']}):
            with self.assertRaisesRegex(ValueError, 'older than 24 hours'):
                verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)

    def evidence_archive(self, finding=False):
        # Synthetic scanner records, not real scan/certification evidence.
        fixture = evidence_fixtures.ReleaseSecurityTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.now = dt.datetime.now(dt.timezone.utc)
        fixture.evidence['created_at'] = fixture.now.isoformat()
        if finding:
            fixture.set_record('go-vulnerabilities', json.dumps({'config': {
                'scan_level': 'package', 'db_last_modified': fixture.now.isoformat()}}) + '\n' +
                json.dumps({'finding': {'osv': 'GO-TEST-1', 'trace': [{'module': 'synthetic'}]}}))
        fixture.check()  # writes the fixture manifest and its real per-record hashes
        for path in fixture.output.iterdir():
            self.files['security/' + path.name] = path.read_bytes()
        self.archive()
        return fixture.now

    def test_real_policy_engine_is_used_for_admission_and_reverification(self):
        self.evidence_archive()
        with patch.object(security, 'verify_artifact') as verify:
            admission.admit(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
            report = verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        self.assertEqual(report['status'], 'reverified')
        self.assertEqual(verify.call_count, 2)

    def test_real_policy_rejects_previously_valid_evidence_after_expiry(self):
        now = self.evidence_archive()
        with patch.object(security, 'verify_artifact'):
            admission.admit(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        class Later(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return now + dt.timedelta(hours=25)
        with patch.object(security.dt, 'datetime', Later), patch.object(security, 'verify_artifact'):
            with self.assertRaisesRegex(ValueError, 'older than 24 hours'):
                verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)

    def test_real_policy_rejects_finding_despite_existing_receipt(self):
        self.evidence_archive(finding=True)
        self.run_admission()  # deliberately bypass the policy only to construct a negative fixture
        with patch.object(security, 'verify_artifact'), self.assertRaisesRegex(ValueError, 'violate policy'):
            verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)

    def test_malformed_or_false_receipt_claims_fail_closed(self):
        original = self.stage()
        values = ({'schema_version': True}, {'signature_verified_at_admission': False}, {'predicates': []},
                  {'verified_at': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat()},
                  {'sequence_guard': {}}, {'payload_sha256': {}})
        for value in values:
            with self.subTest(value=value):
                security.write_json(self.output / 'admission.json', original)
                self.mutate_receipt(**value)
                with self.assertRaises(ValueError):
                    self.reverify()

    def test_policy_and_state_mutations_during_verification_block(self):
        self.stage()
        original = self.policy_path.read_bytes()
        def change_policy(*args):
            self.policy_path.write_bytes(original + b' ')
        with patch.object(security, 'verify_artifact', side_effect=change_policy), patch.object(
                security, 'check', return_value={'status': 'passed'}):
            with self.assertRaisesRegex(ValueError, 'policy changed'):
                verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        self.policy_path.write_bytes(original)
        def change_state(*args):
            path = self.state_dir / 'sequence.json'; value = security.read_json(path)
            value['highest_verified_sequence'] += 1; security.write_json(path, value)
        with patch.object(security, 'verify_artifact', side_effect=change_state), patch.object(
                security, 'check', return_value={'status': 'passed'}):
            with self.assertRaisesRegex(ValueError, 'state changed'):
                verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)

    def test_changed_directory_membership_after_hashing_blocks(self):
        self.stage()
        original = verifier._inspect_tree
        def mutate(path):
            result = original(path)
            (path / 'late-file').write_bytes(b'appeared after hashing')
            return result
        with patch.object(verifier, '_inspect_tree', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'changed'):
                self.reverify()

    def test_busy_state_blocks_and_reports_are_not_state_updates(self):
        self.stage()
        with sequence.locked_state(self.state_dir, admission.load_policy(self.policy_path)):
            with self.assertRaisesRegex(ValueError, 'busy'):
                self.reverify()
        self.assertEqual(self.reverify()['status'], 'reverified')

    def test_size_entry_receipt_limits_fail_closed(self):
        self.stage()
        for owner, key in ((verifier, 'MAX_RECEIPT'), (admission, 'MAX_FILES'), (admission, 'MAX_EXPANDED'), (admission, 'MAX_ARCHIVE')):
            with self.subTest(key=key), patch.object(owner, key, 1), self.assertRaises(ValueError):
                self.reverify()

    def test_candidate_private_copy_detects_mutation(self):
        self.archive()
        actual = admission.os.fstat
        def mutate(fd):
            info = actual(fd)
            with self.artifact.open('ab') as f:
                f.write(b'changed')
            return info
        with patch.object(admission.os, 'fstat', side_effect=mutate), self.assertRaisesRegex(ValueError, 'changed'):
            admission.copy_candidate(self.artifact, self.root / 'copy')

    def test_candidate_hard_link_is_rejected(self):
        self.archive()
        alias = self.root / 'alias.tar.gz'
        os.link(self.artifact, alias)
        with self.assertRaisesRegex(ValueError, 'single-link'):
            admission.copy_candidate(alias, self.root / 'copy')

    def test_cli_returns_structured_result_and_rejects_failed_verifier(self):
        self.stage()
        args = ['reverify_release.py', str(self.artifact), '--policy', str(self.policy_path), '--commit', self.commit,
                '--release-dir', str(self.output), '--state-dir', str(self.state_dir)]
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', args), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with patch.object(security, 'verify_artifact'), patch.object(security, 'check', return_value={'status': 'passed'}):
                self.assertEqual(verifier.main(), 0)
            self.assertFalse(json.loads(out.getvalue())['production_activation_authorized'])
            with patch.object(security, 'verify_artifact', side_effect=subprocess.CalledProcessError(1, 'gh')):
                self.assertEqual(verifier.main(), 1)
        self.assertIn('blocked', err.getvalue())

    @unittest.skipUnless(os.name == 'posix', 'Linux permission semantics')
    def test_group_writable_umask_does_not_publish_writable_directories(self):
        self.files['nested/path/payload.txt'] = b'protected payload'
        self.archive()
        previous = os.umask(0o002)
        try:
            self.run_admission()
        finally:
            os.umask(previous)
        for path in [self.output, *self.output.rglob('*')]:
            with self.subTest(path=path.relative_to(self.output).as_posix()):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o022, 0)
        self.assertEqual(self.reverify()['status'], 'reverified')

    @unittest.skipUnless(os.name == 'posix', 'Linux permission and special-file semantics')
    def test_staged_links_fifo_and_unsafe_modes_are_rejected_without_repair(self):
        self.stage()
        extra = self.output / 'extra'
        extra.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            self.reverify()
        extra.unlink(); os.mkfifo(extra)
        with self.assertRaises(ValueError):
            self.reverify()
        extra.unlink()
        for path in (self.output / 'bin', self.output / 'admission.json', self.output / 'bin/aegis-admin'):
            before = stat.S_IMODE(path.stat().st_mode)
            path.chmod(before | 0o020)
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                self.reverify()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), before | 0o020)
            path.chmod(before)
        (self.output / 'bin/aegis-admin').chmod(0o4755)
        with self.assertRaisesRegex(ValueError, 'permissions'):
            self.reverify()

    @unittest.skipUnless(os.name == 'posix', 'Linux link and special-file semantics')
    def test_candidate_symlink_and_fifo_rejected_before_copy(self):
        self.archive()
        link = self.root / 'alias'
        link.symlink_to(self.artifact)
        with self.assertRaises(ValueError):
            admission.copy_candidate(link, self.root / 'copy')
        link.unlink(); os.mkfifo(link)
        with self.assertRaises(ValueError):
            admission.copy_candidate(link, self.root / 'copy')

    @unittest.skipUnless(os.name == 'posix', 'Linux policy permissions')
    def test_policy_permissions_are_rechecked_after_signature_verification(self):
        self.stage()
        def weaken(*args):
            self.policy_path.chmod(0o666)
        for action in ('reverify', 'admit'):
            self.policy_path.chmod(0o600)
            with self.subTest(action=action), patch.object(security, 'verify_artifact', side_effect=weaken), patch.object(
                    security, 'check', return_value={'status': 'passed'}), self.assertRaisesRegex(ValueError, 'unsafe'):
                if action == 'reverify':
                    verifier.reverify(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
                else:
                    admission.admit(self.artifact, self.policy_path, self.commit, self.root / 'another-stage', self.state_dir)
if __name__ == '__main__':
    unittest.main()
