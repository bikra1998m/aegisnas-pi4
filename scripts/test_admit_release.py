import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import admit_release as admission
import release_security as security
import release_sequence as sequence


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.commit = "a" * 40
        self.policy = {"schema_version": 1, "repository": "owner/repo", "platform": "linux-arm64",
                       "minimum_sequence": 12, "allowed_commits": [self.commit]}
        self.policy_path = self.root / "policy.json"
        security.write_json(self.policy_path, self.policy)
        self.policy_path.chmod(0o600)
        self.state_dir = self.root / "sequence-state"
        sequence.initialize(self.state_dir, admission.load_policy(self.policy_path))
        self.files = {
            "release.json": json.dumps({"schema_version": 1, "source_commit": self.commit,
                                       "repository": "owner/repo", "platform": "linux-arm64",
                                       "release_sequence": 12}).encode(),
            "SOURCE_COMMIT": (self.commit + "\n").encode(),
            "bin/aegis-admin": b"test binary, not executable",
            "security/evidence.json": json.dumps({"source": {"commit": self.commit}}).encode(),
        }
        self.output = self.root / "release"
        self.artifact = self.root / "candidate.tar.gz"

    def archive(self, extra=None):
        import hashlib
        files = {**self.files}
        files["SHA256SUMS"] = "".join(f"{hashlib.sha256(data).hexdigest()}  ./{name}\n"
                                       for name, data in files.items()).encode()
        if extra:
            files.update(extra)
        with tarfile.open(self.artifact, "w:gz") as tar:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))

    def run_admission(self):
        # These are admission-unit fixtures, not cryptographic certification.
        with patch.object(security, "verify_artifact") as verify, patch.object(
                security, "check", return_value={"status": "passed"}):
            receipt = admission.admit(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
            verify.assert_called_once()
            return receipt

    def test_verified_candidate_is_staged_with_receipt(self):
        self.archive()
        receipt = self.run_admission()
        self.assertEqual(receipt["status"], "admitted")
        self.assertTrue((self.output / "admission.json").exists())
        self.assertIn("bin/aegis-admin", receipt["payload_sha256"])
        self.assertEqual(receipt["artifact_sha256"], security.digest(self.artifact))

    def test_failed_signature_writes_no_payload(self):
        self.archive()
        with patch.object(security, "verify_artifact", side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                admission.admit(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        self.assertFalse(self.output.exists())

    def test_unapproved_commit_and_downgrade_are_rejected(self):
        self.archive()
        with self.assertRaisesRegex(ValueError, "not authorized"):
            admission.admit(self.artifact, self.policy_path, "b" * 40, self.output, self.state_dir)
        self.policy["minimum_sequence"] = 13
        security.write_json(self.policy_path, self.policy)
        with self.assertRaisesRegex(ValueError, "downgrade"):
            self.run_admission()
        self.assertFalse(self.output.exists())

    def test_wrong_platform_and_source_are_rejected(self):
        for field, value in (("platform", "linux-amd64"), ("source_commit", "b" * 40)):
            with self.subTest(field=field):
                manifest = json.loads(self.files["release.json"])
                manifest[field] = value
                self.files["release.json"] = json.dumps(manifest).encode()
                self.archive()
                with self.assertRaises(ValueError):
                    self.run_admission()

    def test_tampered_or_unlisted_payload_is_rejected(self):
        for extra in ({"bin/aegis-admin": b"tampered"}, {"evil": b"unlisted"}):
            self.archive(extra)
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.run_admission()
            self.assertFalse(self.output.exists())

    def test_existing_release_is_never_overwritten(self):
        self.archive()
        self.output.mkdir()
        (self.output / "marker").write_text("preserve")
        with self.assertRaisesRegex(ValueError, "already exist"):
            self.run_admission()
        self.assertEqual((self.output / "marker").read_text(), "preserve")

    def test_path_escape_links_duplicates_and_resource_limits(self):
        for name in ("../outside", "/outside", "C:/outside", "a\\outside", "bad. /file"):
            with self.subTest(name=name):
                self.archive({name: b"bad"})
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    self.run_admission()
        self.archive()
        with patch.object(admission, "MAX_EXPANDED", 1), self.assertRaisesRegex(ValueError, "size limit"):
            self.run_admission()
        with patch.object(admission, "MAX_FILES", 1), self.assertRaisesRegex(ValueError, "too many"):
            self.run_admission()
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE):
            with tarfile.open(self.artifact, "w:gz") as tar:
                entry = tarfile.TarInfo("link")
                entry.type, entry.linkname = kind, "/outside"
                tar.addfile(entry)
            with self.assertRaisesRegex(ValueError, "special files"):
                self.run_admission()
        with tarfile.open(self.artifact, "w:gz") as tar:
            for name in ("file", "FILE"):
                tar.addfile(tarfile.TarInfo(name), io.BytesIO())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_admission()

    def test_failed_evidence_cannot_be_admitted(self):
        self.archive()
        with patch.object(security, "verify_artifact"), patch.object(
                security, "check", return_value={"status": "blocked", "blockers": ["expired"]}):
            with self.assertRaisesRegex(ValueError, "evidence blocked"):
                admission.admit(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        self.assertFalse(self.output.exists())

    def change_sequence(self, number):
        manifest = json.loads(self.files["release.json"])
        manifest["release_sequence"] = number
        self.files["release.json"] = json.dumps(manifest).encode()
        self.archive()

    def state(self):
        return sequence.read_state(self.state_dir, self.policy)

    def test_durable_floor_survives_policy_lowering(self):
        self.change_sequence(14)
        self.run_admission()
        self.output = self.root / "older-release"
        self.policy["minimum_sequence"] = 1
        security.write_json(self.policy_path, self.policy)
        self.change_sequence(13)
        with self.assertRaisesRegex(ValueError, "durable state"):
            self.run_admission()
        self.assertEqual(self.state()["highest_verified_sequence"], 14)
        self.assertFalse(self.output.exists())

    def test_sequence_cannot_identify_a_different_artifact(self):
        self.archive()
        self.run_admission()
        self.output = self.root / "different-release"
        self.files["bin/aegis-admin"] = b"a different binary"
        self.archive()
        with self.assertRaisesRegex(ValueError, "another artifact"):
            self.run_admission()
        self.assertFalse(self.output.exists())

    def test_identical_artifact_can_be_reverified_and_staged_again(self):
        self.archive()
        first = self.run_admission()
        self.output = self.root / "retry"
        second = self.run_admission()
        self.assertEqual(first["sequence_guard"], second["sequence_guard"])
        self.assertEqual(self.state()["artifact_sha256"], security.digest(self.artifact))

    def test_initialization_never_resets_existing_or_damaged_state(self):
        for corrupt in (False, True):
            if corrupt:
                (self.state_dir / "sequence.json").write_text("damaged")
            before = (self.state_dir / "sequence.json").read_bytes()
            with self.assertRaises(FileExistsError):
                sequence.initialize(self.state_dir, self.policy)
            self.assertEqual((self.state_dir / "sequence.json").read_bytes(), before)

    def test_missing_corrupt_or_mismatched_state_fails_closed(self):
        self.archive()
        original = self.state()
        values = [b"not JSON", b"[]", b" " * 65537]
        for key, value in (("repository", "other/repo"), ("platform", "linux-amd64"),
                           ("highest_verified_sequence", True), ("highest_verified_sequence", -1),
                           ("source_commit", "invalid"), ("state_id", "invalid")):
            values.append(json.dumps({**original, key: value}).encode())
        missing = {k: v for k, v in original.items() if k != "artifact_sha256"}
        values.append(json.dumps(missing).encode())
        for raw in values:
            (self.state_dir / "sequence.json").write_bytes(raw)
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                self.run_admission()
            self.assertFalse(self.output.exists())
        (self.state_dir / "sequence.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_admission()

    def test_missing_lock_fails_closed(self):
        self.archive()
        (self.state_dir / "sequence.lock").unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_admission()
        self.assertFalse(self.output.exists())

    def test_state_cannot_be_inside_payload_or_contain_it(self):
        self.archive()
        for output in (self.state_dir, self.root, self.state_dir / "payload"):
            self.output = output
            with self.assertRaisesRegex(ValueError, "outside"):
                self.run_admission()
        with self.assertRaisesRegex(ValueError, "outside"):
            admission.admit(self.artifact, self.policy_path, self.commit, self.state_dir / "payload",
                            self.root / "unused" / ".." / "sequence-state")

    def test_failed_verifier_and_policy_change_never_advance_floor(self):
        self.archive()
        before = self.state()
        with patch.object(security, "verify_artifact", side_effect=ValueError("signature rejected")):
            with self.assertRaisesRegex(ValueError, "signature rejected"):
                admission.admit(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        self.assertEqual(self.state(), before)
        def change_policy(*args):
            security.write_json(self.policy_path, {**self.policy, "minimum_sequence": 13})
        with patch.object(security, "verify_artifact", side_effect=change_policy), patch.object(
                security, "check", return_value={"status": "passed"}):
            with self.assertRaisesRegex(ValueError, "policy changed"):
                admission.admit(self.artifact, self.policy_path, self.commit, self.output, self.state_dir)
        self.assertEqual(self.state(), before)
        self.assertFalse(self.output.exists())

    def test_state_write_or_payload_flush_failure_prevents_publication(self):
        self.archive()
        before = self.state()
        for method in ("_write_state", "sync_payload"):
            with patch.object(sequence, method, side_effect=OSError("injected I/O failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    self.run_admission()
            self.assertEqual(self.state(), before)
            self.assertFalse(self.output.exists())

    def test_state_directory_flush_failure_prevents_publication(self):
        self.archive()
        original = sequence.sync_directory
        def fail_state_sync(path):
            if path == self.state_dir:
                raise OSError("injected directory flush failure")
            original(path)
        with patch.object(sequence, "sync_directory", side_effect=fail_state_sync):
            with self.assertRaisesRegex(OSError, "flush failure"):
                self.run_admission()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.state()["highest_verified_sequence"], 12)
        self.run_admission()  # Retry preserves the reservation.

    def test_publication_failure_consumes_sequence_and_allows_identical_retry(self):
        self.archive()
        with patch.object(admission.os, "rename", side_effect=OSError("injected publication failure")):
            with self.assertRaisesRegex(OSError, "publication failure"):
                self.run_admission()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.state()["highest_verified_sequence"], 12)
        self.run_admission()
        self.assertTrue(self.output.exists())

    def test_concurrent_process_is_rejected_and_killed_owner_releases_lock(self):
        marker = self.root / "lock-acquired"
        code = """
import pathlib, sys
import admit_release, release_sequence
state, policy, marker = map(pathlib.Path, sys.argv[1:])
with release_sequence.locked_state(state, admit_release.load_policy(policy)):
    marker.write_text('locked')
    sys.stdin.read()
"""
        child = subprocess.Popen([sys.executable, "-c", code, str(self.state_dir),
                                  str(self.policy_path), str(marker)],
                                 cwd=Path(__file__).parent, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 15
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(marker.exists(), "child did not acquire the lock")
            with self.assertRaisesRegex(ValueError, "busy"):
                with sequence.locked_state(self.state_dir, self.policy):
                    self.fail("concurrent lock acquired")
            child.kill()
            child.communicate(timeout=10)
            with sequence.locked_state(self.state_dir, self.policy) as state:
                self.assertEqual(state["highest_verified_sequence"], 11)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def test_process_death_before_and_after_publication_preserves_floor(self):
        self.archive()
        for published in (False, True):
            self.output = self.root / ("crash-published" if published else "crash-reserved")
            code = """
import os, pathlib, sys
from unittest.mock import patch
import admit_release, release_security
artifact, policy, state, output = map(pathlib.Path, sys.argv[1:5])
original = os.rename
def die_before_return(source, destination):
    if sys.argv[5] == 'yes':
        original(source, destination)
    os._exit(73)
with patch.object(release_security, 'verify_artifact'), patch.object(release_security, 'check', return_value={'status': 'passed'}), patch.object(admit_release.os, 'rename', side_effect=die_before_return):
    admit_release.admit(artifact, policy, 'a'*40, output, state)
"""
            result = subprocess.run([sys.executable, "-c", code, str(self.artifact),
                                     str(self.policy_path), str(self.state_dir), str(self.output),
                                     "yes" if published else "no"], cwd=Path(__file__).parent,
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 73, result.stderr.decode())
            self.assertEqual(self.output.exists(), published)
            self.assertEqual(self.state()["highest_verified_sequence"], 12)
            self.assertEqual(self.state()["artifact_sha256"], security.digest(self.artifact))
            if published:
                self.assertEqual(security.read_json(self.output / "admission.json")["sequence_guard"][
                    "state_id"], self.state()["state_id"])
            self.output = self.root / ("retry-published" if published else "retry-reserved")
            self.run_admission()

    @unittest.skipUnless(os.name == "posix", "production Linux ownership/link checks")
    def test_untrusted_state_policy_and_output_paths_are_rejected(self):
        self.archive()
        for path in (self.state_dir, self.state_dir / "sequence.json", self.state_dir / "sequence.lock",
                     self.policy_path, self.root):
            mode = path.stat().st_mode & 0o777
            try:
                path.chmod(mode | 0o022)
                with self.assertRaisesRegex(ValueError, "permissions|private"):
                    self.run_admission()
            finally:
                path.chmod(mode)
        state_file = self.state_dir / "sequence.json"
        saved = self.state_dir / "saved.json"
        state_file.rename(saved)
        try:
            state_file.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                self.run_admission()
            state_file.unlink()
            os.link(saved, state_file)
            with self.assertRaisesRegex(ValueError, "hard links"):
                self.run_admission()
        finally:
            state_file.unlink(missing_ok=True)
            saved.rename(state_file)

    def test_cli_requires_existing_state_and_explicit_initialization(self):
        command = [sys.executable, str(Path(admission.__file__).resolve())]
        args = ["--policy", str(self.policy_path), "--state-dir", str(self.root / "cli-state")]
        missing = subprocess.run([*command, str(self.artifact), *args,
                                  "--commit", self.commit, "--output", str(self.output)],
                                 capture_output=True, timeout=30)
        self.assertNotEqual(missing.returncode, 0)
        initialized = subprocess.run([*command, "--initialize-state", *args], capture_output=True, timeout=30)
        self.assertEqual(initialized.returncode, 0, initialized.stderr.decode())
        repeated = subprocess.run([*command, "--initialize-state", *args], capture_output=True, timeout=30)
        self.assertNotEqual(repeated.returncode, 0)


if __name__ == "__main__":
    unittest.main()
