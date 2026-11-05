import datetime as dt
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_security as security


class ReleaseSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)
        self.now = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)
        self.evidence = {
            "schema_version": 1, "feature_id": "NAS-0116", "created_at": self.now.isoformat(),
            "source": {"commit": "a" * 40, "dirty": False, "inputs": {}}, "commands": {},
        }
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "metadata": {"component": {"type": "application", "name": "app"}},
               "components": [{"type": "library", "name": "lib", "version": "1.0"}]}
        counts = {k: 0 for k in ("info", "low", "moderate", "high", "critical", "total")}
        for name, value in {
            "go-mod-verify": "all modules verified",
            "go-sbom": bom, "npm-sbom": bom,
            "go-vulnerabilities": {"config": {"scan_level": "package", "db_last_modified": self.now.isoformat()}},
            "go-vulnerabilities-arm64": {"config": {"scan_level": "package", "db_last_modified": self.now.isoformat()}},
            "npm-vulnerabilities": {"auditReportVersion": 2, "vulnerabilities": {},
                                    "metadata": {"vulnerabilities": counts}},
        }.items():
            self.set_record(name, value)

    def set_record(self, name, value, code=0):
        data = value if isinstance(value, str) else json.dumps(value)
        path = self.output / (name + ".json")
        path.write_text(data, encoding="utf-8")
        err = self.output / (name + ".stderr")
        err.write_text("", encoding="utf-8")
        self.evidence["commands"][name] = {
            "argv": list(security.COMMANDS[name]), "cwd": security.CWD[name],
            "env": security.SCAN_ENV.get(name, {}), "exit_code": code,
            "sha256": security.digest(path), "stderr_sha256": security.digest(err),
        }

    def check(self):
        security.write_json(self.output / "evidence.json", self.evidence)
        return security.check(self.output, require_clean=True, now=self.now)

    def test_complete_clean_evidence_passes_without_claiming_signature(self):
        report = self.check()
        self.assertEqual(report["status"], "passed", report)
        self.assertFalse(report["signature_verified"])

    def test_evidence_schema_requires_integer_version(self):
        for version in (True, 1.0, "1", None):
            with self.subTest(version=version):
                self.evidence["schema_version"] = version
                self.assertEqual(self.check()["status"], "blocked")

    def test_npm_report_schema_requires_integer_version(self):
        audit = security.read_json(self.output / "npm-vulnerabilities.json")
        for version in (True, 2.0, "2", None):
            with self.subTest(version=version):
                audit["auditReportVersion"] = version
                self.set_record("npm-vulnerabilities", audit)
                self.assertEqual(self.check()["status"], "blocked")

    def test_go_json_zero_exit_with_vulnerabilities_blocks(self):
        self.set_record("go-vulnerabilities", json.dumps({"config": {
            "scan_level": "package", "db_last_modified": self.now.isoformat()}}) + "\n" +
            json.dumps({"finding": {"osv": "GO-TEST-1", "trace": [{"module": "bad"}]}}))
        self.assertEqual(self.check()["status"], "blocked")

    def test_npm_high_blocks_even_with_inconsistent_summary(self):
        audit = security.read_json(self.output / "npm-vulnerabilities.json")
        audit["vulnerabilities"]["bad"] = {"severity": "high"}
        self.set_record("npm-vulnerabilities", audit, 1)
        self.assertEqual(self.check()["status"], "blocked")

    def test_npm_moderate_is_report_only(self):
        audit = security.read_json(self.output / "npm-vulnerabilities.json")
        audit["metadata"]["vulnerabilities"].update(moderate=1, total=1)
        audit["vulnerabilities"]["review"] = {"severity": "moderate"}
        self.set_record("npm-vulnerabilities", audit, 1)
        self.assertEqual(self.check()["status"], "passed")

    def test_npm_network_error_fails_closed(self):
        self.set_record("npm-vulnerabilities", {"error": {"code": "ECONNRESET"}}, 1)
        self.assertEqual(self.check()["status"], "blocked")

    def test_malformed_and_empty_scanner_output_blocks(self):
        for data in ("", "{}", "[]", "{", '{"config": {}}', '{"config": {}} garbage'):
            with self.subTest(data=data):
                self.set_record("go-vulnerabilities", data)
                self.assertEqual(self.check()["status"], "blocked")

    def test_missing_or_tampered_file_blocks(self):
        path = self.output / "go-sbom.json"
        path.write_text("{}", encoding="utf-8")
        self.assertEqual(self.check()["status"], "blocked")
        path.unlink()
        self.assertEqual(self.check()["status"], "blocked")

    def test_dirty_changed_stale_future_evidence_blocks(self):
        self.evidence["source"]["dirty"] = True
        self.assertEqual(self.check()["status"], "blocked")
        self.evidence["source"]["dirty"] = False
        self.evidence["source_changed_during_scan"] = True
        self.assertEqual(self.check()["status"], "blocked")
        del self.evidence["source_changed_during_scan"]
        for delta in (-25, 1):
            self.evidence["created_at"] = (self.now + dt.timedelta(hours=delta)).isoformat()
            self.assertEqual(self.check()["status"], "blocked")

    def test_missing_tool_and_wrong_command_block(self):
        for name in security.COMMANDS:
            with self.subTest(name=name):
                old = self.evidence["commands"][name]["exit_code"]
                self.evidence["commands"][name]["exit_code"] = 127
                self.assertEqual(self.check()["status"], "blocked")
                self.evidence["commands"][name]["exit_code"] = old
        self.evidence["commands"]["go-vulnerabilities"]["argv"] = ["echo", "pass"]
        self.assertEqual(self.check()["status"], "blocked")

    def test_lockfile_or_source_mismatch_blocks(self):
        self.check()
        with patch.object(security, "source_state", return_value={"commit": "b" * 40}):
            report = security.check(self.output, Path("."), now=self.now)
        self.assertEqual(report["status"], "blocked")

    def test_no_empty_inventory_pass(self):
        bom = security.read_json(self.output / "go-sbom.json")
        bom["components"] = []
        self.set_record("go-sbom", bom)
        self.assertEqual(self.check()["status"], "blocked")

    def test_signature_verification_binds_repo_workflow_source_and_both_predicates(self):
        with patch.object(security.shutil, "which", return_value="gh"), patch.object(security.subprocess, "run") as run:
            security.verify_artifact(self.output / "artifact.tar.gz", "owner/repo", "a" * 40)
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            args = call.args[0]
            self.assertIn("owner/repo/.github/workflows/release-candidate.yml", args)
            self.assertIn("refs/heads/main", args)
            self.assertIn("--deny-self-hosted-runners", args)
            self.assertIn("a" * 40, args)
            self.assertTrue(call.kwargs["check"])
            self.assertIs(call.kwargs['stdout'], security.sys.stderr)

    def test_invalid_signature_and_missing_verifier_do_not_fallback(self):
        with patch.object(security.shutil, "which", return_value=None), self.assertRaises(ValueError):
            security.verify_artifact(Path("a"), "owner/repo", "a" * 40)
        with patch.object(security.shutil, "which", return_value="gh"), patch.object(
                security.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                security.verify_artifact(Path("a"), "owner/repo", "a" * 40)

    def test_collect_refuses_existing_output(self):
        with self.assertRaises(FileExistsError):
            security.collect(Path("."), self.output)


if __name__ == "__main__":
    unittest.main()
