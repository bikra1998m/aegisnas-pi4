import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import scan_os_release as scanner


class OSScanTests(unittest.TestCase):
    def report(self, items):
        return {'SchemaVersion': 2, 'Metadata': {'OS': {'Family': 'ubuntu'}},
                'Results': [{'Class': 'os-pkgs', 'Vulnerabilities': items}]}

    def test_high_critical_unknown_block_and_medium_remains_report_only(self):
        for severity in ('HIGH', 'CRITICAL', 'UNKNOWN'):
            result = scanner.evaluate(self.report([{'VulnerabilityID': 'CVE-test', 'Severity': severity}]))
            self.assertEqual(result['status'], 'blocked')
        self.assertEqual(scanner.evaluate(self.report([{'VulnerabilityID': 'CVE-test', 'Severity': 'MEDIUM'}]))['status'], 'passed')

    def test_missing_os_and_malformed_reports_block(self):
        for value in ({}, {'SchemaVersion': 2, 'Results': []}, self.report([{'Severity': 'HIGH'}])):
            self.assertEqual(scanner.evaluate(value)['status'], 'blocked')

    def test_report_schema_requires_integer_version(self):
        for version in (True, 2.0, '2', None):
            with self.subTest(version=version):
                report = self.report([])
                report['SchemaVersion'] = version
                self.assertEqual(scanner.evaluate(report)['status'], 'blocked')

    def test_missing_scanner_is_not_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(scanner.shutil, 'which', return_value=None):
            output = Path(tmp) / 'evidence'
            result = scanner.collect(Path(tmp), output)
            self.assertEqual(result['status'], 'blocked')
            self.assertTrue((output / 'os-gate.json').exists())
            self.assertFalse(result['signature_verified'])


if __name__ == '__main__':
    unittest.main()
