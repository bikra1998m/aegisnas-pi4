import unittest

from analyze_go_exposure import classify


class ExposureTests(unittest.TestCase):
    def messages(self, imports=None):
        return [{"osv": {"id": "GO-test", "affected": [{"package": {"name": "example/module"},
                 "ecosystem_specific": {"imports": imports if imports is not None else [{"path": "example/module/unused"}]}}]}},
                {"finding": {"osv": "GO-test", "trace": [{"module": "example/module", "version": "v1.0.0"}]}}]

    def test_module_present_does_not_imply_affected_package_is_shipped(self):
        result = classify(self.messages(), {"example/module/used"})[0]
        self.assertEqual(result["classification"], "affected_packages_not_imported")
        self.assertFalse(result["policy_waived"])

    def test_import_is_not_proof_of_symbol_reachability(self):
        result = classify(self.messages(), {"example/module/unused"})[0]
        self.assertEqual(result["classification"], "affected_package_imported")
        self.assertEqual(result["symbol_reachability"], "not_tested")

    def test_missing_advisory_is_unknown(self):
        self.assertEqual(classify(self.messages()[1:], set())[0]["classification"], "unknown")

    def test_empty_import_metadata_is_unknown(self):
        self.assertEqual(classify(self.messages([]), set())[0]["classification"], "unknown")

    def test_other_module_metadata_cannot_prove_absence(self):
        messages = self.messages()
        messages[0]["osv"]["affected"][0]["package"]["name"] = "another/module"
        self.assertEqual(classify(messages, set())[0]["classification"], "unknown")

    def test_package_trace_is_retained(self):
        messages = self.messages()
        messages[1]["finding"]["trace"][0]["package"] = "example/module/unused"
        result = classify(messages, {"example/module/unused"})[0]
        self.assertEqual(result["scanner_scope"], "package")
        self.assertEqual(result["scanner_trace"], messages[1]["finding"]["trace"])

    def test_incomplete_affected_entry_cannot_prove_absence(self):
        messages = self.messages()
        messages[0]["osv"]["affected"].append({"package": {"name": "example/module"}})
        self.assertEqual(classify(messages, set())[0]["classification"], "unknown")

    def test_only_actual_findings_are_reported(self):
        self.assertEqual(classify(self.messages()[:1], {"example/module/unused"}), [])


if __name__ == "__main__":
    unittest.main()
