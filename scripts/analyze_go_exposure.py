#!/usr/bin/env python3
"""Explain existing Go findings against shipped command imports; never waive a gate.

This is package-level evidence, not a symbol-reachability or exploitability test.
The original scanner output remains authoritative for the conservative gate.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys

import release_security as security


def classify(messages: list[dict], packages: set[str]) -> list[dict]:
    advisories = {m["osv"]["id"]: m["osv"] for m in messages if "osv" in m}
    result = []
    for message in messages:
        if "finding" not in message:
            continue
        finding = message["finding"]
        trace = finding.get("trace", [])
        modules = {frame.get("module") for frame in trace}
        advisory = advisories.get(finding["osv"], {})
        affected = [item for item in advisory.get("affected", [])
                    if item.get("package", {}).get("name") in modules]
        imports = {item["path"] for entry in affected
                   for item in entry.get("ecosystem_specific", {}).get("imports", [])
                   if isinstance(item.get("path"), str)}
        # Missing affected-package metadata cannot establish absence.
        complete = bool(affected) and all(entry.get("ecosystem_specific", {}).get("imports")
                                         for entry in affected)
        imported = sorted(imports & packages)
        classification = ("affected_package_imported" if imported else
                          "affected_packages_not_imported" if complete and imports else "unknown")
        result.append({"id": finding["osv"], "scanner_trace": trace,
                       "scanner_scope": "package" if any(f.get("package") for f in trace) else "module",
                       "affected_packages": sorted(imports), "shipped_affected_imports": imported,
                       "classification": classification, "symbol_reachability": "not_tested",
                       "policy_waived": False})
    return result


def analyze(root: Path, evidence_dir: Path, output: Path) -> dict:
    gate = security.check(evidence_dir)
    integrity_blockers = [b for b in gate["blockers"]
                          if not b.endswith("dependency vulnerability findings violate policy")]
    if integrity_blockers:
        raise ValueError("unusable scanner evidence: " + "; ".join(integrity_blockers))
    evidence = security.read_json(evidence_dir / "evidence.json")
    before = security.source_state(root)
    if evidence["source"]["inputs"] != before["inputs"]:
        raise ValueError("dependency inputs differ from scanner evidence; rescan first")
    output.mkdir(parents=True, exist_ok=False)
    targets = {}
    for scan, target in security.SCAN_ENV.items():
        command = ["go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/..."]
        name = target["GOARCH"]
        graph, errors = output / (name + "-imports.txt"), output / (name + "-imports.stderr")
        with graph.open("wb") as out, errors.open("wb") as err:
            completed = subprocess.run(command, cwd=root, stdout=out, stderr=err, timeout=180,
                env={**os.environ, **target, "GOWORK": str(root / "go.work")})
        if completed.returncode:
            raise ValueError(f"{name}: shipped package graph failed ({completed.returncode})")
        packages = set(graph.read_text(encoding="utf-8").splitlines())
        if not packages or not any("/cmd/" in p for p in packages):
            raise ValueError("shipped command package graph is empty")
        messages = security.json_stream((evidence_dir / (scan + ".json")).read_text(encoding="utf-8"))
        targets[name] = {"env": target, "argv": command, "exit_code": completed.returncode,
                         "package_count": len(packages), "graph_sha256": security.digest(graph),
                         "stderr_sha256": security.digest(errors),
                         "scanner_sha256": security.digest(evidence_dir / (scan + ".json")),
                         "findings": classify(messages, packages)}
    if security.source_state(root) != before:
        raise ValueError("source changed during import analysis")
    report = {"schema_version": 1, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "source": before, "scanner_source": evidence["source"],
              "scanner_created_at": evidence["created_at"],
              "scanner_evidence_sha256": security.digest(evidence_dir / "evidence.json"),
              "same_dependency_inputs": True,
              "same_source_snapshot": evidence["source"] == before,
              "targets": targets, "original_gate": gate, "policy_waived": False,
              "scope": "All ./cmd/... imports, Linux AMD64/ARM64, CGO disabled; no tests. "
                       "Package absence is not a replacement vulnerability scan or signed-binary proof."}
    security.write_json(output / "exposure.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = analyze(security.ROOT, args.evidence, args.output)
        print(json.dumps({"analysis": "complete", "original_gate": report["original_gate"]["status"],
                          "policy_waived": False, "report": str(args.output / "exposure.json")}))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"exposure analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
