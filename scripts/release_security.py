#!/usr/bin/env python3
"""Collect and check NAS-0116 supply-chain evidence. Requires Python 3.10+."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("go.mod", "go.sum", "go.work", "go.work.sum",
          "web/admin-ui/package.json", "web/admin-ui/package-lock.json")
TOOLS = {"govulncheck": "v1.9.0", "cyclonedx-gomod": "v1.12.0"}
COMMANDS = {
    "go-mod-verify": ("go", "mod", "verify"),
    "go-sbom": ("cyclonedx-gomod", "mod", "-std", "-json"),
    "npm-sbom": ("npm", "sbom", "--sbom-format=cyclonedx", "--package-lock-only"),
    # Scan ALL packages and tests for each shipped target. Module-only findings
    # are retained and still block; JSON mode's exit code alone is NOT a gate.
    "go-vulnerabilities": ("govulncheck", "-json", "-scan=package", "-test", "./..."),
    "go-vulnerabilities-arm64": ("govulncheck", "-json", "-scan=package", "-test", "./..."),
    "npm-vulnerabilities": ("npm", "audit", "--json"),
}
CWD = {name: ("web/admin-ui" if name.startswith("npm-") else ".") for name in COMMANDS}
SCAN_ENV = {name: {"GOOS": "linux", "GOARCH": "arm64" if name.endswith("arm64") else "amd64",
                   "CGO_ENABLED": "0"} for name in COMMANDS if name.startswith("go-vulnerabilities")}


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def json_stream(text: str) -> list[dict]:
    decoder = json.JSONDecoder()
    values = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        if not isinstance(value, dict):
            raise ValueError("expected JSON object in scanner stream")
        values.append(value)
        text = text.lstrip()[end:]
    if not values:
        raise ValueError("empty scanner output")
    return values


def source_state(root: Path) -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    tree = hashlib.sha256()
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root)
    for raw in sorted(set(names.split(b"\0")) - {b""}):
        path = root / os.fsdecode(raw)
        tree.update(raw + b"\0")
        tree.update((digest(path) if path.is_file() else "missing").encode() + b"\0")
    return {
        "commit": git("rev-parse", "HEAD"),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=normal")),
        "tree_sha256": tree.hexdigest(),
        "inputs": {name: digest(root / name) for name in INPUTS if (root / name).exists()},
    }


def collect(root: Path, output: Path, timeout: int = 900) -> dict:
    # Never reuse a directory containing stale successful evidence.
    output.mkdir(parents=True, exist_ok=False)
    source = source_state(root)
    evidence = {"schema_version": 1, "feature_id": "NAS-0116", "source": source,
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "commands": {}, "tool_pins": TOOLS}
    for name, args in COMMANDS.items():
        started = time.monotonic()
        stdout, stderr = output / (name + ".json"), output / (name + ".stderr")
        cwd = root / CWD[name]
        executable = shutil.which(args[0])
        code = 127
        try:
            if not executable:
                raise FileNotFoundError(f"required tool missing: {args[0]}")
            with stdout.open("wb") as out, stderr.open("wb") as err:
                code = subprocess.run([executable, *args[1:]], cwd=cwd,
                                      stdout=out, stderr=err, timeout=timeout,
                                      env={**os.environ, "GOWORK": str(root / "go.work"),
                                           **SCAN_ENV.get(name, {})}).returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            stderr.write_text(str(exc) + "\n", encoding="utf-8")
            stdout.touch(exist_ok=True)
        evidence["commands"][name] = {
            "argv": list(args), "cwd": CWD[name], "env": SCAN_ENV.get(name, {}), "exit_code": code,
            "duration_seconds": round(time.monotonic() - started, 3),
            "sha256": digest(stdout), "stderr_sha256": digest(stderr),
        }
    if source_state(root) != source:
        evidence["source_changed_during_scan"] = True
    write_json(output / "evidence.json", evidence)
    return evidence


def check(output: Path, root: Path | None = None, require_clean: bool = False,
          now: dt.datetime | None = None) -> dict:
    """An offline policy check; authenticity comes from the signed artifact."""
    blockers, findings = [], []
    try:
        evidence = read_json(output / "evidence.json")
        if (type(evidence.get("schema_version")) is not int
                or evidence["schema_version"] != 1 or evidence.get("feature_id") != "NAS-0116"):
            raise ValueError("unsupported evidence schema")
        created = dt.datetime.fromisoformat(evidence["created_at"])
        age = ((now or dt.datetime.now(dt.timezone.utc)) - created).total_seconds()
        if age < -300 or age > 86400:
            blockers.append("scan evidence is future-dated or older than 24 hours")
        source = evidence["source"]
        if not re.fullmatch(r"[0-9a-f]{40}", source.get("commit", "")):
            blockers.append("missing source commit")
        if not isinstance(source.get("dirty"), bool) or (require_clean and source["dirty"]):
            blockers.append("candidate requires a clean committed source tree")
        if evidence.get("source_changed_during_scan"):
            blockers.append("source changed during scan")
        if root is not None and source != source_state(root):
            blockers.append("evidence does not match current source and dependency inputs")
        for name, args in COMMANDS.items():
            record = evidence["commands"].get(name, {})
            path = output / (name + ".json")
            if record.get("argv") != list(args) or record.get("cwd") != CWD[name]:
                blockers.append(f"{name}: missing or unexpected scan command")
            if record.get("env", {}) != SCAN_ENV.get(name, {}):
                blockers.append(f"{name}: missing or unexpected build target")
            if record.get("sha256") != digest(path) or record.get("stderr_sha256") != digest(output / (name + ".stderr")):
                blockers.append(f"{name}: evidence checksum mismatch")
            # npm audit uses 1 for findings; JSON must still be valid and complete.
            accepted = (0, 1) if name == "npm-vulnerabilities" else (0,)
            if type(record.get("exit_code")) is not int or record["exit_code"] not in accepted:
                blockers.append(f"{name}: scanner failed (exit {record.get('exit_code')})")
        for name in ("go-sbom", "npm-sbom"):
            bom = read_json(output / (name + ".json"))
            if (bom.get("bomFormat") != "CycloneDX" or not bom.get("specVersion")
                    or not isinstance(bom.get("components"), list) or not bom["components"]
                    or not bom.get("metadata", {}).get("component")):
                blockers.append(f"{name}: incomplete CycloneDX inventory")
        for name in SCAN_ENV:
            messages = json_stream((output / (name + ".json")).read_text(encoding="utf-8-sig"))
            configs = [m["config"] for m in messages if "config" in m]
            if len(configs) != 1 or configs[0].get("scan_level") != "package" or not configs[0].get("db_last_modified"):
                blockers.append(f"{name}: Go vulnerability scan metadata is missing or has the wrong scan level")
            for message in messages:
                if "finding" in message:
                    finding = message["finding"]
                    if not finding.get("osv") or not finding.get("trace"):
                        blockers.append("malformed Go vulnerability finding")
                    else:
                        findings.append({"ecosystem": "Go", "id": finding["osv"], "target": SCAN_ENV[name],
                                         "trace": finding["trace"], "fixed_version": finding.get("fixed_version", "")})
                if "error" in message:
                    blockers.append("Go vulnerability scanner reported an error")
        audit = read_json(output / "npm-vulnerabilities.json")
        counts = audit.get("metadata", {}).get("vulnerabilities", {})
        if (type(audit.get("auditReportVersion")) is not int or audit["auditReportVersion"] != 2 or "error" in audit
                or not isinstance(audit.get("vulnerabilities"), dict)
                or any(type(counts.get(k)) is not int or counts[k] < 0
                       for k in ("info", "low", "moderate", "high", "critical", "total"))):
            blockers.append("npm audit response is incomplete or contains an error")
        else:
            if counts["high"] or counts["critical"]:
                blockers.append(f"npm audit: {counts['high']} high and {counts['critical']} critical vulnerabilities")
            for name, item in audit["vulnerabilities"].items():
                if item.get("severity") in ("high", "critical"):
                    findings.append({"ecosystem": "npm", "id": name, "severity": item["severity"]})
        if findings:
            blockers.append(f"{len(findings)} dependency vulnerability findings violate policy")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        blockers.append(f"missing or invalid evidence: {exc}")
    return {"schema_version": 1, "feature_id": "NAS-0116", "status": "blocked" if blockers else "passed",
            "signature_verified": False, "blockers": blockers, "findings": findings}


def verify_artifact(artifact: Path, repo: str, commit: str) -> None:
    """Require GitHub's verifier, trusted workflow, source ref and source SHA."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("expected owner/repository")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected full source commit SHA")
    gh = shutil.which("gh")
    if not gh:
        raise ValueError("GitHub CLI is required for cryptographic verification")
    for predicate in ("https://slsa.dev/provenance/v1", "https://cyclonedx.org/bom"):
        subprocess.run([gh, "attestation", "verify", str(artifact.resolve()), "--repo", repo,
                        "--signer-workflow", f"{repo}/.github/workflows/release-candidate.yml",
                        "--source-ref", "refs/heads/main", "--source-digest", commit,
                        "--deny-self-hosted-runners", "--predicate-type", predicate],
                       check=True, timeout=120, stdout=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "check"):
        command = sub.add_parser(name)
        command.add_argument("--output", required=True, type=Path)
        command.add_argument("--require-clean", action="store_true")
    command = sub.add_parser("verify")
    command.add_argument("artifact", type=Path)
    command.add_argument("--repo", required=True)
    command.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            verify_artifact(args.artifact, args.repo, args.commit)
            return 0
        if args.command == "scan":
            collect(ROOT, args.output.resolve())
        report = check(args.output, ROOT, args.require_clean)
        write_json(args.output / "gate.json", report)
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "passed" else 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"release security blocked: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
