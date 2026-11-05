#!/usr/bin/env python3
"""Inventory and scan a Linux root filesystem or OCI image archive with pinned Trivy.

This is a separate OS gate. A rootfs scan describes that snapshot, not every
snap, mounted disk, firmware or the immutable image used to provision a node.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

import release_security as security

TRIVY_VERSION = '0.76.0'


def evaluate(report):
    blockers, findings = [], []
    if not isinstance(report, dict):
        return {'status': 'blocked', 'blockers': ['Invalid OS report'], 'findings': []}
    if (type(report.get('SchemaVersion')) is not int or report['SchemaVersion'] != 2
            or not isinstance(report.get('Metadata'), dict)
            or not isinstance(report['Metadata'].get('OS'), dict) or not report['Metadata']['OS'].get('Family')
            or not isinstance(report.get('Results'), list)
            or not all(isinstance(r, dict) for r in report['Results'])
            or not any(r.get('Class') == 'os-pkgs' for r in report['Results'])):
        return {'status': 'blocked', 'blockers': ['Incomplete OS vulnerability report'], 'findings': []}
    for result in report['Results']:
        vulnerabilities = result.get('Vulnerabilities', [])
        if not isinstance(vulnerabilities, list):
            blockers.append('Malformed OS vulnerability list')
            continue
        for item in vulnerabilities:
            if not isinstance(item, dict) or not item.get('VulnerabilityID') or item.get('Severity') not in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                blockers.append('Malformed OS vulnerability finding')
            elif item['Severity'] in ('HIGH', 'CRITICAL', 'UNKNOWN'):
                findings.append({'id': item['VulnerabilityID'], 'package': item.get('PkgName'),
                                 'severity': item['Severity'], 'fixed_version': item.get('FixedVersion', '')})
    if findings:
        blockers.append(f'{len(findings)} high, critical or unknown-severity OS findings')
    return {'status': 'blocked' if blockers else 'passed', 'blockers': blockers, 'findings': findings}


def collect(target: Path, output: Path, kind='rootfs'):
    output.mkdir(parents=True, exist_ok=False)
    trivy = shutil.which('trivy')
    evidence = {'schema_version': 1, 'feature_id': 'NAS-0116', 'target_kind': kind,
                'created_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'trivy_version': TRIVY_VERSION,
                'scope': 'OS package inventory only; snap contents and firmware require separate evidence.', 'commands': {}}
    if kind == 'image':
        evidence['artifact_sha256'] = security.digest(target)
    else:
        evidence['os_inputs'] = {p: security.digest(target / p) for p in ('etc/os-release', 'var/lib/dpkg/status')
                                 if (target / p).is_file()}
    def run(name, argv):
        started = time.monotonic()
        with (output / (name + '.json')).open('wb') as stdout, (output / (name + '.stderr')).open('wb') as stderr:
            code = subprocess.run([trivy, *argv], stdout=stdout, stderr=stderr, timeout=1800).returncode
        evidence['commands'][name] = {'argv': ['trivy', *argv], 'exit_code': code,
            'seconds': time.monotonic() - started, 'sha256': security.digest(output / (name + '.json')),
            'stderr_sha256': security.digest(output / (name + '.stderr'))}
        if code:
            raise ValueError(name + ' scanner failed')
        return security.read_json(output / (name + '.json'))
    try:
        if not trivy:
            raise ValueError('pinned Trivy scanner is missing')
        version = run('version', ['version', '--format', 'json'])
        if version.get('Version') != TRIVY_VERSION:
            raise ValueError('unexpected Trivy version')
        base = [kind, '--scanners', 'vuln', '--pkg-types', 'os', '--list-all-pkgs', '--exit-code', '0']
        location = ['--input', str(target)] if kind == 'image' else [str(target)]
        bom = run('os-sbom', [*base, '--format', 'cyclonedx', *location])
        if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
            raise ValueError('empty OS inventory')
        report = run('os-vulnerabilities', [*base, '--format', 'json', *location])
        result = evaluate(report)
        if kind == 'image' and evidence['artifact_sha256'] != security.digest(target):
            result['blockers'].append('image changed during scan')
        if kind == 'rootfs' and any(security.digest(target / p) != digest for p, digest in evidence['os_inputs'].items()):
            result['blockers'].append('OS package state changed during scan')
        if result['blockers']:
            result['status'] = 'blocked'
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {'status': 'blocked', 'blockers': [str(exc)], 'findings': []}
    result.update(feature_id='NAS-0116', signature_verified=False, scope=evidence['scope'])
    security.write_json(output / 'os-evidence.json', evidence)
    security.write_json(output / 'os-gate.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--kind', choices=['rootfs', 'image'], default='rootfs')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = collect(args.target.resolve(), args.output.resolve(), args.kind)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'passed' else 1
    except (OSError, ValueError) as exc:
        print(f'OS scan blocked: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
