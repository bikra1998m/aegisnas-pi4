# Verified release admission (NAS-0116)

`scripts/admit_release.py` verifies and stages a candidate into a new directory.
It does not stop services, overwrite a deployment, migrate a database, or activate
the staged release. All current source-build VM deployment scripts remain lab
workflows; they are not production signature admission paths.

After admission, use [staged release re-verification](release-reverification.md)
to recheck the original signed archive, every staged file, current policy and
persistent sequence reservation. This does not activate the release. New
admissions explicitly protect directory and receipt permissions even under a
group-writable umask; older staged content is not silently repaired.

## Trust boundary and policy

Install Python 3.10+ and GitHub CLI from trusted distribution channels. Provision
the expected repository, exact allowed source commits, architecture and minimum
release sequence through the appliance's trusted administrative channel. On
Linux, the policy, release parent, persistent sequence directory and admission
scripts (`admit_release.py`, `release_sequence.py`, `release_security.py`) must
be root-owned and not writable by the service account. Keep policy files mode
0600, sequence directories 0700 and sequence files 0600. The implementation
rejects symbolic/hard links and unsafe ownership/write permissions on trusted
paths. Non-root staging is supported for isolated tests; production uses root.
Do not copy policy or sequence state from the candidate.
The caller's local administrative access is part of this trust boundary.

Example `/etc/aegisnas/release-policy.json` (replace the commit from a reviewed
release record; the placeholder deliberately cannot match a real release):

```json
{
  "schema_version": 1,
  "repository": "bikra1998m/aegisnas-pi4",
  "platform": "linux-arm64",
  "minimum_sequence": 12,
  "allowed_commits": ["0000000000000000000000000000000000000000"]
}
```

```sh
# One-time provisioning, after reviewing all previously admitted releases.
# Parent directories must already be protected and administratively owned.
sudo python3 scripts/admit_release.py --initialize-state \
  --policy /etc/aegisnas/release-policy.json \
  --state-dir /var/lib/aegisnas-release-sequence

sudo python3 scripts/admit_release.py aegisnas-linux-arm64.tar.gz \
  --policy /etc/aegisnas/release-policy.json \
  --state-dir /var/lib/aegisnas-release-sequence \
  --commit FULL_REVIEWED_SOURCE_COMMIT \
  --output /opt/aegisnas/releases/REVIEWED_RELEASE_ID
```

The verifier checks both provenance and SBOM attestations against the repository,
main branch, workflow identity, full source SHA, artifact digest and hosted
builder requirement. Admission then checks the signed release manifest, target,
sequence floor, complete payload checksums and fresh passing dependency evidence.
It rejects duplicate/escaping paths, links/devices, oversized payloads and an
archive-supplied admission receipt. Verification uses a private copy to prevent
replacement of the downloaded file during extraction. A changed policy or an
existing destination blocks admission. Only a completely checked directory is
renamed into place. There is no unsigned or force-admit option.

The `admission.json` receipt records the artifact and policy hashes, source,
sequence, verification time, predicates and payload hashes. Preserve each
release's immutable receipt with its signed attestation bundles in the operator's
audit archive. A receipt is an installation record, not a portable signature.

## Persistent sequence protection and interrupted admission

Every admission must use the same persistent `--state-dir` for its repository
and platform, outside all release destinations. This argument is required by
both the CLI and Python API; it has no disposable default. Initialization refuses
any existing directory. Missing, malformed, over-permissive or wrong-scope state
blocks admission rather than silently recreating it. On an existing installation,
set the policy's initial minimum above the highest previously admitted sequence
before initializing; initialization cannot discover another installation's history.

An OS file lock serializes admissions and is released when its owner exits or
dies. A second process fails with a busy error. After all signature, evidence and
payload checks, the tool atomically writes and flushes a reservation before
publishing the payload. A lower sequence is rejected even if the policy floor
is later lowered. A repeated sequence must identify the exact same archive hash
and source commit; a newly packaged artifact needs a higher sequence.

If admission fails after reservation, retain the state and failed-attempt logs.
Retry the identical archive into a new, absent output directory with the same
state; all verification and freshness checks run again. An existing output is
never overwritten. The receipt's `sequence_guard` records the state ID, sequence
and artifact hash. It records a reservation, not activation or a fresh signature.
Do not delete `sequence.lock`, recreate state to clear an error, or restore an old
state backup. State recovery needs an independent, current release ledger; a
general state-recovery/rollback command is deliberately not provided.

Production durability targets a local Linux filesystem honoring `fsync` and
atomic rename. Windows tests cover logic and interprocess locks, not directory
durability or Windows ACL enforcement. Network filesystems, actual power-loss
recovery and administrator rollback of the whole disk are not certified. This
store is not a TPM monotonic counter. CI creates isolated runner-local state to
test admission; it never replaces an appliance's persistent state.

## Upgrade and rollback boundary

Keep the policy floor at or above the last approved release. Older releases
are rejected even when correctly signed. Lowering policy alone no longer permits
a rollback below the durable reservation. Recovery requires a newly reviewed,
signed candidate with a higher sequence, compatible recovery behavior, fresh
passing evidence and an authorized source commit. Preserve the policy and
incident record; never reset the state to bypass a failed gate. Coordinated
activation and database/config rollback are still unimplemented.

Database/config rollback archives from `ubuntu-upgrade-rollback-restore.sh` are
local recovery data, not GitHub-built binary candidates. This admission command
does not authenticate those raw archives. The separate
[authenticated recovery staging commands](authenticated-recovery-staging.md)
now encrypt SQLite snapshots and require a protected key, recovery context and
independently approved digest before staging. The legacy restore script does
not consume that authentication receipt. Coordination with binary activation
and enforcement at every restore entry point remain outstanding.

## Operator visibility

Set `AEGIS_RELEASE_DIR` to the admitted release directory when running the API.
The default is `/opt/aegisnas/current`. `GET /api/v1/system/release-security`, the
Release Security page and `api/release-security.json` in support bundles report
missing/malformed receipts and whether the on-disk API executable matches its
recorded checksum. The endpoint never calls its local receipt a fresh signature
verification, and does not certify other services, kernel, OS or network devices.
A process whose executable has been replaced in place must be restarted through
the deployment procedure; this endpoint hashes the executable path on disk, not
every page mapped into a running process.

## Vulnerability handling and retention

Current enforced policy has **no exceptions**: every Go finding, including
module-only findings, blocks; npm high/critical findings block; OS high, critical
and unknown-severity findings block the separate OS gate. Failed scanners block.
No approver identities, remediation deadlines, retention periods or risk
acceptances have been invented on behalf of the organization. The release owner
must approve those operational policies before production certification.

For each finding retain the raw scanner report, affected package/target, fix
version, remediation change and the final rescan. Any proposed package-exposure
exception (for example, unimported OpenPGP code in x/crypto) requires a separately
reviewed policy implementation with proof, expiry, revocation, named ownership
and audit history. There is currently no ignore-file mechanism.

## OS and image evidence

Install Trivy **0.76.0**, then scan an immutable rootfs snapshot or OCI archive:

```sh
python3 scripts/scan_os_release.py --kind rootfs --target /path/to/rootfs \
  --output build/os-security
python3 scripts/scan_os_release.py --kind image --target appliance-oci.tar \
  --output build/image-security
```

The command retains CycloneDX, raw vulnerability JSON, tool version, hashes,
exit codes and durations. An image archive is hashed before and after scanning;
Debian rootfs package state is checked for changes. A running-rootfs scan is
diagnostic evidence, not proof about a separately built image. Snap contents,
firmware and image signing/activation are not covered by this OS-only scanner.

## Repeatable real API check

```sh
go build -o build/test-bin/aegis-admin ./cmd/aegis-admin
go build -o build/test-bin/aegis-admin-api ./cmd/aegis-admin-api
npm ci --prefix web/admin-ui
npm run build --prefix web/admin-ui
python3 scripts/live_api_smoke.py --bin-dir build/test-bin --output build/live-api
```

Use a new output directory each time. This starts a real API with an isolated
SQLite database, captures support-bundle integration, checks fail-closed release
state and measures 100 sequential loopback requests. It terminates only its own
API process. These results do not measure NAS forwarding capacity or certify
external telecom equipment.
