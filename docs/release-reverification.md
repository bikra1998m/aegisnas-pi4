# Staged release re-verification

NAS-0116 remains **Partial**. `scripts/reverify_release.py` rechecks an already
admitted release against its original archive, current administrative policy
and persistent sequence reservation. This is a point-in-time check before a
future activation procedure. It does not activate binaries, restore data,
restart services or authorize a production deployment.

## Inputs and trust boundary

Use the original archive and the same protected `--state-dir` used for admission.
The policy must still authorize the full source commit, repository, platform and
sequence. Use the concrete release directory, not a `current` symlink. On Linux,
the scripts, policy, state and staged content must be administratively owned and
not writable by service accounts. Production uses root ownership; isolated tests
may use their own account. Windows tests do not certify ACLs or Linux durability.

```bash
sudo python3 scripts/reverify_release.py /protected/candidates/aegisnas-linux-arm64.tar.gz \
  --policy /etc/aegisnas/release-policy.json \
  --state-dir /var/lib/aegisnas-release-sequence \
  --commit FULL_REVIEWED_SOURCE_COMMIT \
  --release-dir /opt/aegisnas/releases/REVIEWED_RELEASE_ID
```

The command takes the existing admission lock and makes a bounded private copy
of the archive. Candidate inputs must be regular single-link files. It binds the
archive digest, source commit, receipt, historical admission policy hash and
sequence-guard identity to the current reservation. A different artifact or an
older reserved sequence fails. A new policy may further restrict admission;
its current rules are checked even when the old receipt remains unchanged.
Policy and release schema versions must be integer `1`; JSON booleans are
rejected rather than being interpreted as integers.

The GitHub verifier then checks both provenance and SBOM attestations using the
existing repository/workflow/main-branch/source-commit/hosted-builder constraints.
There is no receipt-only, offline-success or force option. Missing GitHub CLI,
failed verification, failed scanners, stale evidence or a policy violation block.
The original 24-hour evidence freshness limit is unchanged: an old archive may
require a newly reviewed higher-sequence candidate with fresh scan evidence.

The archive is safely extracted into temporary private space and checked with
the real dependency policy engine. Every staged file, the checksum manifest and
the receipt are checked; extra/missing files, extra directories, modified content,
symbolic/hard links, special files and unsafe Linux permissions fail. Expected
file modes are 0755 under `bin/` and 0644 elsewhere, including the receipt;
subdirectories are 0755. Ordinary concurrent file/directory changes are detected.
Policy path protection and contents, and sequence state, are rechecked before
returning. Failed checks never repair the release or rewrite its state.

The JSON success result reports `status: reverified`, `signature_reverified: true`
and `production_activation_authorized: false`, with artifact/receipt/current-policy
digests and the checked manifest. Verifier diagnostics go to stderr so stdout
can contain the command's JSON result. Store that result outside the staged
directory; adding files to the release makes its next check fail.

## Permission correction for new admissions

An executed Linux regression demonstrated that umask 002 previously left staged
directories group-writable. New admissions now explicitly set directories to
0755 and the receipt to 0644 before publication. Extracted payload files already
received explicit modes. The verifier does not silently repair older directories.
Review and re-admit an eligible original artifact into a new destination; if its
evidence has expired, obtain a new reviewed candidate. Do not reset sequence state
or merely edit a receipt to bypass a failed check.

## Limits and validation

This does not create an activation transaction or protect against an administrator
who maliciously controls the filesystem/state. A saved report cannot authorize
a later activation after the files or policy change. Activation must integrate
verification with immutable payload handling, service quiescence, compatible
database/config recovery and transaction recovery. Host architecture, OS/snap/
firmware coverage and live enforcement certification remain separate gates.

The existing admission bounds apply: 2 GiB archive, 4 GiB expanded payload,
10,000 archive entries; receipt reads are capped at 4 MiB. These are rejection
ceilings, not demonstrated appliance capacity. Re-verification needs temporary
space for the private archive and extracted payload, and hashes the installed
files. Use an isolated build/staging host for large artifacts; do not repeat
the prior heavy live-VM inventory workload. No new capacity claim is made.

Run `python3 -m unittest discover -s scripts -p 'test_*.py' -v`. Tests include
tampering, forged receipts, current policy changes, stale/failing real policy
evaluation, sequence rollback, locking, unsafe permissions and special files.
Positive local tests mock the signature verifier and use synthetic scanner
records; they are not cryptographic certification. The release workflow now
requires re-verification of both signed candidates before verified artifact
upload, with separate evidence retention on failure. An actual passing trusted
workflow remains required before milestone completion.
