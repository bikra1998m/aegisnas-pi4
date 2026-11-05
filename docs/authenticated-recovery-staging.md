# Authenticated SQLite recovery staging (NAS-0116)

Status: **Partial milestone; local encrypted snapshot and authenticated staging
implemented**. These commands prepare recovery data. They do not stop services,
install binaries, restore a running database, authorize a downgrade, or establish
production readiness. The existing raw ZIP API/CLI and Ubuntu restore scripts
remain legacy lab recovery paths. Do not treat them as authenticated production
activation entry points.

## Key and recovery record

Provision a dedicated 32-byte random key through the appliance's administrative
channel. Store it in a root-owned mode-0600 regular file under a protected
directory. Keep a separately protected recovery copy; losing the key prevents
decryption. Never include it in a support bundle, source repository, downloaded
package, command-line value, or test report. The argument is a **file path**,
not a password. The implementation rejects other key lengths, symbolic/hard
links, non-regular files and unsafe ownership or permissions on Linux.

Example one-time provisioning on Linux (an existing key is never replaced):

```sh
sudo install -d -m 0700 /etc/aegisnas/recovery-keys
sudo python3 - <<'PY'
import os
path = '/etc/aegisnas/recovery-keys/key-1'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as key:
    key.write(os.urandom(32))
    key.flush()
    os.fsync(key.fileno())
PY
```

Create a protected destination directory before running the command. Select a
stable appliance/recovery-scope identifier using 1–128 ASCII letters, digits,
periods, underscores, colons, slashes or hyphens, beginning with a letter/digit.
The scope is authenticated but is supplied by the operator rather than read
from the archive.

```sh
sudo aegis-admin create-sealed-upgrade-rollback-package \
  --config /etc/aegisnas/config.yaml \
  --key-file /etc/aegisnas/recovery-keys/key-1 \
  --recovery-context appliance-42/recovery-1 \
  --output /protected/backups/snapshot-1.aegis-recovery
```

Record the returned `sealed_sha256`, context, key reference/version, snapshot
time, schema and intended compatible release in an independent trusted recovery
record. The package's sidecar or a checksum downloaded with it is not that
record. Selecting this record is an operator decision; the tool cannot decide
whether a snapshot is operationally appropriate. Never derive the expected
digest from an untrusted input at restore time. Key rotation creates a new key
and new record; retain older keys only under the approved recovery policy.

## Authenticate and stage

Use the digest and context from that independent record. The parent directory
must already exist and be protected. The output directory must **not** exist.

```sh
sudo aegis-admin extract-sealed-upgrade-rollback-package \
  --input /protected/backups/snapshot-1.aegis-recovery \
  --key-file /etc/aegisnas/recovery-keys/key-1 \
  --recovery-context appliance-42/recovery-1 \
  --expected-sha256 FULL_DIGEST_FROM_TRUSTED_RECOVERY_RECORD \
  --output-dir /protected/recovery/review-1
```

The command verifies the approved digest and AEAD authentication before ZIP
parsing or extraction. Wrong keys, contexts, tampering and a different authentic
snapshot fail closed. There is no unsigned fallback. A successful receipt says
`authenticated_for_staging` and `production_activation_authorized: false`.
It is a local observation, not a portable signature or release attestation.

The output contains plaintext secrets: keep the workspace private. Files use
0600 and directories use 0700. Existing destinations are refused. Extraction
uses a directory-bound filesystem handle and exclusive file creation. On an
I/O failure an incomplete private workspace may remain; it is not a successful
recovery and must not be installed. File writes are flushed, but this is not a
transaction across config, database and services, nor a power-loss certification.

The snapshot uses SQLite `VACUUM INTO`. It does not provide an atomic snapshot
of independently changing configuration and database state. Arrange a coordinated
maintenance snapshot before production use. PostgreSQL configurations are
explicitly rejected; the raw ZIP download API returns HTTP 409 for that backend.
Use the separate PostgreSQL logical backup procedure until coordinated backup
and activation are implemented.

Upgrade-readiness reports also identify PostgreSQL rehearsals as unsupported
instead of inspecting an unrelated local SQLite database. SQLite migration
rehearsals use a consistent `VACUUM INTO` snapshot so committed WAL pages are
included. This still does not coordinate database, config and binary activation.

## Format and bounds

The versioned prefix is `AEGISNAS-RECOVERY` followed by bytes `00 01`. The remaining
bytes are the standard Go AES-256-GCM random-nonce representation: a 12-byte
nonce followed by ciphertext and a 16-byte tag. The prefix/version concatenated
with the recovery context forms the authenticated associated data. There is
no password derivation or new cryptographic dependency. The implementation uses
[Go's random-nonce GCM API](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce).
That API requires fewer than 2^32 encryptions per key; operational key rotation
must respect this bound. No key-use counter or KMS integration is claimed.

The compressed ZIP and total expanded payload are each limited to 512 MiB.
The four permitted entries are `manifest.json` (64 KiB), `config/config.yaml`
(4 MiB), `config/system-settings.json` (4 MiB), and `database/data.db` (within the
total limit). Duplicate/unknown names, special files, unsupported manifest
versions, directory traversal and excessive sizes are rejected before expansion.
These checks also protect the legacy reader. The API caps the whole multipart
request before parsing and removes temporary upload files after reading.

Processing is in memory and may require multiple times the archive size.
The maximum size is a security ceiling, not a demonstrated Raspberry Pi capacity
limit. Windows exercises logic only; Linux ownership checks are not Windows ACL
certification. This work does not establish FIPS certification.

## Executable checks and remaining integration

```sh
go test -count=1 ./internal/upgrade ./internal/adminapi ./cmd/aegis-admin
go build -o build/recovery-bin/aegis-admin ./cmd/aegis-admin
python3 scripts/test_recovery_cli.py \
  --admin-bin build/recovery-bin/aegis-admin --output build/recovery-cli
```

The CLI fixture uses a new populated SQLite database, confirms recovered data
and SQLite integrity, tests rejection paths, and verifies that the original
database/config remain unchanged. It never accesses the deployed database or
restarts services. CI and release-candidate workflows include this fixture;
configured workflow coverage is distinct from an executed trusted hosted run.

Remaining NAS-0116 work includes trusted candidate signing execution, coordinated
quiescing/activation and DB/config/binary rollback, enforcement at every installer
and API entry point, image/snap/firmware coverage, and approved retention,
remediation and exception governance. A safe production recovery transaction
must still bind the independently approved snapshot to an admitted compatible
release without resetting the durable release sequence floor.
