# Appliance artifact inventory

NAS-0116 remains **Partial**. `scripts/inventory_appliance.py` inventories the
snap blob store, firmware files and boot files in a Linux root filesystem. It
streams SHA-256 hashes with size, time and entry limits, records links without
recursively following directory aliases, and detects ordinary changes during
collection. Missing directories, unreadable entries, special files, escaping
links and exhausted limits produce **BLOCKED**, with partial evidence retained.

This is a file inventory, not a package SBOM, vulnerability clearance, signature
verification or production activation. Both successful collection and successful
comparison explicitly retain `release_gate.status: BLOCKED`. Snap filenames do
not establish publisher identity, revision approval or whether a revision is
active. Files in the installed firmware directory do not identify the firmware
actually loaded by a device or its EEPROM contents.

Prefer an immutable, read-only snapshot of the image being qualified. A live
host inventory detects ordinary changes but cannot prove an atomic snapshot or
defend against a privileged writer who controls the source. Resolve absolute
Linux symlinks within the supplied root, including merged `/usr` layouts; links
may not escape their component scope. The scanner never executes firmware,
mounts snaps, changes services, or reads file contents into reports.

On Linux, use a new output path outside the collected directories. Elevated
read access may be needed for boot files. For a live lab VM, run with low CPU/I/O
priority and monitor service latency:

```bash
sudo nice -n 19 ionice -c 3 python3 scripts/inventory_appliance.py collect \
  --root / --output /protected/evidence/appliance-inventory.json \
  --timeout-seconds 300
```

Keep the returned inventory and record its SHA-256 independently in a protected
evidence record. The expected digest must come from that record; computing it
from a newly downloaded, untrusted manifest is not authentication. To compare:

```bash
sudo nice -n 19 ionice -c 3 python3 scripts/inventory_appliance.py verify \
  --root / --inventory /protected/evidence/appliance-inventory.json \
  --expected-sha256 "$APPROVED_INVENTORY_SHA256" \
  --output /protected/evidence/appliance-comparison.json
```

The CLI exits zero only for a successful **inventory or comparison**. It never
authorizes a release. Comparison detects changed, added and removed files and
changed links; a failed/partial inventory cannot be used as a passing baseline.
Existing evidence files are never overwritten. Default bounds are 100,000
entries, 8 GiB per file, 32 GiB total bytes and a 64 MiB comparison manifest.
The default time budget is 300 seconds (configurable from 1 to 3600). Expiry or
SIGINT/SIGTERM requests retain a blocked partial report after the current read
returns. These bounds do not provide a kernel-level deadline for a stalled
filesystem read; monitor the process on unhealthy storage. Recollect after an
intentional package or firmware update. Windows exercises portable logic;
Linux link and filesystem semantics require the Ubuntu tests.

Remaining full-image evidence includes nested snap package inventories and
vulnerability scans, publisher/assertion verification, exact artifact-to-image
binding, firmware vendor/version/advisory mapping, Raspberry Pi boot/EEPROM
qualification and a signed full-image build. The existing OS package gate and
the Go/npm gate remain separate, conservative requirements. Neither is waived
by this inventory.

Run the automated checks with:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

The snap build contracts in that suite use fake compiler/packager processes to
exercise failure handling; they do not certify a real Snapcraft build. See
[snap packaging](../snaps/README.md) and [image prerequisites](../image/README.md).
