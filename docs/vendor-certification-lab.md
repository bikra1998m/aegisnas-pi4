# Vendor Certification Lab

Use `scripts/vendor-certification-lab.sh` to collect repeatable evidence for one NAS compatibility pack at a time. The harness does not claim vendor certification by itself; it proves what was tested, on which revision, and whether each required check passed.

## Safety Model

The default run is read-only. It checks:

- AegisNAS vendor identity and Private Enterprise Number status
- runtime vendor-pack catalog coverage
- vendor reply and ACL rendering
- expected vendor attribute presence where the pack has a direct reply mapping

Live RADIUS, packet capture, controller actions, device reachability, upgrade smoke tests, and rollback rehearsal are opt-in. Controller push additionally requires `AEGIS_CERTIFY_CONTROLLER_PUSH=YES`. The rollback rehearsal prepares and validates restore state but does not apply a restore.

Production certification fails while the product uses the placeholder PEN. `--allow-placeholder-pen` exists only for lab work before IANA assigns the real enterprise number.

## API-Only Lab Run

```bash
export AEGIS_ADMIN_TOKEN='<admin-token>'

bash scripts/vendor-certification-lab.sh \
  --pack cisco \
  --nas-type cisco \
  --allow-placeholder-pen
```

Remove `--allow-placeholder-pen` for the production gate.

Run the API checks across the major packs:

```bash
for pack in cisco aruba ruckus fortinet mikrotik ubnt juniper mist; do
  bash scripts/vendor-certification-lab.sh \
    --pack "$pack" \
    --allow-placeholder-pen || exit 1
done
```

Use `--expected-attribute NAME` when a site requires a specific VSA beyond the harness's built-in mapping.

## Live RADIUS And Packet Capture

Install `freeradius-utils`, `tcpdump`, and `jq`, then provide test credentials through environment variables:

```bash
sudo -E env \
  AEGIS_ADMIN_TOKEN="$AEGIS_ADMIN_TOKEN" \
  AEGIS_CERT_RADIUS_PASSWORD="$AEGIS_CERT_RADIUS_PASSWORD" \
  AEGIS_RADIUS_SECRET="$AEGIS_RADIUS_SECRET" \
  bash scripts/vendor-certification-lab.sh \
    --pack aruba \
    --radius-user certification-user \
    --freeradius-check \
    --capture-interface eth1 \
    --capture-seconds 60 \
    --device-ip 192.168.50.2 \
    --allow-placeholder-pen
```

During the capture window, connect a real client through the AP or switch and complete authentication. The evidence bundle contains `packets.pcap`, decoded packet text, `radtest` output, accounting output, device reachability, and API results. Inspect the capture for Access-Request/Accept, accounting, VLAN or role attributes, and any CoA/Disconnect traffic generated during the test.

## Controller Pull And Push

Start with read-only pull and fail on drift:

```bash
bash scripts/vendor-certification-lab.sh \
  --pack cisco \
  --controller-pull
```

`--allow-drift` keeps a known drift result from failing a diagnostic lab run. Do not use it for final production certification.

After reviewing `controller-push-preview.json`, run the explicit mutation gate:

```bash
AEGIS_CERTIFY_CONTROLLER_PUSH=YES \
bash scripts/vendor-certification-lab.sh \
  --pack cisco \
  --controller-pull \
  --controller-push
```

The admin API still enforces its own `PUSH CONTROLLER POLICY` confirmation. A successful HTTP response is not enough: the harness also fails when the controller reports failed items.

## Upgrade And Rollback Evidence

On a disposable Ubuntu VM:

```bash
sudo -E bash scripts/vendor-certification-lab.sh \
  --pack cisco \
  --upgrade-smoke \
  --rollback-rehearsal \
  --wan ens33 \
  --lan ens37
```

This delegates to the existing upgrade smoke and rollback rehearsal scripts, preserving their detailed artifacts while adding the outcome to the vendor certification summary.

## Evidence And Pass Criteria

Each run writes to:

```text
/var/tmp/aegisnas-vendor-certification/<timestamp>-<pack>/
```

`summary.json` contains the Git revision, pack, NAS type, required failures, and every artifact. A production pass requires:

1. `status` is `passed` and `required_failures` is `0`.
2. The vendor identity check uses a non-placeholder IANA PEN.
3. Reply attributes match the real device's enforcement behavior.
4. Live RADIUS and accounting pass when those paths are in scope.
5. Packet capture proves the expected exchange through the real AP or switch.
6. Controller pull reports no unexplained drift before any push.
7. Upgrade and rollback evidence passes for the release candidate.

Archive the whole evidence directory with the release record. Repeat certification after firmware, controller, FreeRADIUS, dictionary, policy-renderer, or major AegisNAS upgrades.
