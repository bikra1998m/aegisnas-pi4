# Upgrade Rollback Runbook

This runbook is the operator path for the version-aware upgrade rollback workflow.

Use it when you want to:

- create a rollback package before an upgrade
- inspect a rollback package and understand whether online restore is supported
- rehearse the rollback path on an Ubuntu VM
- prepare an offline restore workspace
- run a guarded offline restore on a lab appliance

Use this guide together with:

- [Ubuntu VM Deployment And Full Flow Test Runbook](ubuntu-vm-runbook.md)
- [VMware Workstation 17 Player Full Product Runbook](vmware-workstation-17-player-full-test.md)
- [Operations Guide](operations.md)
- [Backup and Restore Procedures](backup-restore.md)

## What The Upgrade Rollback Package Contains

The upgrade rollback package is different from the older full appliance backup.

It contains:

- `manifest.json`
- `config/config.yaml`
- `config/system-settings.json`
- `database/data.db`

The manifest records:

- current schema version
- target schema version
- config path
- database path
- deployment profile and form
- whether the package contains secrets

Treat every rollback package like credential material because it includes live appliance data.

## Online Restore Versus Offline Restore

Use **online restore** when the inspection result says:

- `compatibility_status: online_supported`
- `online_restore_supported: true`

That means:

- the package has the needed files
- the rollback package schema matches the current runtime expectations
- the packaged database path matches the current appliance database path
- the restored config validates cleanly

Use **offline restore** when the inspection result says:

- `compatibility_status: offline_required`

That usually means one of these:

- schema mismatch
- database path mismatch
- missing package content
- config validation warnings

The offline path is the safer answer when you are stepping back onto an older runtime or doing recovery work on a lab clone.

## Admin UI Workflow

In `Backups`, use this order:

1. `Upgrade Readiness`
2. `Download Rollback Package`
3. `Rollback Package Restore`

For restore:

1. choose the rollback package zip
2. select `Inspect Rollback Package`
3. review:
   - compatibility
   - schema context
   - config validation
   - warnings
   - restore steps
4. only when `online_restore_supported` is true, type the required confirmation text
5. select `Restore From Rollback Package`

The online restore path captures a fresh safety rollback package before replacing live state.

## CLI Workflow

Create a rollback package:

```bash
sudo /opt/aegisnas/bin/aegis-admin create-upgrade-rollback-package \
  --config /etc/aegisnas/config.yaml \
  --output /var/tmp/aegisnas-upgrade-rollback.zip
```

Inspect it:

```bash
sudo /opt/aegisnas/bin/aegis-admin inspect-upgrade-rollback-package \
  --config /etc/aegisnas/config.yaml \
  --input /var/tmp/aegisnas-upgrade-rollback.zip
```

Extract it for review or offline restore planning:

```bash
sudo /opt/aegisnas/bin/aegis-admin extract-upgrade-rollback-package \
  --input /var/tmp/aegisnas-upgrade-rollback.zip \
  --output-dir /var/tmp/aegisnas-upgrade-rollback-extracted
```

If inspection says online restore is supported, the direct CLI restore path is:

```bash
sudo /opt/aegisnas/bin/aegis-admin restore-upgrade-rollback-package \
  --config /etc/aegisnas/config.yaml \
  --input /var/tmp/aegisnas-upgrade-rollback.zip
```

## Ubuntu VM Rehearsal

For a dry rehearsal on a live Ubuntu VM without applying a restore:

```bash
cd ~/aegisnas-pi4
sudo bash scripts/ubuntu-upgrade-rollback-rehearsal.sh
```

That helper:

- runs `upgrade-readiness`
- creates or reuses a rollback package
- inspects the package
- extracts the package
- validates the extracted config
- checks SQLite integrity on the extracted database
- runs the offline helper in workspace-only mode
- saves artifacts under `/var/tmp/aegisnas-upgrade-rollback-rehearsal/<timestamp>/`

If you want to rehearse a specific rollback package instead of creating a fresh one:

```bash
sudo bash scripts/ubuntu-upgrade-rollback-rehearsal.sh \
  --package /var/tmp/aegisnas-upgrade-rollback.zip
```

## Offline Restore Helper

When inspection says offline restore is required, or when you want a lab-only recovery drill, use:

```bash
cd ~/aegisnas-pi4
sudo bash scripts/ubuntu-upgrade-rollback-restore.sh \
  --package /var/tmp/aegisnas-upgrade-rollback.zip
```

That prepares a workspace and writes guided next steps without changing the appliance.

To apply the offline restore on a lab node:

```bash
sudo bash scripts/ubuntu-upgrade-rollback-restore.sh \
  --package /var/tmp/aegisnas-upgrade-rollback.zip \
  --apply \
  --confirm "APPLY OFFLINE ROLLBACK"
```

Before you do that:

- use a VM console
- take a hypervisor snapshot
- confirm you have a fresh support bundle
- confirm you understand which config and database paths will be replaced

## Minimum Acceptance Check Before Production Change Windows

Before relying on this flow for a production upgrade:

1. run `upgrade-readiness`
2. create a fresh rollback package
3. inspect it and confirm the compatibility result is understood
4. run `ubuntu-upgrade-rollback-rehearsal.sh`
5. store the rollback package and support bundle off-device
6. do at least one lab-only offline restore drill on a clone or disposable VM
## Vendor Identity Upgrade and Rollback

Upgrade to schema v15 before migrating from the lab PEN. Backups must include the config and database together. The PEN apply workflow automatically restores the prior config/runtime when FreeRADIUS apply fails; an applied, failed, or interrupted record can be restored with `ROLLBACK <migration-id>`. Do not downgrade during an active legacy decode window without first proving old/new peer behavior and preserving the schema-v15 database. See `vendor-identity.md`.

## Attribute Registry Upgrade

Record the old and new `/api/v1/system/attribute-registry?limit=1` source hashes before rollout. Review every added, removed, renumbered, retyped, or remapped entry. Mixed hashes are not supported in one HA pair. Roll back the binary and generated registry together; NAS-0002 has no database downgrade because the registry is immutable build content.

## Accounting Charging Upgrade

Schema v46 adds `radius_accounting_charging_records`,
`radius_accounting_charging_exports`, and
`radius_accounting_charging_export_records`. After upgrade, run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/accounting-charging | jq '.report.status, .report.summary'
```

If the upgraded appliance imports old FreeRADIUS `radacct` data, run a bounded
charging reconcile before exporting billing data. Roll back the application and
database together if an older runtime does not understand schema v46.
