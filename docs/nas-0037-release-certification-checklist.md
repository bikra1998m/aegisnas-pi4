# NAS-0037 Release Certification Checklist

NAS-0037 software engineering is complete when automated tests and builds pass.
The items below require external devices, production Linux services, customer
environments, or long-running validation, so they do not block development of
NAS-0038.

## External Certification / Deployment

- Capture FreeRADIUS accounting packets from at least one Cisco, Juniper,
  Huawei, Cambium, MikroTik, and generic RFC 2866 NAS with gigaword counters.
- Import production Linux FreeRADIUS `radacct` rows containing
  `Acct-Input-Gigawords` and `Acct-Output-Gigawords`; verify AegisNAS 64-bit
  totals match packet captures.
- Run a controlled NAS reboot/counter-reset drill and confirm reset evidence is
  visible in `/api/v1/system/accounting-counters`, `radacct`, support bundles,
  and production readiness.
- Run an HA failover drill while accounting events are replayed; verify the
  standby node preserves maximum session counters and does not double count
  reset evidence.
- Benchmark sustained accounting ingestion with long-lived sessions crossing
  4 GiB, 4 TiB, and large enterprise billing thresholds.
- Run a long-duration soak test with SQL reconciliation, event replay, and
  dashboard/API polling enabled.
- Perform security review for counter evidence retention, support bundle
  redaction, and tenant-scoped access to accounting data.
- Record exact vendor, model, firmware, FreeRADIUS release, database backend,
  and HA topology in the release evidence package.

## Software Evidence To Attach

- `make test-radius-accounting-counters`
- `go build ./...`
- `cd web/admin-ui && npm run build`
- `/api/v1/system/accounting-counters`
- `/api/v1/system/status`
- `/api/v1/system/production-readiness`
- support bundle entry `api/accounting-counters.json`
