# NAS-0055 Release Certification Checklist

NAS-0055 software engineering is complete when the code, tests, migrations,
APIs, UI, documentation, and CI pass. The items below require external systems
or production-like environments and do not keep the roadmap item open.

## External Certification

- [ ] Obtain packet captures for `Framed-Route` and `Framed-IPv6-Route` from a
  production Linux FreeRADIUS deployment.
- [ ] Validate Cisco `Cisco-AVPair` route, VRF, owner, revision, CoA update, and
  withdrawal behavior on the supported IOS/IOS-XE/NX-OS product scope.
- [ ] Validate Juniper/ERX and Junos route AVPair behavior on the supported
  firmware scope.
- [ ] Validate Huawei and H3C route AVPair behavior on the supported VRP /
  Comware firmware scope.
- [ ] Validate Nokia / Alcatel-Lucent service-router route AVPair behavior on
  the supported SR OS scope.
- [ ] Validate standards-only route injection on a NAS that consumes
  `Framed-Route` and `Framed-IPv6-Route`.
- [ ] Validate MikroTik route behavior where route attributes are supported by
  the target RouterOS workflow.

## Deployment Validation

- [ ] Prove old-version to new-version migration from schema v59 to v60.
- [ ] Prove rollback from v60 preserves pre-upgrade service state.
- [ ] Run Accounting Stop and Accounting-Off withdrawal drills.
- [ ] Run CoA route update drills through direct and proxied NAS paths.
- [ ] Run HA failover with active route ownership rows and confirm standby
  status/report continuity.
- [ ] Confirm support bundles include `api/route-policy.json` and
  `api/route-policy-history.json`.

## Performance And Security

- [ ] Benchmark compile latency for 1, 8, 32, and 256 route policies.
- [ ] Run long-duration soak with repeated Start, Interim, Stop, and CoA
  updates.
- [ ] Run malformed prefix, gateway-family mismatch, excessive-route,
  unsupported-pack, and conflicting-route packet tests against a lab server.
- [ ] Complete security review for route ownership evidence, RBAC, audit
  retention, and route metadata disclosure.

## Release Evidence

- [ ] Attach vendor/product/firmware matrix.
- [ ] Attach packet captures and command output proving installed/withdrawn
  route behavior.
- [ ] Attach HA failover logs and database replication proof.
- [ ] Attach performance and soak reports.
- [ ] Attach customer or lab acceptance sign-off.
