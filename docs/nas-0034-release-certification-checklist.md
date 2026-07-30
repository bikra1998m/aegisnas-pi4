# NAS-0034 Release Certification Checklist

Feature: Hard tenant isolation and delegated policy trees

Software implementation is complete when code, schema, APIs, UI, tests,
automation, and documentation are committed. The items below require external
devices, production-like Linux hosts, third-party environments, or release
sign-off evidence.

## External Certification / Deployment

- [ ] Validate delegated-admin tenant claims through the production SSO or LDAP
  source used by the customer environment.
- [ ] Verify tenant A admins cannot list, read, simulate, analyze, approve,
  activate, roll back, or bind tenant B resources in a staging deployment.
- [ ] Verify monitor-mode migration records denied decisions without breaking
  existing operations.
- [ ] Verify enforce-mode failures return stable forbidden responses and do not
  fall back to global policy.
- [ ] Run active/standby failover drills with tenant profiles, resource
  bindings, policy versions, simulations, activation events, and isolation
  events replicated.
- [ ] Restore a backup containing tenant-owned policy sets and confirm hashes,
  active versions, events, and resource ownership remain intact.
- [ ] Smoke test Cisco, Aruba/HPE, Juniper Mist, Ruckus, Fortinet, Meraki,
  UniFi, and Extreme controller workflows with tenant-scoped policy ownership.
- [ ] Confirm tenant-owned secret namespaces, CA namespaces, dictionary
  profiles, NAS clients, and certificate templates map to the expected external
  systems when those later integrations are enabled.
- [ ] Run negative tests for missing tenant profiles, retired resource bindings,
  shared resources, out-of-scope admins, disabled tenants, and database
  fail-closed behavior.
- [ ] Benchmark policy evaluation and list/read API latency with production
  tenant counts and policy-set history.
- [ ] Run long-duration delegated-admin soak with policy creation, simulation,
  activation, rollback, and support-bundle collection.
- [ ] Archive support bundles containing tenant isolation status, policy-set
  evidence, production-readiness output, and redacted configuration.
- [ ] Complete customer acceptance testing for tenant naming, data residency,
  billing references, delegated roles, and operational runbooks.
