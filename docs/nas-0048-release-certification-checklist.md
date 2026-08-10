# NAS-0048 Release Certification Checklist

NAS-0048 software implementation is complete when code, migrations, API, UI,
tests, and documentation are merged. The items below are external release
validation and must not block engineering from moving to NAS-0049.

## Software Status

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes

## External Certification / Deployment

- Run FreeRADIUS interoperability on production Linux for ACL policies created
  from flat `acl_rules`, AST-only payloads, and mixed payloads where the AST
  becomes the source of truth.
- Capture Access-Accept packet traces proving rendered `NAS-Filter-Rule`,
  Cisco `Cisco-AVPair`, Aruba filter rule, AegisNAS ACL VSA, and profile-style
  vendor hints match the enabled compatibility packs.
- Validate Cisco downloadable ACL behavior on representative IOS-XE, Catalyst,
  WLC, and ISE-compatible lab targets.
- Validate Aruba/ClearPass and Aruba Central ACL behavior for filter-rule and
  role/profile outputs.
- Validate Fortinet, Ruckus, MikroTik, Juniper, Huawei, H3C, HP, D-Link, Pica8,
  and Colubris policy/profile outputs against exact product and firmware scope.
- Run negative tests for object groups, service groups, applications, URL
  categories, state, TCP flags, ICMP types, DSCP, and time ranges on devices
  that cannot consume those fields; confirm diagnostics remain visible and no
  unsupported field is silently enforced.
- Run HA upgrade, failover, backup restore, and rollback drills with persisted
  ACL AST policies and config revision snapshots.
- Run performance and soak tests with large ACL libraries near configured rule,
  object, service, application, and URL category limits.
- Review support bundle output to confirm AST fingerprints and diagnostics are
  useful without exposing secrets or unsafe identity data.
- Complete security review for JSON input validation, denial-of-service bounds,
  audit visibility, RBAC, tenant isolation, and rollback behavior.
- Record customer or lab acceptance evidence for every production vendor ACL
  claim before documenting the target as certified.
