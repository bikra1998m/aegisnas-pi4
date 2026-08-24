# NAS-0060 Release Certification Checklist

NAS-0060 software engineering is complete when automated code, API, database,
UI, documentation, and CI checks pass. The items below are external release
certification work and do not block engineering closure.

## External Certification

- Obtain real vendor hardware or controller access for each of the 28 mapped
  namespaces.
- Validate the generated FreeRADIUS dictionary and reply output on production
  Linux FreeRADIUS packages.
- Capture Access-Request, Access-Accept, Accounting, CoA, and Disconnect packet
  traces for representative mappings.
- Confirm malformed, unknown, oversized, repeated, grouped, tagged, and
  unsupported VSA behavior against vendor firmware.
- Validate inbound semantic mapping for role, VLAN, bandwidth, posture,
  device group, tenant, quarantine, accounting identity, and accounting
  counters.
- Validate outbound reply rendering for role, VLAN, ACL, dynamic ACL, portal,
  bandwidth, quota, quarantine, and session-action mappings.
- Confirm HA active/standby nodes produce the same certification fingerprint.
- Run upgrade and rollback drills from the previous release to the NAS-0060
  build.
- Run performance and soak tests with realistic RADIUS auth/accounting packet
  rates.
- Complete security review for raw VSA retention, support-bundle redaction, API
  authorization, and event immutability.
- Record customer acceptance evidence before publishing environment-specific
  compatibility claims.

## Release Sign-off

Use `/api/v1/system/vendor-mapping-certification` to capture the software
fingerprint. Store packet captures, hardware/controller versions, FreeRADIUS
package versions, HA evidence, test dates, and operator approvals in the release
evidence archive.

Do not mark a mapping externally certified until its evidence names the exact
vendor, product family, firmware or controller version, transport, direction,
attribute, packet trace, and test result.
