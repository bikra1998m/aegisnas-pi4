# NAS-0072 Release Certification Checklist

NAS-0072 software implementation is complete when automated code, API, UI,
configuration, packet, database, CI, and documentation work passes. The items
below are external release gates and do not block engineering completion.

## External Validation

- [ ] Validate the generated AegisNAS dictionary and NAS-0072 VSA names against
  FreeRADIUS on the target Linux release.
- [ ] Import the pinned FreeRADIUS 3.2.8 dictionaries and confirm the source
  hash, vendor count, row count, and long-tail fingerprint match the software
  report.
- [ ] Capture Access-Request, Access-Accept, Accounting-Request, CoA, or
  Disconnect packets for each customer-facing long-tail vendor family included
  in a release claim.
- [ ] Validate role, VLAN, ACL/filter, bandwidth, quota, portal, address,
  route, VRF, posture, tenant, controller, certificate, and accounting behavior
  on representative devices where the vendor exposes those capabilities.
- [ ] Validate secret redaction with real token, password, key, certificate,
  private, and challenge attributes where the vendor dictionary defines them.
- [ ] Validate RFC 5176 CoA and Disconnect workflows for vendors that expose
  reauth, remediation, disconnect, or session-action semantics.
- [ ] Validate HA failover while long-tail vendor authentications, accounting
  packets, and dynamic authorization requests are in flight.
- [ ] Run scale and performance benchmarks on lite, branch, enterprise, and
  high-spec hardware profiles with the `long-tail` compatibility pack enabled.
- [ ] Run long-duration soak tests covering 802.1X reauthentication,
  MAC-auth/MAB churn, hotspot sessions, accounting rollover, dynamic
  authorization retries, and support-bundle collection.
- [ ] Complete an external security review for VSA evidence storage,
  redaction, support bundles, opaque pass-through policy boundaries, shared
  secrets, and admin API authorization.
- [ ] Attach firmware versions, device models, controller versions, packet
  captures, logs, test run IDs, operator approvals, customer acceptance
  evidence, and any not-applicable decisions to the release record.

## Release Claim Rules

- Software-ready claims may reference `long_tail_namespace_program` readiness
  and `long_tail_namespace_events` evidence.
- Hardware-certified claims require firmware-scoped packet captures for each
  named vendor family.
- Controller-certified claims require controller API or management-system drift
  evidence where the device needs controller-side policy before enforcing a
  RADIUS VSA.
- CoA/Disconnect claims require live ACK/NAK evidence from the target device or
  controller firmware.
- A long-tail vendor must not be advertised as fully certified unless its exact
  namespace, product family, firmware, dictionary release, packet captures, HA
  result, security review, and customer acceptance evidence are attached.

