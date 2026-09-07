# NAS-0071 Release Certification Checklist

NAS-0071 software implementation is complete when automated code, API, UI,
configuration, packet, database, CI, and documentation work passes. The items
below are external release gates and do not block engineering completion.

## External Validation

- [ ] Validate the generated AegisNAS dictionary and all NAS-0071 VSA names
  against FreeRADIUS on the target Linux release.
- [ ] Capture Access-Accept packets for 3Com access level, VLAN name, SSID,
  portal URL, encryption, and host IP attributes.
- [ ] Capture Access-Accept packets for Arista AVPair, user privilege, user
  role, CVP role, command, WebAuth, block/unblock MAC, port-flap, captive
  portal, and segment/interface context.
- [ ] Capture Brocade and Force10 AVPair packet behavior for role, ACL, VLAN,
  VRF, QoS, and command authorization tokens.
- [ ] Capture Dell EMC group-name and AVpair behavior on supported PowerSwitch
  or Dell Networking firmware.
- [ ] Capture EqualLogic administrative access behavior for privilege, account
  type, pool access, replication-site access, poll interval, and admin identity
  attributes.
- [ ] Re-run the NAS-0063 Extreme validation matrix for NetLogin, extended
  VLAN, CLI authorization, security profile, VM context, and VRF behavior.
- [ ] Re-run the NAS-0064 Foundry/ICX validation matrix for command
  authorization, ACL, 802.1X, MAC-auth, VLAN/QoS, CoA, SI role, and voice phone
  configuration behavior.
- [ ] Validate RFC 5176 CoA and Disconnect workflows for vendors that expose
  block, unblock, port-flap, reauth, or disconnect semantics.
- [ ] Validate switch-controller or fabric-manager integrations where the
  platform requires a controller-side policy object before a RADIUS VSA is
  enforceable.
- [ ] Validate HA failover with active/standby nodes while switch
  authentications, accounting packets, and dynamic authorization requests are in
  flight.
- [ ] Run scale and performance benchmarks on lite, branch, enterprise, and
  high-spec hardware profiles.
- [ ] Run long-duration soak tests covering 802.1X reauthentication,
  MAC-auth/MAB churn, accounting rollover, controller drift, and dynamic
  authorization retries.
- [ ] Complete an external security review for support-bundle output, VSA
  evidence storage, AVPair input validation, command authorization context,
  RADIUS shared secrets, and controller credentials.
- [ ] Attach firmware versions, switch model, controller version, packet
  captures, logs, test run IDs, operator approvals, and customer acceptance
  evidence to the release record.

## Release Claim Rules

- Software-ready claims may reference `switching_vendor_pack` readiness and
  `switching_vendor_pack_events` evidence.
- Hardware-certified claims require firmware-scoped packet captures for each
  named vendor family.
- Controller-certified claims require controller API or fabric-manager drift
  evidence for each product family.
- CoA/Disconnect claims require live ACK/NAK evidence from the target switch
  firmware.
- Extreme and Foundry claims may reuse NAS-0063/NAS-0064 evidence only when the
  firmware, model, dictionary release, and packet captures match the NAS-0071
  release scope.
