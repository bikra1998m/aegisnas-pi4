# NAS-0062 Aruba/HPE Family Pack

NAS-0062 closes the software engineering scope for the Aruba/HPE-family
FreeRADIUS dictionaries: Aruba, HP/ArubaOS-Switch, Aerohive/Extreme, and
Colubris/HP MSM.

## Software Scope

The pack derives its authoritative coverage from the pinned FreeRADIUS 3.2.8
attribute registry. It software-certifies all 125 rows in this family:

- Aruba role, VLAN, NAS filter rule, ClearPass CPPM role, AirGroup, MDPS
  device context, MPSK/DPP metadata, UBT/gateway, QoS, and port-control
  attributes.
- HP/ArubaOS-Switch role, privilege, command, captive portal, bandwidth, ACL,
  egress VLAN, Bonjour, URI, and port-bounce attributes.
- Aerohive/Extreme VLAN, profile, AVPair, IDM redirect/message, client monitor,
  user language, and authentication-source attributes.
- Colubris/HP MSM intercept/quarantine state.

Software readiness means the server can parse, classify, render, store bounded
evidence, expose APIs/UI, and report readiness without making hardware-certified
claims. Real device acceptance is tracked separately in
`nas-0062-release-certification-checklist.md`.

## Packet Handling

Known Aruba/HPE-family VSAs are normalized into existing AegisNAS policy fields:

- roles and ClearPass roles -> `access.role`
- numeric and named VLANs -> `access.vlan`
- Aruba NAS filter rules and HP raw filters -> `enforcement.acl`
- captive portal redirects -> `guest.portal_profile`
- AirGroup, Bonjour, MPSK key names, IDM, and AVPair hints -> policy tags
- MDPS, AP, client monitor, and device identity attributes -> posture or
  accounting identity
- HP and Aruba port-bounce controls -> dynamic authorization intent
- Colubris intercept -> quarantine

Secret-bearing attributes such as MPSK passphrases, DPP passphrases, DPP
bootstrap material, Aerohive PPSK requests, and PMK values are redacted before
they reach persistent evidence or generic vendor evidence lists.

## Operator Flow

1. Inspect `/api/v1/system/aruba-family-pack`.
2. Confirm software coverage is 100% and `software_blocked_mappings` is zero.
3. Record the current fingerprint with
   `/api/v1/system/aruba-family-pack/record`.
4. Export a support bundle for release evidence.
5. Run the external release certification checklist before publishing
   hardware-certified compatibility claims.

## External Scope

The following never block software completion:

- ArubaOS, Aruba Central, ClearPass, ArubaOS-Switch, Aerohive/Extreme, and
  Colubris/MSM hardware or controller testing
- FreeRADIUS interoperability on production Linux
- HA failover, performance, soak, security, deployment, and customer acceptance
  validation
