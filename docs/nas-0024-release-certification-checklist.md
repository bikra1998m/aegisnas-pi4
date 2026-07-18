# NAS-0024 Release Certification Checklist

NAS-0024 software implementation is complete when code, tests, APIs, UI,
configuration, documentation, CI, and migration behavior pass. The items below
are external release evidence and must not block engineering closure.

## External Certification / Deployment

- Obtain FreeRADIUS production Linux evidence with `rlm_eap_fast` and
  `rlm_eap_pwd` installed and generated `mods-enabled/eap` passing
  `freeradius -XC`.
- Capture packet traces for EAP-FAST PAC, PAC key, PAC opaque state, PAC
  acknowledgement, cryptobinding, EAP-Payload, tunnel result, and PAC-required
  rejection paths.
- Capture packet traces for EAP-PWD commit, confirm, password-proof, group
  mismatch, missing identity, and replay rejection paths.
- Validate supplicant interoperability for every claimed Windows, macOS,
  Linux, iOS, Android, embedded Wi-Fi, and managed-device profile.
- Validate AP/controller interoperability for Cisco, Aruba, HPE, Ruckus,
  Fortinet, UniFi, and any deployment-specific enterprise Wi-Fi profile that
  advertises FAST or PWD.
- Run downgrade drills for missing Message-Authenticator, weak PWD group,
  missing FAST cryptobinding, anonymous PAC provisioning, missing PWD proof,
  unsupported FAST inner method, and TLS version bounds.
- Run HA failover while FAST/PWD conversations are active and verify no stale
  method state, PAC state, or replay state is accepted after failover.
- Run performance and long-duration soak tests for Lite, Branch, and Enterprise
  profiles with FAST and PWD enabled separately and together.
- Attach support bundle evidence containing `api/eap-framework-fast-pwd.json`,
  `api/eap-framework.json`, production readiness output, generated FreeRADIUS
  config, and sanitized packet captures.
- Complete security review for PAC governance, server ID handling, password
  verifier policy, replay protection, identity privacy, log redaction, and admin
  API authorization.

## Release Sign-Off

- Exact FreeRADIUS version and package source recorded.
- Exact supplicant versions and OS builds recorded.
- Exact AP/controller model, firmware, and configuration profile recorded.
- Known limitations documented in the compatibility catalog.
- No unresolved Critical or High security defects remain.
