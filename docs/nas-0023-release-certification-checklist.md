# NAS-0023 Release Certification Checklist

NAS-0023 software implementation is complete when code, tests, APIs, UI,
configuration, documentation, CI, and migration behavior pass. The items below
are external release evidence and must not block engineering closure.

## External Certification / Deployment

- Obtain FreeRADIUS production Linux evidence with `rlm_eap_teap` installed and
  generated `mods-enabled/eap` passing `freeradius -XC`.
- Capture packet traces for TEAP Identity-Type, EAP-Payload, Crypto-Binding,
  Channel-Binding, Result, Intermediate-Result, Error, and PAC TLVs.
- Validate supplicant interoperability for Windows, macOS, Linux, iOS, Android,
  and managed device agents where TEAP is claimed.
- Validate AP/controller interoperability for Cisco, Aruba, Microsoft/NPS
  environments, and any certified enterprise Wi-Fi profile.
- Run machine-only, user-only, machine-then-user, and migration `either` chain
  drills.
- Run downgrade drills for missing cryptobinding, missing Identity-Type,
  invalid channel binding, Basic-Password-Auth rejection, PAC-required missing,
  and unsupported inner method.
- Run HA failover while TEAP conversations are active and verify no stale chain
  state is accepted after failover.
- Run performance and long-duration soak tests for Lite, Branch, and Enterprise
  profiles with TEAP enabled.
- Attach support bundle evidence containing `api/eap-framework-teap.json`,
  `api/eap-framework.json`, production readiness output, generated FreeRADIUS
  config, and sanitized packet captures.
- Complete security review for TEAP identity privacy, PAC governance,
  cryptobinding handling, log redaction, and admin API authorization.

## Release Sign-Off

- Exact FreeRADIUS version and package source recorded.
- Exact supplicant versions and OS builds recorded.
- Exact AP/controller model, firmware, and configuration profile recorded.
- Known limitations documented in the compatibility catalog.
- No unresolved Critical or High security defects remain.
