# Enterprise Certificate Lifecycle

NAS-0027 adds a production software layer for enterprise certificate
enrollment, renewal, revocation readiness, issuer rotation, and evidence
collection. It does not store private keys or raw certificate identities in the
audit tables.

## Problem

EAP-TLS and BYOD deployments need more than a CA path. Operators need a
deterministic gate that decides whether an enrollment or renewal request is safe
to accept before a certificate is issued or trusted.

The feature supports:

- EST, SCEP, BYOD portal, admin, and API enrollment entry points
- CSR parsing and proof-of-possession validation
- RSA, ECDSA, and Ed25519 key policy
- subjectAltName and bound-device checks
- default and named certificate templates
- active and staged issuer rotation
- renewal-window detection
- CRL or OCSP readiness checks before fail-closed operation
- private-key escrow governance
- hashed lifecycle event history and inventory

## Vendor And Standards Scope

Comparable lifecycle workflows exist in Cisco ISE, Aruba ClearPass, Microsoft
ADCS/NPS, Jamf, Intune, Fortinet, Juniper Mist, and UniFi-backed enterprise
WLAN deployments.

Relevant standards and dictionaries:

- RFC 5280 for X.509 certificate and revocation semantics
- RFC 7030 for EST enrollment semantics
- RFC 8894 for SCEP enrollment semantics
- RFC 6960 for OCSP
- RFC 5216 and RFC 9190 for EAP-TLS behavior
- standard RADIUS EAP attributes: `EAP-Message`, `Message-Authenticator`,
  `User-Name`, `Calling-Station-Id`, `NAS-Identifier`, and `Class`
- FreeRADIUS TLS certificate request context such as client certificate
  subject, issuer, serial, and common-name fields when available

## Configuration

```yaml
onboarding:
  device_inventory_enabled: true
  portal_enabled: true
  certificate_enrollment_enabled: true
  eap_tls_enabled: true
  ca_mode: internal
  ca_cert_path: /etc/aegisnas/pki/ca.crt
  ca_key_path: /etc/aegisnas/pki/ca.key
  certificate_lifecycle:
    enabled: true
    mode: enforce
    fail_closed: true
    default_template: device-eap-tls
    templates: ["device-eap-tls", "byod-eap-tls"]
    active_issuer: aegisnas-local
    issuer_rotation_mode: disabled
    issuer_overlap_seconds: 2592000
    certificate_validity_days: 365
    max_certificate_validity_days: 825
    renewal_window_days: 30
    require_csr: true
    require_proof_of_possession: true
    require_device_binding: true
    require_subject_alt_name: true
    allowed_key_types: ["rsa", "ecdsa", "ed25519"]
    min_rsa_bits: 2048
    allowed_ecdsa_curves: ["P-256", "P-384", "P-521"]
    allow_server_key_generation: false
    escrow_policy: forbid
    crl_enabled: true
    ocsp_enabled: false
    est_enabled: true
    scep_enabled: true
    byod_portal_enabled: true
    audit_enabled: true
    event_retention_limit: 6000
    inventory_retention_limit: 100000
```

Use monitor mode while introducing a new CA, supplicant profile, or enrollment
protocol. Use enforce mode only when CRL or OCSP evidence is clean and the
configured CA path is production-ready.

## API

```text
GET  /api/v1/system/certificate-lifecycle
POST /api/v1/system/certificate-lifecycle/evaluate
```

The `GET` response includes effective policy, template and issuer state,
capability catalog, runtime summary, recent hashed events, inventory, blockers,
warnings, and the release certification checklist name.

The `evaluate` endpoint accepts enrollment facts such as protocol, template,
issuer, device ID, CSR PEM, requested validity, renewal state, revocation
evidence, CRL/OCSP reachability, certificate metadata, and an optional `audit`
flag. When `audit_enabled` is true, AegisNAS stores hashed evidence and updates
certificate inventory.

## Stored State

`certificate_lifecycle_events` stores append-only enrollment and renewal
decisions.

`certificate_lifecycle_inventory` stores the latest bounded certificate state.

Both tables store hashes for device IDs, subjects, SAN values, and serials.
Raw usernames, device identities, certificate subjects, SANs, and serials are
not persisted.

## Operational Rules

- Keep `require_csr: true` and `require_proof_of_possession: true`.
- Keep `require_device_binding: true` for enterprise EAP-TLS devices.
- Keep `escrow_policy: forbid` unless an admin-approved escrow workflow is
  legally and operationally required.
- Do not use enforce/fail-closed mode without CRL or OCSP readiness.
- During issuer rotation, set `issuer_rotation_mode: staged`,
  `staged_issuer`, and a bounded overlap window.
- Retain `api/certificate-lifecycle.json` from support bundles for change
  windows and incidents.

## Software Completion

Software implementation is complete when config validation, evaluator logic,
database migrations, REST APIs, RBAC, OpenAPI, support bundles, dashboard,
Access Settings, production-readiness checks, automated tests, CI target, and
documentation pass.

External validation remains in
[nas-0027-release-certification-checklist.md](nas-0027-release-certification-checklist.md).
