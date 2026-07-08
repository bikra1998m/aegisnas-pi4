# AegisNAS Vendor Identity and PEN Migration

Feature: `NAS-0001`
Status: engineering implementation complete; ready for external validation.

## Purpose

RADIUS Vendor-Specific Attributes use attribute type 26 from RFC 2865. The first four octets of its value identify the vendor by the IANA Private Enterprise Number; the remaining bytes use that vendor's private type and length format. A unique assigned PEN prevents AegisNAS attributes from colliding with another organization and gives dictionaries, packet captures, controllers, support tools, and certification evidence one stable namespace.

This is identity governance, not merely a numeric configuration field. Cisco (PEN 9), Juniper (2636), Aruba (14823), Huawei (2011), MikroTik (14988), Fortinet (12356), Ruckus (25053), Microsoft (311), and other enterprise vendors use assigned PENs across their NAS, switch, controller, firewall, VPN, broadband, and AAA products. FreeRADIUS represents these identities with `VENDOR` declarations in the corresponding dictionaries. No individual VSA performs PEN assignment; every vendor VSA depends on the enclosing PEN.

Applicable standards and registries:

- RFC 2865, section 5.26, defines `Vendor-Specific` and its four-octet Vendor-Id.
- RFC 5612 reserves PEN 32473 for documentation and testing; AegisNAS rejects it for production.
- IANA's [Private Enterprise Numbers registry](https://www.iana.org/assignments/enterprise-numbers/) is authoritative for assignment ownership.

On 2026-07-08, the live IANA text registry was last updated 2026-07-06 and contained no exact `AegisNAS` organization entry. Existing organizations containing “Aegis” are unrelated and must not be reused. The product owner must submit the IANA application and use the exact assigned organization returned by IANA.

## Existing implementation assessment

Before NAS-0001, the repository already provided:

- The explicit lab PEN `55555`, `dictionary.aegisnas`, and 13 product attributes.
- Environment/config selection, dictionary rendering and installation, compatibility reporting, readiness warnings, and a lab-only certification override.
- RADIUS packet encode/decode using the configured product PEN.
- A guarded dictionary installer and UI visibility.

The prior implementation was partial because any non-placeholder integer looked production-like, YAML and environment identity sources could disagree, no assignment evidence was persisted, changes had no preview/apply/rollback transaction, old-PEN packets had no bounded transition path, and readiness checked only “not 55555.”

## Production architecture

### Identity authority

The authoritative runtime fields live under `radius.vendor`. `identity_mode` is:

- `lab`: PEN 55555 or RFC 5612 test use; never production-ready.
- `unverified`: a non-placeholder value may be staged only while product VSA processing is disabled.
- `production`: the config includes exact IANA organization, registry URL/update date, verification time, registry SHA-256, and assignment-record SHA-256.

General settings updates cannot change these fields. Only the verified migration workflow can write them.

### Verification

Preview fetches the fixed IANA HTTPS text registry with a 20-second timeout and 8 MiB bound. It rejects reserved, placeholder, documentation, absent, and organization-mismatched PENs. Evidence excludes registry contact details and retains only assignment identity, timestamps, source URL, and hashes.

### Database

Schema version 15 adds:

- `vendor_identity_assignments`: verified evidence and exactly one active assignment.
- `vendor_identity_migrations`: preview, one-time confirmation digest, expiry, identity-only before/after snapshots, apply/failure/rollback state, actor, timestamps, and failure detail.

The tables are included automatically in existing database backup and HA package replication. They contain no RADIUS secret or complete system configuration.

### Packet and session behavior

After apply, all outbound product VSAs and accounting attributes use the assigned PEN. The previous PEN may be decoded inbound until `legacy_accept_until`; the current PEN always has precedence. Expired legacy IDs are ignored without requiring a restart. Existing sessions remain intact and accounting stops arriving under the old PEN can be interpreted during the bounded window.

Policy semantics and enforcement values do not change. The migration changes only the namespace containing AegisNAS attributes.

### Apply and rollback

Preview produces a cryptographically random one-time confirmation token and stores only its SHA-256 digest. The token expires after 15 minutes. Apply rejects reused, expired, or stale previews, validates the candidate config and generated dictionary, writes the config atomically, applies and validates FreeRADIUS, and restarts both `freeradius` and `aegis-radius`. A validation or restart failure triggers automatic config and runtime restoration.

An applied, failed, or interrupted migration can be restored with the exact phrase `ROLLBACK <migration-id>`. Interrupted `applying` records remain visible for operator recovery.

### Security and HA

- Only `super_admin` may preview, apply, or roll back; authenticated roles may read lifecycle status.
- Confirmation comparison is constant-time; tokens are never persisted or logged in plaintext.
- IANA URL selection is not user-controlled, preventing registry-fetch SSRF.
- Config writes use same-directory temporary files, `fsync`, restrictive mode, and atomic rename.
- The process serializes migration changes. Active/standby replication carries config and database evidence; only the active node should execute apply.

### Monitoring and logging

The status API reports lifecycle state, evidence validity, legacy-window state, migration history, preview/apply/failure/rollback counters, and last event time. Every preview, apply, failure, and rollback is written to the existing audit log without confirmation secrets. Production readiness is blocked unless config evidence and the active database assignment agree.

## REST API

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/v1/system/vendor-identity?limit=50` | authenticated | Current lifecycle, evidence, history, recovery warnings, and counters |
| POST | `/api/v1/system/vendor-identity/migrations/preview` | `super_admin` | Verify the IANA assignment and create a 15-minute migration preview |
| POST | `/api/v1/system/vendor-identity/migrations/apply` | `super_admin` | Consume the one-time token, persist config, validate/restart FreeRADIUS and the broker, activate evidence |
| POST | `/api/v1/system/vendor-identity/migrations/{id}/rollback` | `super_admin` | Restore the previous identity and FreeRADIUS state |

Preview request:

```json
{
  "pen": 12345,
  "expected_organization": "Exact Legal Organization From IANA",
  "legacy_acceptance_hours": 168
}
```

Apply uses `migration_id` and the `confirmation_token` returned once by preview. Rollback uses `confirmation_text` equal to `ROLLBACK <migration-id>`.

## Operator procedure

1. Apply for a PEN at the IANA URL shown in the UI. Do not use another Aegis organization or an example number.
2. Wait until the assigned PEN and exact organization appear in IANA's registry.
3. Back up config/database and confirm HA peer health.
4. Open **Vendor Compatibility**, enter the PEN and exact organization, and preview.
5. Review active sessions, affected systems, hashes, deadline, and peer-update warning.
6. Update peer dictionaries/controllers within the planned maintenance window.
7. Apply the preview before its token expires.
8. Confirm `/system/vendor-identity` reports `production_verified`, run `freeradius -XC`, and perform packet/device smoke tests.
9. Remove legacy acceptance after peers are migrated; it expires automatically at the configured deadline.
10. Use the typed rollback phrase if validation, packet, or peer testing fails.

## Deployment and upgrade

Fresh production deployments should complete this workflow before enabling the `aegisnas` compatibility pack on devices. Existing installations upgrade in lab mode without changing PEN 55555. Schema v15 is additive. Downgrade must first roll back an active migration or preserve the schema-15 database for re-upgrade; older binaries ignore the new tables but do not understand the production evidence fields.

The standalone installer now requires `--organization` (or `AEGISNAS_IANA_ORGANIZATION`) for non-placeholder PENs and verifies it against IANA or an operator-pinned registry snapshot. `--allow-placeholder` remains lab-only.

## Test coverage

Automated coverage includes registry parsing and bounds, reserved/mismatched/tampered evidence, schema migration and lifecycle, one-time apply and automatic recovery, explicit rollback, stale identity protection, direct-settings mutation rejection, current/legacy packet precedence and expiry, current-only outbound encoding, OpenAPI/RBAC, TypeScript build, and browser preview/apply flow.

Activities requiring an external organization, production Linux deployment, physical vendor hardware, an HA lab, or a sustained test environment are tracked separately in the [NAS-0001 Release Certification Checklist](nas-0001-release-certification-checklist.md). They gate a certified production release, but do not keep the engineering feature open.

## Completion report

| Measure | Result |
|---|---:|
| Software Implementation | 100% Complete |
| Engineering Implementation | 100% Complete |
| Ready for External Validation | Yes |
| NAS-0001 status | Closed |

There is no remaining NAS-0001 software implementation work. Production activation remains fail-closed until valid IANA evidence is supplied, and release certification remains governed by the separate checklist.
