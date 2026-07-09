# NAS-0007 Release Certification Checklist

NAS-0007 software implementation is complete when the provider interface,
configuration, database migration, APIs, UI, tests, and documentation are done.
The items below require external environments or release sign-off and do not
block engineering closure.

## External Certification / Deployment

- [ ] Confirm production IANA PEN identity is already active from NAS-0001.
- [ ] Validate `env:` refs under the target Linux service manager.
- [ ] Validate `file:` refs with production ownership, group, and mode policy.
- [ ] Run FreeRADIUS interoperability on the target Ubuntu image.
- [ ] Confirm generated `clients.conf`, `proxy.conf`, and LDAP module files load under the packaged FreeRADIUS version.
- [ ] Run HA active/standby failover while file and environment refs are present on both nodes.
- [ ] Run a secret-rotation drill for RADIUS client, upstream AAA, and LDAP refs.
- [ ] Run a rollback drill from ref-backed config to the previous release package.
- [ ] Run a security review of support bundles and admin API output to confirm no secret values are disclosed.
- [ ] Run long-duration soak tests with periodic `radius-apply` and provider report refreshes.
- [ ] Confirm customer or lab hardware can authenticate using ref-backed UDP client secrets.
- [ ] Capture signed release evidence with API responses from `/api/v1/system/secret-providers` and `/api/v1/system/production-readiness`.

## Future External Provider Scope

Vault, HSM, TPM, hardware attestation, and envelope encryption are tracked by
NAS-0112. NAS-0007 provides the software interface and fail-closed reference
handling that those providers will plug into.
