# NAS-0019 Release Certification Checklist

NAS-0019 software engineering is complete when automated tests, builds, schema migration, API, UI, and documentation pass. The items below require real environments, hardware, third-party systems, or release sign-off and do not block the next roadmap feature.

## External Validation

- [ ] Validate local-first and LDAP-first source orders against a production-like LDAP or AD directory.
- [ ] Run controlled LDAP bind/search outage drills and confirm circuit-open evidence in `/api/v1/system/identity-failover`.
- [ ] Validate stale cache behavior only when `identity.failover.cache_credentials=true`.
- [ ] Confirm stale cache expiry and bad-password rejection with real directory credentials.
- [ ] Confirm split-result denial with a real conflicting local and directory identity.
- [ ] Capture packet/session evidence for portal fallback during upstream AAA outage.
- [ ] Validate support bundle includes `api/identity-failover.json`.
- [ ] Validate HA database replication for `identity_source_events` and `identity_source_cache`.
- [ ] Run failover and failback on active/standby nodes.
- [ ] Complete long-duration soak with source failure/recovery cycles.
- [ ] Complete performance benchmark for local and LDAP fallback auth rates.
- [ ] Complete security review of credential-cache policy, retention, redaction, and access controls.
- [ ] Complete customer acceptance testing for intended identity-source order and failure posture.

## Release Evidence

- [ ] `/api/v1/system/identity-failover` report exported.
- [ ] `/api/v1/system/production-readiness` exported with `identity_source_failover`.
- [ ] Support bundle archived.
- [ ] Test directory topology documented.
- [ ] HA topology and database backend documented.
- [ ] Any deployment exception or waiver approved.
