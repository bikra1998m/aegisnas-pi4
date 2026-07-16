# NAS-0018 Release Certification Checklist

NAS-0018 software engineering is complete when code, migrations, APIs, UI,
automation, tests, and documentation pass. The items below require third-party
systems, production Linux environments, physical or virtual lab infrastructure,
customer environments, or external review and do not block roadmap engineering
closure.

## Feature

- Feature ID: NAS-0018
- Feature Name: Active Directory Kerberos and winbind
- Engineering status: Complete after the NAS-0018 commit and validation pass
- Ready for external validation: Yes

## External Certification / Deployment

- [ ] IANA/vendor-neutral product release notes mention AD verifier scope.
- [ ] FreeRADIUS 3.2.x interoperability run on production Linux with generated
      `mods-enabled/ldap`, `mods-enabled/mschap`, `sites-enabled/default`, and
      `inner-tunnel`.
- [ ] Packet captures collected for PEAP/MSCHAPv2, PAP portal login, reject,
      timeout, and missing-user flows.
- [ ] Microsoft Active Directory lab validates LDAPS service bind, user bind,
      group lookup, nested groups, disabled user, locked user, expired password,
      and password-change-required outcomes.
- [ ] Kerberos lab validates `kinit`, bad password, clock skew, missing realm,
      missing `krb5.conf`, keytab presence check, and credential cache cleanup.
- [ ] Samba/winbind lab validates domain join, `wbinfo -t`, `ntlm_auth`, helper
      rejection, helper timeout, and group extraction.
- [ ] Cisco, Aruba, Ruckus, Extreme, Fortinet, UniFi, and Microsoft supplicant
      smoke tests confirm expected authorization attributes after AD auth.
- [ ] HA validation proves cache/audit behavior across active/standby failover.
- [ ] Performance benchmark covers concurrent AD-backed portal auth and
      PEAP/MSCHAPv2 auth through FreeRADIUS.
- [ ] Long-duration soak test covers domain-controller outage, recovery, cache
      expiry, and support-bundle export.
- [ ] Security audit reviews credential handling, helper invocation, Kerberos
      cache isolation, secret references, and audit redaction.
- [ ] Operator runbook dry-run completed by a non-developer.
- [ ] Customer acceptance evidence attached for the supported AD forest and
      device firmware matrix.

## Evidence Artifacts

- [ ] Generated FreeRADIUS archive
- [ ] `/api/v1/system/active-directory` JSON
- [ ] `/api/v1/system/production-readiness` JSON
- [ ] Support bundle with `api/active-directory.json`
- [ ] Packet captures
- [ ] Domain controller test notes
- [ ] AP/controller firmware matrix
- [ ] HA failover transcript
- [ ] Benchmark report
- [ ] Security review report

## Release Gate

Release certification is accepted only when all required evidence is attached
for the exact product version, OS image, FreeRADIUS version, domain controller
version, and AP/controller firmware matrix being released.
