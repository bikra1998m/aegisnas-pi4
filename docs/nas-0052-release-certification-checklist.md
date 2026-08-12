# NAS-0052 Release Certification Checklist

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

NAS-0052 is closed for engineering when code, tests, automation, UI, API,
database schema, and documentation are complete. The items below require real
hosts, vendor devices, controllers, third-party environments, or production
release processes and do not block the next roadmap feature.

## External Certification / Deployment

- [ ] Verify Linux `tc flower` IPv6 classifiers on the supported Ubuntu LTS
  kernels and appliance images.
- [ ] Capture IPv4-only, IPv6-only, and dual-stack traffic proving the expected
  download and upload classes are hit.
- [ ] Validate IFB ingress redirection for IPv4 and IPv6 under reboot, apply,
  rollback, and service restart.
- [ ] Run FreeRADIUS interoperability on production Linux for MikroTik, WISPr,
  UBNT, Huawei, H3C, TPLink, ZTE, and shared kbps vendor attributes.
- [ ] Smoke test real AP/controller firmware for each supported vendor unit
  profile and attach packet captures.
- [ ] Confirm UBNT bps values and WISPr/Huawei/H3C/TPLink/ZTE kbps values are
  interpreted as intended by device firmware.
- [ ] Confirm MikroTik basic and extended `Mikrotik-Rate-Limit` grammar on
  supported RouterOS versions.
- [ ] Validate HA failover and rollback when the active node changes during
  preview/apply/sync.
- [ ] Benchmark throughput and latency for IPv4, IPv6, and dual-stack sessions
  across lite, branch, and enterprise hardware profiles.
- [ ] Run long-duration soak with mixed dual-stack churn, accounting updates,
  CoA updates, and rollback drills.
- [ ] Complete external security review for rate input validation, evidence
  retention, RBAC, and support-bundle redaction.
- [ ] Complete production deployment acceptance and customer sign-off.

## Evidence To Attach

- `go test` and admin UI build logs from the release branch.
- `tc -s class show` and `tc -s filter show` outputs before and after apply.
- Packet captures showing class selection for IPv4 and IPv6.
- RADIUS packet captures for every certified vendor unit profile.
- Vendor firmware/controller versions and exact model list.
- HA failover timeline and rollback evidence.
- Throughput, latency, and CPU/RAM/storage utilization reports.
- Security review notes and accepted residual risks.
