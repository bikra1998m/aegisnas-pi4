# NAS-0053 Release Certification Checklist

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

NAS-0053 is closed for engineering when code, tests, automation, UI, API,
database schema, and documentation are complete. The items below require real
hosts, vendor devices, controllers, third-party environments, or production
release processes and do not block the next roadmap feature.

## External Certification / Deployment

- [ ] Verify Linux bridge and VLAN subinterface creation on supported Ubuntu
  LTS kernels and appliance images.
- [ ] Validate idempotent `ip link` apply behavior across reboot, service
  restart, duplicate apply, rollback, and partial pre-existing state.
- [ ] Confirm generated hostapd `dynamic_vlan=1` and `vlan_file` behavior on
  supported local radio hardware.
- [ ] Capture RADIUS Access-Accept packets carrying `Tunnel-Type`,
  `Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`, `Egress-VLANID`, and
  AegisNAS/vendor VLAN attributes.
- [ ] Run FreeRADIUS interoperability on production Linux with standard tunnel
  attributes and enabled vendor VLAN packs.
- [ ] Smoke test real AP, switch, and controller firmware for VLAN assignment,
  hostapd VLAN file handling, reauthentication after VLAN CoA, and accounting
  visibility.
- [ ] Validate native controller behavior for Cisco, Aruba, UniFi, Ruckus,
  Fortinet, Mist, MikroTik, Meraki, and OpenWiFi where static or dynamic VLAN
  fields are managed.
- [ ] Validate HA failover and rollback when the active node changes during
  preview, apply, sync, rollback, or hostapd restart.
- [ ] Benchmark apply latency, command count, file size, CPU, memory, and
  storage use across lite, branch, and enterprise profiles.
- [ ] Run long-duration soak with VLAN churn, accounting updates, CoA VLAN
  changes, hostapd reloads, and rollback drills.
- [ ] Complete external security review for command argument validation,
  managed-file permissions, RBAC, evidence retention, and support-bundle
  redaction.
- [ ] Complete production deployment acceptance and customer sign-off.

## Evidence To Attach

- `go test` and admin UI build logs from the release branch.
- `ip -d link show`, `bridge link`, and `bridge vlan show` outputs before and
  after apply.
- The generated hostapd config and managed VLAN file.
- Packet captures for standard tunnel attributes and every certified vendor
  VLAN pack.
- Vendor firmware/controller versions and exact model list.
- HA failover timeline and rollback evidence.
- Apply latency, scale, CPU/RAM/storage utilization, and soak reports.
- Security review notes and accepted residual risks.
