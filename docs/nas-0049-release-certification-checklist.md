# NAS-0049 Release Certification Checklist

NAS-0049 software engineering is complete. This checklist tracks external
certification and deployment work that must not block development of NAS-0050.

## Software Implementation

- [x] Code complete
- [x] Database migration complete
- [x] REST APIs complete
- [x] Admin UI complete
- [x] Configuration behavior complete
- [x] Unit tests complete
- [x] Integration tests complete
- [x] Packet/compiler tests complete
- [x] Automation and CI-ready checks complete
- [x] Documentation complete

Software Implementation: 100% Complete
Engineering Implementation: 100% Complete
Ready for External Validation: Yes

## External Certification / Deployment

- [ ] FreeRADIUS 3.2.x Linux interoperability for generated
  `NAS-Filter-Rule`, AegisNAS, Cisco, Aruba, HP/ArubaOS-Switch, D-Link, and
  Pica8 ACL attributes.
- [ ] Packet-capture proof for Access-Accept replies containing every
  software-certified compiler output.
- [ ] Cisco switch/WLAN/VPN acceptance for `Cisco-AVPair` `ip:inacl` and
  `ip:outacl` generated grammar.
- [ ] Aruba and HP/ArubaOS-Switch acceptance for `Aruba-NAS-Filter-Rule` and
  `Ip-Filter-Raw`.
- [ ] D-Link and Pica8 device or controller acceptance for downloadable ACL
  profile and rule attributes.
- [ ] MikroTik, Fortinet, Ruckus, Juniper, Huawei, and H3C controller/device
  proof that profile-reference attributes map to existing named policies.
- [ ] Unsupported vendor fail-closed proof for Palo Alto and other packs without
  certified ACL compilers.
- [ ] HA validation that compiler evidence history replicates and support
  bundles from active/standby nodes agree after failover.
- [ ] Upgrade and rollback drill from schema v53 to v54 and back with evidence
  retention policy documented.
- [ ] Performance benchmark for large compile/decompile previews under Lite,
  Branch, and Enterprise hardware profiles.
- [ ] Long-duration soak test with repeated compile/decompile previews and
  support-bundle generation.
- [ ] Security review for diagnostics, fingerprints, actor logging, RBAC, and
  evidence retention.
- [ ] Customer acceptance testing for operator workflow in Vendor Compatibility
  and Access Settings reply preview.

## Evidence To Attach

- FreeRADIUS configtest output and packet captures.
- Vendor model, firmware, and controller version matrix.
- Accepted and rejected packet examples for every certified pack.
- HA failover logs and database replication evidence.
- Performance and soak reports.
- Security review sign-off.
- Production deployment notes and customer acceptance record.
