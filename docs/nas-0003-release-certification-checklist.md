# NAS-0003 Release Certification Checklist

NAS-0003 software implementation is complete. The items below require external environments, real firmware, third-party releases, lab hardware, or production deployment evidence. They do not block development of NAS-0004.

## FreeRADIUS Release Verification

- [ ] Rebuild the registry from a clean FreeRADIUS 3.2.8 source package on the target production Linux distribution.
- [ ] Compare source file count, VSA record count, and SHA-256 with the embedded release profile.
- [ ] Confirm vendor aliases do not hide duplicate or conflicting dictionary namespaces.
- [ ] Archive source package metadata, generation logs, and registry diff evidence.

## Firmware And Hardware Scope

- [ ] Test RouterOS firmware releases declared under `mikrotik-routeros`.
- [ ] Test UniFi Network controller and AP firmware declared under `ubiquiti-unifi-network`.
- [ ] Test ArubaOS controller/AP firmware declared under `aruba-aos-controller`.
- [ ] Test Cisco IOS/IOS-XE switch or controller firmware declared under `cisco-ios-xe`.
- [ ] Test Junos releases declared under `juniper-junos`.
- [ ] Test H3C/Huawei Comware releases declared under `huawei-h3c-comware`.
- [ ] Test TP-Link Omada controller/AP firmware declared under `tplink-omada`.
- [ ] Test Nokia SR OS releases declared under `nokia-sros`.
- [ ] Test TIP OpenWiFi gateway and AP firmware declared under `openwifi-tip`.

## HA And Upgrade Evidence

- [ ] Verify every HA node reports the same `dictionary_release_profile.id` and registry SHA-256.
- [ ] Perform old-build to new-build upgrade with the release profile endpoint sampled before and after restart.
- [ ] Rehearse rollback to the previous build and confirm unknown release IDs fail closed.
- [ ] Archive API responses, service logs, and upgrade/rollback transcripts.

## Security And Operations

- [ ] Confirm release profile APIs are read-only for all non-superadmin roles and unavailable without authentication.
- [ ] Confirm support bundles include release profile evidence without exposing secrets.
- [ ] Review operator documentation with release engineering and support.
- [ ] Record customer acceptance evidence for the firmware profiles enabled in the deployment.
