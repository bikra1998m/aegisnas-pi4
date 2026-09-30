# NAS-0082 Release Certification Checklist

Engineering implementation is complete when software, tests, documentation, API, UI, configuration, and CI are finished. The items below require physical hardware, third-party devices, production-like networks, or external release approval.

## External Validation

- [ ] IANA/vendor identity claims verified against current release metadata.
- [ ] FreeRADIUS interoperability test on production Linux with generated dictionaries and NAS-0082 APIs.
- [ ] Cisco BNG/ASR PPPoE session smoke test.
- [ ] Juniper ERX/E-Series PPPoE session smoke test.
- [ ] Huawei BRAS/BNG PPPoE session smoke test.
- [ ] Nokia/Alcatel-Lucent SR OS PPPoE session smoke test.
- [ ] MikroTik RouterOS PPPoE access concentrator smoke test.
- [ ] H3C and ZTE broadband dictionary attribute smoke tests.
- [ ] DSLAM/OLT/ONT or equivalent access-node discovery relay test.

## Packet Evidence

- [ ] PADI/PADO/PADR/PADS/PADT packet captures.
- [ ] PPP LCP negotiation capture.
- [ ] PAP and CHAP authentication captures.
- [ ] IPCP IPv4 address assignment capture.
- [ ] IPv6CP and delegated prefix capture.
- [ ] RADIUS Access-Request, Access-Accept, Accounting-Start, Interim-Update, Stop captures.
- [ ] CoA and Disconnect capture with positive and negative cases.

## Operations Evidence

- [ ] HA active/standby failover with active PPPoE sessions.
- [ ] Restart/upgrade/rollback test with session accounting reconciliation.
- [ ] Scale benchmark for configured session count and per-MAC limits.
- [ ] Long-duration soak with accounting, CoA, address pools, route export, QoS, and NAT.
- [ ] Security audit of access interface exposure and management isolation.
- [ ] Support bundle containing `api/pppoe-access-lifecycle.json` and `api/pppoe-access-lifecycle-history.json`.
- [ ] Customer acceptance test for target deployment profile.

## Release Sign-Off

- [ ] Exact hardware model, NIC driver, kernel, firmware, vendor product, and version matrix attached.
- [ ] Waivers documented for unsupported vendor modes or hardware variants.
- [ ] Production deployment runbook reviewed.
- [ ] No unresolved Critical defects.
