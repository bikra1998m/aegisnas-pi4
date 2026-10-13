# NAS-0095 Release Certification Checklist

NAS-0095 software implementation is complete. This checklist tracks work that requires external systems, physical devices, production environments, or independent release sign-off.

## Software Completion

- Software Implementation: 100% Complete
- Engineering Implementation: 100% Complete
- Ready for External Validation: Yes
- Feature ID: NAS-0095
- Feature: PCRF/PCF-style policy, QoS, and roaming

## Release Certification

- [ ] Validate with production FreeRADIUS on Linux using packet captures for Access-Accept, Accounting, CoA, and Disconnect flows.
- [ ] Validate 3GPP PCRF/PCF/PCEF behavior with a carrier packet-core simulator or lab core.
- [ ] Validate Starent/Cisco ASR policy and QoS attributes against documented firmware scope.
- [ ] Validate Ericsson/Redback and Ericsson packet-core policy attributes against documented firmware scope.
- [ ] Validate WiMAX ASN gateway QoS and service-flow policy behavior against documented firmware scope.
- [ ] Validate roaming home/visited policy, MCC-MNC matching, local-breakout behavior, and steering outcomes with a roaming lab or clearinghouse simulator.
- [ ] Validate quota-threshold and roaming feedback CoA behavior with real NAS devices.
- [ ] Validate HA replay of `mobile_policy_control_events` and `mobile_policy_control_profiles`.
- [ ] Run scale, failover, soak, and rollback tests with signed evidence.
- [ ] Complete security review for subscriber privacy, redaction, hashed identity evidence, secrets, logs, and support-bundle export.
- [ ] Record customer acceptance evidence and exact vendor/product/firmware scope.

## Exit Criteria

- All external evidence is attached to the release record.
- No unresolved Critical defects remain.
- Compatibility claims list exact vendor, product, firmware, dictionary, and test date.
