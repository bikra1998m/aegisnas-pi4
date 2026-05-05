# Edge Network Operations Guide

Use this guide for the day-two network workflow in `Access Settings` when you are changing:

- managed interfaces
- upstream gateways
- static routes
- DNS upstreams and search domains
- DHCP reservations
- firewall rules, DoS controls, and free sites

This guide covers the new safety flow around:

- `Preview Edge Network`
- risky-change confirmation
- post-apply validation
- rollback snapshots
- lease history
- network apply history

## Normal Operator Flow

The intended operator flow is:

1. edit the network-related settings in `Access Settings`
2. click `Save Settings`
3. click `Preview Edge Network`
4. review the saved-config delta, generated dnsmasq and firewall state, and risk banner
5. if the preview is acceptable, click `Apply Edge Network`
6. review the post-apply validation result
7. confirm the new state and history entries look correct
8. if needed, use `Rollback Edge Network`

The preview always reflects the last saved appliance config, not unsaved browser edits.

## Preview Edge Network

`Preview Edge Network` shows:

- saved config delta
- DNS and DHCP preview state
- rollback safety-net count
- change summary for interfaces, gateways, and routes
- rollback snapshot list
- network apply history

Operators should preview before every production-facing apply, especially when WAN, LAN, gateway, or route objects changed.

## Risky-Change Confirmation

Some changes now require an explicit typed confirmation before apply.

The admin UI will lock the apply button until the operator types the confirmation phrase exactly.

Confirmation is required when the saved config changes primary connectivity, including:

- primary LAN address changes
- primary static WAN address changes
- default gateway changes

The risk panel also shows warning-only changes such as:

- managed interface removals
- gateway removals
- static route removals

Treat the confirmation prompt as a pause point, not a nuisance. It is there to catch the kind of change that can strand your management session.

## Apply Validation

`Apply Edge Network` now does more than just write config:

1. captures a rollback snapshot first
2. builds dnsmasq and firewall content before touching live state
3. applies managed network changes
4. restarts or reapplies managed services
5. runs local post-apply validation

Post-apply validation checks:

- managed interface state
- gateway and route state
- `dnsmasq` service health
- local daemon health endpoints such as:
  - `aegis-gateway`
  - `aegis-admin-api`
  - `aegis-portal`

The admin UI records the last validation result and shows each check as passed or failed.

## Automatic Rollback

If the apply fails after the rollback snapshot is captured, AegisNAS attempts to restore the previous managed network state automatically.

This rollback restores the state AegisNAS manages:

- interfaces and managed addresses
- gateways
- static routes
- dnsmasq state
- firewall ruleset

It does not promise to restore arbitrary manual Linux changes outside the product.

## Rollback Snapshots

Every successful or attempted apply creates a snapshot before touching the live network state.

The rollback list in `Access Settings` shows:

- snapshot ID
- creation time
- actor
- reason
- object counts

Use `Rollback Edge Network` when:

- a newly applied network change behaves incorrectly
- you want to return to the last known-good appliance state
- you are rehearsing rollback drills in a lab

## Lease History And Apply History

The `Access Settings` page now tracks two useful history streams.

### DHCP Lease History

The lease report shows the live `dnsmasq` lease table.

The history table stores lease observations, including:

- observed time
- IP
- MAC
- hostname
- reservation status
- active or expired state

At the moment, lease history is captured when the report is loaded or refreshed.

### Network Apply History

The network apply history table records:

- action type such as `apply` or `rollback`
- status
- summary
- backup ID
- rollback ID
- actor
- timestamp

Use this table for operator audit and after-action review.

## Safe Production Checklist

Before applying edge-network changes in production:

1. verify you still have console or hypervisor access
2. export a config backup
3. confirm rollback snapshots already exist or note that the first apply will create one
4. preview the change
5. read the risk banner
6. if confirmation is required, double-check WAN, LAN, and gateway intent
7. apply during a maintenance window when possible
8. confirm the validation result is healthy
9. review lease and apply history after the change

## Lab Drill: Manual Rollback Rehearsal

Use this drill to practice a normal rollback without intentionally breaking services.

1. make a small benign change such as:
   - add a DNS search domain
   - add a free-site domain
   - add a DHCP reservation for a lab client
2. save settings
3. preview the edge network
4. apply the change
5. confirm validation passes
6. record the new rollback snapshot ID
7. click `Rollback Edge Network`
8. confirm the previous state returns and a rollback history row is created

## Lab Drill: Controlled Failure And Automatic Rollback

Only run this in a lab or isolated VM.

This drill deliberately causes `dnsmasq` restart failure so the new auto-rollback path is exercised.

1. open a VM console session first
2. mask `dnsmasq`

```bash
sudo systemctl mask dnsmasq
```

3. in `Access Settings`, make a benign network change and save it
4. click `Preview Edge Network`
5. click `Apply Edge Network`
6. expect the apply to fail and the UI to report automatic rollback
7. unmask and restart `dnsmasq`

```bash
sudo systemctl unmask dnsmasq
sudo systemctl restart dnsmasq aegis-gateway aegis-admin-api
```

8. refresh the network apply history and confirm the failed apply plus rollback evidence are present

## Related Guides

- [Operations Guide](operations.md)
- [Ubuntu VM Deployment And Full Flow Test Runbook](ubuntu-vm-runbook.md)
- [VMware Workstation 17 Player Full Product Runbook](vmware-workstation-17-player-full-test.md)
