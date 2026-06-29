# Hardware Sizing And Deployment Matrix

This document helps you choose the right AegisNAS product tier for customer deployments, internal labs, and appliance builds.

Use it together with:

- [Ubuntu Appliance Deployment](ubuntu-appliance-deployment.md)
- [Deployment Profiles](deployment-profiles.md)
- [Feature Capability Framework](feature-capability-framework.md)
- [Wireless Access And UI Guide](wireless-access-ui-guide.md)
- [External AAA Product Mode](external-aaa-product-mode.md)

## What This Matrix Covers

AegisNAS is a Network Access Server and AAA edge appliance. In this repo, that means:

- gateway and captive portal
- FreeRADIUS broker and upstream AAA integration
- LDAP-backed auth flows
- session tracking, CoA, disconnect handling, and policy enforcement
- admin UI and manual operator workflows

It does not size storage NAS features such as Samba, NFS, ZFS, RAID, or share hosting. If you add those later on the same box, size the hardware above the guidance in this document.

## Sizing Drivers

The main things that change hardware needs are:

1. number of concurrent clients
2. number of APs, switches, or RADIUS clients talking to the appliance
3. auth method mix:
   - captive portal and vouchers are lighter
   - PAP and LDAP are moderate
   - PEAP, TTLS, and especially EAP-TLS are heavier
4. whether live per-session bandwidth shaping is enabled
5. whether the appliance also runs the Wi-Fi radio locally through `hostapd`
6. how much logging, backup retention, and telemetry history you keep
7. whether full AI analysis runs against a local or nearby OpenAI-compatible model endpoint

## Quick Recommendation Table

| Tier | Form | Typical Hardware | Best For | Notes |
| --- | --- | --- | --- | --- |
| Tier 0 | Lab VM | 2 vCPU, 4 GB RAM, 40 GB SSD, 2 vNICs | demos, QA, trials, training | use external APs or switches; no local Wi-Fi radio unless passthrough is available |
| Tier 1 | Low-power appliance | 4 ARM64 cores or 2-4 x86 cores, 4-8 GB RAM, 64 GB SSD, 2 NICs | home lab, micro branch, pilot edge site | good fit for Raspberry Pi 4 class or small mini-PC hardware |
| Tier 2 | Standard branch appliance | 4 x86 cores, 8 GB RAM, 120 GB SSD, 2 Intel/Realtek NICs | branch office, school, retail, SMB | recommended default production tier |
| Tier 3 | High-capacity edge appliance | 8+ cores, 16-32 GB RAM, 240+ GB SSD, 2-4 server-grade NICs | many APs, heavier EAP, larger policy load | best fit when shaping, AAA proxying, and multi-SSID policy all run together |
| Tier 4 | Central VM appliance | 4-8 vCPU, 8-16 GB RAM, 120+ GB SSD, 2 vNICs | central AAA, lab core, virtual edge gateway | strong option for VMware, Hyper-V, Proxmox, or KVM |

## Configured Scaling Modes

The product also uses declared hardware hints to choose an operational scaling mode. Set these in YAML or Access Settings:

```yaml
deployment:
  hardware:
    memory_mb: 4096
    cpu_cores: 2
    storage_gb: 32
```

| Scaling mode | Selection rule | Best match |
| --- | --- | --- |
| `lite` | below branch floor, or unknown CPU/RAM | Tier 0, constrained Tier 1 |
| `branch` | 2 cores, 4096 MB RAM, and unknown or at least 32 GB storage | Tier 1, Tier 2, smaller Tier 4 |
| `enterprise` | 4 cores, 8192 MB RAM, and unknown or at least 64 GB storage | Tier 3, larger Tier 4 |

The scaling mode does not replace the selected deployment profile. It protects the appliance when the selected profile is too ambitious for the declared box by shortening retention targets and gating heavyweight features such as posture, MDM sync, HA failover, multi-tenant governance, certificate enrollment, and controller automation. Declare `storage_gb` on production systems so long-retention guidance reflects real disk headroom.

## Detailed Product Tiers

### Tier 0: Lab VM

Use this tier when you want:

- demo environments
- developer and QA testing
- customer proof-of-concept rollouts
- easy snapshot and rollback behavior

Recommended baseline:

- 2 vCPU
- 4 GB RAM
- 40 GB SSD
- 2 vNICs

Recommended mode:

- use AegisNAS as gateway, portal, RADIUS, and AAA broker
- use external APs or switches for actual client attachment
- keep `wireless.enabled: false` if the VM does not have real Wi-Fi passthrough
- set `deployment.hardware.wireless_passthrough: true` only when a real USB or PCI radio is attached to the VM

Good fit:

- captive portal validation
- upstream RADIUS integration tests
- admin UI operation and manual workflow testing
- guest workflow rehearsals, including self-registration and sponsor approval when transport is configured
- onboarding and profiling smoke tests with device inventory enabled and runtime scope kept small
- SIEM export, controller automation, and admin SSO smoke tests when integrations are enabled one at a time

Less ideal for:

- high user counts
- local `hostapd` radio operation
- heavy live shaping across many concurrent clients

### Tier 1: Low-Power Appliance

Use this tier when you want:

- compact branch deployment
- low power draw
- small office or lab edge control
- appliance delivery on affordable hardware

Recommended baseline:

- Raspberry Pi 4 class ARM64 hardware or similar
- 4 cores
- 4-8 GB RAM
- 64 GB SSD or reliable USB-attached SSD
- 2 NICs, or 1 NIC plus VLAN trunking if the design is carefully planned

Recommended mode:

- portal plus local users, vouchers, or LDAP
- modest upstream AAA usage
- modest AP count
- moderate session volume

Good fit:

- guest Wi-Fi with captive portal
- a few APs or a small downstream switch
- branch deployments with light to moderate enterprise auth
- device inventory and internal-onboarding pilot work without heavy posture pressure
- lighter SIEM export and guest approval workflows
- keep authoritative MDM sync, controller automation at scale, and multi-tenant governance off unless the deployment is intentionally stepped up

Important notes:

- prefer SSD over SD card for runtime stability
- EAP-TLS and heavy shaping will consume more CPU than captive portal or PAP
- if using local Wi-Fi broadcasting, make sure the radio and driver are supported by Ubuntu and `hostapd`

### Tier 2: Standard Branch Appliance

This is the recommended default production tier.

This is also the first tier where guest self-registration and sponsor approval should be treated as normal production features, provided SMTP or SMS delivery is configured and tested.

This is also the first tier where device inventory, onboarding portal pilots, and passive profiling should be considered normal production-adjacent features, as long as certificate enrollment and posture remain off unless the site is intentionally moving into enterprise-grade onboarding.

This is also the first tier where SIEM export, controller automation, and lighter admin SSO or delegated-admin workflows are reasonable production goals.

Recommended baseline:

- 4 x86 cores
- 8 GB RAM
- 120 GB SSD
- 2 stable Linux-supported NICs

Recommended mode:

- mixed captive portal and enterprise SSIDs
- LDAP and upstream AAA in normal branch volumes
- live runtime shaping enabled where needed
- local admin UI and day-two operations on-box

Good fit:

- branch office
- school or campus edge zone
- hotel, retail, or hospitality deployments
- multi-SSID environments with guest and staff separation
- pilot BYOD registration and light passive profiling
- SIEM export and controller-linked branch automation

This is the safest place to start if you are packaging the product for pilot production and do not yet know the final customer profile.

### Tier 3: High-Capacity Edge Appliance

Use this tier when you expect:

- larger AP counts
- more concurrent authenticated users
- more frequent CoA and policy changes
- heavier EAP usage
- more extensive live bandwidth shaping
- enterprise onboarding, certificate handling, and posture-driven access decisions
- authoritative MDM or UEM sync and delegated multi-admin operations

Recommended baseline:

- 8 or more modern CPU cores
- 16-32 GB RAM
- 240+ GB SSD
- 2-4 server-grade NICs

Recommended mode:

- external APs or switches feed the appliance
- upstream AAA is active
- accounting and policy enforcement remain local
- full AI mode can be enabled for richer operator recommendations
- certificate enrollment and EAP-TLS onboarding can be enabled once CA material is ready
- passive profiling and posture checks can be treated as real production features
- admin SSO, delegated admin, and multi-tenant governance can be treated as real production features
- controller automation can be used for larger external AP estates
- operator teams use the admin UI and config revision flow regularly

Good fit:

- high-density branch edge
- larger educational or enterprise floor deployments
- environments with more demanding AAA behavior and longer retention expectations
- sites that need BYOD inventory, certificate onboarding, and compliance-aware policy

### Tier 4: Central VM Appliance

Use this when you want a virtual appliance product in:

- VMware
- Hyper-V
- Proxmox
- KVM

Recommended baseline:

- 4-8 vCPU
- 8-16 GB RAM
- 120+ GB SSD
- 2 vNICs

Recommended mode:

- external APs and switches send RADIUS and client traffic to the VM appliance
- AegisNAS handles portal, brokered AAA, accounting, policy, and admin workflows
- local Wi-Fi broadcasting stays off unless PCI or USB radio passthrough is provided
- certificate enrollment and posture should be reserved for enterprise-sized VMs with real integration dependencies in place
- admin SSO, SIEM export, and controller automation work well here when the VM has enough headroom and the downstream estate is controller-managed

Good fit:

- customer trial image
- central policy node
- VM-based edge deployments
- easy export, clone, snapshot, and rollback

## Deployment Form Matrix

| Deployment Form | Supported | Recommended | Notes |
| --- | --- | --- | --- |
| Physical appliance with 2 wired NICs | Yes | Yes | best default for real edge deployments |
| Physical appliance with VLAN trunking | Yes | Yes, with care | make sure switch design and VLAN model are clean |
| Physical appliance with local Wi-Fi radio | Yes | Yes, on supported hardware | requires a Ubuntu and `hostapd` compatible radio |
| VM with external APs | Yes | Yes | strongest VM pattern |
| VM with local Wi-Fi SSID broadcasting via plain virtual NIC | No | No | virtual NICs are not real radios |
| VM with USB or PCI Wi-Fi passthrough | Yes | Conditional | depends on hypervisor and hardware support |

## Authentication Mode Guidance

| Auth Mode | Relative Load | Best Tier Starting Point | Notes |
| --- | --- | --- | --- |
| Captive portal with local users | Low | Tier 0 or Tier 1 | easiest place to start |
| Captive portal with vouchers | Low | Tier 0 or Tier 1 | very good on low-power hardware |
| Captive portal with LDAP | Moderate | Tier 1 or Tier 2 | LDAP latency matters as much as local CPU |
| Portal through brokered RADIUS | Moderate | Tier 1 or Tier 2 | good fit for external AAA integration |
| WPA2/WPA3 Enterprise with PEAP or TTLS | Moderate to high | Tier 2 | common production baseline |
| EAP-TLS heavy environments | High | Tier 2 or Tier 3 | certificate-heavy auth deserves more CPU headroom |
| BYOD onboarding with certificate enrollment | High | Tier 3 or Tier 4 | needs CA material, stronger EAP settings, and more operator care |
| Passive profiling with posture inputs | Moderate to high | Tier 3 or Tier 4 | integration-heavy and best treated as enterprise scope |
| Controller-managed Wi-Fi automation | Moderate to high | Tier 2 or Tier 4 | best when the appliance follows the external AP model |
| Admin SSO, delegated admin, and SIEM export | Moderate | Tier 2 or Tier 4 | integration-heavy, but reasonable on production branch and central VM tiers |

## Radio And Wi-Fi Notes

For real SSID broadcasting:

- physical appliance deployments can run `hostapd` locally
- VM deployments should usually use external APs
- low-power hardware can still work well if the Wi-Fi chipset has stable Ubuntu support

For the most predictable product behavior:

- use AegisNAS as the control plane and policy engine
- use external APs if you want broad hardware compatibility
- reserve local `hostapd` mode for appliance SKUs where you control the wireless hardware

## Headroom Guidance

Choose the next higher tier when any of these are true:

- you expect rapid customer growth and do not want to replatform soon
- you are enabling live bandwidth shaping for most sessions
- you are relying heavily on EAP enterprise auth
- you want to enable certificate enrollment, EAP-TLS onboarding, or posture checks
- you want authoritative MDM sync, delegated admin, or multi-tenant governance
- the appliance will service multiple APs and many simultaneous clients
- you want longer backup, telemetry, and audit retention on-box
- the same unit may later host storage NAS features alongside AegisNAS

## Recommended Product SKUs

If you want simple commercial packaging, these product shapes are a good starting point:

### AegisNAS Starter

- Tier 1
- guest portal, vouchers, LDAP-capable branch appliance
- good for labs, cafes, small offices, and pilot installs

### AegisNAS Branch

- Tier 2
- default production edge appliance
- supports mixed guest and staff access, upstream AAA, and shaping

### AegisNAS Enterprise Edge

- Tier 3
- for heavier enterprise auth and larger AP counts
- best for more demanding production sites

### AegisNAS Virtual

- Tier 0 or Tier 4 depending on scale
- packaged as VMware, Hyper-V, Proxmox, or KVM appliance
- best with external APs and switches

## Practical Decision Guide

Choose:

- Tier 0 if you need a lab or proof-of-concept VM
- Tier 1 if you need the lowest-cost physical edge appliance
- Tier 2 if you want the default production recommendation
- Tier 3 if you expect heavier enterprise auth or more client density
- Tier 4 if you want a virtual product image with stronger shared infrastructure

If you are unsure, start with Tier 2. It is the most forgiving balance of cost, performance, and deployment flexibility.
