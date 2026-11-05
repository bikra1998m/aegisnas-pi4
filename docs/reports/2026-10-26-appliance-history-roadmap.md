# Historical reconciliation and consolidated roadmap — 2026-10-26

The previous archive reconciliation remains authoritative historical evidence:
[streamed archive report](2026-10-15-history-reconciliation.md) and
[recovery addendum](2026-10-26-recovery-history.md). The approximately 534 MiB
archive was not loaded again or used to overwrite newer work. Prior requirements
remain: a network AAA platform, stable NAS feature IDs, dependency-ordered work,
live enforcement evidence distinct from configuration, advisory AI outside
authentication, and hardware-specific qualification.

This continuation found additional disagreement between reference assets and
production expectations: image documentation implied a flashable Core image,
while the model contains placeholder identities and the RADIUS snap uses classic
confinement. Snap recipes also had caller/source-directory assumptions and an
old Go bootstrap channel. Build helpers and documentation were repaired; real
confinement/interface/runtime integration was not invented or marked complete.
Canonical's primary model/confinement/build references are linked in the
[image](../../image/README.md) and [snap](../../snaps/README.md) guides.

The authoritative backlog and implementation sequence still contain 135 features:
**90 recorded Complete, 21 Partial, 24 Missing**. No feature is newly promoted.
The complete row-level dependency/status/remaining-work ledger is attached as
`2026-10-26-appliance-milestones.csv`. Previously Complete labels were not
re-certified merely because this regression suite passed.

| Dependency position | Feature | Current decision |
|---|---|---|
| 4 | NAS-0116 | Partial; first unfinished. Inventory/build work advanced, but strict findings, trusted workflow, full image coverage, coordinated activation/recovery and governance remain |
| 6 | NAS-0008 | Partial; next independent unfinished track. Conversion, coordinated PostgreSQL backups, complete service writes, HA/outage/soak and production acceptance remain |
| 16 | NAS-0099 | Missing; depends on NAS-0008 |
| Telecom NAS-0092..0097 | Live integrations | Partial preserved; persistence/configuration/preview does not certify packet enforcement or hardware |

Unavailable or unqualified prerequisites include a supported isolated Snapcraft/
Core image builder, provisioned real Store/model identities and signing workflow,
Pi firmware/boot certification hardware, external telecom peers/devices, approved
exception/retention governance, and sufficient isolated resources for full image
inventory and stress testing. There is also unfinished software; these milestones
are not described as complete merely awaiting infrastructure.

No GitHub commit or push was performed. Publication remains conditional on
completed milestones and successful required tests; those conditions are not met.
The working tree, prior evidence, historical reports and existing deployment
configuration were preserved. The observed automatic FreeRADIUS restart is
explicitly recorded as an operational failure, not hidden by that preservation claim.
