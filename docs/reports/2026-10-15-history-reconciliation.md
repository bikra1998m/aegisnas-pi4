# Historical context reconciliation — 2026-10-15

**PASS: archive parsed and reconciled without modifying it.** Historical plans and assistant claims are not completion evidence. The current user's preservation, infrastructure and no-push restrictions govern this continuation.

## Provenance and method

Source: `C:\Users\BIKRAM MAITY\.codex\archived_sessions\rollout-2026-04-17T15-42-04-019d9aed-1cd1-7b51-9776-3315b90daf91.jsonl`.

- 560,372,183 bytes; SHA-256 `a50a2633f7670a564524487d9edbe6cc650e7bdfc33f1dd9748e9b6cde4c3361`.
- 169,946 records, from `2026-04-17T10:16:38.007Z` through `2026-10-15T06:40:37.851Z`; zero JSON parse errors.
- Read-only, line-by-line binary parsing and incremental hashing; largest line 2,286,564 bytes. Source metadata remained unchanged.
- 520 user and 13,550 assistant response-message records identified; 821 bounded, redacted messages indexed for targeted review. Duplicated event messages, large tool payloads and repeated requests were not treated as new requirements.
- Reproducibility files: `.tmp/reconcile-20261015/stream_history.py`, `history-index.json`, `history-messages.jsonl`. The extract is local evidence, not a publication artifact. Relevant decisions below cite original one-based archive lines.

This was a full streaming record inventory with targeted semantic review, not a claim that every historical tool-output byte was manually reviewed. Original SVG/HTML/DOCX attachments referenced in April were not independently reopened in this continuation; recovered requirements come from the archive and current repository.

## Requirements reconciled with current implementation

| Historical source | Requirement / decision | Current evidence and reconciliation |
|---|---|---|
| Apr 17, lines 6, 1156, 1651, 2139 | Complete manual administration, staged configuration, rollback/backup, VM installation and start/stop/build scripts; VMware Workstation | README, `docs/architecture.md`, `internal/adminapi`, `web/admin-ui`, Ubuntu scripts and the running VMware guest exist. Earlier browser/API evidence is retained. Complete end-to-end coverage of every operation is **NOT TESTED**; especially do not equate a rollback button with safe signed production recovery. |
| Apr 17, lines 3235, 3498; Apr 21, 8783, 8828 | Product is a **Network Access Server / AAA platform**; external primary/secondary AAA, retry/failover, PAP/MSCHAP/EAP forwarding, accounting, stable session IDs, CoA/Disconnect, policy reply mapping and break-glass behavior | `docs/external-aaa-product-mode.md`, RADIUS/session/policy services, upstream history/telemetry and tests are later implementations. April statements that portal upstream or CoA were still pending are not automatically current gaps. Broad external-vendor interoperability remains certification work; a negative FreeRADIUS PAP check proves only that tested path. |
| Apr 22, lines 8853, 9320, 9400 | Own vendor identity and one central dictionary/typed attribute source | `internal/vendoridentity`, generated registry, dictionary release profiles and installation scripts implement governance. Production IANA PEN assignment and deployment identity evidence remain external gates; lab identity is not production authorization. |
| Apr 22, 9626; Jun 12, 44778; Jun 15–16, 47030/48607 | Low-spec through enterprise appliances, optional full AI, hardware profiles, controller integrations, posture, certificates, observability | `docs/full-ai-engine.md`, `internal/ailite`, `internal/config/profile.go`, `docs/hardware-sizing-and-deployment-matrix.md`, controller adapters and certificate lifecycle code exist. Preserve advisory AI outside the authentication path. Provider credentials, physical appliances and controller labs are not available as broad certification evidence. |
| Jul 7, 57366 | Vendor-superset ambition; dictionary availability must never stand in for packet, policy or enforcement functionality | Current 195-vendor / 7,654-attribute FreeRADIUS 3.2.8 audit is a versioned baseline, not proof of parity with every future vendor release. Preserve NAS-0092…0097 **Partial** where live domain integration is missing. No unsupported “100% vendor parity” claim. |
| Jul 7, 57671 | Each feature needs backend, schema, packets, policy, enforcement, APIs/UI, configuration, monitoring, security, HA, tests and documentation | The 135-row engineering backlog retains this contract. NAS-0116 has real implementation gaps beyond certification: activation/recovery integration, whole-image coverage and exception/SLA/retention governance. NAS-0008 runtime SQL is incomplete despite successful migration tests. |
| Jul 8, 58570 | Stable feature IDs and dependency order, phases 0–15, acceptance and production-readiness criteria | `enterprise-nas-engineering-backlog.csv` and `enterprise-nas-implementation-sequence.csv` are authoritative. First unfinished: NAS-0116 (sequence 4), then NAS-0008 (6), NAS-0099 (16), NAS-0112 (17), NAS-0106 (20). NAS-0008's independent prerequisite NAS-0002 permits bounded compatibility repairs while NAS-0116 remains explicitly open. |
| Jul 8, 59596 and 59602 | Separate software completion from external certification; complete engineering before closing a feature; Conventional Commit required at closure | Retain per-feature certification checklists. External hardware/IANA/customer acceptance alone does not reopen completed software. Missing runtime integration does. Neither NAS-0116 nor NAS-0008 is closed here; no new commit or push was made. Old requests to push/clean up are not revived as authorization. |

## Changed assumptions and conflicts resolved

1. **April pilot readiness versus enterprise release:** early conditional packaging claims do not override later enterprise acceptance criteria or current blocked security gates.
2. **Historical “Complete” versus actual runtime:** successful migrations did not prove PostgreSQL application behavior. New lifecycle tests reproduced boolean, timestamp and ordering failures. They are fixed for this slice; broader NAS-0008 remains Partial. The master roadmap's stale NAS-0008 / Phase 0 checked boxes are corrected in this continuation.
3. **External validation versus missing software:** the July completion-policy revision supersedes the earlier “wait for every external certification” sequencing rule. It does not excuse persistence-only telecom features without the promised runtime behavior.
4. **Platform scope:** architecture describes Ubuntu Core 24 and Ubuntu Server 24.04; the accessible lab is Ubuntu 22.04 on x86-64. Cross-building ARM64 is not Raspberry Pi execution, and a successful lab check is not certification of the stated production OS matrix.
5. **Cleanup/reboot/push instructions:** archived cleanup instructions (for example line 2882), old commit/push requests and the one previously authorized VM recovery do not supersede the current instruction to preserve evidence and avoid new disruptive operations.
6. **Security upgrades:** retain the current Go/dependency and React Router upgrades. Do not restore earlier versions merely to match archived instructions or logs.
7. **Release control surface:** read-only admission state in API/UI is deliberate. The historical desire for complete manual administration does not justify exposing privileged signing or activation through an unreviewed endpoint. Safe activation and recovery remain explicit software gaps.

## Requirements still requiring evidence

Trusted signing and actual tamper rejection; signed recovery/activation with failure compensation; full OS/snap/firmware coverage; PostgreSQL service-wide runtime tests and secure deployment; physical AP/controller and telecom enforcement; real RadSec peers; HA partition/failover and long-duration accounting; production-scale throughput, independent security review and customer acceptance. These retain **BLOCKED** or **NOT TESTED** status rather than being inferred from plans.

See the [current readiness assessment](2026-10-15-reconciliation-readiness.md) for current-session evidence and the complete report index.
