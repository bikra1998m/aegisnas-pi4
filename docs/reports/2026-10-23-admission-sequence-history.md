# Historical context reconciliation - admission continuation

The original streaming archive reconciliation was reused, not restarted. Its recorded archive size is 560,372,183 bytes with SHA-256 `a50a2633f7670a564524487d9edbe6cc650e7bdfc33f1dd9748e9b6cde4c3361`; the earlier October 23 continuation rechecked that checksum read-only. No new full archive parsing or checksum execution is claimed here. The original [reconciliation](2026-10-15-history-reconciliation.md) and [October 23 history](2026-10-23-continuation-history.md) remain preserved.

This continuation verified **166 preceding October 23 raw artifacts** and **66 inherited report files** against their recorded/baseline hashes. All 904 previously tested Go/dependency inputs remain unchanged. Earlier successful and failed attempts were retained, as were all inherited working-tree changes.

New gap found: admission only checked an externally supplied minimum sequence; it did not remember the last verified archive across invocations. A later lowered policy could therefore authorize a downgrade. Persistent reservation now closes that gap. Changed operational assumption: the old runbook's reviewed floor-lowering rollback is no longer sufficient or supported. Recovery must move forward to a separately reviewed signed candidate with a higher sequence, and authenticated DB/config rollback is still unfinished. This is a documented security hardening, not blind application of historical instructions.

Requirements retained: AAA/NAS appliance scope; canonical dependency order; no hardware/enforcement claim from config/persistence alone; no fabricated signature/certification; conservative Go/OS gates; distinct SQLite/PostgreSQL behavior; production secrecy and non-disruptive testing. No telecom Partial classification was promoted. Recorded Complete milestones remain historical engineering assertions pending their own live certification evidence.

The current tests are a new admission-only epoch. October 15, October 22 and the earlier October 23 Go/browser/PG results remain separate; counts were not summed or re-described as fresh executions.
