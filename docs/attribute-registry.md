# Generated Typed Attribute Registry

Feature: `NAS-0002`

Status: engineering implementation complete; ready for external validation.

## Purpose

FreeRADIUS dictionaries define wire names, numbers, types, options, and enumerated values. They do not prove that a NAS can parse an attribute, map it into policy, persist it, enforce it, render it in a reply, or interoperate with a specific device. NAS-0002 provides one versioned typed contract for those distinct concerns and removes packet decoding from the compatibility scanner's separate interpretation.

The pinned FreeRADIUS 3.2.8 source contains 246 dictionary files represented by 7,654 VSA records across 195 namespaces. The effective AegisNAS registry adds seven runtime annotations omitted or classified differently by the source audit and two Ubiquiti runtime extensions, producing 7,661 effective entries across 196 namespaces. It records 148 mapped entries and generates 134 unique packet decoders. A mapped entry remains `partial` unless later evidence work proves full behavior.

RFC 2865 section 5.26 defines Vendor-Specific Attribute type 26 and its PEN/type/length payload. Attribute-specific RFCs apply to standard attributes; vendor dictionaries remain vendor contracts rather than standards. Cisco, Juniper, Aruba, HPE, Huawei, MikroTik, Ubiquiti, Fortinet, Ruckus, Nokia, Ericsson, broadband vendors, mobile namespaces, and every other namespace in the pinned source use the same registry model.

## Architecture

### Generated source

`configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv` is generated from the reviewed audit source. `aegis-attribute-registry-gen` validates the exact schema, bounded input size, row count, file manifest count, and optional SHA-256 before atomically writing it. CI runs the generator in check mode and rejects stale or unreviewed source changes.

The registry exposes:

- schema version, FreeRADIUS release, source file count, source attribute count, and source SHA-256;
- stable entry and wire keys;
- vendor, PEN, name, number or OID, wire type, enum count, and capability family;
- compatibility pack, neutral semantic, directions, dictionary status, and functionality;
- packet decoder kind and rate divisor where executable decoding exists;
- source provenance for upstream and AegisNAS runtime extensions.

Indexes support exact vendor/name and PEN/number lookups. PEN/number lookup returns all aliases because multiple dictionary names may intentionally share one wire identifier.

### Packet processing

Inbound vendor decoding is generated from `AttributeRegistry.RuntimeMappings()`. Pack enablement remains the enforcement gate. The compiler derives ordinary string, integer, VLAN, boolean, and rate codecs and applies explicit annotations for AVPairs, extended VLANs, portal status, session actions, Nokia BCD, and source-audit discrepancies. Unsupported or missing attributes are metadata only and are never executed.

Existing packet tests prove the generated map preserves every pre-registry PEN/type/semantic/codec contract. Product PEN migration continues to use its dynamic AegisNAS dictionary and is not coupled to the pinned third-party release.

### Scanner and policy metadata

The dictionary scanner merges pack declarations with typed registry mappings. Attributes known only to packet processing are no longer reported as ignored. Scan output reports registry mapped and executable decoder counts, but clearly distinguishes mapping from enforcement and device certification. Policy, reply preview, metrics, and later evidence-state work consume registry semantics instead of inferring behavior from attribute names.

### API and UI

`GET /api/v1/system/attribute-registry` is available to authenticated read roles. It supports exact `vendor`, `pen`, `pack`, `semantic`, and `status` filters, case-insensitive `search`, `limit` from 1 to 500, and an opaque `cursor`. Cursors bind the source hash and normalized filters; stale, malformed, cross-filter, and out-of-range cursors are rejected.

The Vendor Compatibility page displays provenance, counts, filters, wire identifiers, types, directions, semantics, decoder kinds, and incremental pages. The interface states that mapping is not certification.

### Database and HA

NAS-0002 adds no database migration. Registry data is immutable, generated at build time, content-addressed, and identical on every node running the same binary. Persisting 7,661 duplicate rows in SQLite would introduce mutable HA state without adding authority. Runtime configuration and evidence records reference stable registry keys and hashes; later dictionary-release profile work owns activation history and upgrade profiles.

HA nodes must run binaries with the same registry source hash. The production readiness endpoint validates the embedded contract and exposes its hash, allowing deployment automation to reject a mixed-registry cluster.

### Security and limits

- The runtime registry is embedded and cannot be replaced through the API or UI.
- Generation reads at most 32 MiB and validates every row and wire type.
- Duplicate vendor/name keys, malformed PENs, numbers, OIDs, statuses, and headers fail closed.
- API pages are capped at 500 rows and filter text at 200 characters.
- Cursors are opaque, source-bound, filter-bound, and bounds checked.
- Dictionary metadata never causes execution unless an explicit decoder annotation exists and its compatibility pack is active.

### Monitoring and logging

Production readiness reports an `attribute_registry` check with release, schema, source count, and SHA-256. The API reports source/effective/mapped/filter counts. Registry reads are side-effect free and do not log attribute values or user data.

## Generation and verification

Regenerate after reviewing an updated source audit:

```bash
go generate ./configs
```

Verify the pinned 3.2.8 artifact:

```bash
make test-attribute-registry
```

Any upstream release change must use a new reviewed source artifact and update the expected release, file count, row count, and SHA-256 in one commit. Do not overwrite the existing artifact with an unreviewed installed dictionary tree.

## Test coverage

Automated coverage includes source contract and SHA validation, duplicate/malformed rejection, name and wire alias indexes, runtime codec derivation, atomic generation, size bounds, pre-registry packet-contract preservation, scanner reconciliation, API filtering and cursor pagination, RBAC/OpenAPI, production readiness, TypeScript build, mock API behavior, and browser filtering.

External interoperability, sustained performance, physical hardware, HA deployment, and security review are tracked in the [NAS-0002 Release Certification Checklist](nas-0002-release-certification-checklist.md). They gate certification, not engineering completion.

## Completion report

| Measure | Result |
|---|---:|
| Software Implementation | 100% Complete |
| Engineering Implementation | 100% Complete |
| Ready for External Validation | Yes |
| NAS-0002 status | Closed |

There is no remaining NAS-0002 software implementation work. Dictionary release aliases and firmware profiles were completed by NAS-0003; independent evidence states belong to NAS-0004; extended/grouped/tagged wire formats belong to NAS-0005.

The active registry entries include `release_profile_id` and `semantic_provenance`, and release aliases plus firmware scopes are documented in [dictionary-release-profiles.md](dictionary-release-profiles.md).
