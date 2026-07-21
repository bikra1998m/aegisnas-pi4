# Policy Simulation, Conflict, And Shadow Analysis

NAS-0031 adds replay-based analysis for candidate policy-set versions. It
answers the operator question that matters before activation: what would this
candidate change for recent or supplied policy requests?

## What It Solves

Single-request simulation is useful for debugging, but it does not show blast
radius. NAS-0031 compares a candidate policy-set version against the active
baseline over retained replay samples or explicit manual samples and reports:

- decision changes
- allow-to-deny and deny-to-allow counts
- quarantine, VLAN, bandwidth, ACL, portal, and timeout changes
- candidate conflict counts
- invalid candidate rule counts
- rules that never match replay samples
- rules that match but do not affect final decisions
- risk level and activation recommendation

Risk is classified as `unknown`, `low`, `medium`, `high`, or `critical`.
Deny-to-allow changes, conflicts, or broad blast radius produce critical risk.
Allow-to-deny and quarantine changes produce high or critical risk depending on
sample impact.

## APIs

```text
POST /api/v1/system/policy-sets/versions/{id}/analyze
GET  /api/v1/system/policy-sets/analyses
```

Example analysis request using retained history:

```json
{
  "sample_source": "history",
  "limit": 100,
  "include_trace": false
}
```

Example analysis request with explicit samples:

```json
{
  "sample_source": "manual",
  "requests": [
    {
      "authenticated": true,
      "groups": ["employees"],
      "tenant": "corp",
      "ssid": "CorpWiFi",
      "risk_score": 40
    }
  ]
}
```

`sample_source` may be `history`, `manual`, or `mixed`.

## Replay Safety

Policy evaluation audit records store redacted username and calling-station
hashes separately. The replay snapshot intentionally omits `username` and
`calling_station_id`. It preserves bounded policy facts required for replay,
including groups, tenant, realm, SSID, NAS facts, VLAN, posture, risk score,
and sanitized custom attributes.

Custom replay attributes are bounded and keys containing sensitive markers such
as password, secret, token, credential, key, MSCHAP, challenge, response, cert,
or cookie are excluded.

## Storage

Schema v36 adds:

- `policy_engine_evaluations.request_replay_json`
- `policy_simulation_analyses`

`policy_simulation_analyses` stores the analysis ID, candidate version, active
version, policy hashes, sample source, blast-radius counters, risk level,
summary JSON, and full result JSON. Retention is bounded by
`policy.simulation_retention_limit`.

## Configuration

```yaml
policy:
  simulation_replay_limit: 100
  simulation_retention_limit: 1000
```

`simulation_replay_limit` bounds retained history replay in one analysis.
`simulation_retention_limit` bounds stored analysis reports.

## Operations

Before activating a candidate version:

1. Create and submit the candidate policy-set version.
2. Run `/api/v1/system/policy-sets/versions/{id}/analyze`.
3. Review risk level, decision deltas, shadowed rules, and ineffective rules.
4. Resolve critical or high-risk findings or document the approved blast radius.
5. Attach external lab evidence through the NAS-0031 release certification checklist.

Evidence appears in:

- `/api/v1/system/policy-sets`
- `/api/v1/system/policy-sets/analyses`
- `/api/v1/system/status` under `radius.policy_simulation_analyses`
- production readiness key `policy_simulation_analysis`
- support bundle capture `api/policy-simulation-analyses.json`
- Policies and Dashboard UI cards

## External Certification

Software implementation is complete when automated tests, API/UI, migrations,
and documentation pass. Real FreeRADIUS replay, AP/controller smoke tests,
HA validation, performance, soak, security review, and customer acceptance are
tracked in `nas-0031-release-certification-checklist.md`.
