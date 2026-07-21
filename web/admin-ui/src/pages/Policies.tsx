import { useEffect, useState } from "react";
import CrudPage from "../components/CrudPage";
import api from "../api/client";

const compactJSON = (value: unknown) => JSON.stringify(value ?? {}, null, 0);

type PolicyEngineReport = {
  status: string;
  message: string;
  schema_version: number;
  config?: {
    mode: string;
    fail_closed: boolean;
    audit_enabled: boolean;
    allow_legacy_conditions: boolean;
    require_typed_rules: boolean;
  };
  summary?: {
    total_records: number;
    allowed_count: number;
    denied_count: number;
    quarantine_count: number;
    last_decision?: string;
    last_evaluated_at?: string;
  };
  rules?: Array<{
    enabled: boolean;
    typed: boolean;
    legacy: boolean;
    valid: boolean;
  }>;
  fields?: Array<{ name: string; type: string }>;
  operators?: Array<{ name: string }>;
  policy_sets?: {
    status: string;
    message: string;
    summary?: {
      total_versions: number;
      pending_approval_count: number;
      active_version?: number;
      simulation_count: number;
    };
    config?: {
      replay_limit: number;
    };
    analysis_summary?: {
      total_analyses: number;
      last_risk_level?: string;
      last_sample_count: number;
      last_decision_change_count: number;
      last_shadowed_rule_count: number;
      last_ineffective_rule_count: number;
    };
    recent_analyses?: PolicySimulationAnalysis[];
    active?: PolicySetVersion;
    versions?: PolicySetVersion[];
  };
};

type PolicySetVersion = {
  id: number;
  set_key: string;
  version: number;
  status: string;
  description?: string;
  policy_sha256: string;
  rule_count: number;
  child_set_count: number;
  max_depth: number;
  approval_count: number;
  min_approvals: number;
  created_by?: string;
  created_at: string;
  activated_at?: string;
};

type PolicySimulationAnalysis = {
  analysis_id: string;
  version_id: number;
  risk_level: string;
  sample_count: number;
  decision_change_count: number;
  shadowed_rule_count: number;
  ineffective_rule_count: number;
  created_at: string;
};

const typedDefaultExpression = `{
  "all": [
    { "field": "authenticated", "op": "eq", "value": true },
    { "field": "groups", "op": "contains", "value": "employees" },
    { "field": "risk_score", "op": "lte", "value": 50 }
  ]
}`;

function PolicyEnginePanel() {
  const [report, setReport] = useState<PolicyEngineReport | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");

  const loadReport = () => {
    api
      .get("/system/policy-engine")
      .then(({ data }) => {
        setReport(data);
      })
      .catch((err) => {
        setError(err.response?.data || err.message || "Could not load policy engine.");
      });
  };

  useEffect(() => {
    let cancelled = false;
    api
      .get("/system/policy-engine")
      .then(({ data }) => {
        if (!cancelled) setReport(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data || err.message || "Could not load policy engine.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const runVersionAction = async (action: string, version?: PolicySetVersion) => {
    setBusy(version ? `${action}-${version.id}` : action);
    setMessage("");
    try {
      if (action === "create") {
        await api.post("/system/policy-sets/versions", {
          from_current: true,
          description: "Version created from current policy rules.",
          submit: true,
        });
        setMessage("Policy version created and submitted.");
      } else if (version) {
        if (action === "analyze") {
          await api.post(`/system/policy-sets/versions/${version.id}/analyze`, {
            sample_source: "history",
            limit: report?.policy_sets?.config?.replay_limit || 25,
          });
          setMessage(`Policy version ${version.version} analysis completed.`);
        } else {
          await api.post(`/system/policy-sets/versions/${version.id}/${action}`, {
            note: `Policy version ${action}`,
            comment: `Policy version ${action}`,
          });
          setMessage(`Policy version ${version.version} ${action} request completed.`);
        }
      }
      loadReport();
    } catch (err: any) {
      setError(err.response?.data || err.message || "Policy version action failed.");
    } finally {
      setBusy("");
    }
  };

  if (error) {
    return (
      <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
        {error}
      </div>
    );
  }
  if (!report) {
    return (
      <div className="rounded-md border border-gray-200 bg-white px-4 py-3 text-sm text-gray-600">
        Loading policy engine...
      </div>
    );
  }

  const rules = report.rules || [];
  const enabledRules = rules.filter((rule) => rule.enabled);
  const typedRules = enabledRules.filter((rule) => rule.typed && rule.valid).length;
  const legacyRules = enabledRules.filter((rule) => rule.legacy).length;
  const invalidRules = enabledRules.filter((rule) => !rule.valid).length;
  const policySets = report.policy_sets;
  const versions = policySets?.versions || [];
  const analysisSummary = policySets?.analysis_summary;
  const recentAnalyses = policySets?.recent_analyses || [];

  return (
    <div className="space-y-3 rounded-md border border-gray-200 bg-white p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold uppercase text-gray-500">
            Typed Policy Engine
          </div>
          <div className="mt-1 text-lg font-semibold text-gray-900">
            {report.status}
          </div>
          <p className="mt-1 max-w-3xl text-sm text-gray-600">{report.message}</p>
        </div>
        <div className="text-right text-sm text-gray-600">
          <div>Schema {report.schema_version}</div>
          <div>Mode {report.config?.mode || "monitor"}</div>
          <div>{report.config?.fail_closed ? "Fail closed" : "Fail open"}</div>
        </div>
      </div>
      <div className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-md border border-gray-200 p-3">
          <div className="text-gray-500">Enabled Rules</div>
          <div className="text-xl font-semibold">{enabledRules.length}</div>
        </div>
        <div className="rounded-md border border-gray-200 p-3">
          <div className="text-gray-500">Typed</div>
          <div className="text-xl font-semibold">{typedRules}</div>
        </div>
        <div className="rounded-md border border-gray-200 p-3">
          <div className="text-gray-500">Legacy</div>
          <div className="text-xl font-semibold">{legacyRules}</div>
        </div>
        <div className="rounded-md border border-gray-200 p-3">
          <div className="text-gray-500">Invalid</div>
          <div className="text-xl font-semibold">{invalidRules}</div>
        </div>
        <div className="rounded-md border border-gray-200 p-3">
          <div className="text-gray-500">Decisions</div>
          <div className="text-xl font-semibold">{report.summary?.total_records ?? 0}</div>
        </div>
      </div>
      <div className="grid gap-3 text-sm md:grid-cols-3">
        <div>
          Fields: {report.fields?.length ?? 0}
        </div>
        <div>
          Operators: {report.operators?.length ?? 0}
        </div>
        <div>
          Last decision: {report.summary?.last_decision || "none"}
        </div>
      </div>
      {message && (
        <div className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">
          {message}
        </div>
      )}
      <div className="rounded-md border border-gray-200 p-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-semibold uppercase text-gray-500">
              Versioned Policy Sets
            </div>
            <div className="mt-1 text-base font-semibold text-gray-900">
              {policySets?.status || "unknown"}
            </div>
            <p className="mt-1 text-sm text-gray-600">
              {policySets?.message || "Policy set governance has not reported yet."}
            </p>
          </div>
          <button
            type="button"
            onClick={() => void runVersionAction("create")}
            disabled={!!busy}
            className="rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            Create Version
          </button>
        </div>
        <div className="mt-3 grid gap-3 text-sm sm:grid-cols-4">
          <div>Total versions {policySets?.summary?.total_versions ?? 0}</div>
          <div>Active v{policySets?.summary?.active_version ?? "none"}</div>
          <div>Pending {policySets?.summary?.pending_approval_count ?? 0}</div>
          <div>Simulations {policySets?.summary?.simulation_count ?? 0}</div>
        </div>
        <div className="mt-3 grid gap-3 text-sm sm:grid-cols-5">
          <div>Analyses {analysisSummary?.total_analyses ?? 0}</div>
          <div>Risk {analysisSummary?.last_risk_level || "none"}</div>
          <div>Samples {analysisSummary?.last_sample_count ?? 0}</div>
          <div>Changes {analysisSummary?.last_decision_change_count ?? 0}</div>
          <div>
            Shadow {analysisSummary?.last_shadowed_rule_count ?? 0}/
            {analysisSummary?.last_ineffective_rule_count ?? 0}
          </div>
        </div>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-gray-200 text-gray-500">
              <tr>
                <th className="py-2 pr-3">Version</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Rules</th>
                <th className="py-2 pr-3">Approvals</th>
                <th className="py-2 pr-3">Hash</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {versions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-3 text-gray-500">
                    No policy versions yet.
                  </td>
                </tr>
              ) : (
                versions.map((version) => (
                  <tr key={version.id} className="border-b border-gray-100">
                    <td className="py-2 pr-3">v{version.version}</td>
                    <td className="py-2 pr-3">{version.status}</td>
                    <td className="py-2 pr-3">{version.rule_count}</td>
                    <td className="py-2 pr-3">
                      {version.approval_count}/{version.min_approvals}
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs">
                      {version.policy_sha256.slice(0, 12)}
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex flex-wrap gap-2">
                        {version.status === "draft" && (
                          <button type="button" className="rounded-md border border-gray-300 px-2 py-1" disabled={!!busy} onClick={() => void runVersionAction("submit", version)}>Submit</button>
                        )}
                        {(version.status === "pending_approval" || version.status === "approved") && (
                          <button type="button" className="rounded-md border border-gray-300 px-2 py-1" disabled={!!busy} onClick={() => void runVersionAction("approve", version)}>Approve</button>
                        )}
                        {version.status === "approved" && (
                          <button type="button" className="rounded-md bg-gray-900 px-2 py-1 text-white" disabled={!!busy} onClick={() => void runVersionAction("activate", version)}>Activate</button>
                        )}
                        {version.status === "superseded" && (
                          <button type="button" className="rounded-md border border-gray-300 px-2 py-1" disabled={!!busy} onClick={() => void runVersionAction("rollback", version)}>Rollback</button>
                        )}
                        {version.status !== "active" && (
                          <button type="button" className="rounded-md border border-gray-300 px-2 py-1" disabled={!!busy} onClick={() => void runVersionAction("analyze", version)}>Analyze</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {recentAnalyses.length > 0 && (
          <div className="mt-3 rounded-md border border-gray-200 p-3 text-sm">
            <div className="font-semibold text-gray-900">Recent Analysis</div>
            <div className="mt-2 grid gap-2">
              {recentAnalyses.slice(0, 3).map((analysis) => (
                <div key={analysis.analysis_id} className="flex flex-wrap justify-between gap-2 border-b border-gray-100 pb-2 last:border-b-0 last:pb-0">
                  <span className="font-mono text-xs">{analysis.analysis_id}</span>
                  <span>risk {analysis.risk_level}</span>
                  <span>{analysis.decision_change_count}/{analysis.sample_count} changed</span>
                  <span>{analysis.shadowed_rule_count} shadowed</span>
                  <span>{analysis.ineffective_rule_count} ineffective</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function Policies() {
  return (
    <CrudPage
      title="Policies"
      endpoint="/policies"
      itemName="Policy"
      topContent={<PolicyEnginePanel />}
      columns={[
        { key: "name", label: "Name" },
        { key: "priority", label: "Priority" },
        { key: "enabled", label: "Enabled", render: (item) => (item.enabled ? "Yes" : "No") },
        { key: "valid", label: "Valid", render: (item) => (item.valid ? "Yes" : item.validation_error || "No") },
        { key: "typed", label: "Type", render: (item) => (item.typed ? "Typed" : item.legacy ? "Legacy" : "Invalid") },
        { key: "match_conditions", label: "Match", render: (item) => <code>{compactJSON(item.typed_expression || item.match_conditions)}</code> },
        { key: "action", label: "Action" },
        { key: "vlan", label: "VLAN" },
        { key: "acl_policy_name", label: "ACL Policy" },
      ]}
      fields={[
        { name: "name", label: "Name", required: true },
        { name: "description", label: "Description" },
        { name: "priority", label: "Priority", type: "number", defaultValue: 0 },
        { name: "enabled", label: "Enabled", type: "checkbox", defaultValue: true },
        { name: "match_conditions", label: "Typed Match Expression JSON", type: "json", required: true, defaultValue: typedDefaultExpression },
        {
          name: "action",
          label: "Action",
          type: "select",
          required: true,
          defaultValue: "allow",
          options: [
            { value: "allow", label: "Allow" },
            { value: "deny", label: "Deny" },
            { value: "quarantine", label: "Quarantine" },
          ],
        },
        { name: "vlan", label: "VLAN", type: "number" },
        { name: "bandwidth_profile", label: "Bandwidth Profile" },
        { name: "session_timeout", label: "Session Timeout Seconds", type: "number" },
        { name: "idle_timeout", label: "Idle Timeout Seconds", type: "number" },
        { name: "portal_profile", label: "Portal Profile" },
        { name: "acl_policy_name", label: "ACL Policy Name" },
        { name: "quarantine", label: "Quarantine", type: "checkbox" },
      ]}
    />
  );
}
