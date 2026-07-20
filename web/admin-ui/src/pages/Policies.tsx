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

  useEffect(() => {
    let cancelled = false;
    api
      .get("/system/policy-engine")
      .then(({ data }) => {
        if (!cancelled) setReport(data);
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.response?.data || err.message || "Could not load policy engine.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
