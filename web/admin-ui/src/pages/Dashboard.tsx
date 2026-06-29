import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api/client";

type ServiceStatus = {
  key: string;
  label: string;
  kind: string;
  status: string;
  message: string;
  port?: number;
  url?: string;
};

type RuntimeStatus = {
  status?: string;
  message?: string;
  details?: Record<string, any>;
  updated_at?: string;
};

type VendorObservability = {
  status?: string;
  message?: string;
  summary?: {
    total_vendors: number;
    auth_success_count: number;
    auth_failure_count: number;
    vsa_parsed_count: number;
    vsa_parse_failure_count: number;
    unsupported_attribute_count: number;
    coa_success_count: number;
    coa_failure_count: number;
    disconnect_success_count: number;
    disconnect_failure_count: number;
    compatibility_score: number;
    worst_vendor_key?: string;
    last_event_at?: string;
  };
  vendors?: Array<{
    vendor_key: string;
    nas_type: string;
    auth_success_count: number;
    auth_failure_count: number;
    vsa_parsed_count: number;
    vsa_parse_failure_count: number;
    unsupported_attribute_count: number;
    coa_success_count: number;
    coa_failure_count: number;
    disconnect_success_count: number;
    disconnect_failure_count: number;
    compatibility_score: number;
    last_message?: string;
    last_event_at?: string;
  }>;
};

type UpstreamServerStatus = {
  name: string;
  address: string;
  auth_port: number;
  acct_port: number;
  status: string;
  message: string;
  response_code?: string;
  latency_ms?: number;
  checked_at?: string;
  supports_status_server: boolean;
};

type DeploymentCapability = {
  key: string;
  label: string;
  state: "enabled" | "available" | "warned" | "degraded" | "blocked";
  active: boolean;
  summary: string;
  recommendation?: string;
};

type ProductionReadinessSummary = {
  status: "ready" | "warned" | "degraded" | "blocked";
  ready: boolean;
  score: number;
  message: string;
  blocking_count: number;
  warning_count: number;
  degraded_count: number;
  passing_count: number;
};

type ProductionReadinessCheck = {
  key: string;
  category: string;
  label: string;
  status: "passed" | "warned" | "degraded" | "blocked";
  summary: string;
  recommendation?: string;
  dependencies?: string[];
};

type ProductionReadinessReport = ProductionReadinessSummary & {
  checks?: ProductionReadinessCheck[];
};

type SystemStatus = {
  generated_at: string;
  summary: {
    users: number;
    active_sessions: number;
    quarantined_sessions: number;
    shaped_sessions: number;
    pending_changes: number;
    unacknowledged_alerts: number;
    healthy_services: number;
    total_services: number;
    session_methods: Record<string, number>;
  };
  services: ServiceStatus[];
  production_readiness?: ProductionReadinessSummary;
  deployment: {
    profile: string;
    form: string;
    label: string;
    summary: string;
    recommended_min_memory: number;
    recommended_min_cores: number;
    hardware: {
      memory_mb: number;
      cpu_cores: number;
      storage_gb?: number;
      prefer_external_ap: boolean;
      wireless_passthrough: boolean;
    };
    scaling?: {
      mode: string;
      selected_profile: string;
      recommended_profile: string;
      hardware_known: boolean;
      storage_known: boolean;
      can_run_selected: boolean;
      summary: string;
      reason: string;
      resource_summary: string;
      recommended_retention?: {
        analytics_retention_hours: number;
        profiling_retention_hours: number;
        lease_history_poll_seconds: number;
        description: string;
      };
      recommended_limits?: {
        radius_max_sessions: number;
        recommendation_limit: number;
        controller_sync_mode: string;
        preferred_ap_model: string;
      };
      gating_actions?: Array<{
        key: string;
        label: string;
        state: string;
        active: boolean;
        summary: string;
        recommendation?: string;
      }>;
    };
    warnings: string[];
    capabilities: DeploymentCapability[];
  };
  radius: {
    upstream_enabled: boolean;
    realm: string;
    pool_strategy: string;
    configured_servers: Array<{
      name: string;
      address: string;
      auth_port: number;
      acct_port: number;
    }>;
    server_statuses: UpstreamServerStatus[];
    enabled_radius_clients: number;
    broker_auth: RuntimeStatus;
    broker_accounting: RuntimeStatus;
    probe_error?: string;
  };
  wireless: {
    enabled: boolean;
    interface: string;
    country_code: string;
    channel: number;
    hostapd_config_path: string;
    ssid_count: number;
    auth_modes: string[];
  };
  enforcement: {
    shaping_enabled: boolean;
    shaping_interface: string;
    shaped_sessions: number;
    shaper: RuntimeStatus;
  };
  high_availability: {
    enabled: boolean;
    role: string;
    peer_api_url: string;
    virtual_ip: string;
    heartbeat_interval_seconds: number;
    failover_timeout_seconds: number;
    replication_interval_seconds: number;
    replication_stale_after_seconds: number;
    split_brain_protection_enabled: boolean;
    auto_stage_shared_package: boolean;
    auto_activate_on_failover: boolean;
    witness_api_url: string;
    witness_urls: string[];
    witness_quorum: number;
    witness_weights: Record<string, number>;
    witness_weight_threshold: number;
    witness_groups: Record<string, string>;
    witness_min_distinct_groups: number;
    witness_required_groups: string[];
    witness_sources: Record<string, string>;
    witness_source_confidence: Record<string, string>;
    witness_required_sources: string[];
    witness_required_urls: string[];
    witness_required_sources_by_tier: Record<string, string[]>;
    witness_required_urls_by_tier: Record<string, string[]>;
    witness_required_groups_by_tier: Record<string, string[]>;
    witness_policy_mode: string;
    witness_policy_mode_by_tier: Record<string, string>;
    witness_failure_tolerance: number;
    witness_failure_weight_tolerance: number;
    witness_min_approvals_by_tier: Record<string, number>;
    witness_min_weight_by_tier: Record<string, number>;
    witness_min_distinct_groups_by_tier: Record<string, number>;
    witness_min_distinct_sources_by_tier: Record<string, number>;
    witness_max_age_by_tier: Record<string, number>;
    witness_required_node_by_tier: Record<string, string>;
    witness_signature_required_tiers: string[];
    witness_replay_required_tiers: string[];
    witness_failure_tolerance_by_tier: Record<string, number>;
    witness_failure_weight_tolerance_by_tier: Record<string, number>;
    witness_blocking_tiers: string[];
    witness_token_env: string;
    witness_signing_key_env: string;
    witness_max_age_seconds: number;
    witness_required_node: string;
    witness_replay_protection_enabled: boolean;
    preempt: boolean;
    preempt_holdoff_seconds: number;
    shared_state_dir: string;
    runtime: RuntimeStatus;
    replication_runtime: RuntimeStatus;
    post_failover_recovery: RuntimeStatus;
    history_stats: {
      total_records: number;
      failover_promotions: number;
      failover_returns: number;
      peer_failures: number;
      peer_recoveries: number;
      vip_acquisitions: number;
      vip_preemptions: number;
      vip_releases: number;
      vip_announcements: number;
      vip_announcement_failures: number;
      replication_publishes: number;
      replication_failures: number;
      replication_stale_count: number;
      shared_stages: number;
      activations: number;
      last_event_at: string;
    };
  };
  integrations: {
    admin_sso: {
      enabled: boolean;
      provider: string;
      issuer_url: string;
      redirect_url: string;
      groups_claim: string;
      session: RuntimeStatus;
    };
    siem: {
      enabled: boolean;
      provider: string;
      endpoint: string;
      batch_size: number;
      export: RuntimeStatus;
    };
    controller: {
      enabled: boolean;
      platform: string;
      endpoint: string;
      sync_mode: string;
      site: string;
      adapter?: string;
      ready?: boolean;
      site_required?: boolean;
      readiness_warnings?: string[];
      selected_adapter?: {
        platform?: string;
        label?: string;
        adapter?: string;
        operational_state?: string;
        operational_guidance?: string;
        native_policy_push?: boolean;
        drift_detection?: boolean;
        health_report?: boolean;
        dynamic_acl?: boolean;
        coa?: boolean;
        supported_sync_modes?: string[];
      };
      sync: RuntimeStatus;
    };
  };
  profiling: {
    mac_inventory_enabled: boolean;
    passive_enabled: boolean;
    posture_enabled: boolean;
    mdm_sync_enabled: boolean;
    mdm_provider: string;
    mdm_endpoint: string;
    compliance_webhook: string;
    device_inventory: RuntimeStatus;
    mdm_sync: RuntimeStatus;
    posture_checks: RuntimeStatus;
  };
  telemetry: {
    enabled: boolean;
    prometheus_port: number;
    lease_history_poll_seconds: number;
    support_bundle_exports: {
      enabled: boolean;
      directory: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    diagnostics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    audit_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    session_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    session_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    voucher_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    voucher_aging_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    voucher_redemption_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    voucher_expiry_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    guest_lifecycle_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    guest_invite_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    guest_conversion_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    guest_rejection_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    guest_delivery_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    guest_delivery_failures_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    guest_sponsor_analytics_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    integration_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    ha_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    network_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    upstream_aaa_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
    upgrade_readiness_exports: {
      enabled: boolean;
      directory: string;
      format: string;
      interval_minutes: number;
      retention_count: number;
      runtime: RuntimeStatus;
    };
  };
  network_observability: {
    apply_stats: {
      total_records: number;
      apply_success_count: number;
      apply_failure_count: number;
      pending_confirmation_count: number;
      confirmed_count: number;
      rollback_count: number;
      auto_rollback_count: number;
      auto_rollback_failure_count: number;
      last_applied_at?: string;
      last_failure_at?: string;
    };
    lease_trends: {
      window_hours: number;
      total_records: number;
      unique_macs_window: number;
      unique_ips_window: number;
      active_observations_window: number;
      expired_observations_window: number;
      reservation_observations_window: number;
      peak_concurrent_leases_window: number;
      latest_observed_at?: string;
    };
    recovery?: {
      pending?: boolean;
      backup_id?: string;
      deadline?: string;
      status?: string;
      message?: string;
    } | null;
    controller_sync?: RuntimeStatus;
    vendor_observability?: VendorObservability;
  };
};

const statusTone: Record<string, string> = {
  ok: "border-emerald-200 bg-emerald-50 text-emerald-800",
  ready: "border-emerald-200 bg-emerald-50 text-emerald-800",
  passed: "border-emerald-200 bg-emerald-50 text-emerald-800",
  degraded: "border-amber-200 bg-amber-50 text-amber-800",
  down: "border-red-200 bg-red-50 text-red-800",
  blocked: "border-red-200 bg-red-50 text-red-800",
  disabled: "border-gray-200 bg-gray-100 text-gray-700",
  unknown: "border-slate-200 bg-slate-100 text-slate-700",
  warned: "border-amber-200 bg-amber-50 text-amber-800",
};

const cardTone: Record<string, string> = {
  sky: "bg-sky-100 text-sky-700",
  emerald: "bg-emerald-100 text-emerald-700",
  amber: "bg-amber-100 text-amber-700",
  rose: "bg-rose-100 text-rose-700",
  violet: "bg-violet-100 text-violet-700",
  indigo: "bg-indigo-100 text-indigo-700",
};

const capabilityTone: Record<DeploymentCapability["state"], string> = {
  enabled: "border-emerald-200 bg-emerald-50 text-emerald-800",
  available: "border-sky-200 bg-sky-50 text-sky-800",
  warned: "border-amber-200 bg-amber-50 text-amber-800",
  degraded: "border-orange-200 bg-orange-50 text-orange-800",
  blocked: "border-red-200 bg-red-50 text-red-800",
};

function MetricCard({
  label,
  value,
  mark,
  tone,
}: {
  label: string;
  value: number | string;
  mark: string;
  tone: keyof typeof cardTone;
}) {
  return (
    <div className="rounded-lg bg-white p-6 shadow">
      <div className="flex items-center">
        <div
          className={`flex h-10 w-10 items-center justify-center rounded-md font-bold ${cardTone[tone]}`}
        >
          {mark}
        </div>
        <div className="ml-4">
          <p className="text-sm text-gray-500">{label}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const tone = statusTone[status] || statusTone.unknown;
  return (
    <span
      className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${tone}`}
    >
      {status}
    </span>
  );
}

export default function Dashboard() {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [productionReadiness, setProductionReadiness] =
    useState<ProductionReadinessReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadStatus = async (includeReadiness = true) => {
    try {
      const [statusResponse, readinessResponse] = await Promise.all([
        api.get("/system/status"),
        includeReadiness
          ? api.get("/system/production-readiness").catch(() => null)
          : Promise.resolve(null),
      ]);
      setSystemStatus(statusResponse.data);
      if (includeReadiness) {
        setProductionReadiness(readinessResponse?.data || null);
      }
      setError("");
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not load appliance status.",
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
    const timer = window.setInterval(() => loadStatus(false), 15000);
    return () => window.clearInterval(timer);
  }, []);

  if (loading) {
    return <div className="text-gray-600">Loading appliance status...</div>;
  }

  if (!systemStatus) {
    return (
      <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
        {error || "Appliance status is unavailable."}
      </div>
    );
  }

  const services = systemStatus.services ?? [];
  const deploymentWarnings = systemStatus.deployment?.warnings ?? [];
  const deploymentCapabilities = systemStatus.deployment?.capabilities ?? [];
  const scaling = systemStatus.deployment?.scaling;
  const activeScalingActions =
    scaling?.gating_actions?.filter(
      (action) => action.active && action.state !== "allow",
    ) ?? [];
  const configuredServers = systemStatus.radius?.configured_servers ?? [];
  const radiusServerStatuses = systemStatus.radius?.server_statuses ?? [];
  const wirelessAuthModes = systemStatus.wireless?.auth_modes ?? [];
  const serviceProblems = services.filter(
    (service) => !["ok", "disabled"].includes(service.status),
  );
  const sessionMethods = Object.entries(
    systemStatus.summary?.session_methods || {},
  );
  const networkObservability = systemStatus.network_observability;
  const vendorObservability = networkObservability?.vendor_observability;
  const readinessSummary =
    productionReadiness || systemStatus.production_readiness;
  const readinessIssues =
    productionReadiness?.checks?.filter((check) => check.status !== "passed") ||
    [];
  const highAvailabilityStatus =
    systemStatus.high_availability.replication_runtime?.status === "degraded"
      ? "degraded"
      : systemStatus.high_availability.replication_runtime?.status ===
            "pending" && !systemStatus.high_availability.runtime?.status
        ? "pending"
        : systemStatus.high_availability.runtime?.status ||
          (systemStatus.high_availability.enabled ? "unknown" : "disabled");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Dashboard</h2>
          <p className="mt-1 text-sm text-gray-600">
            Live appliance health, access posture, and service readiness.
          </p>
        </div>
        <button
          onClick={() => loadStatus(true)}
          className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {String(error)}
        </div>
      )}

      {readinessSummary ? (
        <section
          className={`rounded-lg border bg-white p-6 shadow-sm ${
            readinessSummary.status === "blocked"
              ? "border-red-300"
              : readinessSummary.status === "ready"
                ? "border-emerald-300"
                : "border-amber-300"
          }`}
          aria-labelledby="production-readiness-heading"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <h3
                id="production-readiness-heading"
                className="text-lg font-semibold text-gray-900"
              >
                Production Readiness
              </h3>
              <p className="mt-1 text-sm text-gray-600">
                {readinessSummary.message}
              </p>
            </div>
            <StatusBadge status={readinessSummary.status} />
          </div>

          <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-5">
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Score
              </div>
              <div className="mt-1 text-2xl font-bold text-gray-900">
                {readinessSummary.score}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Blocked
              </div>
              <div className="mt-1 text-2xl font-bold text-red-700">
                {readinessSummary.blocking_count}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Degraded
              </div>
              <div className="mt-1 text-2xl font-bold text-amber-700">
                {readinessSummary.degraded_count}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Warnings
              </div>
              <div className="mt-1 text-2xl font-bold text-amber-700">
                {readinessSummary.warning_count}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Passed
              </div>
              <div className="mt-1 text-2xl font-bold text-emerald-700">
                {readinessSummary.passing_count}
              </div>
            </div>
          </div>

          {readinessIssues.length ? (
            <div className="mt-5 border-t border-gray-200">
              {readinessIssues.slice(0, 4).map((check) => (
                <div
                  key={check.key}
                  className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-100 py-4 last:border-b-0"
                >
                  <div className="min-w-0 flex-1">
                    <div className="font-medium text-gray-900">
                      {check.label}
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {check.summary}
                    </div>
                    {check.recommendation ? (
                      <div className="mt-1 text-xs text-gray-500">
                        {check.recommendation}
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge status={check.status} />
                </div>
              ))}
              {readinessIssues.length > 4 ? (
                <div className="pb-3 text-xs text-gray-500">
                  {readinessIssues.length - 4} more readiness issue(s) are
                  available from the production readiness API.
                </div>
              ) : null}
            </div>
          ) : null}

          <div className="mt-4 flex flex-wrap gap-3">
            <Link
              to="/access-settings"
              className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white"
            >
              Open Access Settings
            </Link>
            <Link
              to="/vendor-compatibility"
              className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
            >
              Vendor Compatibility
            </Link>
          </div>
        </section>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <MetricCard
          label="Users"
          value={systemStatus.summary.users}
          mark="US"
          tone="sky"
        />
        <MetricCard
          label="Active Sessions"
          value={systemStatus.summary.active_sessions}
          mark="SE"
          tone="emerald"
        />
        <MetricCard
          label="Quarantined Sessions"
          value={systemStatus.summary.quarantined_sessions}
          mark="QN"
          tone="rose"
        />
        <MetricCard
          label="Shaped Sessions"
          value={systemStatus.summary.shaped_sessions}
          mark="BW"
          tone="indigo"
        />
        <MetricCard
          label="Pending Changes"
          value={systemStatus.summary.pending_changes}
          mark="CH"
          tone="violet"
        />
        <MetricCard
          label="Unacknowledged Alerts"
          value={systemStatus.summary.unacknowledged_alerts}
          mark="AL"
          tone="amber"
        />
        <MetricCard
          label="Healthy Services"
          value={`${systemStatus.summary.healthy_services}/${systemStatus.summary.total_services}`}
          mark="SV"
          tone="sky"
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr,1fr]">
        <section className="rounded-lg bg-white p-6 shadow">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">
                Service Health
              </h3>
              <p className="mt-1 text-sm text-gray-600">
                Go services, core Linux services, and publish path readiness.
              </p>
            </div>
            <div className="text-sm text-gray-500">
              {systemStatus.generated_at}
            </div>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {services.map((service) => (
              <div
                key={service.key}
                className="rounded-md border border-gray-200 px-4 py-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      {service.label}
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {service.message || "No status message."}
                    </div>
                    {service.port ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Port {service.port}
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge status={service.status} />
                </div>
              </div>
            ))}
          </div>
        </section>

        <div className="space-y-6">
          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">
              Deployment Profile
            </h3>
            <div className="mt-4 rounded-md border border-gray-200 px-4 py-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-gray-900">
                    {systemStatus.deployment.label}
                  </div>
                  <div className="mt-1 text-sm text-gray-600">
                    {systemStatus.deployment.summary}
                  </div>
                </div>
                <StatusBadge
                  status={deploymentWarnings.length === 0 ? "ok" : "degraded"}
                />
              </div>
              <div className="mt-3 text-sm text-gray-600">
                {systemStatus.deployment.form} form,{" "}
                {systemStatus.deployment.hardware.cpu_cores || "unknown"} cores,{" "}
                {systemStatus.deployment.hardware.memory_mb || "unknown"} MB
                RAM,{" "}
                {systemStatus.deployment.hardware.storage_gb || "unknown"} GB
                storage.
              </div>
              <div className="mt-1 text-xs text-gray-500">
                Recommended floor:{" "}
                {systemStatus.deployment.recommended_min_cores} cores and{" "}
                {systemStatus.deployment.recommended_min_memory} MB RAM.
              </div>
              {scaling ? (
                <div className="mt-3 rounded-md border border-gray-200 bg-gray-50 px-3 py-2 text-sm text-gray-700">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-gray-900">
                      Scaling mode: {scaling.mode || "unknown"}
                    </span>
                    <span
                      className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${
                        scaling.can_run_selected
                          ? statusTone.ok
                          : statusTone.degraded
                      }`}
                    >
                      {scaling.can_run_selected ? "fits" : "gated"}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-gray-600">
                    {scaling.reason || scaling.summary}
                  </div>
                  {scaling.recommended_retention ? (
                    <div className="mt-1 text-xs text-gray-500">
                      Retention target:{" "}
                      {scaling.recommended_retention.analytics_retention_hours}h
                      analytics,{" "}
                      {scaling.recommended_retention.profiling_retention_hours}h
                      profiling, lease poll every{" "}
                      {scaling.recommended_retention.lease_history_poll_seconds}s.
                    </div>
                  ) : null}
                  {activeScalingActions.length ? (
                    <div className="mt-2 space-y-1 text-xs text-amber-700">
                      {activeScalingActions.slice(0, 3).map((action) => (
                        <div key={action.key}>{action.summary}</div>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
            <div className="mt-4 grid gap-3">
              {deploymentCapabilities.map((capability) => (
                <div
                  key={capability.key}
                  className="rounded-md border border-gray-200 px-4 py-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-medium text-gray-900">
                        {capability.label}
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {capability.summary}
                      </div>
                    </div>
                    <span
                      className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${capabilityTone[capability.state]}`}
                    >
                      {capability.state}
                    </span>
                  </div>
                  {capability.recommendation ? (
                    <div className="mt-2 text-xs text-gray-500">
                      {capability.recommendation}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
            <div className="mt-4 space-y-2">
              {deploymentWarnings.length === 0 ? (
                <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-600">
                  Hardware and feature choices look aligned with the selected
                  profile.
                </div>
              ) : (
                deploymentWarnings.map((warning, index) => (
                  <div
                    key={`deployment-warning-${index}`}
                    className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800"
                  >
                    {warning}
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">
              Upstream AAA
            </h3>
            <div className="mt-4 grid gap-3">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      {systemStatus.radius.upstream_enabled
                        ? "Upstream AAA Enabled"
                        : "Upstream AAA Disabled"}
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      Realm {systemStatus.radius.realm || "not set"} with{" "}
                      {systemStatus.radius.pool_strategy || "no"} pool strategy.
                    </div>
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.radius.upstream_enabled ? "ok" : "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Broker Auth Path
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.radius.broker_auth?.message ||
                        "No broker auth activity recorded yet."}
                    </div>
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.radius.broker_auth?.status || "unknown"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Broker Accounting Path
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.radius.broker_accounting?.message ||
                        "No broker accounting activity recorded yet."}
                    </div>
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.radius.broker_accounting?.status || "unknown"
                    }
                  />
                </div>
              </div>
            </div>
            {systemStatus.radius.probe_error ? (
              <div className="mt-4 rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                {systemStatus.radius.probe_error}
              </div>
            ) : null}
            <div className="mt-4 space-y-3">
              {radiusServerStatuses.length === 0 ? (
                <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-600">
                  No upstream AAA servers configured.
                </div>
              ) : (
                radiusServerStatuses.map((server) => (
                  <div
                    key={`${server.name}-${server.address}-${server.auth_port}`}
                    className="rounded-md border border-gray-200 px-4 py-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-medium text-gray-900">
                          {server.name}
                        </div>
                        <div className="mt-1 text-sm text-gray-600">
                          {server.address}:{server.auth_port} auth,{" "}
                          {server.acct_port} acct
                        </div>
                        <div className="mt-1 text-sm text-gray-600">
                          {server.message || "No per-server probe message."}
                        </div>
                        <div className="mt-1 text-xs text-gray-500">
                          {server.supports_status_server
                            ? `Status-Server probe${server.latency_ms ? ` ${server.latency_ms} ms` : ""}${server.response_code ? `, ${server.response_code}` : ""}`
                            : "Per-server active probe disabled by config"}
                        </div>
                      </div>
                      <StatusBadge status={server.status || "unknown"} />
                    </div>
                  </div>
                ))
              )}
            </div>
            <div className="mt-4 rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-600">
              {configuredServers.length === 0
                ? `No upstream AAA servers configured. ${systemStatus.radius.enabled_radius_clients} RADIUS clients are still allowed on the appliance.`
                : `${configuredServers.length} upstream AAA servers configured and ${systemStatus.radius.enabled_radius_clients} RADIUS clients allowed on the appliance.`}
            </div>
          </section>

          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">
              Wireless And Sessions
            </h3>
            <div className="mt-4 space-y-3">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      {systemStatus.wireless.enabled
                        ? "Wireless Enabled"
                        : "Wireless Disabled"}
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.wireless.enabled
                        ? `${systemStatus.wireless.interface || "radio unset"} on channel ${systemStatus.wireless.channel} with ${systemStatus.wireless.ssid_count} SSIDs.`
                        : "Use an external AP or enable the radio in Access Settings."}
                    </div>
                  </div>
                  <StatusBadge
                    status={systemStatus.wireless.enabled ? "ok" : "disabled"}
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="font-medium text-gray-900">SSID Auth Modes</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {wirelessAuthModes.length === 0 ? (
                    <span className="text-sm text-gray-500">
                      No SSIDs configured yet.
                    </span>
                  ) : (
                    wirelessAuthModes.map((mode) => (
                      <span
                        key={mode}
                        className="rounded-md bg-gray-100 px-2 py-1 text-xs font-medium text-gray-700"
                      >
                        {mode}
                      </span>
                    ))
                  )}
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="font-medium text-gray-900">Session Mix</div>
                <div className="mt-2 space-y-2">
                  {sessionMethods.length === 0 ? (
                    <div className="text-sm text-gray-500">
                      No active sessions yet.
                    </div>
                  ) : (
                    sessionMethods.map(([method, count]) => (
                      <div
                        key={method}
                        className="flex items-center justify-between text-sm text-gray-700"
                      >
                        <span>{method}</span>
                        <span className="font-semibold">{count}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Runtime Bandwidth Enforcement
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.enforcement.shaping_enabled
                        ? `${systemStatus.enforcement.shaping_interface || "downstream interface unset"} is shaping ${systemStatus.enforcement.shaped_sessions} active sessions.`
                        : "Runtime shaping is disabled until a downstream interface is configured."}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      {systemStatus.enforcement.shaper?.message ||
                        "No shaping status recorded yet."}
                    </div>
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.enforcement.shaper?.status ||
                      (systemStatus.enforcement.shaping_enabled
                        ? "unknown"
                        : "disabled")
                    }
                  />
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">
              External Integrations
            </h3>
            <div className="mt-4 space-y-3">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">Admin SSO</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.integrations.admin_sso.enabled
                        ? `${systemStatus.integrations.admin_sso.provider || "Provider unset"} admin sign-in is configured.`
                        : "Token login remains available until you enable admin SSO."}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      {systemStatus.integrations.admin_sso.session?.message ||
                        "No admin SSO runtime status recorded yet."}
                    </div>
                    {systemStatus.integrations.admin_sso.redirect_url ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        {systemStatus.integrations.admin_sso.redirect_url}
                      </div>
                    ) : null}
                    {systemStatus.integrations.admin_sso.session?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Updated{" "}
                        {systemStatus.integrations.admin_sso.session.updated_at}
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.integrations.admin_sso.session?.status ||
                      (systemStatus.integrations.admin_sso.enabled
                        ? "unknown"
                        : "disabled")
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">SIEM Export</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.integrations.siem.enabled
                        ? `${systemStatus.integrations.siem.provider || "Provider unset"} batch size ${systemStatus.integrations.siem.batch_size || 0}.`
                        : "Configure webhook, Splunk HEC, or Elastic export when you need external event delivery."}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      {systemStatus.integrations.siem.export?.message ||
                        "No SIEM runtime status recorded yet."}
                    </div>
                    {systemStatus.integrations.siem.endpoint ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        {systemStatus.integrations.siem.endpoint}
                      </div>
                    ) : null}
                    {systemStatus.integrations.siem.export?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Updated{" "}
                        {systemStatus.integrations.siem.export.updated_at}
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.integrations.siem.export?.status ||
                      (systemStatus.integrations.siem.enabled
                        ? "unknown"
                        : "disabled")
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Controller Automation
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.integrations.controller.enabled
                        ? `${systemStatus.integrations.controller.platform || "Platform unset"} sync mode ${systemStatus.integrations.controller.sync_mode || "unset"}${systemStatus.integrations.controller.site ? ` for ${systemStatus.integrations.controller.site}` : ""}.`
                        : "Enable this only when AegisNAS is feeding an external AP or controller estate."}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      {systemStatus.integrations.controller.sync?.message ||
                        "No controller runtime status recorded yet."}
                    </div>
                    {systemStatus.integrations.controller.selected_adapter ? (
                      <div className="mt-2 flex flex-wrap gap-2 text-xs">
                        <span className="rounded-md border border-gray-200 bg-gray-50 px-2 py-1 text-gray-700">
                          {systemStatus.integrations.controller.selected_adapter
                            .label ||
                            systemStatus.integrations.controller.adapter ||
                            "Generic REST"}
                        </span>
                        {systemStatus.integrations.controller.enabled ? (
                          <span
                            className={`rounded-md border px-2 py-1 ${
                              systemStatus.integrations.controller.ready
                                ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                                : "border-amber-200 bg-amber-50 text-amber-800"
                            }`}
                          >
                            {systemStatus.integrations.controller.ready
                              ? "Ready"
                              : "Needs setup"}
                          </span>
                        ) : null}
                        {systemStatus.integrations.controller.selected_adapter
                          .native_policy_push ? (
                          <span className="rounded-md border border-gray-200 px-2 py-1 text-gray-600">
                            Native push
                          </span>
                        ) : null}
                        {systemStatus.integrations.controller.selected_adapter
                          .drift_detection ? (
                          <span className="rounded-md border border-gray-200 px-2 py-1 text-gray-600">
                            Drift watch
                          </span>
                        ) : null}
                        {systemStatus.integrations.controller.selected_adapter
                          .dynamic_acl ? (
                          <span className="rounded-md border border-gray-200 px-2 py-1 text-gray-600">
                            Dynamic ACL
                          </span>
                        ) : null}
                        {systemStatus.integrations.controller.selected_adapter
                          .coa ? (
                          <span className="rounded-md border border-gray-200 px-2 py-1 text-gray-600">
                            CoA
                          </span>
                        ) : null}
                      </div>
                    ) : null}
                    {systemStatus.integrations.controller.enabled &&
                    systemStatus.integrations.controller.readiness_warnings
                      ?.length ? (
                      <div className="mt-2 space-y-1 text-xs text-amber-700">
                        {systemStatus.integrations.controller.readiness_warnings
                          .slice(0, 3)
                          .map((warning) => (
                            <div key={warning}>Needs attention: {warning}</div>
                          ))}
                      </div>
                    ) : null}
                    {systemStatus.integrations.controller.endpoint ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        {systemStatus.integrations.controller.endpoint}
                      </div>
                    ) : null}
                    {systemStatus.integrations.controller.sync?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Updated{" "}
                        {systemStatus.integrations.controller.sync.updated_at}
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.integrations.controller.sync?.status ||
                      (systemStatus.integrations.controller.enabled
                        ? "unknown"
                        : "disabled")
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      High Availability
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.high_availability.enabled
                        ? `${systemStatus.high_availability.role || "standby"} role watching ${systemStatus.high_availability.peer_api_url || "peer unset"} with VIP ${systemStatus.high_availability.virtual_ip || "unset"}.`
                        : "Enterprise HA peer monitoring is disabled on this node."}
                    </div>
                    {systemStatus.high_availability.runtime?.details
                      ?.effective_role ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Effective role{" "}
                        {String(
                          systemStatus.high_availability.runtime.details
                            .effective_role,
                        )}
                        {systemStatus.high_availability.runtime?.details
                          ?.vip_assigned
                          ? ", VIP currently assigned locally."
                          : ", VIP not assigned locally."}
                      </div>
                    ) : null}
                    {systemStatus.high_availability.runtime?.details
                      ?.lease_holder ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Lease holder{" "}
                        {String(
                          systemStatus.high_availability.runtime.details
                            .lease_holder,
                        )}
                        {systemStatus.high_availability.runtime?.details
                          ?.lease_expires_at
                          ? ` until ${String(systemStatus.high_availability.runtime.details.lease_expires_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.preempt ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Preempt{" "}
                        {String(
                          systemStatus.high_availability.runtime?.details
                            ?.preempt_status || "enabled",
                        )}
                        {systemStatus.high_availability.runtime?.details
                          ?.preempt_holdoff_remaining_seconds !== undefined
                          ? `, holdoff remaining ${String(systemStatus.high_availability.runtime.details.preempt_holdoff_remaining_seconds)}s`
                          : systemStatus.high_availability
                                .preempt_holdoff_seconds
                            ? `, configured holdoff ${String(systemStatus.high_availability.preempt_holdoff_seconds)}s`
                            : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.preempt_ready_at
                          ? `, ready at ${String(systemStatus.high_availability.runtime.details.preempt_ready_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.runtime?.details
                      ?.vip_announcement_status ? (
                      <div className="mt-1 text-xs text-gray-500">
                        VIP announcement{" "}
                        {String(
                          systemStatus.high_availability.runtime.details
                            .vip_announcement_status,
                        )}
                        {systemStatus.high_availability.runtime?.details
                          ?.vip_announcement_at
                          ? ` at ${String(systemStatus.high_availability.runtime.details.vip_announcement_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.runtime?.details
                      ?.vip_announcement_error ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        {String(
                          systemStatus.high_availability.runtime.details
                            .vip_announcement_error,
                        )}
                      </div>
                    ) : null}
                    <div className="mt-1 text-xs text-gray-500">
                      {systemStatus.high_availability.replication_runtime
                        ?.message ||
                        `Shared replication every ${systemStatus.high_availability.replication_interval_seconds || 300}s with stale threshold ${systemStatus.high_availability.replication_stale_after_seconds || 900}s.`}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Split-brain protection{" "}
                      {systemStatus.high_availability
                        .split_brain_protection_enabled
                        ? "enabled"
                        : "disabled"}
                      {systemStatus.high_availability.runtime?.details
                        ?.fencing_status
                        ? `, status ${String(systemStatus.high_availability.runtime.details.fencing_status)}`
                        : ""}
                      .
                    </div>
                    {systemStatus.high_availability.witness_api_url ||
                    systemStatus.high_availability.witness_urls?.length ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        Witness{" "}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_status
                          ? String(
                              systemStatus.high_availability.runtime.details
                                .witness_status,
                            )
                          : "configured"}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_allow_count !== undefined &&
                        systemStatus.high_availability.runtime?.details
                          ?.witness_total_count !== undefined
                          ? `, approvals ${String(systemStatus.high_availability.runtime.details.witness_allow_count)}/${String(systemStatus.high_availability.runtime.details.witness_total_count)}`
                          : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_allow_weight !== undefined &&
                        systemStatus.high_availability.runtime?.details
                          ?.witness_total_weight !== undefined
                          ? `, weight ${String(systemStatus.high_availability.runtime.details.witness_allow_weight)}/${String(systemStatus.high_availability.runtime.details.witness_total_weight)}`
                          : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_allow_group_count !== undefined &&
                        systemStatus.high_availability.runtime?.details
                          ?.witness_total_group_count !== undefined
                          ? `, groups ${String(systemStatus.high_availability.runtime.details.witness_allow_group_count)}/${String(systemStatus.high_availability.runtime.details.witness_total_group_count)}`
                          : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_allow_source_count !== undefined &&
                        systemStatus.high_availability.witness_required_sources
                          ?.length
                          ? `, sources ${String(systemStatus.high_availability.runtime.details.witness_allow_source_count)}/${String(systemStatus.high_availability.witness_required_sources.length)}`
                          : ""}
                        {systemStatus.high_availability.witness_urls?.length
                          ? `, quorum ${systemStatus.high_availability.witness_quorum}`
                          : ""}
                        {systemStatus.high_availability
                          .witness_weight_threshold > 0
                          ? `, weight threshold ${systemStatus.high_availability.witness_weight_threshold}`
                          : ""}
                        {systemStatus.high_availability
                          .witness_min_distinct_groups > 0
                          ? `, distinct groups ${systemStatus.high_availability.witness_min_distinct_groups}`
                          : ""}
                        {systemStatus.high_availability.witness_required_groups
                          ?.length
                          ? `, required groups ${systemStatus.high_availability.witness_required_groups.join(", ")}`
                          : ""}
                        {systemStatus.high_availability.witness_policy_mode
                          ? `, policy ${systemStatus.high_availability.witness_policy_mode}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_policy_mode_by_tier || {},
                        ).length > 0
                          ? `, tier policy ${Object.entries(
                              systemStatus.high_availability
                                .witness_policy_mode_by_tier,
                            )
                              .map(([tier, mode]) => `${tier}=${mode}`)
                              .join(", ")}`
                          : ""}
                        {systemStatus.high_availability
                          .witness_failure_tolerance > 0
                          ? `, failure budget ${systemStatus.high_availability.witness_failure_tolerance}`
                          : ""}
                        {systemStatus.high_availability
                          .witness_failure_weight_tolerance > 0
                          ? `, failure weight budget ${systemStatus.high_availability.witness_failure_weight_tolerance}`
                          : ""}
                        {systemStatus.high_availability.witness_required_sources
                          ?.length
                          ? `, required sources ${systemStatus.high_availability.witness_required_sources.join(", ")}`
                          : ""}
                        {systemStatus.high_availability.witness_required_urls
                          ?.length
                          ? `, required urls ${systemStatus.high_availability.witness_required_urls.join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_required_sources_by_tier || {},
                        ).length > 0
                          ? `, tier sources ${Object.entries(
                              systemStatus.high_availability
                                .witness_required_sources_by_tier,
                            )
                              .map(
                                ([tier, sources]) =>
                                  `${tier}=${(sources || []).join(",")}`,
                              )
                              .join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_required_urls_by_tier || {},
                        ).length > 0
                          ? `, tier urls ${Object.entries(
                              systemStatus.high_availability
                                .witness_required_urls_by_tier,
                            )
                              .map(
                                ([tier, urls]) =>
                                  `${tier}=${(urls || []).join(",")}`,
                              )
                              .join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_required_groups_by_tier || {},
                        ).length > 0
                          ? `, tier groups ${Object.entries(
                              systemStatus.high_availability
                                .witness_required_groups_by_tier,
                            )
                              .map(
                                ([tier, groups]) =>
                                  `${tier}=${(groups || []).join(",")}`,
                              )
                              .join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_min_distinct_groups_by_tier || {},
                        ).length > 0
                          ? `, tier group diversity ${Object.entries(
                              systemStatus.high_availability
                                .witness_min_distinct_groups_by_tier,
                            )
                              .map(([tier, count]) => `${tier}=${count}`)
                              .join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_min_distinct_sources_by_tier || {},
                        ).length > 0
                          ? `, tier source diversity ${Object.entries(
                              systemStatus.high_availability
                                .witness_min_distinct_sources_by_tier,
                            )
                              .map(([tier, count]) => `${tier}=${count}`)
                              .join(", ")}`
                          : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_allow_promotion !== undefined
                          ? `, allow promotion ${String(systemStatus.high_availability.runtime.details.witness_allow_promotion)}`
                          : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_auth_status
                          ? `, auth ${String(systemStatus.high_availability.runtime.details.witness_auth_status)}`
                          : systemStatus.high_availability.witness_token_env
                            ? ", auth configured"
                            : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_signature_status
                          ? `, signature ${String(systemStatus.high_availability.runtime.details.witness_signature_status)}`
                          : systemStatus.high_availability
                                .witness_signing_key_env
                            ? ", signature configured"
                            : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_observed_age_seconds !== undefined
                          ? `, observed age ${String(systemStatus.high_availability.runtime.details.witness_observed_age_seconds)}s`
                          : ""}
                        {systemStatus.high_availability.witness_required_node
                          ? `, required node ${systemStatus.high_availability.witness_required_node}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_required_node_by_tier || {},
                        ).length > 0
                          ? `, tier node ${Object.entries(
                              systemStatus.high_availability
                                .witness_required_node_by_tier,
                            )
                              .map(([tier, node]) => `${tier}=${node}`)
                              .join(", ")}`
                          : ""}
                        {systemStatus.high_availability
                          .witness_signature_required_tiers?.length
                          ? `, tier signature ${systemStatus.high_availability.witness_signature_required_tiers.join(", ")}`
                          : ""}
                        {systemStatus.high_availability
                          .witness_replay_required_tiers?.length
                          ? `, tier replay ${systemStatus.high_availability.witness_replay_required_tiers.join(", ")}`
                          : ""}
                        {systemStatus.high_availability
                          .witness_max_age_seconds > 0
                          ? `, max age ${systemStatus.high_availability.witness_max_age_seconds}s`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_max_age_by_tier || {},
                        ).length > 0
                          ? `, tier max age ${Object.entries(
                              systemStatus.high_availability
                                .witness_max_age_by_tier,
                            )
                              .map(([tier, seconds]) => `${tier}=${seconds}`)
                              .join(", ")}`
                          : ""}
                        {systemStatus.high_availability.runtime?.details
                          ?.witness_replay_status
                          ? `, replay ${String(systemStatus.high_availability.runtime.details.witness_replay_status)}`
                          : systemStatus.high_availability
                                .witness_replay_protection_enabled
                            ? ", replay configured"
                            : ""}
                        :{" "}
                        {systemStatus.high_availability.witness_urls?.length
                          ? systemStatus.high_availability.witness_urls.join(
                              ", ",
                            )
                          : systemStatus.high_availability.witness_api_url}
                      </div>
                    ) : null}
                    {Object.keys(
                      systemStatus.high_availability
                        .witness_source_confidence || {},
                    ).length > 0 ||
                    Object.keys(
                      systemStatus.high_availability
                        .witness_min_approvals_by_tier || {},
                    ).length > 0 ||
                    Object.keys(
                      systemStatus.high_availability
                        .witness_min_weight_by_tier || {},
                    ).length > 0 ||
                    Object.keys(
                      systemStatus.high_availability
                        .witness_failure_tolerance_by_tier || {},
                    ).length > 0 ||
                    Object.keys(
                      systemStatus.high_availability
                        .witness_failure_weight_tolerance_by_tier || {},
                    ).length > 0 ||
                    systemStatus.high_availability.witness_blocking_tiers
                      ?.length ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_source_confidence || {},
                        ).length > 0
                          ? `Confidence ${Object.entries(
                              systemStatus.high_availability
                                .witness_source_confidence,
                            )
                              .map(([source, tier]) => `${source}=${tier}`)
                              .join(", ")}`
                          : "Confidence standard"}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_min_approvals_by_tier || {},
                        ).length > 0
                          ? `, tier minimums ${Object.entries(
                              systemStatus.high_availability
                                .witness_min_approvals_by_tier,
                            )
                              .map(([tier, count]) => `${tier}=${count}`)
                              .join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_min_weight_by_tier || {},
                        ).length > 0
                          ? `, tier weights ${Object.entries(
                              systemStatus.high_availability
                                .witness_min_weight_by_tier,
                            )
                              .map(([tier, count]) => `${tier}=${count}`)
                              .join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_failure_tolerance_by_tier || {},
                        ).length > 0
                          ? `, tier failure budgets ${Object.entries(
                              systemStatus.high_availability
                                .witness_failure_tolerance_by_tier,
                            )
                              .map(([tier, budget]) => `${tier}=${budget}`)
                              .join(", ")}`
                          : ""}
                        {Object.keys(
                          systemStatus.high_availability
                            .witness_failure_weight_tolerance_by_tier || {},
                        ).length > 0
                          ? `, tier weight budgets ${Object.entries(
                              systemStatus.high_availability
                                .witness_failure_weight_tolerance_by_tier,
                            )
                              .map(([tier, budget]) => `${tier}=${budget}`)
                              .join(", ")}`
                          : ""}
                        {systemStatus.high_availability.witness_blocking_tiers
                          ?.length
                          ? `, blocking tiers ${systemStatus.high_availability.witness_blocking_tiers.join(", ")}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.runtime?.details
                      ?.peer_shared_heartbeat_present ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Peer shared heartbeat age{" "}
                        {systemStatus.high_availability.runtime?.details
                          ?.peer_shared_heartbeat_age_seconds !== undefined
                          ? `${String(systemStatus.high_availability.runtime.details.peer_shared_heartbeat_age_seconds)}s`
                          : "unknown"}
                        {systemStatus.high_availability.runtime?.details
                          ?.peer_shared_heartbeat_stale
                          ? ", marked stale."
                          : ", marked fresh."}
                      </div>
                    ) : null}
                    {systemStatus.high_availability
                      .auto_stage_shared_package ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Auto-stage{" "}
                        {String(
                          systemStatus.high_availability.replication_runtime
                            ?.details?.auto_stage_status || "enabled",
                        )}
                        {systemStatus.high_availability.replication_runtime
                          ?.details?.auto_stage_stage_id
                          ? ` with staged package ${String(systemStatus.high_availability.replication_runtime.details.auto_stage_stage_id)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability
                      .auto_activate_on_failover ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Auto-activate on failover{" "}
                        {String(
                          systemStatus.high_availability.runtime?.details
                            ?.auto_activate_status || "enabled",
                        )}
                        {systemStatus.high_availability.runtime?.details
                          ?.auto_activate_stage_id
                          ? ` using staged package ${String(systemStatus.high_availability.runtime.details.auto_activate_stage_id)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.post_failover_recovery
                      ?.message ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Post-failover recovery{" "}
                        {String(
                          systemStatus.high_availability.post_failover_recovery
                            .status || "unknown",
                        )}
                        :{" "}
                        {
                          systemStatus.high_availability.post_failover_recovery
                            .message
                        }
                      </div>
                    ) : null}
                    {systemStatus.high_availability.post_failover_recovery
                      ?.details?.validated_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Validated{" "}
                        {String(
                          systemStatus.high_availability.post_failover_recovery
                            .details.validated_at,
                        )}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.post_failover_recovery
                      ?.details?.rolled_back_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Rolled back{" "}
                        {String(
                          systemStatus.high_availability.post_failover_recovery
                            .details.rolled_back_at,
                        )}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.replication_runtime?.details
                      ?.latest_source_node ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Latest shared package from{" "}
                        {String(
                          systemStatus.high_availability.replication_runtime
                            .details.latest_source_node,
                        )}
                        {systemStatus.high_availability.replication_runtime
                          ?.details?.latest_age_seconds !== undefined
                          ? `, age ${String(systemStatus.high_availability.replication_runtime.details.latest_age_seconds)}s`
                          : ""}
                        {systemStatus.high_availability.replication_runtime
                          ?.details?.stale
                          ? ", marked stale."
                          : ", marked fresh."}
                      </div>
                    ) : null}
                    <div className="mt-1 text-xs text-gray-500">
                      Promotions{" "}
                      {systemStatus.high_availability.history_stats
                        ?.failover_promotions ?? 0}
                      , peer failures{" "}
                      {systemStatus.high_availability.history_stats
                        ?.peer_failures ?? 0}
                      , VIP announcements{" "}
                      {systemStatus.high_availability.history_stats
                        ?.vip_announcements ?? 0}
                      , replication publishes{" "}
                      {systemStatus.high_availability.history_stats
                        ?.replication_publishes ?? 0}
                      .
                    </div>
                    {systemStatus.high_availability.history_stats
                      ?.last_event_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        HA history last updated{" "}
                        {
                          systemStatus.high_availability.history_stats
                            .last_event_at
                        }
                      </div>
                    ) : null}
                    <div className="mt-1 text-xs text-gray-500">
                      {systemStatus.high_availability.runtime?.message ||
                        "No HA runtime status recorded yet."}
                    </div>
                    {systemStatus.high_availability.runtime?.details
                      ?.peer_health_url ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        {String(
                          systemStatus.high_availability.runtime.details
                            .peer_health_url,
                        )}
                      </div>
                    ) : null}
                    {systemStatus.high_availability.replication_runtime
                      ?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Replication updated{" "}
                        {
                          systemStatus.high_availability.replication_runtime
                            .updated_at
                        }
                      </div>
                    ) : null}
                    {systemStatus.high_availability.runtime?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Updated{" "}
                        {systemStatus.high_availability.runtime.updated_at}
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge status={highAvailabilityStatus} />
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">
              Edge Network Observability
            </h3>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="font-medium text-gray-900">
                  Apply And Rollback Counters
                </div>
                <div className="mt-2 grid gap-2 text-sm text-gray-700">
                  <div className="flex items-center justify-between">
                    <span>Apply successes</span>
                    <span className="font-semibold">
                      {networkObservability.apply_stats.apply_success_count}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Apply failures</span>
                    <span className="font-semibold">
                      {networkObservability.apply_stats.apply_failure_count}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Pending confirmations</span>
                    <span className="font-semibold">
                      {
                        networkObservability.apply_stats
                          .pending_confirmation_count
                      }
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Manual rollbacks</span>
                    <span className="font-semibold">
                      {networkObservability.apply_stats.rollback_count}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Auto-rollbacks</span>
                    <span className="font-semibold">
                      {networkObservability.apply_stats.auto_rollback_count}
                    </span>
                  </div>
                </div>
                <div className="mt-3 text-xs text-gray-500">
                  Last apply{" "}
                  {networkObservability.apply_stats.last_applied_at ||
                    "not recorded"}
                  .
                  {networkObservability.apply_stats.last_failure_at
                    ? ` Last failure ${networkObservability.apply_stats.last_failure_at}.`
                    : ""}
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="font-medium text-gray-900">
                  DHCP Lease Trend
                </div>
                <div className="mt-2 grid gap-2 text-sm text-gray-700">
                  <div className="flex items-center justify-between">
                    <span>Window</span>
                    <span className="font-semibold">
                      {networkObservability.lease_trends.window_hours}h
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Unique MACs</span>
                    <span className="font-semibold">
                      {networkObservability.lease_trends.unique_macs_window}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Active observations</span>
                    <span className="font-semibold">
                      {
                        networkObservability.lease_trends
                          .active_observations_window
                      }
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Expired observations</span>
                    <span className="font-semibold">
                      {
                        networkObservability.lease_trends
                          .expired_observations_window
                      }
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Peak concurrent leases</span>
                    <span className="font-semibold">
                      {
                        networkObservability.lease_trends
                          .peak_concurrent_leases_window
                      }
                    </span>
                  </div>
                </div>
                <div className="mt-3 text-xs text-gray-500">
                  Latest lease observation{" "}
                  {networkObservability.lease_trends.latest_observed_at ||
                    "not recorded"}
                  .
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Management-Loss Safety Timer
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {networkObservability.recovery?.message ||
                        "No risky edge-network recovery window is active."}
                    </div>
                    {networkObservability.recovery?.deadline ? (
                      <div className="mt-2 text-xs text-gray-500">
                        Deadline{" "}
                        {String(networkObservability.recovery.deadline)}
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={networkObservability.recovery?.status || "disabled"}
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Controller Runtime Counters
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {networkObservability.controller_sync?.message ||
                        "No controller runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Syncs{" "}
                      {networkObservability.controller_sync?.details
                        ?.sync_count ?? 0}
                      , successes{" "}
                      {networkObservability.controller_sync?.details
                        ?.success_count ?? 0}
                      , failures{" "}
                      {networkObservability.controller_sync?.details
                        ?.failure_count ?? 0}
                      , last duration{" "}
                      {networkObservability.controller_sync?.details
                        ?.last_duration_ms ?? 0}{" "}
                      ms, adapter{" "}
                      {String(
                        networkObservability.controller_sync?.details
                          ?.adapter || "unknown",
                      )}
                      , auth{" "}
                      {String(
                        networkObservability.controller_sync?.details
                          ?.auth_scheme || "unknown",
                      )}
                      .
                    </div>
                  </div>
                  <StatusBadge
                    status={
                      networkObservability.controller_sync?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Vendor Observability
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {vendorObservability?.message ||
                        "No vendor counters have been recorded yet."}
                    </div>
                    <div className="mt-2 grid gap-1 text-xs text-gray-500">
                      <div>
                        Score{" "}
                        {vendorObservability?.summary?.compatibility_score ??
                          100}
                        , auth failures{" "}
                        {vendorObservability?.summary?.auth_failure_count ?? 0}
                        , unsupported attributes{" "}
                        {vendorObservability?.summary
                          ?.unsupported_attribute_count ?? 0}
                        , VSA parse failures{" "}
                        {vendorObservability?.summary
                          ?.vsa_parse_failure_count ?? 0}
                        .
                      </div>
                      {vendorObservability?.vendors?.length ? (
                        <div className="space-y-1">
                          {vendorObservability.vendors
                            .slice(0, 3)
                            .map((vendor) => (
                              <div
                                key={`${vendor.vendor_key}-${vendor.nas_type}`}
                              >
                                {vendor.vendor_key}/{vendor.nas_type}: score{" "}
                                {vendor.compatibility_score}, auth{" "}
                                {vendor.auth_success_count}/
                                {vendor.auth_failure_count}, CoA{" "}
                                {vendor.coa_success_count}/
                                {vendor.coa_failure_count}
                              </div>
                            ))}
                        </div>
                      ) : null}
                    </div>
                  </div>
                  <StatusBadge
                    status={vendorObservability?.status || "unknown"}
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      MDM And Posture Runtime
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.profiling?.mdm_sync?.message ||
                        "No MDM runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Provider {systemStatus.profiling?.mdm_provider || "unset"}
                      , total{" "}
                      {systemStatus.profiling?.mdm_sync?.details
                        ?.total_records ?? 0}
                      , compliant{" "}
                      {systemStatus.profiling?.mdm_sync?.details
                        ?.compliant_records ?? 0}
                      , non-compliant{" "}
                      {systemStatus.profiling?.mdm_sync?.details
                        ?.non_compliant_records ?? 0}
                      , remediation{" "}
                      {systemStatus.profiling?.posture_checks?.details
                        ?.remediation_records ?? 0}
                      .
                    </div>
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.profiling?.mdm_sync?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Support Bundle Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.support_bundle_exports?.runtime
                        ?.message ||
                        "No scheduled support bundle export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      ZIP bundle every{" "}
                      {systemStatus.telemetry?.support_bundle_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.support_bundle_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.support_bundle_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.support_bundle_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.support_bundle_exports.runtime
                            .details.last_export_at,
                        )}
                        {systemStatus.telemetry?.support_bundle_exports?.runtime
                          ?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.support_bundle_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.support_bundle_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Diagnostics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.diagnostics_exports?.runtime
                        ?.message ||
                        "No scheduled diagnostics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.diagnostics_exports?.format ||
                        "json"}
                      , every{" "}
                      {systemStatus.telemetry?.diagnostics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.diagnostics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.diagnostics_exports?.directory ||
                        "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.diagnostics_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.diagnostics_exports.runtime
                            .details.last_export_at,
                        )}
                        {systemStatus.telemetry?.diagnostics_exports?.runtime
                          ?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.diagnostics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.diagnostics_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Audit Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.audit_exports?.runtime
                        ?.message ||
                        "No scheduled audit export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.audit_exports?.format || "json"},
                      every{" "}
                      {systemStatus.telemetry?.audit_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.audit_exports?.retention_count ||
                        0}
                      , directory{" "}
                      {systemStatus.telemetry?.audit_exports?.directory ||
                        "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.audit_exports?.runtime?.details
                      ?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.audit_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry?.audit_exports?.runtime?.details
                          ?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.audit_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.audit_exports?.runtime?.status ||
                      "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Session Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.session_exports?.runtime
                        ?.message ||
                        "No scheduled session export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.session_exports?.format ||
                        "json"}
                      , every{" "}
                      {systemStatus.telemetry?.session_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.session_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.session_exports?.directory ||
                        "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.session_exports?.runtime?.details
                      ?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.session_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry?.session_exports?.runtime
                          ?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.session_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.session_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Session Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.session_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled session analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.session_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.session_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.session_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.session_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.session_analytics_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.session_analytics_exports
                            .runtime.details.last_export_at,
                        )}
                        {systemStatus.telemetry?.session_analytics_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.session_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.session_analytics_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Voucher Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.voucher_analytics_exports?.runtime
                        ?.message ||
                        "No scheduled voucher analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.voucher_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.voucher_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.voucher_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.voucher_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.voucher_analytics_exports
                          ?.runtime?.details?.window_hours || 720,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.voucher_analytics_exports
                          ?.runtime?.details?.bucket_count || 30,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.voucher_analytics_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.voucher_analytics_exports
                            .runtime.details.last_export_at,
                        )}
                        {systemStatus.telemetry?.voucher_analytics_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.voucher_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.voucher_analytics_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Voucher Aging Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.voucher_aging_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled voucher aging analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.voucher_aging_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.voucher_aging_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.voucher_aging_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.voucher_aging_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.voucher_aging_analytics_exports
                          ?.runtime?.details?.window_hours || 720,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.voucher_aging_analytics_exports
                          ?.runtime?.details?.bucket_count || 30,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.voucher_aging_analytics_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry
                            .voucher_aging_analytics_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry
                          ?.voucher_aging_analytics_exports?.runtime?.details
                          ?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.voucher_aging_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.voucher_aging_analytics_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Voucher Redemption Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry
                        ?.voucher_redemption_analytics_exports?.runtime
                        ?.message ||
                        "No scheduled voucher redemption analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry
                        ?.voucher_redemption_analytics_exports?.format ||
                        "json"}
                      , every{" "}
                      {systemStatus.telemetry
                        ?.voucher_redemption_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry
                        ?.voucher_redemption_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry
                        ?.voucher_redemption_analytics_exports?.directory ||
                        "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry
                          ?.voucher_redemption_analytics_exports?.runtime
                          ?.details?.window_hours || 720,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry
                          ?.voucher_redemption_analytics_exports?.runtime
                          ?.details?.bucket_count || 30,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry
                      ?.voucher_redemption_analytics_exports?.runtime?.details
                      ?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry
                            .voucher_redemption_analytics_exports.runtime
                            .details.last_export_at,
                        )}
                        {systemStatus.telemetry
                          ?.voucher_redemption_analytics_exports?.runtime
                          ?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.voucher_redemption_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry
                        ?.voucher_redemption_analytics_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Voucher Expiry Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.voucher_expiry_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled voucher expiry analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.voucher_expiry_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.voucher_expiry_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.voucher_expiry_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.voucher_expiry_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.voucher_expiry_analytics_exports
                          ?.runtime?.details?.window_hours || 720,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.voucher_expiry_analytics_exports
                          ?.runtime?.details?.bucket_count || 30,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.voucher_expiry_analytics_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry
                            .voucher_expiry_analytics_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry?.voucher_expiry_analytics_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.voucher_expiry_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.voucher_expiry_analytics_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Guest Lifecycle Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.guest_lifecycle_exports?.runtime
                        ?.message ||
                        "No scheduled guest lifecycle export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.guest_lifecycle_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.guest_lifecycle_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.guest_lifecycle_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.guest_lifecycle_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.guest_lifecycle_exports?.runtime
                          ?.details?.window_hours || 24,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.guest_lifecycle_exports?.runtime
                          ?.details?.bucket_count || 24,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.guest_lifecycle_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.guest_lifecycle_exports.runtime
                            .details.last_export_at,
                        )}
                        {systemStatus.telemetry?.guest_lifecycle_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.guest_lifecycle_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.guest_lifecycle_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Guest Invite Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.guest_invite_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled guest invite analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.guest_invite_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.guest_invite_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.guest_invite_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.guest_invite_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.guest_invite_analytics_exports
                          ?.runtime?.details?.window_hours || 24,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.guest_invite_analytics_exports
                          ?.runtime?.details?.bucket_count || 24,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.guest_invite_analytics_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.guest_invite_analytics_exports
                            .runtime.details.last_export_at,
                        )}
                        {systemStatus.telemetry?.guest_invite_analytics_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.guest_invite_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.guest_invite_analytics_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Guest Conversion Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.guest_conversion_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled guest conversion analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.guest_conversion_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.guest_conversion_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.guest_conversion_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.guest_conversion_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.guest_conversion_analytics_exports
                          ?.runtime?.details?.window_hours || 24,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.guest_conversion_analytics_exports
                          ?.runtime?.details?.bucket_count || 24,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.guest_conversion_analytics_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry
                            .guest_conversion_analytics_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry?.guest_conversion_analytics_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.guest_conversion_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.guest_conversion_analytics_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Guest Rejection Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.guest_rejection_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled guest rejection analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.guest_rejection_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.guest_rejection_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.guest_rejection_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.guest_rejection_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.guest_rejection_analytics_exports
                          ?.runtime?.details?.window_hours || 24,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.guest_rejection_analytics_exports
                          ?.runtime?.details?.bucket_count || 24,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.guest_rejection_analytics_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry
                            .guest_rejection_analytics_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry?.guest_rejection_analytics_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.guest_rejection_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.guest_rejection_analytics_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Guest Delivery Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.guest_delivery_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled guest delivery analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.guest_delivery_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.guest_delivery_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.guest_delivery_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.guest_delivery_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.guest_delivery_analytics_exports
                          ?.runtime?.details?.window_hours || 24,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.guest_delivery_analytics_exports
                          ?.runtime?.details?.bucket_count || 24,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.guest_delivery_analytics_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry
                            .guest_delivery_analytics_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry
                          ?.guest_delivery_analytics_exports?.runtime?.details
                          ?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.guest_delivery_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.guest_delivery_analytics_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Guest Delivery Failure Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.guest_delivery_failures_exports
                        ?.runtime?.message ||
                        "No scheduled guest delivery failure export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.guest_delivery_failures_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.guest_delivery_failures_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.guest_delivery_failures_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.guest_delivery_failures_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.guest_delivery_failures_exports
                          ?.runtime?.details?.window_hours || 24,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.guest_delivery_failures_exports
                          ?.runtime?.details?.bucket_count || 24,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.guest_delivery_failures_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.guest_delivery_failures_exports
                            .runtime.details.last_export_at,
                        )}
                        {systemStatus.telemetry?.guest_delivery_failures_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.guest_delivery_failures_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.guest_delivery_failures_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Guest Sponsor Analytics Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.guest_sponsor_analytics_exports
                        ?.runtime?.message ||
                        "No scheduled guest sponsor analytics export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.guest_sponsor_analytics_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.guest_sponsor_analytics_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.guest_sponsor_analytics_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.guest_sponsor_analytics_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      Window{" "}
                      {String(
                        systemStatus.telemetry?.guest_sponsor_analytics_exports
                          ?.runtime?.details?.window_hours || 24,
                      )}{" "}
                      hours with{" "}
                      {String(
                        systemStatus.telemetry?.guest_sponsor_analytics_exports
                          ?.runtime?.details?.bucket_count || 24,
                      )}{" "}
                      buckets.
                    </div>
                    {systemStatus.telemetry?.guest_sponsor_analytics_exports
                      ?.runtime?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.guest_sponsor_analytics_exports
                            .runtime.details.last_export_at,
                        )}
                        {systemStatus.telemetry?.guest_sponsor_analytics_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.guest_sponsor_analytics_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.guest_sponsor_analytics_exports
                        ?.runtime?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Integration Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.integration_exports?.runtime
                        ?.message ||
                        "No scheduled integration export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.integration_exports?.format ||
                        "json"}
                      , every{" "}
                      {systemStatus.telemetry?.integration_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.integration_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.integration_exports?.directory ||
                        "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.integration_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.integration_exports.runtime
                            .details.last_export_at,
                        )}
                        {systemStatus.telemetry?.integration_exports?.runtime
                          ?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.integration_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.integration_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled HA Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.ha_exports?.runtime?.message ||
                        "No scheduled HA export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.ha_exports?.format || "json"},
                      every{" "}
                      {systemStatus.telemetry?.ha_exports?.interval_minutes ||
                        0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.ha_exports?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.ha_exports?.directory || "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.ha_exports?.runtime?.details
                      ?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.ha_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry?.ha_exports?.runtime?.details
                          ?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.ha_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.ha_exports?.runtime?.status ||
                      "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Network Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.network_exports?.runtime
                        ?.message ||
                        "No scheduled network export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.network_exports?.format ||
                        "json"}
                      , every{" "}
                      {systemStatus.telemetry?.network_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.network_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.network_exports?.directory ||
                        "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.network_exports?.runtime?.details
                      ?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.network_exports.runtime.details
                            .last_export_at,
                        )}
                        {systemStatus.telemetry?.network_exports?.runtime
                          ?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.network_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.network_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Upstream AAA Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.upstream_aaa_exports?.runtime
                        ?.message ||
                        "No scheduled upstream AAA export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.upstream_aaa_exports?.format ||
                        "json"}
                      , every{" "}
                      {systemStatus.telemetry?.upstream_aaa_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.upstream_aaa_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.upstream_aaa_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.upstream_aaa_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.upstream_aaa_exports.runtime
                            .details.last_export_at,
                        )}
                        {systemStatus.telemetry?.upstream_aaa_exports?.runtime
                          ?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.upstream_aaa_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.upstream_aaa_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">
                      Scheduled Upgrade Readiness Exports
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.telemetry?.upgrade_readiness_exports
                        ?.runtime?.message ||
                        "No scheduled upgrade readiness export runtime status recorded yet."}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Format{" "}
                      {systemStatus.telemetry?.upgrade_readiness_exports
                        ?.format || "json"}
                      , every{" "}
                      {systemStatus.telemetry?.upgrade_readiness_exports
                        ?.interval_minutes || 0}{" "}
                      minutes, retain{" "}
                      {systemStatus.telemetry?.upgrade_readiness_exports
                        ?.retention_count || 0}
                      , directory{" "}
                      {systemStatus.telemetry?.upgrade_readiness_exports
                        ?.directory || "unset"}
                      .
                    </div>
                    {systemStatus.telemetry?.upgrade_readiness_exports?.runtime
                      ?.details?.last_export_at ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Last export{" "}
                        {String(
                          systemStatus.telemetry.upgrade_readiness_exports
                            .runtime.details.last_export_at,
                        )}
                        {systemStatus.telemetry?.upgrade_readiness_exports
                          ?.runtime?.details?.next_due_at
                          ? `, next due ${String(systemStatus.telemetry.upgrade_readiness_exports.runtime.details.next_due_at)}`
                          : ""}
                        .
                      </div>
                    ) : null}
                  </div>
                  <StatusBadge
                    status={
                      systemStatus.telemetry?.upgrade_readiness_exports?.runtime
                        ?.status || "disabled"
                    }
                  />
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>

      <section className="rounded-lg bg-white p-6 shadow">
        <h3 className="text-lg font-semibold text-gray-900">Operator Notes</h3>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <div className="rounded-md border border-gray-200 px-4 py-3 text-sm text-gray-700">
            {serviceProblems.length === 0
              ? "All required services are healthy or intentionally disabled."
              : `${serviceProblems.length} services need attention. Check the status cards above before changing auth or Wi-Fi policy.`}
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3 text-sm text-gray-700">
            Quarantined sessions are enforced immediately on the gateway path
            when a session is mapped into quarantine role, Filter-Id, or VLAN
            99.
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3 text-sm text-gray-700">
            Bandwidth profile changes now rebuild live shaping, and VLAN
            reassignment requests trigger reauthentication so clients re-enter
            the correct segment cleanly.
          </div>
        </div>
      </section>
    </div>
  );
}
