import { useEffect, useState } from 'react';
import api from '../api/client';

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
  state: 'enabled' | 'available' | 'warned' | 'degraded' | 'blocked';
  active: boolean;
  summary: string;
  recommendation?: string;
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
      prefer_external_ap: boolean;
      wireless_passthrough: boolean;
    };
    warnings: string[];
    capabilities: DeploymentCapability[];
  };
  radius: {
    upstream_enabled: boolean;
    realm: string;
    pool_strategy: string;
    configured_servers: Array<{ name: string; address: string; auth_port: number; acct_port: number }>;
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
    auto_stage_shared_package: boolean;
    preempt: boolean;
    shared_state_dir: string;
    runtime: RuntimeStatus;
    replication_runtime: RuntimeStatus;
    history_stats: {
      total_records: number;
      failover_promotions: number;
      failover_returns: number;
      peer_failures: number;
      peer_recoveries: number;
      vip_acquisitions: number;
      vip_preemptions: number;
      vip_releases: number;
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
      sync: RuntimeStatus;
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
  };
};

const statusTone: Record<string, string> = {
  ok: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  degraded: 'border-amber-200 bg-amber-50 text-amber-800',
  down: 'border-red-200 bg-red-50 text-red-800',
  disabled: 'border-gray-200 bg-gray-100 text-gray-700',
  unknown: 'border-slate-200 bg-slate-100 text-slate-700',
};

const cardTone: Record<string, string> = {
  sky: 'bg-sky-100 text-sky-700',
  emerald: 'bg-emerald-100 text-emerald-700',
  amber: 'bg-amber-100 text-amber-700',
  rose: 'bg-rose-100 text-rose-700',
  violet: 'bg-violet-100 text-violet-700',
  indigo: 'bg-indigo-100 text-indigo-700',
};

const capabilityTone: Record<DeploymentCapability['state'], string> = {
  enabled: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  available: 'border-sky-200 bg-sky-50 text-sky-800',
  warned: 'border-amber-200 bg-amber-50 text-amber-800',
  degraded: 'border-orange-200 bg-orange-50 text-orange-800',
  blocked: 'border-red-200 bg-red-50 text-red-800',
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
        <div className={`flex h-10 w-10 items-center justify-center rounded-md font-bold ${cardTone[tone]}`}>{mark}</div>
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
  return <span className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${tone}`}>{status}</span>;
}

export default function Dashboard() {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadStatus = async () => {
    try {
      const { data } = await api.get('/system/status');
      setSystemStatus(data);
      setError('');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load appliance status.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
    const timer = window.setInterval(loadStatus, 15000);
    return () => window.clearInterval(timer);
  }, []);

  if (loading) {
    return <div className="text-gray-600">Loading appliance status...</div>;
  }

  if (!systemStatus) {
    return <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{error || 'Appliance status is unavailable.'}</div>;
  }

  const services = systemStatus.services ?? [];
  const deploymentWarnings = systemStatus.deployment?.warnings ?? [];
  const deploymentCapabilities = systemStatus.deployment?.capabilities ?? [];
  const configuredServers = systemStatus.radius?.configured_servers ?? [];
  const radiusServerStatuses = systemStatus.radius?.server_statuses ?? [];
  const wirelessAuthModes = systemStatus.wireless?.auth_modes ?? [];
  const serviceProblems = services.filter((service) => !['ok', 'disabled'].includes(service.status));
  const sessionMethods = Object.entries(systemStatus.summary?.session_methods || {});
  const networkObservability = systemStatus.network_observability;
  const highAvailabilityStatus =
    systemStatus.high_availability.replication_runtime?.status === 'degraded'
      ? 'degraded'
      : systemStatus.high_availability.replication_runtime?.status === 'pending' &&
          !systemStatus.high_availability.runtime?.status
        ? 'pending'
        : systemStatus.high_availability.runtime?.status || (systemStatus.high_availability.enabled ? 'unknown' : 'disabled');

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Dashboard</h2>
          <p className="mt-1 text-sm text-gray-600">Live appliance health, access posture, and service readiness.</p>
        </div>
        <button onClick={loadStatus} className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700">
          Refresh
        </button>
      </div>

      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <MetricCard label="Users" value={systemStatus.summary.users} mark="US" tone="sky" />
        <MetricCard label="Active Sessions" value={systemStatus.summary.active_sessions} mark="SE" tone="emerald" />
        <MetricCard label="Quarantined Sessions" value={systemStatus.summary.quarantined_sessions} mark="QN" tone="rose" />
        <MetricCard label="Shaped Sessions" value={systemStatus.summary.shaped_sessions} mark="BW" tone="indigo" />
        <MetricCard label="Pending Changes" value={systemStatus.summary.pending_changes} mark="CH" tone="violet" />
        <MetricCard label="Unacknowledged Alerts" value={systemStatus.summary.unacknowledged_alerts} mark="AL" tone="amber" />
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
              <h3 className="text-lg font-semibold text-gray-900">Service Health</h3>
              <p className="mt-1 text-sm text-gray-600">Go services, core Linux services, and publish path readiness.</p>
            </div>
            <div className="text-sm text-gray-500">{systemStatus.generated_at}</div>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {services.map((service) => (
              <div key={service.key} className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">{service.label}</div>
                    <div className="mt-1 text-sm text-gray-600">{service.message || 'No status message.'}</div>
                    {service.port ? <div className="mt-1 text-xs text-gray-500">Port {service.port}</div> : null}
                  </div>
                  <StatusBadge status={service.status} />
                </div>
              </div>
            ))}
          </div>
        </section>

        <div className="space-y-6">
          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">Deployment Profile</h3>
            <div className="mt-4 rounded-md border border-gray-200 px-4 py-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-gray-900">{systemStatus.deployment.label}</div>
                  <div className="mt-1 text-sm text-gray-600">{systemStatus.deployment.summary}</div>
                </div>
                <StatusBadge status={deploymentWarnings.length === 0 ? 'ok' : 'degraded'} />
              </div>
              <div className="mt-3 text-sm text-gray-600">
                {systemStatus.deployment.form} form, {systemStatus.deployment.hardware.cpu_cores || 'unknown'} cores,{' '}
                {systemStatus.deployment.hardware.memory_mb || 'unknown'} MB RAM.
              </div>
              <div className="mt-1 text-xs text-gray-500">
                Recommended floor: {systemStatus.deployment.recommended_min_cores} cores and {systemStatus.deployment.recommended_min_memory} MB RAM.
              </div>
            </div>
            <div className="mt-4 grid gap-3">
              {deploymentCapabilities.map((capability) => (
                <div key={capability.key} className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-medium text-gray-900">{capability.label}</div>
                      <div className="mt-1 text-sm text-gray-600">{capability.summary}</div>
                    </div>
                    <span className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${capabilityTone[capability.state]}`}>{capability.state}</span>
                  </div>
                  {capability.recommendation ? <div className="mt-2 text-xs text-gray-500">{capability.recommendation}</div> : null}
                </div>
              ))}
            </div>
            <div className="mt-4 space-y-2">
              {deploymentWarnings.length === 0 ? (
                <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-600">
                  Hardware and feature choices look aligned with the selected profile.
                </div>
              ) : (
                deploymentWarnings.map((warning, index) => (
                  <div key={`deployment-warning-${index}`} className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                    {warning}
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">Upstream AAA</h3>
            <div className="mt-4 grid gap-3">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">{systemStatus.radius.upstream_enabled ? 'Upstream AAA Enabled' : 'Upstream AAA Disabled'}</div>
                    <div className="mt-1 text-sm text-gray-600">
                      Realm {systemStatus.radius.realm || 'not set'} with {systemStatus.radius.pool_strategy || 'no'} pool strategy.
                    </div>
                  </div>
                  <StatusBadge status={systemStatus.radius.upstream_enabled ? 'ok' : 'disabled'} />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">Broker Auth Path</div>
                    <div className="mt-1 text-sm text-gray-600">{systemStatus.radius.broker_auth?.message || 'No broker auth activity recorded yet.'}</div>
                  </div>
                  <StatusBadge status={systemStatus.radius.broker_auth?.status || 'unknown'} />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">Broker Accounting Path</div>
                    <div className="mt-1 text-sm text-gray-600">{systemStatus.radius.broker_accounting?.message || 'No broker accounting activity recorded yet.'}</div>
                  </div>
                  <StatusBadge status={systemStatus.radius.broker_accounting?.status || 'unknown'} />
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
                  <div key={`${server.name}-${server.address}-${server.auth_port}`} className="rounded-md border border-gray-200 px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-medium text-gray-900">{server.name}</div>
                        <div className="mt-1 text-sm text-gray-600">
                          {server.address}:{server.auth_port} auth, {server.acct_port} acct
                        </div>
                        <div className="mt-1 text-sm text-gray-600">{server.message || 'No per-server probe message.'}</div>
                        <div className="mt-1 text-xs text-gray-500">
                          {server.supports_status_server
                            ? `Status-Server probe${server.latency_ms ? ` ${server.latency_ms} ms` : ''}${server.response_code ? `, ${server.response_code}` : ''}`
                            : 'Per-server active probe disabled by config'}
                        </div>
                      </div>
                      <StatusBadge status={server.status || 'unknown'} />
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
            <h3 className="text-lg font-semibold text-gray-900">Wireless And Sessions</h3>
            <div className="mt-4 space-y-3">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">{systemStatus.wireless.enabled ? 'Wireless Enabled' : 'Wireless Disabled'}</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.wireless.enabled
                        ? `${systemStatus.wireless.interface || 'radio unset'} on channel ${systemStatus.wireless.channel} with ${systemStatus.wireless.ssid_count} SSIDs.`
                        : 'Use an external AP or enable the radio in Access Settings.'}
                    </div>
                  </div>
                  <StatusBadge status={systemStatus.wireless.enabled ? 'ok' : 'disabled'} />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="font-medium text-gray-900">SSID Auth Modes</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {wirelessAuthModes.length === 0 ? (
                    <span className="text-sm text-gray-500">No SSIDs configured yet.</span>
                  ) : (
                    wirelessAuthModes.map((mode) => (
                      <span key={mode} className="rounded-md bg-gray-100 px-2 py-1 text-xs font-medium text-gray-700">
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
                    <div className="text-sm text-gray-500">No active sessions yet.</div>
                  ) : (
                    sessionMethods.map(([method, count]) => (
                      <div key={method} className="flex items-center justify-between text-sm text-gray-700">
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
                    <div className="font-medium text-gray-900">Runtime Bandwidth Enforcement</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.enforcement.shaping_enabled
                        ? `${systemStatus.enforcement.shaping_interface || 'downstream interface unset'} is shaping ${systemStatus.enforcement.shaped_sessions} active sessions.`
                        : 'Runtime shaping is disabled until a downstream interface is configured.'}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">{systemStatus.enforcement.shaper?.message || 'No shaping status recorded yet.'}</div>
                  </div>
                  <StatusBadge status={systemStatus.enforcement.shaper?.status || (systemStatus.enforcement.shaping_enabled ? 'unknown' : 'disabled')} />
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">External Integrations</h3>
            <div className="mt-4 space-y-3">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">Admin SSO</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.integrations.admin_sso.enabled
                        ? `${systemStatus.integrations.admin_sso.provider || 'Provider unset'} admin sign-in is configured.`
                        : 'Token login remains available until you enable admin SSO.'}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">{systemStatus.integrations.admin_sso.session?.message || 'No admin SSO runtime status recorded yet.'}</div>
                    {systemStatus.integrations.admin_sso.redirect_url ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">{systemStatus.integrations.admin_sso.redirect_url}</div>
                    ) : null}
                    {systemStatus.integrations.admin_sso.session?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">Updated {systemStatus.integrations.admin_sso.session.updated_at}</div>
                    ) : null}
                  </div>
                  <StatusBadge status={systemStatus.integrations.admin_sso.session?.status || (systemStatus.integrations.admin_sso.enabled ? 'unknown' : 'disabled')} />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">SIEM Export</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.integrations.siem.enabled
                        ? `${systemStatus.integrations.siem.provider || 'Provider unset'} batch size ${systemStatus.integrations.siem.batch_size || 0}.`
                        : 'Configure webhook, Splunk HEC, or Elastic export when you need external event delivery.'}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">{systemStatus.integrations.siem.export?.message || 'No SIEM runtime status recorded yet.'}</div>
                    {systemStatus.integrations.siem.endpoint ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">{systemStatus.integrations.siem.endpoint}</div>
                    ) : null}
                    {systemStatus.integrations.siem.export?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">Updated {systemStatus.integrations.siem.export.updated_at}</div>
                    ) : null}
                  </div>
                  <StatusBadge status={systemStatus.integrations.siem.export?.status || (systemStatus.integrations.siem.enabled ? 'unknown' : 'disabled')} />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">Controller Automation</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.integrations.controller.enabled
                        ? `${systemStatus.integrations.controller.platform || 'Platform unset'} sync mode ${systemStatus.integrations.controller.sync_mode || 'unset'}${systemStatus.integrations.controller.site ? ` for ${systemStatus.integrations.controller.site}` : ''}.`
                        : 'Enable this only when AegisNAS is feeding an external AP or controller estate.'}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">{systemStatus.integrations.controller.sync?.message || 'No controller runtime status recorded yet.'}</div>
                    {systemStatus.integrations.controller.endpoint ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">{systemStatus.integrations.controller.endpoint}</div>
                    ) : null}
                    {systemStatus.integrations.controller.sync?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">Updated {systemStatus.integrations.controller.sync.updated_at}</div>
                    ) : null}
                  </div>
                  <StatusBadge status={systemStatus.integrations.controller.sync?.status || (systemStatus.integrations.controller.enabled ? 'unknown' : 'disabled')} />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">High Availability</div>
                    <div className="mt-1 text-sm text-gray-600">
                      {systemStatus.high_availability.enabled
                        ? `${systemStatus.high_availability.role || 'standby'} role watching ${systemStatus.high_availability.peer_api_url || 'peer unset'} with VIP ${systemStatus.high_availability.virtual_ip || 'unset'}.`
                        : 'Enterprise HA peer monitoring is disabled on this node.'}
                    </div>
                    {systemStatus.high_availability.runtime?.details?.effective_role ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Effective role {String(systemStatus.high_availability.runtime.details.effective_role)}
                        {systemStatus.high_availability.runtime?.details?.vip_assigned ? ', VIP currently assigned locally.' : ', VIP not assigned locally.'}
                      </div>
                    ) : null}
                    {systemStatus.high_availability.runtime?.details?.lease_holder ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Lease holder {String(systemStatus.high_availability.runtime.details.lease_holder)}
                        {systemStatus.high_availability.runtime?.details?.lease_expires_at
                          ? ` until ${String(systemStatus.high_availability.runtime.details.lease_expires_at)}`
                          : ''}
                        .
                      </div>
                    ) : null}
                    <div className="mt-1 text-xs text-gray-500">
                      {systemStatus.high_availability.replication_runtime?.message ||
                        `Shared replication every ${systemStatus.high_availability.replication_interval_seconds || 300}s with stale threshold ${systemStatus.high_availability.replication_stale_after_seconds || 900}s.`}
                    </div>
                    {systemStatus.high_availability.auto_stage_shared_package ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Auto-stage {String(systemStatus.high_availability.replication_runtime?.details?.auto_stage_status || 'enabled')}
                        {systemStatus.high_availability.replication_runtime?.details?.auto_stage_stage_id
                          ? ` with staged package ${String(systemStatus.high_availability.replication_runtime.details.auto_stage_stage_id)}`
                          : ''}
                        .
                      </div>
                    ) : null}
                    {systemStatus.high_availability.replication_runtime?.details?.latest_source_node ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Latest shared package from {String(systemStatus.high_availability.replication_runtime.details.latest_source_node)}
                        {systemStatus.high_availability.replication_runtime?.details?.latest_age_seconds !== undefined
                          ? `, age ${String(systemStatus.high_availability.replication_runtime.details.latest_age_seconds)}s`
                          : ''}
                        {systemStatus.high_availability.replication_runtime?.details?.stale ? ', marked stale.' : ', marked fresh.'}
                      </div>
                    ) : null}
                    <div className="mt-1 text-xs text-gray-500">
                      Promotions {systemStatus.high_availability.history_stats?.failover_promotions ?? 0}, peer failures {systemStatus.high_availability.history_stats?.peer_failures ?? 0}, replication publishes {systemStatus.high_availability.history_stats?.replication_publishes ?? 0}.
                    </div>
                    {systemStatus.high_availability.history_stats?.last_event_at ? (
                      <div className="mt-1 text-xs text-gray-500">HA history last updated {systemStatus.high_availability.history_stats.last_event_at}</div>
                    ) : null}
                    <div className="mt-1 text-xs text-gray-500">{systemStatus.high_availability.runtime?.message || 'No HA runtime status recorded yet.'}</div>
                    {systemStatus.high_availability.runtime?.details?.peer_health_url ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">{String(systemStatus.high_availability.runtime.details.peer_health_url)}</div>
                    ) : null}
                    {systemStatus.high_availability.replication_runtime?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">Replication updated {systemStatus.high_availability.replication_runtime.updated_at}</div>
                    ) : null}
                    {systemStatus.high_availability.runtime?.updated_at ? (
                      <div className="mt-1 text-xs text-gray-500">Updated {systemStatus.high_availability.runtime.updated_at}</div>
                    ) : null}
                  </div>
                  <StatusBadge status={highAvailabilityStatus} />
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-lg bg-white p-6 shadow">
            <h3 className="text-lg font-semibold text-gray-900">Edge Network Observability</h3>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="font-medium text-gray-900">Apply And Rollback Counters</div>
                <div className="mt-2 grid gap-2 text-sm text-gray-700">
                  <div className="flex items-center justify-between"><span>Apply successes</span><span className="font-semibold">{networkObservability.apply_stats.apply_success_count}</span></div>
                  <div className="flex items-center justify-between"><span>Apply failures</span><span className="font-semibold">{networkObservability.apply_stats.apply_failure_count}</span></div>
                  <div className="flex items-center justify-between"><span>Pending confirmations</span><span className="font-semibold">{networkObservability.apply_stats.pending_confirmation_count}</span></div>
                  <div className="flex items-center justify-between"><span>Manual rollbacks</span><span className="font-semibold">{networkObservability.apply_stats.rollback_count}</span></div>
                  <div className="flex items-center justify-between"><span>Auto-rollbacks</span><span className="font-semibold">{networkObservability.apply_stats.auto_rollback_count}</span></div>
                </div>
                <div className="mt-3 text-xs text-gray-500">
                  Last apply {networkObservability.apply_stats.last_applied_at || 'not recorded'}.
                  {networkObservability.apply_stats.last_failure_at ? ` Last failure ${networkObservability.apply_stats.last_failure_at}.` : ''}
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="font-medium text-gray-900">DHCP Lease Trend</div>
                <div className="mt-2 grid gap-2 text-sm text-gray-700">
                  <div className="flex items-center justify-between"><span>Window</span><span className="font-semibold">{networkObservability.lease_trends.window_hours}h</span></div>
                  <div className="flex items-center justify-between"><span>Unique MACs</span><span className="font-semibold">{networkObservability.lease_trends.unique_macs_window}</span></div>
                  <div className="flex items-center justify-between"><span>Active observations</span><span className="font-semibold">{networkObservability.lease_trends.active_observations_window}</span></div>
                  <div className="flex items-center justify-between"><span>Expired observations</span><span className="font-semibold">{networkObservability.lease_trends.expired_observations_window}</span></div>
                  <div className="flex items-center justify-between"><span>Peak concurrent leases</span><span className="font-semibold">{networkObservability.lease_trends.peak_concurrent_leases_window}</span></div>
                </div>
                <div className="mt-3 text-xs text-gray-500">
                  Latest lease observation {networkObservability.lease_trends.latest_observed_at || 'not recorded'}.
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">Management-Loss Safety Timer</div>
                    <div className="mt-1 text-sm text-gray-600">{networkObservability.recovery?.message || 'No risky edge-network recovery window is active.'}</div>
                    {networkObservability.recovery?.deadline ? (
                      <div className="mt-2 text-xs text-gray-500">Deadline {String(networkObservability.recovery.deadline)}</div>
                    ) : null}
                  </div>
                  <StatusBadge status={networkObservability.recovery?.status || 'disabled'} />
                </div>
              </div>
              <div className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">Controller Runtime Counters</div>
                    <div className="mt-1 text-sm text-gray-600">{networkObservability.controller_sync?.message || 'No controller runtime status recorded yet.'}</div>
                    <div className="mt-2 text-xs text-gray-500">
                      Syncs {networkObservability.controller_sync?.details?.sync_count ?? 0}, successes {networkObservability.controller_sync?.details?.success_count ?? 0}, failures {networkObservability.controller_sync?.details?.failure_count ?? 0}, last duration {networkObservability.controller_sync?.details?.last_duration_ms ?? 0} ms.
                    </div>
                  </div>
                  <StatusBadge status={networkObservability.controller_sync?.status || 'disabled'} />
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
              ? 'All required services are healthy or intentionally disabled.'
              : `${serviceProblems.length} services need attention. Check the status cards above before changing auth or Wi-Fi policy.`}
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3 text-sm text-gray-700">
            Quarantined sessions are enforced immediately on the gateway path when a session is mapped into quarantine role, Filter-Id, or VLAN 99.
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3 text-sm text-gray-700">
            Bandwidth profile changes now rebuild live shaping, and VLAN reassignment requests trigger reauthentication so clients re-enter the correct segment cleanly.
          </div>
        </div>
      </section>
    </div>
  );
}
