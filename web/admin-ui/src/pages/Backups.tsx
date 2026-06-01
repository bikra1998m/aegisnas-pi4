import { useEffect, useState } from "react";
import api from "../api/client";

type ReplicationManifest = {
  generated_at: string;
  source_node: string;
  source_role: string;
  schema_version: number;
  signature?: string;
  signature_algorithm?: string;
};

type StagedReplicationPackage = {
  id: string;
  imported_at: string;
  imported_by: string;
  imported_source?: string;
  activated_at?: string;
  activated_by?: string;
  ready: boolean;
  status: string;
  summary: string;
  config_valid: boolean;
  database_valid: boolean;
  network_state_present: boolean;
  package_checksum?: string;
  content_fingerprint?: string;
  encryption_algorithm?: string;
  encryption_status?: string;
  signature?: string;
  signature_algorithm?: string;
  signature_status?: string;
  activation_backup?: string;
  manifest: ReplicationManifest;
};

type SharedReplicationStatus = {
  present: boolean;
  package_path: string;
  metadata_path: string;
  published_at?: string;
  generated_at?: string;
  publish_mode?: string;
  source_node?: string;
  source_role?: string;
  schema_version?: number;
  package_size_bytes?: number;
  package_checksum?: string;
  content_fingerprint?: string;
  security_profile_hash?: string;
  encryption_algorithm?: string;
  encryption_status?: string;
  signature?: string;
  signature_algorithm?: string;
  signature_status?: string;
  network_state_present?: boolean;
};

type HAHistoryRecord = {
  id: number;
  event_type: string;
  status: string;
  summary: string;
  node_role?: string;
  actor?: string;
  details?: Record<string, any>;
  created_at: string;
};

type HAHistoryStats = {
  total_records: number;
  failover_promotions: number;
  failover_returns: number;
  peer_failures: number;
  peer_recoveries: number;
  vip_acquisitions: number;
  vip_preemptions: number;
  vip_releases: number;
  vip_announcements?: number;
  vip_announcement_failures?: number;
  replication_publishes: number;
  replication_failures: number;
  replication_stale_count: number;
  shared_stages: number;
  activations: number;
  last_event_at?: string;
};

type IntegrationHistoryRecord = {
  id: number;
  component: string;
  status: string;
  summary: string;
  details?: Record<string, any>;
  created_at: string;
};

type IntegrationHistoryStats = {
  total_records: number;
  controller_event_count: number;
  controller_success_count: number;
  controller_failure_count: number;
  mdm_sync_event_count: number;
  mdm_sync_success_count: number;
  mdm_sync_failure_count: number;
  posture_event_count: number;
  posture_success_count: number;
  posture_failure_count: number;
  last_event_at?: string;
};

type UpstreamAAAHistoryRecord = {
  id: number;
  server_name: string;
  address: string;
  auth_port: number;
  acct_port: number;
  status: string;
  message: string;
  response_code?: string;
  latency_ms: number;
  supports_status_server: boolean;
  checked_at: string;
  created_at: string;
};

type UpstreamAAAHistoryStats = {
  total_records: number;
  ok_count: number;
  degraded_count: number;
  down_count: number;
  disabled_count: number;
  avg_latency_ms: number;
  last_checked_at?: string;
};

type AuditHistoryRecord = {
  id: number;
  timestamp: string;
  user: string;
  action: string;
  details: string;
  result: string;
  ip_address: string;
};

type AuditHistoryStats = {
  total_records: number;
  unique_users: number;
  export_action_count: number;
  staged_change_count: number;
  network_action_count: number;
  ha_action_count: number;
  upgrade_action_count: number;
  guest_action_count: number;
  last_recorded_at?: string;
};

type SessionHistoryRecord = {
  id: string;
  username: string;
  mac: string;
  ip: string;
  auth_method: string;
  identity_source: string;
  vlan: number;
  role: string;
  bandwidth_profile: string;
  filter_id: string;
  radius_class: string;
  session_timeout: number;
  idle_timeout: number;
  acct_session_time: number;
  called_station_id: string;
  nas_identifier: string;
  radius_session_id: string;
  start_time: string;
  last_activity: string;
  end_time: string;
  stop_reason: string;
  bytes_in: number;
  bytes_out: number;
  total_bytes: number;
};

type SessionHistoryStats = {
  total_records: number;
  active_count: number;
  ended_count: number;
  accounted_record_count: number;
  bytes_in_total: number;
  bytes_out_total: number;
  traffic_total: number;
  acct_session_seconds_total: number;
  avg_acct_session_seconds: number;
  max_acct_session_seconds: number;
  last_started_at?: string;
  last_ended_at?: string;
};

type UpgradeReadinessReport = {
  generated_at: string;
  config_path: string;
  database_path: string;
  database_exists: boolean;
  database_size_bytes: number;
  current_schema_version: number;
  target_schema_version: number;
  config_valid: boolean;
  config_validation_error?: string;
  deployment_profile?: string;
  deployment_form?: string;
  rehearsal: {
    ran: boolean;
    succeeded: boolean;
    started_schema_version: number;
    result_schema_version: number;
    duration_milliseconds: number;
    error?: string;
  };
  recommendations?: string[];
};

type UpgradeRollbackInspection = {
  manifest: {
    package_version: string;
    generated_at: string;
    config_path: string;
    database_path: string;
    current_schema_version: number;
    target_schema_version: number;
    deployment_profile?: string;
    deployment_form?: string;
    database_copy_mode: string;
    contains_secrets: boolean;
  };
  package_size_bytes: number;
  has_config_yaml: boolean;
  has_system_settings: boolean;
  has_database: boolean;
  current_runtime_schema_version: number;
  runtime_target_schema_version: number;
  config_valid: boolean;
  config_validation_error?: string;
  database_path_matches: boolean;
  compatibility_status: string;
  online_restore_supported: boolean;
  warnings?: string[];
  restore_steps?: string[];
  required_confirmation_text?: string;
};

type SupportBundleSummary = {
  bundle_version: string;
  generated_at: string;
  config_path: string;
  database_path: string;
  deployment_profile?: string;
  deployment_form?: string;
  ha_role?: string;
  contains_secrets: boolean;
  redaction_note: string;
  archive_entries: string[];
  api_captures: string[];
  runtime_entries: string[];
  system_captures: string[];
  log_captures: string[];
  upgrade_diagnostics: string[];
};

type RuntimeStatusView = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type UpstreamAAAHealth = {
  name: string;
  address: string;
  auth_port: number;
  acct_port: number;
  status: string;
  message: string;
  response_code?: string;
  latency_ms?: number;
  checked_at: string;
  supports_status_server: boolean;
};

type DiagnosticsReport = {
  generated_at: string;
  config_path: string;
  database_path: string;
  schema_version: number;
  deployment_profile?: string;
  deployment_form?: string;
  ha_role?: string;
  summary: {
    users: number;
    active_sessions: number;
    quarantined_sessions: number;
    shaped_sessions: number;
    unacknowledged_alerts: number;
    session_methods?: Record<string, number>;
  };
  sessions: SessionHistoryStats;
  guest: {
    summary: {
      total_records: number;
      pending_count: number;
      approved_count: number;
      rejected_count: number;
      completed_count: number;
      approval_delivery_failed_count: number;
      invite_failed_count: number;
      unique_guests_window: number;
      unique_sponsors_window: number;
      avg_approval_minutes: number;
      avg_completion_minutes: number;
      latest_submitted_at?: string;
      latest_completed_at?: string;
    };
    runtime?: RuntimeStatusView;
  };
  audit: AuditHistoryStats;
  network: {
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
    recovery_state?: {
      pending: boolean;
      backup_id?: string;
      deadline?: string;
      remaining_seconds?: number;
      grace_period_seconds?: number;
      risk_summary?: string;
      validation_summary?: string;
      status?: string;
      message?: string;
      requested_by?: string;
      confirmed_by?: string;
      confirmed_at?: string;
      rolled_back_at?: string;
    };
  };
  high_availability: {
    enabled: boolean;
    role?: string;
    stats: HAHistoryStats;
    runtime?: RuntimeStatusView;
  };
  upgrade: UpgradeReadinessReport;
  integrations: {
    controller?: RuntimeStatusView;
    siem?: RuntimeStatusView;
    admin_sso?: RuntimeStatusView;
    device_inventory?: RuntimeStatusView;
    mdm_sync?: RuntimeStatusView;
    posture_checks?: RuntimeStatusView;
    history_stats?: IntegrationHistoryStats;
    upstream_aaa?: UpstreamAAAHealth[];
    upstream_aaa_history?: UpstreamAAAHistoryStats;
    upstream_aaa_probe_error?: string;
  };
  runtime_statuses: RuntimeStatusView[];
};

type DiagnosticsExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type DiagnosticsExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type AuditExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type AuditExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type SessionExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type SessionExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type SessionAnalyticsExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type SessionAnalyticsExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type GuestLifecycleExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type GuestLifecycleExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type GuestDeliveryAnalyticsExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type GuestDeliveryAnalyticsExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type IntegrationExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type IntegrationExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type HAExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type HAExportArtifact = {
  name: string;
  path: string;
  kind?: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type NetworkExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type NetworkExportArtifact = {
  name: string;
  path: string;
  kind: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type UpstreamAAAExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type UpstreamAAAExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type UpgradeReadinessExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type UpgradeReadinessExportArtifact = {
  name: string;
  path: string;
  format: string;
  size_bytes: number;
  created_at: string;
};

type SupportBundleExportRuntime = {
  component: string;
  status: string;
  message: string;
  updated_at: string;
  details?: Record<string, any>;
};

type SupportBundleExportArtifact = {
  name: string;
  path: string;
  size_bytes: number;
  created_at: string;
};

export default function Backups() {
  const [configFile, setConfigFile] = useState<File | null>(null);
  const [replicationFile, setReplicationFile] = useState<File | null>(null);
  const [upgradeRollbackFile, setUpgradeRollbackFile] = useState<File | null>(
    null,
  );
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [stagedPackages, setStagedPackages] = useState<
    StagedReplicationPackage[]
  >([]);
  const [sharedStatus, setSharedStatus] =
    useState<SharedReplicationStatus | null>(null);
  const [haHistory, setHAHistory] = useState<HAHistoryRecord[]>([]);
  const [haHistoryStats, setHAHistoryStats] = useState<HAHistoryStats | null>(
    null,
  );
  const [auditHistory, setAuditHistory] = useState<AuditHistoryRecord[]>([]);
  const [auditHistoryStats, setAuditHistoryStats] =
    useState<AuditHistoryStats | null>(null);
  const [sessionHistory, setSessionHistory] = useState<SessionHistoryRecord[]>(
    [],
  );
  const [sessionHistoryStats, setSessionHistoryStats] =
    useState<SessionHistoryStats | null>(null);
  const [integrationHistory, setIntegrationHistory] = useState<
    IntegrationHistoryRecord[]
  >([]);
  const [integrationHistoryStats, setIntegrationHistoryStats] =
    useState<IntegrationHistoryStats | null>(null);
  const [upstreamAAAHistory, setUpstreamAAAHistory] = useState<
    UpstreamAAAHistoryRecord[]
  >([]);
  const [upstreamAAAHistoryStats, setUpstreamAAAHistoryStats] =
    useState<UpstreamAAAHistoryStats | null>(null);
  const [diagnosticsReport, setDiagnosticsReport] =
    useState<DiagnosticsReport | null>(null);
  const [diagnosticsExportRuntime, setDiagnosticsExportRuntime] =
    useState<DiagnosticsExportRuntime | null>(null);
  const [diagnosticsExportArtifacts, setDiagnosticsExportArtifacts] = useState<
    DiagnosticsExportArtifact[]
  >([]);
  const [auditExportRuntime, setAuditExportRuntime] =
    useState<AuditExportRuntime | null>(null);
  const [auditExportArtifacts, setAuditExportArtifacts] = useState<
    AuditExportArtifact[]
  >([]);
  const [sessionExportRuntime, setSessionExportRuntime] =
    useState<SessionExportRuntime | null>(null);
  const [sessionExportArtifacts, setSessionExportArtifacts] = useState<
    SessionExportArtifact[]
  >([]);
  const [sessionAnalyticsExportRuntime, setSessionAnalyticsExportRuntime] =
    useState<SessionAnalyticsExportRuntime | null>(null);
  const [sessionAnalyticsExportArtifacts, setSessionAnalyticsExportArtifacts] =
    useState<SessionAnalyticsExportArtifact[]>([]);
  const [guestLifecycleExportRuntime, setGuestLifecycleExportRuntime] =
    useState<GuestLifecycleExportRuntime | null>(null);
  const [guestLifecycleExportArtifacts, setGuestLifecycleExportArtifacts] =
    useState<GuestLifecycleExportArtifact[]>([]);
  const [
    guestDeliveryAnalyticsExportRuntime,
    setGuestDeliveryAnalyticsExportRuntime,
  ] = useState<GuestDeliveryAnalyticsExportRuntime | null>(null);
  const [
    guestDeliveryAnalyticsExportArtifacts,
    setGuestDeliveryAnalyticsExportArtifacts,
  ] = useState<GuestDeliveryAnalyticsExportArtifact[]>([]);
  const [integrationExportRuntime, setIntegrationExportRuntime] =
    useState<IntegrationExportRuntime | null>(null);
  const [integrationExportArtifacts, setIntegrationExportArtifacts] = useState<
    IntegrationExportArtifact[]
  >([]);
  const [haExportRuntime, setHAExportRuntime] =
    useState<HAExportRuntime | null>(null);
  const [haExportArtifacts, setHAExportArtifacts] = useState<
    HAExportArtifact[]
  >([]);
  const [networkExportRuntime, setNetworkExportRuntime] =
    useState<NetworkExportRuntime | null>(null);
  const [networkExportArtifacts, setNetworkExportArtifacts] = useState<
    NetworkExportArtifact[]
  >([]);
  const [upstreamAAAExportRuntime, setUpstreamAAAExportRuntime] =
    useState<UpstreamAAAExportRuntime | null>(null);
  const [upstreamAAAExportArtifacts, setUpstreamAAAExportArtifacts] = useState<
    UpstreamAAAExportArtifact[]
  >([]);
  const [upgradeReadinessExportRuntime, setUpgradeReadinessExportRuntime] =
    useState<UpgradeReadinessExportRuntime | null>(null);
  const [upgradeReadinessExportArtifacts, setUpgradeReadinessExportArtifacts] =
    useState<UpgradeReadinessExportArtifact[]>([]);
  const [supportBundleExportRuntime, setSupportBundleExportRuntime] =
    useState<SupportBundleExportRuntime | null>(null);
  const [supportBundleExportArtifacts, setSupportBundleExportArtifacts] =
    useState<SupportBundleExportArtifact[]>([]);
  const [upgradeReadiness, setUpgradeReadiness] =
    useState<UpgradeReadinessReport | null>(null);
  const [upgradeRollbackInspection, setUpgradeRollbackInspection] =
    useState<UpgradeRollbackInspection | null>(null);
  const [supportBundleSummary, setSupportBundleSummary] =
    useState<SupportBundleSummary | null>(null);
  const [loadingStages, setLoadingStages] = useState(true);
  const [loadingSharedStatus, setLoadingSharedStatus] = useState(true);
  const [loadingHAHistory, setLoadingHAHistory] = useState(true);
  const [loadingAuditHistory, setLoadingAuditHistory] = useState(true);
  const [loadingSessionHistory, setLoadingSessionHistory] = useState(true);
  const [loadingIntegrationHistory, setLoadingIntegrationHistory] =
    useState(true);
  const [loadingUpstreamAAAHistory, setLoadingUpstreamAAAHistory] =
    useState(true);
  const [loadingDiagnosticsReport, setLoadingDiagnosticsReport] =
    useState(false);
  const [loadingDiagnosticsExports, setLoadingDiagnosticsExports] =
    useState(false);
  const [loadingAuditExports, setLoadingAuditExports] = useState(false);
  const [loadingSessionExports, setLoadingSessionExports] = useState(false);
  const [loadingSessionAnalyticsExports, setLoadingSessionAnalyticsExports] =
    useState(false);
  const [loadingGuestLifecycleExports, setLoadingGuestLifecycleExports] =
    useState(false);
  const [
    loadingGuestDeliveryAnalyticsExports,
    setLoadingGuestDeliveryAnalyticsExports,
  ] = useState(false);
  const [loadingIntegrationExports, setLoadingIntegrationExports] =
    useState(false);
  const [loadingHAExports, setLoadingHAExports] = useState(false);
  const [loadingNetworkExports, setLoadingNetworkExports] = useState(false);
  const [loadingUpstreamAAAExports, setLoadingUpstreamAAAExports] =
    useState(false);
  const [loadingUpgradeReadinessExports, setLoadingUpgradeReadinessExports] =
    useState(false);
  const [loadingSupportBundleExports, setLoadingSupportBundleExports] =
    useState(false);
  const [loadingUpgradeReadiness, setLoadingUpgradeReadiness] = useState(false);
  const [loadingUpgradeRollbackInspect, setLoadingUpgradeRollbackInspect] =
    useState(false);
  const [loadingSupportBundleSummary, setLoadingSupportBundleSummary] =
    useState(false);
  const [upgradeRollbackConfirmationText, setUpgradeRollbackConfirmationText] =
    useState("");
  const [busyAction, setBusyAction] = useState("");

  const loadStages = async () => {
    setLoadingStages(true);
    try {
      const { data } = await api.get("/system/ha/replication-staged");
      setStagedPackages(data.packages || []);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load staged replication packages.",
      );
    } finally {
      setLoadingStages(false);
    }
  };

  const loadSharedStatus = async () => {
    setLoadingSharedStatus(true);
    try {
      const { data } = await api.get("/system/ha/replication-shared");
      setSharedStatus(data.shared || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load shared HA replication status.",
      );
    } finally {
      setLoadingSharedStatus(false);
    }
  };

  const loadHAHistory = async () => {
    setLoadingHAHistory(true);
    try {
      const { data } = await api.get("/system/ha/history");
      setHAHistory(data.history || []);
      setHAHistoryStats(data.stats || null);
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not load HA history.",
      );
    } finally {
      setLoadingHAHistory(false);
    }
  };

  const loadIntegrationHistory = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingIntegrationHistory(true);
    try {
      const { data } = await api.get("/system/integration-history");
      setIntegrationHistory(data.history || []);
      setIntegrationHistoryStats(data.stats || null);
      if (announce) {
        setMessage("Integration history refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load integration history.",
      );
    } finally {
      setLoadingIntegrationHistory(false);
    }
  };

  const loadUpstreamAAAHistory = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingUpstreamAAAHistory(true);
    try {
      const { data } = await api.get("/system/upstream-aaa-history");
      setUpstreamAAAHistory(data.history || []);
      setUpstreamAAAHistoryStats(data.stats || null);
      if (announce) {
        setMessage("Upstream AAA history refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load upstream AAA history.",
      );
    } finally {
      setLoadingUpstreamAAAHistory(false);
    }
  };

  const loadAuditHistory = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingAuditHistory(true);
    try {
      const { data } = await api.get("/system/audit-history");
      setAuditHistory(data.history || []);
      setAuditHistoryStats(data.stats || null);
      if (announce) {
        setMessage("Audit history refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not load audit history.",
      );
    } finally {
      setLoadingAuditHistory(false);
    }
  };

  const loadSessionHistory = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingSessionHistory(true);
    try {
      const { data } = await api.get("/system/session-history");
      setSessionHistory(data.history || []);
      setSessionHistoryStats(data.stats || null);
      if (announce) {
        setMessage("Session history refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not load session history.",
      );
    } finally {
      setLoadingSessionHistory(false);
    }
  };

  const loadDiagnosticsReport = async (announce = true) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingDiagnosticsReport(true);
    try {
      const { data } = await api.get("/system/diagnostics-report");
      setDiagnosticsReport(data);
      if (announce) {
        setMessage("Diagnostics report refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load diagnostics report.",
      );
    } finally {
      setLoadingDiagnosticsReport(false);
    }
  };

  const loadDiagnosticsExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingDiagnosticsExports(true);
    try {
      const { data } = await api.get("/system/diagnostics-exports");
      setDiagnosticsExportRuntime(data.runtime || null);
      setDiagnosticsExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled diagnostics exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled diagnostics exports.",
      );
    } finally {
      setLoadingDiagnosticsExports(false);
    }
  };

  const loadAuditExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingAuditExports(true);
    try {
      const { data } = await api.get("/system/audit-exports");
      setAuditExportRuntime(data.runtime || null);
      setAuditExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled audit exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled audit exports.",
      );
    } finally {
      setLoadingAuditExports(false);
    }
  };

  const loadSessionExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingSessionExports(true);
    try {
      const { data } = await api.get("/system/session-exports");
      setSessionExportRuntime(data.runtime || null);
      setSessionExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled session exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled session exports.",
      );
    } finally {
      setLoadingSessionExports(false);
    }
  };

  const loadSessionAnalyticsExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingSessionAnalyticsExports(true);
    try {
      const { data } = await api.get("/system/session-analytics-exports");
      setSessionAnalyticsExportRuntime(data.runtime || null);
      setSessionAnalyticsExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled session analytics exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled session analytics exports.",
      );
    } finally {
      setLoadingSessionAnalyticsExports(false);
    }
  };

  const loadGuestLifecycleExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingGuestLifecycleExports(true);
    try {
      const { data } = await api.get("/system/guest-lifecycle-exports");
      setGuestLifecycleExportRuntime(data.runtime || null);
      setGuestLifecycleExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled guest lifecycle exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled guest lifecycle exports.",
      );
    } finally {
      setLoadingGuestLifecycleExports(false);
    }
  };

  const loadGuestDeliveryAnalyticsExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingGuestDeliveryAnalyticsExports(true);
    try {
      const { data } = await api.get(
        "/system/guest-delivery-analytics-exports",
      );
      setGuestDeliveryAnalyticsExportRuntime(data.runtime || null);
      setGuestDeliveryAnalyticsExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled guest delivery analytics exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled guest delivery analytics exports.",
      );
    } finally {
      setLoadingGuestDeliveryAnalyticsExports(false);
    }
  };

  const loadIntegrationExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingIntegrationExports(true);
    try {
      const { data } = await api.get("/system/integration-exports");
      setIntegrationExportRuntime(data.runtime || null);
      setIntegrationExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled integration exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled integration exports.",
      );
    } finally {
      setLoadingIntegrationExports(false);
    }
  };

  const loadHAExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingHAExports(true);
    try {
      const { data } = await api.get("/system/ha/exports");
      setHAExportRuntime(data.runtime || null);
      setHAExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled HA exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled HA exports.",
      );
    } finally {
      setLoadingHAExports(false);
    }
  };

  const loadNetworkExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingNetworkExports(true);
    try {
      const { data } = await api.get("/system/network-exports");
      setNetworkExportRuntime(data.runtime || null);
      setNetworkExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled network exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled network exports.",
      );
    } finally {
      setLoadingNetworkExports(false);
    }
  };

  const loadUpstreamAAAExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingUpstreamAAAExports(true);
    try {
      const { data } = await api.get("/system/upstream-aaa-exports");
      setUpstreamAAAExportRuntime(data.runtime || null);
      setUpstreamAAAExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled upstream AAA exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled upstream AAA exports.",
      );
    } finally {
      setLoadingUpstreamAAAExports(false);
    }
  };

  const loadUpgradeReadinessExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingUpgradeReadinessExports(true);
    try {
      const { data } = await api.get("/system/upgrade-readiness-exports");
      setUpgradeReadinessExportRuntime(data.runtime || null);
      setUpgradeReadinessExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled upgrade readiness exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled upgrade readiness exports.",
      );
    } finally {
      setLoadingUpgradeReadinessExports(false);
    }
  };

  const loadSupportBundleExports = async (announce = false) => {
    if (announce) {
      setError("");
      setMessage("");
    }
    setLoadingSupportBundleExports(true);
    try {
      const { data } = await api.get("/system/support-bundle-exports");
      setSupportBundleExportRuntime(data.runtime || null);
      setSupportBundleExportArtifacts(data.exports || []);
      if (announce) {
        setMessage("Scheduled support bundle exports refreshed.");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load scheduled support bundle exports.",
      );
    } finally {
      setLoadingSupportBundleExports(false);
    }
  };

  useEffect(() => {
    void loadStages();
    void loadSharedStatus();
    void loadHAHistory();
    void loadAuditHistory(false);
    void loadSessionHistory(false);
    void loadIntegrationHistory(false);
    void loadUpstreamAAAHistory(false);
    void loadDiagnosticsReport(false);
    void loadDiagnosticsExports(false);
    void loadAuditExports(false);
    void loadSessionExports(false);
    void loadSessionAnalyticsExports(false);
    void loadGuestLifecycleExports(false);
    void loadGuestDeliveryAnalyticsExports(false);
    void loadIntegrationExports(false);
    void loadHAExports(false);
    void loadNetworkExports(false);
    void loadUpstreamAAAExports(false);
    void loadUpgradeReadinessExports(false);
    void loadSupportBundleExports(false);
    void loadSupportBundleSummary();
  }, []);

  const downloadConfigBackup = async () => {
    setError("");
    setMessage("");
    try {
      const { data } = await api.get("/backups/config", {
        responseType: "blob",
      });
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      link.download = "aegisnas-config-backup.json";
      link.click();
      URL.revokeObjectURL(url);
      setMessage("Config JSON backup downloaded.");
    } catch (err: any) {
      setError(err.response?.data || err.message || "Download failed.");
    }
  };

  const uploadConfigBackup = async () => {
    if (!configFile) return;
    if (
      !confirm(
        "Restore this config JSON? A safety revision will be created first.",
      )
    )
      return;
    setError("");
    setMessage("");
    setBusyAction("config-restore");
    try {
      await api.post("/backups/config", await configFile.text(), {
        headers: { "Content-Type": "application/json" },
      });
      setMessage("Config JSON restored.");
      window.dispatchEvent(new Event("config-applied"));
    } catch (err: any) {
      setError(err.response?.data || err.message || "Upload failed.");
    } finally {
      setBusyAction("");
    }
  };

  const downloadReplicationPackage = async () => {
    setError("");
    setMessage("");
    setBusyAction("replication-download");
    try {
      const response = await api.get("/system/ha/replication-package", {
        responseType: "blob",
      });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || "aegisnas-ha-replication.pkg";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        "HA replication package downloaded. Import it on the standby appliance, then activate it there.",
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download HA replication package.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadSupportBundle = async () => {
    setError("");
    setMessage("");
    setBusyAction("support-bundle");
    try {
      const response = await api.get("/system/support-bundle", {
        responseType: "blob",
      });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || "aegisnas-support-bundle.zip";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        "Support bundle downloaded. It includes redacted settings, runtime health, network, integration, and HA history, plus best-effort service diagnostics.",
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download support bundle.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledSupportBundleExport = async (
    artifact: SupportBundleExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-support-bundle-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/support-bundle-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        `Scheduled support bundle export ${artifact.name} downloaded.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled support bundle export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadDiagnosticsReport = async (format: "json" | "csv") => {
    setError("");
    setMessage("");
    setBusyAction(`diagnostics-report-${format}`);
    try {
      const response = await api.get(
        `/system/diagnostics-report/export?format=${format}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download =
        filenameMatch?.[1] || `aegisnas-diagnostics-report.${format}`;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Diagnostics report downloaded as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download diagnostics report.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledDiagnosticsExport = async (
    artifact: DiagnosticsExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-diagnostics-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/diagnostics-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Scheduled diagnostics export ${artifact.name} downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled diagnostics export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledAuditExport = async (
    artifact: AuditExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-audit-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/audit-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Scheduled audit export ${artifact.name} downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled audit export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledSessionExport = async (
    artifact: SessionExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-session-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/session-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Scheduled session export ${artifact.name} downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled session export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledSessionAnalyticsExport = async (
    artifact: SessionAnalyticsExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-session-analytics-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/session-analytics-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        `Scheduled session analytics export ${artifact.name} downloaded.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled session analytics export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledGuestLifecycleExport = async (
    artifact: GuestLifecycleExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-guest-lifecycle-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/guest-lifecycle-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        `Scheduled guest lifecycle export ${artifact.name} downloaded.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled guest lifecycle export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledGuestDeliveryAnalyticsExport = async (
    artifact: GuestDeliveryAnalyticsExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-guest-delivery-analytics-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/guest-delivery-analytics-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        `Scheduled guest delivery analytics export ${artifact.name} downloaded.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled guest delivery analytics export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledIntegrationExport = async (
    artifact: IntegrationExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-integration-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/integration-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Scheduled integration export ${artifact.name} downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled integration export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledHAExport = async (artifact: HAExportArtifact) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-ha-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/ha/exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Scheduled HA export ${artifact.name} downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled HA export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledNetworkExport = async (
    artifact: NetworkExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-network-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/network-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Scheduled network export ${artifact.name} downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled network export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledUpstreamAAAExport = async (
    artifact: UpstreamAAAExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-upstream-aaa-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/upstream-aaa-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Scheduled upstream AAA export ${artifact.name} downloaded.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled upstream AAA export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const downloadScheduledUpgradeReadinessExport = async (
    artifact: UpgradeReadinessExportArtifact,
  ) => {
    setError("");
    setMessage("");
    setBusyAction(`scheduled-upgrade-readiness-${artifact.name}`);
    try {
      const response = await api.get(
        `/system/upgrade-readiness-exports/download?name=${encodeURIComponent(artifact.name)}`,
        { responseType: "blob" },
      );
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || artifact.name;
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        `Scheduled upgrade readiness export ${artifact.name} downloaded.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download scheduled upgrade readiness export.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const loadSupportBundleSummary = async () => {
    setLoadingSupportBundleSummary(true);
    try {
      const { data } = await api.get("/system/support-bundle/summary");
      setSupportBundleSummary(data);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load support bundle summary.",
      );
    } finally {
      setLoadingSupportBundleSummary(false);
    }
  };

  const downloadOpenAPISchema = async () => {
    setError("");
    setMessage("");
    setBusyAction("openapi-schema");
    try {
      const response = await api.get("/openapi.json", { responseType: "blob" });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || "aegisnas-admin-api-openapi.json";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        "Admin API OpenAPI schema downloaded. It includes endpoint groups, bearer-auth requirements, and AegisNAS role hints.",
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download the OpenAPI schema.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const loadUpgradeReadiness = async () => {
    setError("");
    setLoadingUpgradeReadiness(true);
    try {
      const { data } = await api.get("/system/upgrade-readiness");
      setUpgradeReadiness(data);
      setMessage("Upgrade readiness refreshed.");
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load upgrade readiness.",
      );
    } finally {
      setLoadingUpgradeReadiness(false);
    }
  };

  const downloadUpgradeRollbackPackage = async () => {
    setError("");
    setMessage("");
    setBusyAction("upgrade-rollback-package");
    try {
      const response = await api.get("/system/upgrade-rollback-package", {
        responseType: "blob",
      });
      const { data, headers } = response;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      const disposition = `${headers?.["content-disposition"] || ""}`;
      const filenameMatch = disposition.match(/filename=\"?([^\";]+)\"?/i);
      link.download = filenameMatch?.[1] || "aegisnas-upgrade-rollback.zip";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(
        "Upgrade rollback package downloaded. It contains a live config copy and a consistent database snapshot, so store it like credentials.",
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not download upgrade rollback package.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const inspectUpgradeRollbackPackage = async () => {
    if (!upgradeRollbackFile) return;
    setError("");
    setMessage("");
    setLoadingUpgradeRollbackInspect(true);
    try {
      const form = new FormData();
      form.append("package", upgradeRollbackFile);
      const { data } = await api.post(
        "/system/upgrade-rollback-package/inspect",
        form,
        {
          headers: { "Content-Type": "multipart/form-data" },
        },
      );
      setUpgradeRollbackInspection(data.inspection || null);
      setUpgradeRollbackConfirmationText("");
      setMessage(
        `Rollback package ${data.filename || upgradeRollbackFile.name} inspected.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not inspect upgrade rollback package.",
      );
      setUpgradeRollbackInspection(null);
    } finally {
      setLoadingUpgradeRollbackInspect(false);
    }
  };

  const restoreUpgradeRollbackPackage = async () => {
    if (!upgradeRollbackFile || !upgradeRollbackInspection) return;
    if (
      !confirm(
        "Restore this upgrade rollback package onto the appliance? A safety rollback package will be captured first.",
      )
    )
      return;
    setError("");
    setMessage("");
    setBusyAction("upgrade-rollback-restore");
    try {
      const form = new FormData();
      form.append("package", upgradeRollbackFile);
      form.append("confirmation_text", upgradeRollbackConfirmationText);
      const { data } = await api.post(
        "/system/upgrade-rollback-package/restore",
        form,
        {
          headers: { "Content-Type": "multipart/form-data" },
        },
      );
      setMessage(
        `Upgrade rollback package restored. Safety package saved at ${data.safety_package_path}.${data.restart_required ? " Restart the appliance services before continuing." : ""}`,
      );
      window.dispatchEvent(new Event("config-applied"));
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not restore upgrade rollback package.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const uploadReplicationPackage = async () => {
    if (!replicationFile) return;
    setError("");
    setMessage("");
    setBusyAction("replication-upload");
    try {
      const form = new FormData();
      form.append("package", replicationFile);
      const { data } = await api.post("/system/ha/replication-package", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setMessage(
        `Replication package ${data.package?.id || ""} is staged and validated on this node.`,
      );
      await loadStages();
      await loadHAHistory();
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not stage HA replication package.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const stageLatestSharedPackage = async () => {
    if (
      !confirm(
        "Stage the latest shared HA package on this node? This is intended for the standby appliance before activation.",
      )
    )
      return;
    setError("");
    setMessage("");
    setBusyAction("replication-stage-shared");
    try {
      const { data } = await api.post(
        "/system/ha/replication-stage-shared",
        {},
      );
      setMessage(
        data.message ||
          `Shared replication package ${data.package?.id || ""} is staged on this node.`,
      );
      await loadStages();
      await loadSharedStatus();
      await loadHAHistory();
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not stage the latest shared HA replication package.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const activateReplicationPackage = async (pkg: StagedReplicationPackage) => {
    if (
      !confirm(
        `Activate staged package ${pkg.id}? This is intended for standby appliances and will restart services after local safety backup capture.`,
      )
    )
      return;
    setError("");
    setMessage("");
    setBusyAction(`activate-${pkg.id}`);
    try {
      const { data } = await api.post("/system/ha/replication-activate", {
        id: pkg.id,
      });
      setMessage(
        data.message ||
          `Replication package ${pkg.id} was activated and service restart was scheduled.`,
      );
      await loadStages();
      await loadSharedStatus();
      await loadHAHistory();
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not activate staged HA replication package.",
      );
    } finally {
      setBusyAction("");
    }
  };

  const exportHAHistory = async (format: "csv" | "json") => {
    setError("");
    setMessage("");
    try {
      const response = await api.get(
        `/system/ha/history/export?format=${format}`,
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        format === "json"
          ? "aegisnas-ha-history.json"
          : "aegisnas-ha-history.csv";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`HA history exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not export HA history.",
      );
    }
  };

  const exportIntegrationHistory = async (format: "csv" | "json") => {
    setError("");
    setMessage("");
    try {
      const response = await api.get(
        `/system/integration-history/export?format=${format}`,
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        format === "json"
          ? "aegisnas-integration-history.json"
          : "aegisnas-integration-history.csv";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Integration history exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not export integration history.",
      );
    }
  };

  const exportUpstreamAAAHistory = async (format: "csv" | "json") => {
    setError("");
    setMessage("");
    try {
      const response = await api.get(
        `/system/upstream-aaa-history/export?format=${format}`,
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        format === "json"
          ? "aegisnas-upstream-aaa-history.json"
          : "aegisnas-upstream-aaa-history.csv";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Upstream AAA history exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not export upstream AAA history.",
      );
    }
  };

  const exportAuditHistory = async (format: "csv" | "json") => {
    setError("");
    setMessage("");
    try {
      const response = await api.get(
        `/system/audit-history/export?format=${format}`,
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        format === "json"
          ? "aegisnas-audit-history.json"
          : "aegisnas-audit-history.csv";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Audit history exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not export audit history.",
      );
    }
  };

  const exportSessionHistory = async (format: "csv" | "json") => {
    setError("");
    setMessage("");
    try {
      const response = await api.get(
        `/system/session-history/export?format=${format}`,
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        format === "json"
          ? "aegisnas-session-history.json"
          : "aegisnas-session-history.csv";
      link.click();
      URL.revokeObjectURL(url);
      setMessage(`Session history exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not export session history.",
      );
    }
  };

  const integrationComponentLabel = (component: string) => {
    switch (component) {
      case "controller_automation":
        return "Controller";
      case "mdm_sync":
        return "MDM Sync";
      case "posture_checks":
        return "Posture Checks";
      default:
        return component;
    }
  };

  return (
    <div>
      <h2 className="mb-6 text-2xl font-bold text-gray-900">Backups</h2>
      {message && (
        <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          {message}
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {String(error)}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-2">
        <section className="rounded-lg bg-white p-6 shadow">
          <h3 className="mb-2 text-lg font-semibold">Config Snapshot</h3>
          <p className="mb-4 text-sm text-gray-600">
            Export or restore the admin-managed JSON config snapshot for users,
            vouchers, roles, profiles, policies, identity sources, and RADIUS
            clients.
          </p>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={downloadConfigBackup}
              disabled={busyAction !== ""}
              className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800 disabled:opacity-50"
            >
              Download JSON
            </button>
            <input
              type="file"
              accept="application/json,.json"
              onChange={(event) =>
                setConfigFile(event.target.files?.[0] ?? null)
              }
              className="max-w-full text-sm"
            />
            <button
              disabled={!configFile || busyAction !== ""}
              onClick={uploadConfigBackup}
              className="rounded-md bg-amber-700 px-4 py-2 text-white hover:bg-amber-800 disabled:opacity-50"
            >
              Upload And Restore
            </button>
          </div>
          <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            {loadingSharedStatus ? (
              <span>Loading shared HA replication status...</span>
            ) : sharedStatus?.present ? (
              <span>
                Latest shared package from{" "}
                <span className="font-medium">
                  {sharedStatus.source_node || "unknown"}
                </span>
                {sharedStatus.published_at
                  ? ` published ${sharedStatus.published_at}`
                  : ""}
                .
                {sharedStatus.publish_mode
                  ? ` Publish mode ${sharedStatus.publish_mode}.`
                  : ""}
                {sharedStatus.schema_version
                  ? ` Schema v${sharedStatus.schema_version}.`
                  : ""}
                {sharedStatus.encryption_status
                  ? ` Encryption ${sharedStatus.encryption_status}${sharedStatus.encryption_algorithm ? ` via ${sharedStatus.encryption_algorithm}` : ""}.`
                  : ""}
                {sharedStatus.signature_status
                  ? ` Signature ${sharedStatus.signature_status}.`
                  : ""}
              </span>
            ) : (
              <span>
                No shared HA package has been published yet. The active node
                will create one during the continuous replication interval.
              </span>
            )}
          </div>
        </section>

        <section className="rounded-lg bg-white p-6 shadow">
          <h3 className="mb-2 text-lg font-semibold">
            Standby Replication Package
          </h3>
          <p className="mb-4 text-sm text-gray-600">
            Package the live config, database, and managed network state from
            the active appliance, then stage and activate that package on a
            standby peer.
          </p>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={downloadReplicationPackage}
              disabled={busyAction !== ""}
              className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50"
            >
              Download HA Package
            </button>
            <input
              type="file"
              accept=".pkg,.tar.gz,application/octet-stream,application/gzip,application/x-gzip"
              onChange={(event) =>
                setReplicationFile(event.target.files?.[0] ?? null)
              }
              className="max-w-full text-sm"
            />
            <button
              disabled={!replicationFile || busyAction !== ""}
              onClick={uploadReplicationPackage}
              className="rounded-md bg-emerald-700 px-4 py-2 text-white hover:bg-emerald-800 disabled:opacity-50"
            >
              Stage On This Node
            </button>
            <button
              disabled={busyAction !== "" || !sharedStatus?.present}
              onClick={stageLatestSharedPackage}
              className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50"
            >
              Stage Latest Shared Package
            </button>
          </div>
          <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            Activation keeps the{" "}
            <span className="font-medium">
              local HA role, peer URL, and database path
            </span>{" "}
            so the standby does not accidentally impersonate the active node’s
            identity.
          </div>
        </section>
      </div>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Support Bundle
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Capture a downloadable operator bundle with redacted settings,
              runtime status, HA and network history, and best-effort service
              logs for troubleshooting.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => void downloadOpenAPISchema()}
              disabled={busyAction !== ""}
              className="rounded-md bg-sky-700 px-4 py-2 text-white hover:bg-sky-800 disabled:opacity-50"
            >
              Download OpenAPI JSON
            </button>
            <button
              onClick={() => void downloadSupportBundle()}
              disabled={busyAction !== ""}
              className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50"
            >
              Download Support Bundle
            </button>
          </div>
        </div>
        <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
          The OpenAPI schema documents the admin API surface, bearer-auth
          requirements, and role hints so integrations and runbooks can target
          the same contract the appliance is serving right now.
        </div>
        <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
          {loadingSupportBundleSummary ? (
            <span>Loading support bundle summary...</span>
          ) : supportBundleSummary ? (
            <div className="space-y-2">
              <div>
                Bundle v
                <span className="font-medium">
                  {supportBundleSummary.bundle_version}
                </span>{" "}
                for {supportBundleSummary.deployment_profile || "unknown"} /{" "}
                {supportBundleSummary.deployment_form || "unknown"}
                {supportBundleSummary.ha_role
                  ? ` with HA role ${supportBundleSummary.ha_role}`
                  : ""}
                .
              </div>
              <div>{supportBundleSummary.redaction_note}</div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">
                    API captures
                  </div>
                  <div className="mt-1 font-semibold text-slate-900">
                    {supportBundleSummary.api_captures.length}
                  </div>
                </div>
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">
                    System captures
                  </div>
                  <div className="mt-1 font-semibold text-slate-900">
                    {supportBundleSummary.system_captures.length}
                  </div>
                </div>
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">
                    Log captures
                  </div>
                  <div className="mt-1 font-semibold text-slate-900">
                    {supportBundleSummary.log_captures.length}
                  </div>
                </div>
                <div className="rounded border border-slate-200 bg-white px-3 py-2">
                  <div className="text-xs uppercase tracking-wide text-slate-500">
                    Archive entries
                  </div>
                  <div className="mt-1 font-semibold text-slate-900">
                    {supportBundleSummary.archive_entries.length}
                  </div>
                </div>
              </div>
              <div className="text-xs text-slate-500">
                Upgrade diagnostics included:{" "}
                {supportBundleSummary.upgrade_diagnostics.join(", ")}
              </div>
            </div>
          ) : (
            <span>Support bundle summary is not available yet.</span>
          )}
        </div>
        <div className="mt-4 rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="font-medium text-slate-900">
                Scheduled Support Bundle Exports
              </div>
              <div className="mt-1">
                Keep recurring redacted support bundles on disk so incident
                handoffs already have a durable troubleshooting package without
                waiting for a manual click.
              </div>
            </div>
            <button
              onClick={() => void loadSupportBundleExports(true)}
              disabled={loadingSupportBundleExports || busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {loadingSupportBundleExports
                ? "Refreshing..."
                : "Refresh Scheduled Support Bundle Exports"}
            </button>
          </div>
          {supportBundleExportRuntime ? (
            <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
              <div>
                <span className="font-medium text-slate-900">Runtime:</span>{" "}
                {supportBundleExportRuntime.status} /{" "}
                {supportBundleExportRuntime.message}
              </div>
              <div className="mt-1">
                ZIP bundle every{" "}
                {String(
                  supportBundleExportRuntime.details?.interval_minutes || 0,
                )}{" "}
                minutes, retain{" "}
                {String(
                  supportBundleExportRuntime.details?.retention_count || 0,
                )}
                , directory{" "}
                {String(
                  supportBundleExportRuntime.details?.directory || "unset",
                )}
                .
              </div>
              {supportBundleExportRuntime.details?.last_export_at ? (
                <div className="mt-1">
                  Last export{" "}
                  {String(supportBundleExportRuntime.details.last_export_at)}
                  {supportBundleExportRuntime.details?.next_due_at
                    ? `, next due ${String(supportBundleExportRuntime.details.next_due_at)}`
                    : ""}
                  .
                </div>
              ) : null}
            </div>
          ) : (
            <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
              No scheduled support bundle export runtime has been recorded yet.
            </div>
          )}
          {supportBundleExportArtifacts.length === 0 ? (
            <div className="mt-3 text-xs text-gray-500">
              No scheduled support bundle export artifacts are present yet.
            </div>
          ) : (
            <div className="mt-3 overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 text-xs">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-3 py-2 text-left font-medium text-gray-600">
                      Created
                    </th>
                    <th className="px-3 py-2 text-left font-medium text-gray-600">
                      Name
                    </th>
                    <th className="px-3 py-2 text-left font-medium text-gray-600">
                      Type
                    </th>
                    <th className="px-3 py-2 text-left font-medium text-gray-600">
                      Size
                    </th>
                    <th className="px-3 py-2 text-left font-medium text-gray-600">
                      Path
                    </th>
                    <th className="px-3 py-2 text-left font-medium text-gray-600">
                      Action
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {supportBundleExportArtifacts.map((artifact) => (
                    <tr key={artifact.name}>
                      <td className="px-3 py-2 text-gray-600">
                        {artifact.created_at}
                      </td>
                      <td className="px-3 py-2 font-medium text-gray-900">
                        {artifact.name}
                      </td>
                      <td className="px-3 py-2 text-gray-700">zip</td>
                      <td className="px-3 py-2 text-gray-700">
                        {artifact.size_bytes} bytes
                      </td>
                      <td className="px-3 py-2 text-gray-500 break-all">
                        {artifact.path}
                      </td>
                      <td className="px-3 py-2">
                        <button
                          onClick={() =>
                            void downloadScheduledSupportBundleExport(artifact)
                          }
                          disabled={busyAction !== ""}
                          className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                        >
                          Download
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Diagnostics Report
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Capture one cross-domain operations snapshot with session counts,
              network safety state, HA signals, upgrade readiness, and
              integration health.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => void loadDiagnosticsReport()}
              disabled={loadingDiagnosticsReport || busyAction !== ""}
              className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50"
            >
              {loadingDiagnosticsReport ? "Refreshing..." : "Refresh Report"}
            </button>
            <button
              onClick={() => void downloadDiagnosticsReport("json")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-4 py-2 text-gray-800 hover:bg-gray-50 disabled:opacity-50"
            >
              Download JSON
            </button>
            <button
              onClick={() => void downloadDiagnosticsReport("csv")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-4 py-2 text-gray-800 hover:bg-gray-50 disabled:opacity-50"
            >
              Download CSV
            </button>
          </div>
        </div>

        {!diagnosticsReport ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            {loadingDiagnosticsReport
              ? "Loading diagnostics report..."
              : "Refresh the diagnostics report to capture a current operations snapshot."}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Sessions</div>
                <div className="mt-2">
                  {diagnosticsReport.summary.active_sessions} active,{" "}
                  {diagnosticsReport.summary.quarantined_sessions} quarantined,{" "}
                  {diagnosticsReport.summary.users} users
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Guest Access</div>
                <div className="mt-2">
                  {diagnosticsReport.guest.summary.pending_count} pending,{" "}
                  {diagnosticsReport.guest.summary.approved_count} approved,{" "}
                  {diagnosticsReport.guest.summary.completed_count} completed
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Network Apply</div>
                <div className="mt-2">
                  {diagnosticsReport.network.apply_stats.apply_success_count}{" "}
                  success,{" "}
                  {diagnosticsReport.network.apply_stats.apply_failure_count}{" "}
                  failed, {diagnosticsReport.network.apply_stats.rollback_count}{" "}
                  rollbacks
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Lease Window</div>
                <div className="mt-2">
                  {diagnosticsReport.network.lease_trends.unique_macs_window}{" "}
                  MACs,{" "}
                  {
                    diagnosticsReport.network.lease_trends
                      .peak_concurrent_leases_window
                  }{" "}
                  peak active
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">HA</div>
                <div className="mt-2">
                  {diagnosticsReport.high_availability.enabled
                    ? diagnosticsReport.high_availability.role || "enabled"
                    : "disabled"}
                  ,{" "}
                  {
                    diagnosticsReport.high_availability.stats
                      .failover_promotions
                  }{" "}
                  promotions
                </div>
              </div>
            </div>

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div>
                <span className="font-medium text-slate-900">Generated:</span>{" "}
                {diagnosticsReport.generated_at}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">Deployment:</span>{" "}
                {diagnosticsReport.deployment_profile || "unknown"} /{" "}
                {diagnosticsReport.deployment_form || "unknown"}
                {diagnosticsReport.ha_role
                  ? ` / ${diagnosticsReport.ha_role}`
                  : ""}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">Schema:</span> v
                {diagnosticsReport.schema_version}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">Config path:</span>{" "}
                {diagnosticsReport.config_path}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">
                  Database path:
                </span>{" "}
                {diagnosticsReport.database_path}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">
                  Runtime components tracked:
                </span>{" "}
                {diagnosticsReport.runtime_statuses.length}
              </div>
            </div>

            {diagnosticsReport.network.recovery_state ? (
              <div
                className={`rounded-md border px-4 py-3 text-sm ${diagnosticsReport.network.recovery_state.pending ? "border-amber-200 bg-amber-50 text-amber-900" : "border-slate-200 bg-slate-50 text-slate-700"}`}
              >
                <div className="font-medium">
                  {diagnosticsReport.network.recovery_state.pending
                    ? "Management confirmation is still pending."
                    : "Network recovery state is available."}
                </div>
                <div className="mt-1">
                  {diagnosticsReport.network.recovery_state.message ||
                    "No recovery message was recorded."}
                </div>
                {diagnosticsReport.network.recovery_state.risk_summary ? (
                  <div className="mt-1">
                    <span className="font-medium">Risk:</span>{" "}
                    {diagnosticsReport.network.recovery_state.risk_summary}
                  </div>
                ) : null}
                {diagnosticsReport.network.recovery_state.validation_summary ? (
                  <div className="mt-1">
                    <span className="font-medium">Validation:</span>{" "}
                    {
                      diagnosticsReport.network.recovery_state
                        .validation_summary
                    }
                  </div>
                ) : null}
              </div>
            ) : null}

            <div className="grid gap-4 xl:grid-cols-2">
              <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">
                  Session Methods
                </div>
                {Object.entries(diagnosticsReport.summary.session_methods || {})
                  .length === 0 ? (
                  <div className="mt-2 text-slate-500">
                    No session method data is available yet.
                  </div>
                ) : (
                  <div className="mt-2 space-y-1">
                    {Object.entries(
                      diagnosticsReport.summary.session_methods || {},
                    ).map(([method, count]) => (
                      <div
                        key={method}
                        className="flex items-center justify-between gap-3"
                      >
                        <span>{method}</span>
                        <span className="font-medium text-slate-900">
                          {count}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">
                  Guest Lifecycle
                </div>
                <div className="mt-2">
                  {diagnosticsReport.guest.summary.total_records} requests,{" "}
                  {diagnosticsReport.guest.summary.unique_guests_window} unique
                  guests,{" "}
                  {diagnosticsReport.guest.summary.unique_sponsors_window}{" "}
                  sponsors in the current window.
                </div>
                <div className="mt-2 text-slate-600">
                  {diagnosticsReport.guest.summary.rejected_count} rejected,{" "}
                  {
                    diagnosticsReport.guest.summary
                      .approval_delivery_failed_count
                  }{" "}
                  approval deliveries failed,{" "}
                  {diagnosticsReport.guest.summary.invite_failed_count} invite
                  deliveries failed.
                </div>
                <div className="mt-2 text-slate-600">
                  Average approval{" "}
                  {diagnosticsReport.guest.summary.avg_approval_minutes}{" "}
                  minutes, average completion{" "}
                  {diagnosticsReport.guest.summary.avg_completion_minutes}{" "}
                  minutes.
                </div>
                {diagnosticsReport.guest.summary.latest_submitted_at ? (
                  <div className="mt-2 text-slate-600">
                    Latest guest submission{" "}
                    {diagnosticsReport.guest.summary.latest_submitted_at}
                    {diagnosticsReport.guest.summary.latest_completed_at
                      ? `, latest completion ${diagnosticsReport.guest.summary.latest_completed_at}`
                      : ""}
                    .
                  </div>
                ) : null}
                {diagnosticsReport.guest.runtime ? (
                  <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                    <div className="font-medium text-slate-900">
                      Guest Workflow Runtime
                    </div>
                    <div className="mt-1">
                      {diagnosticsReport.guest.runtime.status}:{" "}
                      {diagnosticsReport.guest.runtime.message || "ok"}
                    </div>
                  </div>
                ) : null}
              </div>

              <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Integrations</div>
                <div className="mt-2 grid gap-2 md:grid-cols-2">
                  {[
                    {
                      label: "Controller",
                      status: diagnosticsReport.integrations.controller,
                    },
                    {
                      label: "SIEM",
                      status: diagnosticsReport.integrations.siem,
                    },
                    {
                      label: "Admin SSO",
                      status: diagnosticsReport.integrations.admin_sso,
                    },
                    {
                      label: "Device Inventory",
                      status: diagnosticsReport.integrations.device_inventory,
                    },
                    {
                      label: "MDM Sync",
                      status: diagnosticsReport.integrations.mdm_sync,
                    },
                    {
                      label: "Posture Checks",
                      status: diagnosticsReport.integrations.posture_checks,
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="rounded border border-slate-200 bg-slate-50 px-3 py-2"
                    >
                      <div className="font-medium text-slate-900">
                        {item.label}
                      </div>
                      <div className="mt-1">
                        {item.status
                          ? `${item.status.status}: ${item.status.message || "ok"}`
                          : "not reported"}
                      </div>
                    </div>
                  ))}
                </div>
                {diagnosticsReport.integrations.upstream_aaa_probe_error ? (
                  <div className="mt-3 text-red-700">
                    <span className="font-medium">
                      Upstream AAA probe error:
                    </span>{" "}
                    {diagnosticsReport.integrations.upstream_aaa_probe_error}
                  </div>
                ) : null}
                {diagnosticsReport.integrations.upstream_aaa &&
                diagnosticsReport.integrations.upstream_aaa.length > 0 ? (
                  <div className="mt-3">
                    <div className="font-medium text-slate-900">
                      Upstream AAA
                    </div>
                    <div className="mt-2 space-y-1">
                      {diagnosticsReport.integrations.upstream_aaa.map(
                        (item) => (
                          <div
                            key={`${item.name || item.address}-${item.auth_port}`}
                            className="flex flex-wrap items-center justify-between gap-3 rounded border border-slate-200 bg-slate-50 px-3 py-2"
                          >
                            <span>{item.name || item.address}</span>
                            <span className="text-slate-900">
                              {item.status}
                              {item.latency_ms
                                ? ` / ${item.latency_ms} ms`
                                : ""}
                            </span>
                          </div>
                        ),
                      )}
                    </div>
                  </div>
                ) : null}
                {diagnosticsReport.integrations.history_stats ? (
                  <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                    <div className="font-medium text-slate-900">
                      Integration History
                    </div>
                    <div className="mt-1">
                      Controller{" "}
                      {
                        diagnosticsReport.integrations.history_stats
                          .controller_success_count
                      }
                      /
                      {
                        diagnosticsReport.integrations.history_stats
                          .controller_event_count
                      }{" "}
                      successful, MDM{" "}
                      {
                        diagnosticsReport.integrations.history_stats
                          .mdm_sync_success_count
                      }
                      /
                      {
                        diagnosticsReport.integrations.history_stats
                          .mdm_sync_event_count
                      }{" "}
                      successful, posture{" "}
                      {
                        diagnosticsReport.integrations.history_stats
                          .posture_success_count
                      }
                      /
                      {
                        diagnosticsReport.integrations.history_stats
                          .posture_event_count
                      }{" "}
                      successful.
                    </div>
                    {diagnosticsReport.integrations.history_stats
                      .last_event_at ? (
                      <div className="mt-1">
                        Last recorded integration event{" "}
                        {
                          diagnosticsReport.integrations.history_stats
                            .last_event_at
                        }
                        .
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {diagnosticsReport.integrations.upstream_aaa_history ? (
                  <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                    <div className="font-medium text-slate-900">
                      Upstream AAA History
                    </div>
                    <div className="mt-1">
                      {
                        diagnosticsReport.integrations.upstream_aaa_history
                          .ok_count
                      }{" "}
                      ok,{" "}
                      {
                        diagnosticsReport.integrations.upstream_aaa_history
                          .degraded_count
                      }{" "}
                      degraded,{" "}
                      {
                        diagnosticsReport.integrations.upstream_aaa_history
                          .down_count
                      }{" "}
                      down,{" "}
                      {
                        diagnosticsReport.integrations.upstream_aaa_history
                          .disabled_count
                      }{" "}
                      disabled.
                    </div>
                    <div className="mt-1">
                      Average healthy latency{" "}
                      {
                        diagnosticsReport.integrations.upstream_aaa_history
                          .avg_latency_ms
                      }{" "}
                      ms
                      {diagnosticsReport.integrations.upstream_aaa_history
                        .last_checked_at
                        ? `, last probe ${diagnosticsReport.integrations.upstream_aaa_history.last_checked_at}`
                        : ""}
                      .
                    </div>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div className="font-medium text-slate-900">Upgrade Signal</div>
              <div className="mt-2">
                Config{" "}
                {diagnosticsReport.upgrade.config_valid ? "valid" : "invalid"},
                schema v{diagnosticsReport.upgrade.current_schema_version} to v
                {diagnosticsReport.upgrade.target_schema_version}, rehearsal{" "}
                {diagnosticsReport.upgrade.rehearsal.ran
                  ? diagnosticsReport.upgrade.rehearsal.succeeded
                    ? "passed"
                    : "failed"
                  : "not run"}
                .
              </div>
              {diagnosticsReport.upgrade.recommendations &&
              diagnosticsReport.upgrade.recommendations.length > 0 ? (
                <div className="mt-2 text-slate-600">
                  {diagnosticsReport.upgrade.recommendations.length} readiness
                  recommendations are attached to this report.
                </div>
              ) : null}
            </div>

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div className="font-medium text-slate-900">Audit Signal</div>
              <div className="mt-2">
                {diagnosticsReport.audit.total_records} audit records across{" "}
                {diagnosticsReport.audit.unique_users} user
                {diagnosticsReport.audit.unique_users === 1 ? "" : "s"}, with{" "}
                {diagnosticsReport.audit.export_action_count} export actions and{" "}
                {diagnosticsReport.audit.network_action_count} network actions.
              </div>
              {diagnosticsReport.audit.last_recorded_at ? (
                <div className="mt-2 text-slate-600">
                  Last recorded audit action{" "}
                  {diagnosticsReport.audit.last_recorded_at}.
                </div>
              ) : null}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Guest Delivery Analytics Exports
                  </div>
                  <div className="mt-1">
                    Keep sponsor backlog, invite delivery failures, and approval
                    timing summaries on disk so operator reviews do not depend
                    on a live pull during a rough moment.
                  </div>
                </div>
                <button
                  onClick={() => void loadGuestDeliveryAnalyticsExports(true)}
                  disabled={
                    loadingGuestDeliveryAnalyticsExports || busyAction !== ""
                  }
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingGuestDeliveryAnalyticsExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Guest Delivery Analytics Exports"}
                </button>
              </div>
              {guestDeliveryAnalyticsExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {guestDeliveryAnalyticsExportRuntime.status} /{" "}
                    {guestDeliveryAnalyticsExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(
                      guestDeliveryAnalyticsExportRuntime.details?.format ||
                        "json",
                    )}
                    , every{" "}
                    {String(
                      guestDeliveryAnalyticsExportRuntime.details
                        ?.interval_minutes || 0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(
                      guestDeliveryAnalyticsExportRuntime.details
                        ?.retention_count || 0,
                    )}
                    , directory{" "}
                    {String(
                      guestDeliveryAnalyticsExportRuntime.details?.directory ||
                        "unset",
                    )}
                    .
                  </div>
                  <div className="mt-1">
                    Window{" "}
                    {String(
                      guestDeliveryAnalyticsExportRuntime.details
                        ?.window_hours || 24,
                    )}{" "}
                    hours with{" "}
                    {String(
                      guestDeliveryAnalyticsExportRuntime.details
                        ?.bucket_count || 24,
                    )}{" "}
                    buckets, limit{" "}
                    {String(
                      guestDeliveryAnalyticsExportRuntime.details?.limit ||
                        5000,
                    )}
                    .
                  </div>
                  {guestDeliveryAnalyticsExportRuntime.details
                    ?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(
                        guestDeliveryAnalyticsExportRuntime.details
                          .last_export_at,
                      )}
                      {guestDeliveryAnalyticsExportRuntime.details?.next_due_at
                        ? `, next due ${String(guestDeliveryAnalyticsExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled guest delivery analytics export runtime has been
                  recorded yet.
                </div>
              )}
              {guestDeliveryAnalyticsExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled guest delivery analytics export artifacts are
                  present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {guestDeliveryAnalyticsExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledGuestDeliveryAnalyticsExport(
                                  artifact,
                                )
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Diagnostics Exports
                  </div>
                  <div className="mt-1">
                    Keep recurring report artifacts on the appliance so support
                    handoffs don’t depend on someone remembering to click export
                    at the right moment.
                  </div>
                </div>
                <button
                  onClick={() => void loadDiagnosticsExports(true)}
                  disabled={loadingDiagnosticsExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingDiagnosticsExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Exports"}
                </button>
              </div>
              {diagnosticsExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {diagnosticsExportRuntime.status} /{" "}
                    {diagnosticsExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(diagnosticsExportRuntime.details?.format || "json")}
                    , every{" "}
                    {String(
                      diagnosticsExportRuntime.details?.interval_minutes || 0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(
                      diagnosticsExportRuntime.details?.retention_count || 0,
                    )}
                    , directory{" "}
                    {String(
                      diagnosticsExportRuntime.details?.directory || "unset",
                    )}
                    .
                  </div>
                  {diagnosticsExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(diagnosticsExportRuntime.details.last_export_at)}
                      {diagnosticsExportRuntime.details?.next_due_at
                        ? `, next due ${String(diagnosticsExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled diagnostics export runtime has been recorded yet.
                </div>
              )}
              {diagnosticsExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled diagnostics export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {diagnosticsExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledDiagnosticsExport(
                                  artifact,
                                )
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Audit Exports
                  </div>
                  <div className="mt-1">
                    Keep a recurring audit timeline on disk so change windows,
                    incident reviews, and handoffs do not depend on manual
                    export clicks.
                  </div>
                </div>
                <button
                  onClick={() => void loadAuditExports(true)}
                  disabled={loadingAuditExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingAuditExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Audit Exports"}
                </button>
              </div>
              {auditExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {auditExportRuntime.status} / {auditExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(auditExportRuntime.details?.format || "json")},
                    every{" "}
                    {String(auditExportRuntime.details?.interval_minutes || 0)}{" "}
                    minutes, retain{" "}
                    {String(auditExportRuntime.details?.retention_count || 0)},
                    directory{" "}
                    {String(auditExportRuntime.details?.directory || "unset")}.
                  </div>
                  {auditExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(auditExportRuntime.details.last_export_at)}
                      {auditExportRuntime.details?.next_due_at
                        ? `, next due ${String(auditExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled audit export runtime has been recorded yet.
                </div>
              )}
              {auditExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled audit export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {auditExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledAuditExport(artifact)
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Session Exports
                  </div>
                  <div className="mt-1">
                    Keep recurring session and accounting exports on disk so
                    access timelines and byte-count handoffs are ready without a
                    manual export step.
                  </div>
                </div>
                <button
                  onClick={() => void loadSessionExports(true)}
                  disabled={loadingSessionExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingSessionExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Session Exports"}
                </button>
              </div>
              {sessionExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {sessionExportRuntime.status} /{" "}
                    {sessionExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(sessionExportRuntime.details?.format || "json")},
                    every{" "}
                    {String(
                      sessionExportRuntime.details?.interval_minutes || 0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(sessionExportRuntime.details?.retention_count || 0)}
                    , directory{" "}
                    {String(sessionExportRuntime.details?.directory || "unset")}
                    .
                  </div>
                  {sessionExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(sessionExportRuntime.details.last_export_at)}
                      {sessionExportRuntime.details?.next_due_at
                        ? `, next due ${String(sessionExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled session export runtime has been recorded yet.
                </div>
              )}
              {sessionExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled session export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {sessionExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledSessionExport(artifact)
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Session Analytics Exports
                  </div>
                  <div className="mt-1">
                    Keep recurring access-pattern snapshots on disk so
                    concurrency, auth mix, and ended-session trend reviews do
                    not depend on a manual analytics export.
                  </div>
                </div>
                <button
                  onClick={() => void loadSessionAnalyticsExports(true)}
                  disabled={loadingSessionAnalyticsExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingSessionAnalyticsExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Session Analytics Exports"}
                </button>
              </div>
              {sessionAnalyticsExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {sessionAnalyticsExportRuntime.status} /{" "}
                    {sessionAnalyticsExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(
                      sessionAnalyticsExportRuntime.details?.format || "json",
                    )}
                    , every{" "}
                    {String(
                      sessionAnalyticsExportRuntime.details?.interval_minutes ||
                        0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(
                      sessionAnalyticsExportRuntime.details?.retention_count ||
                        0,
                    )}
                    , directory{" "}
                    {String(
                      sessionAnalyticsExportRuntime.details?.directory ||
                        "unset",
                    )}
                    .
                  </div>
                  <div className="mt-1">
                    Window{" "}
                    {String(
                      sessionAnalyticsExportRuntime.details?.window_hours || 24,
                    )}{" "}
                    hours with{" "}
                    {String(
                      sessionAnalyticsExportRuntime.details?.bucket_count || 24,
                    )}{" "}
                    buckets.
                  </div>
                  {sessionAnalyticsExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(
                        sessionAnalyticsExportRuntime.details.last_export_at,
                      )}
                      {sessionAnalyticsExportRuntime.details?.next_due_at
                        ? `, next due ${String(sessionAnalyticsExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled session analytics export runtime has been
                  recorded yet.
                </div>
              )}
              {sessionAnalyticsExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled session analytics export artifacts are present
                  yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {sessionAnalyticsExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledSessionAnalyticsExport(
                                  artifact,
                                )
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Guest Lifecycle Exports
                  </div>
                  <div className="mt-1">
                    Keep recurring guest approval and delivery snapshots on disk
                    so sponsor workflows, invite failures, and approval timing
                    stay exportable without a manual pull during an incident.
                  </div>
                </div>
                <button
                  onClick={() => void loadGuestLifecycleExports(true)}
                  disabled={loadingGuestLifecycleExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingGuestLifecycleExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Guest Lifecycle Exports"}
                </button>
              </div>
              {guestLifecycleExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {guestLifecycleExportRuntime.status} /{" "}
                    {guestLifecycleExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(
                      guestLifecycleExportRuntime.details?.format || "json",
                    )}
                    , every{" "}
                    {String(
                      guestLifecycleExportRuntime.details?.interval_minutes ||
                        0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(
                      guestLifecycleExportRuntime.details?.retention_count || 0,
                    )}
                    , directory{" "}
                    {String(
                      guestLifecycleExportRuntime.details?.directory || "unset",
                    )}
                    .
                  </div>
                  <div className="mt-1">
                    Window{" "}
                    {String(
                      guestLifecycleExportRuntime.details?.window_hours || 24,
                    )}{" "}
                    hours with{" "}
                    {String(
                      guestLifecycleExportRuntime.details?.bucket_count || 24,
                    )}{" "}
                    buckets, limit{" "}
                    {String(guestLifecycleExportRuntime.details?.limit || 5000)}
                    .
                  </div>
                  {guestLifecycleExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(
                        guestLifecycleExportRuntime.details.last_export_at,
                      )}
                      {guestLifecycleExportRuntime.details?.next_due_at
                        ? `, next due ${String(guestLifecycleExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled guest lifecycle export runtime has been recorded
                  yet.
                </div>
              )}
              {guestLifecycleExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled guest lifecycle export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {guestLifecycleExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledGuestLifecycleExport(
                                  artifact,
                                )
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Integration Exports
                  </div>
                  <div className="mt-1">
                    Keep controller, MDM, and posture automation history on disk
                    so support handoffs and incident reviews have a recurring
                    export trail ready.
                  </div>
                </div>
                <button
                  onClick={() => void loadIntegrationExports(true)}
                  disabled={loadingIntegrationExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingIntegrationExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Integration Exports"}
                </button>
              </div>
              {integrationExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {integrationExportRuntime.status} /{" "}
                    {integrationExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(integrationExportRuntime.details?.format || "json")}
                    , every{" "}
                    {String(
                      integrationExportRuntime.details?.interval_minutes || 0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(
                      integrationExportRuntime.details?.retention_count || 0,
                    )}
                    , directory{" "}
                    {String(
                      integrationExportRuntime.details?.directory || "unset",
                    )}
                    .
                  </div>
                  {integrationExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(integrationExportRuntime.details.last_export_at)}
                      {integrationExportRuntime.details?.next_due_at
                        ? `, next due ${String(integrationExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled integration export runtime has been recorded yet.
                </div>
              )}
              {integrationExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled integration export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {integrationExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledIntegrationExport(
                                  artifact,
                                )
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled HA Exports
                  </div>
                  <div className="mt-1">
                    Keep failover, VIP, and replication history on disk so HA
                    drills and incident reviews have a recurring export trail
                    ready to hand off.
                  </div>
                </div>
                <button
                  onClick={() => void loadHAExports(true)}
                  disabled={loadingHAExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingHAExports
                    ? "Refreshing..."
                    : "Refresh Scheduled HA Exports"}
                </button>
              </div>
              {haExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {haExportRuntime.status} / {haExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format {String(haExportRuntime.details?.format || "json")},
                    every{" "}
                    {String(haExportRuntime.details?.interval_minutes || 0)}{" "}
                    minutes, retain{" "}
                    {String(haExportRuntime.details?.retention_count || 0)},
                    directory{" "}
                    {String(haExportRuntime.details?.directory || "unset")}.
                  </div>
                  {haExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(haExportRuntime.details.last_export_at)}
                      {haExportRuntime.details?.next_due_at
                        ? `, next due ${String(haExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled HA export runtime has been recorded yet.
                </div>
              )}
              {haExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled HA export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {haExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledHAExport(artifact)
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Network Exports
                  </div>
                  <div className="mt-1">
                    Keep managed network apply history and DHCP lease history on
                    disk so rollback reviews, client troubleshooting, and change
                    windows have a recurring export trail ready.
                  </div>
                </div>
                <button
                  onClick={() => void loadNetworkExports(true)}
                  disabled={loadingNetworkExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingNetworkExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Network Exports"}
                </button>
              </div>
              {networkExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {networkExportRuntime.status} /{" "}
                    {networkExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(networkExportRuntime.details?.format || "json")},
                    every{" "}
                    {String(
                      networkExportRuntime.details?.interval_minutes || 0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(networkExportRuntime.details?.retention_count || 0)}
                    , directory{" "}
                    {String(networkExportRuntime.details?.directory || "unset")}
                    .
                  </div>
                  {networkExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(networkExportRuntime.details.last_export_at)}
                      {networkExportRuntime.details?.next_due_at
                        ? `, next due ${String(networkExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled network export runtime has been recorded yet.
                </div>
              )}
              {networkExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled network export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Kind
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {networkExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.kind}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledNetworkExport(artifact)
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Upstream AAA Exports
                  </div>
                  <div className="mt-1">
                    Keep recurring upstream AAA probe artifacts on disk so
                    fail-over review, reject analysis, and timeout
                    investigations already have a durable handoff package
                    waiting.
                  </div>
                </div>
                <button
                  onClick={() => void loadUpstreamAAAExports(true)}
                  disabled={loadingUpstreamAAAExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingUpstreamAAAExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Upstream AAA Exports"}
                </button>
              </div>
              {upstreamAAAExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {upstreamAAAExportRuntime.status} /{" "}
                    {upstreamAAAExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(upstreamAAAExportRuntime.details?.format || "json")}
                    , every{" "}
                    {String(
                      upstreamAAAExportRuntime.details?.interval_minutes || 0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(
                      upstreamAAAExportRuntime.details?.retention_count || 0,
                    )}
                    , directory{" "}
                    {String(
                      upstreamAAAExportRuntime.details?.directory || "unset",
                    )}
                    .
                  </div>
                  {upstreamAAAExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(upstreamAAAExportRuntime.details.last_export_at)}
                      {upstreamAAAExportRuntime.details?.next_due_at
                        ? `, next due ${String(upstreamAAAExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled upstream AAA export runtime has been recorded
                  yet.
                </div>
              )}
              {upstreamAAAExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled upstream AAA export artifacts are present yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {upstreamAAAExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledUpstreamAAAExport(
                                  artifact,
                                )
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-900">
                    Scheduled Upgrade Readiness Exports
                  </div>
                  <div className="mt-1">
                    Keep recurring readiness and migration-rehearsal artifacts
                    on disk so maintenance windows already have saved upgrade
                    evidence before anyone touches the live database.
                  </div>
                </div>
                <button
                  onClick={() => void loadUpgradeReadinessExports(true)}
                  disabled={loadingUpgradeReadinessExports || busyAction !== ""}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingUpgradeReadinessExports
                    ? "Refreshing..."
                    : "Refresh Scheduled Upgrade Readiness Exports"}
                </button>
              </div>
              {upgradeReadinessExportRuntime ? (
                <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                  <div>
                    <span className="font-medium text-slate-900">Runtime:</span>{" "}
                    {upgradeReadinessExportRuntime.status} /{" "}
                    {upgradeReadinessExportRuntime.message}
                  </div>
                  <div className="mt-1">
                    Format{" "}
                    {String(
                      upgradeReadinessExportRuntime.details?.format || "json",
                    )}
                    , every{" "}
                    {String(
                      upgradeReadinessExportRuntime.details?.interval_minutes ||
                        0,
                    )}{" "}
                    minutes, retain{" "}
                    {String(
                      upgradeReadinessExportRuntime.details?.retention_count ||
                        0,
                    )}
                    , directory{" "}
                    {String(
                      upgradeReadinessExportRuntime.details?.directory ||
                        "unset",
                    )}
                    .
                  </div>
                  {upgradeReadinessExportRuntime.details?.last_export_at ? (
                    <div className="mt-1">
                      Last export{" "}
                      {String(
                        upgradeReadinessExportRuntime.details.last_export_at,
                      )}
                      {upgradeReadinessExportRuntime.details?.next_due_at
                        ? `, next due ${String(upgradeReadinessExportRuntime.details.next_due_at)}`
                        : ""}
                      .
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-dashed border-gray-300 px-3 py-4 text-xs text-gray-500">
                  No scheduled upgrade readiness export runtime has been
                  recorded yet.
                </div>
              )}
              {upgradeReadinessExportArtifacts.length === 0 ? (
                <div className="mt-3 text-xs text-gray-500">
                  No scheduled upgrade readiness export artifacts are present
                  yet.
                </div>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-xs">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Created
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Name
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Format
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Size
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Path
                        </th>
                        <th className="px-3 py-2 text-left font-medium text-gray-600">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {upgradeReadinessExportArtifacts.map((artifact) => (
                        <tr key={artifact.name}>
                          <td className="px-3 py-2 text-gray-600">
                            {artifact.created_at}
                          </td>
                          <td className="px-3 py-2 font-medium text-gray-900">
                            {artifact.name}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.format}
                          </td>
                          <td className="px-3 py-2 text-gray-700">
                            {artifact.size_bytes} bytes
                          </td>
                          <td className="px-3 py-2 text-gray-500 break-all">
                            {artifact.path}
                          </td>
                          <td className="px-3 py-2">
                            <button
                              onClick={() =>
                                void downloadScheduledUpgradeReadinessExport(
                                  artifact,
                                )
                              }
                              disabled={busyAction !== ""}
                              className="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Upgrade Readiness
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Rehearse database migration on a temporary copy, compare schema
              versions, and catch upgrade blockers before touching the live
              appliance.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => void loadUpgradeReadiness()}
              disabled={loadingUpgradeReadiness || busyAction !== ""}
              className="rounded-md bg-indigo-700 px-4 py-2 text-white hover:bg-indigo-800 disabled:opacity-50"
            >
              {loadingUpgradeReadiness
                ? "Checking..."
                : "Run Upgrade Readiness"}
            </button>
            <button
              onClick={() => void downloadUpgradeRollbackPackage()}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-4 py-2 text-gray-800 hover:bg-gray-50 disabled:opacity-50"
            >
              Download Rollback Package
            </button>
          </div>
        </div>

        {!upgradeReadiness ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Run the readiness check to compare the current database schema,
            validate config, and rehearse migrations safely on a temporary copy.
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Schema</div>
                <div className="mt-2">
                  Current v{upgradeReadiness.current_schema_version}, target v
                  {upgradeReadiness.target_schema_version}
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Config</div>
                <div className="mt-2">
                  {upgradeReadiness.config_valid ? "Valid" : "Needs attention"}
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Database</div>
                <div className="mt-2">
                  {upgradeReadiness.database_exists
                    ? `${upgradeReadiness.database_size_bytes} bytes`
                    : "Missing"}
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">
                  Migration Rehearsal
                </div>
                <div className="mt-2">
                  {upgradeReadiness.rehearsal.ran
                    ? upgradeReadiness.rehearsal.succeeded
                      ? "Passed"
                      : "Failed"
                    : "Not run"}
                </div>
              </div>
            </div>

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div>
                <span className="font-medium text-slate-900">Config path:</span>{" "}
                {upgradeReadiness.config_path}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">
                  Database path:
                </span>{" "}
                {upgradeReadiness.database_path}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">Deployment:</span>{" "}
                {upgradeReadiness.deployment_profile || "unknown"} /{" "}
                {upgradeReadiness.deployment_form || "unknown"}
              </div>
              {upgradeReadiness.config_validation_error ? (
                <div className="mt-2 text-red-700">
                  <span className="font-medium">Validation error:</span>{" "}
                  {upgradeReadiness.config_validation_error}
                </div>
              ) : null}
              {upgradeReadiness.rehearsal.error ? (
                <div className="mt-2 text-red-700">
                  <span className="font-medium">Rehearsal error:</span>{" "}
                  {upgradeReadiness.rehearsal.error}
                </div>
              ) : null}
              {upgradeReadiness.rehearsal.ran ? (
                <div className="mt-2">
                  Started on schema v
                  {upgradeReadiness.rehearsal.started_schema_version}, ended on
                  v{upgradeReadiness.rehearsal.result_schema_version} in{" "}
                  {upgradeReadiness.rehearsal.duration_milliseconds} ms.
                </div>
              ) : null}
            </div>

            {upgradeReadiness.recommendations &&
            upgradeReadiness.recommendations.length > 0 ? (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                <div className="font-medium">Recommendations</div>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {upgradeReadiness.recommendations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Rollback Package Restore
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Inspect an upgrade rollback package first, then restore it only
              when the runtime says online restore is supported for this schema
              and path context.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <input
            type="file"
            accept=".zip,application/zip"
            onChange={(event) =>
              setUpgradeRollbackFile(event.target.files?.[0] ?? null)
            }
            className="max-w-full text-sm"
          />
          <button
            disabled={
              !upgradeRollbackFile ||
              loadingUpgradeRollbackInspect ||
              busyAction !== ""
            }
            onClick={() => void inspectUpgradeRollbackPackage()}
            className="rounded-md bg-slate-900 px-4 py-2 text-white hover:bg-black disabled:opacity-50"
          >
            {loadingUpgradeRollbackInspect
              ? "Inspecting..."
              : "Inspect Rollback Package"}
          </button>
        </div>

        {!upgradeRollbackInspection ? (
          <div className="mt-4 rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Choose a rollback package zip and inspect it before any restore
            action.
          </div>
        ) : (
          <div className="mt-4 space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Compatibility</div>
                <div className="mt-2">
                  {upgradeRollbackInspection.compatibility_status}
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Schema</div>
                <div className="mt-2">
                  Package v
                  {upgradeRollbackInspection.manifest.current_schema_version} to
                  runtime target v
                  {upgradeRollbackInspection.runtime_target_schema_version}
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">
                  Config Validation
                </div>
                <div className="mt-2">
                  {upgradeRollbackInspection.config_valid ? "Valid" : "Failed"}
                </div>
              </div>
              <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Online Restore</div>
                <div className="mt-2">
                  {upgradeRollbackInspection.online_restore_supported
                    ? "Supported"
                    : "Offline required"}
                </div>
              </div>
            </div>

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div>
                <span className="font-medium text-slate-900">Config path:</span>{" "}
                {upgradeRollbackInspection.manifest.config_path || "unknown"}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">
                  Database path:
                </span>{" "}
                {upgradeRollbackInspection.manifest.database_path || "unknown"}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">Contents:</span>{" "}
                config YAML{" "}
                {upgradeRollbackInspection.has_config_yaml
                  ? "present"
                  : "missing"}
                , system settings{" "}
                {upgradeRollbackInspection.has_system_settings
                  ? "present"
                  : "missing"}
                , database{" "}
                {upgradeRollbackInspection.has_database ? "present" : "missing"}
              </div>
              <div className="mt-1">
                <span className="font-medium text-slate-900">
                  Database path match:
                </span>{" "}
                {upgradeRollbackInspection.database_path_matches ? "yes" : "no"}
              </div>
              {upgradeRollbackInspection.config_validation_error ? (
                <div className="mt-2 text-red-700">
                  <span className="font-medium">Validation error:</span>{" "}
                  {upgradeRollbackInspection.config_validation_error}
                </div>
              ) : null}
            </div>

            {upgradeRollbackInspection.warnings &&
            upgradeRollbackInspection.warnings.length > 0 ? (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                <div className="font-medium">Warnings</div>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {upgradeRollbackInspection.warnings.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}

            {upgradeRollbackInspection.restore_steps &&
            upgradeRollbackInspection.restore_steps.length > 0 ? (
              <div className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Restore Steps</div>
                <ol className="mt-2 list-decimal space-y-1 pl-5">
                  {upgradeRollbackInspection.restore_steps.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ol>
              </div>
            ) : null}

            <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <div className="font-medium text-slate-900">Confirm Restore</div>
              <p className="mt-1">
                Type{" "}
                <span className="font-mono">
                  {upgradeRollbackInspection.required_confirmation_text ||
                    "RESTORE UPGRADE ROLLBACK"}
                </span>{" "}
                to allow the restore action.
              </p>
              <input
                value={upgradeRollbackConfirmationText}
                onChange={(event) =>
                  setUpgradeRollbackConfirmationText(event.target.value)
                }
                className="mt-3 w-full rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-900"
                placeholder={
                  upgradeRollbackInspection.required_confirmation_text ||
                  "RESTORE UPGRADE ROLLBACK"
                }
              />
              <div className="mt-3">
                <button
                  disabled={
                    busyAction !== "" ||
                    !upgradeRollbackInspection.online_restore_supported ||
                    upgradeRollbackConfirmationText !==
                      (upgradeRollbackInspection.required_confirmation_text ||
                        "RESTORE UPGRADE ROLLBACK")
                  }
                  onClick={() => void restoreUpgradeRollbackPackage()}
                  className="rounded-md bg-amber-700 px-4 py-2 text-white hover:bg-amber-800 disabled:opacity-50"
                >
                  Restore From Rollback Package
                </button>
              </div>
            </div>
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Staged HA Packages
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Import on the standby, validate the package, then activate it to
              lay down the replicated config and database before the service
              restart.
            </p>
          </div>
          <button
            onClick={() => {
              void loadStages();
              void loadSharedStatus();
            }}
            disabled={loadingStages || busyAction !== ""}
            className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            Refresh
          </button>
        </div>

        {loadingStages ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading staged replication packages...
          </div>
        ) : stagedPackages.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No staged HA packages yet. Download a package from the active node,
            then upload it here.
          </div>
        ) : (
          <div className="space-y-4">
            {stagedPackages.map((pkg) => (
              <div
                key={pkg.id}
                className="rounded-md border border-gray-200 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-gray-900">
                      {pkg.id}
                    </div>
                    <div className="mt-1 text-sm text-gray-600">
                      {pkg.summary}
                    </div>
                    <div className="mt-2 text-xs text-gray-500">
                      Imported {pkg.imported_at} by {pkg.imported_by}. Source:{" "}
                      {pkg.manifest?.source_node || "unknown"} (
                      {pkg.manifest?.source_role || "unknown"}).
                    </div>
                    {pkg.imported_source ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Imported via {pkg.imported_source}.
                      </div>
                    ) : null}
                    {pkg.package_checksum ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        Archive checksum {pkg.package_checksum}
                      </div>
                    ) : null}
                    {pkg.content_fingerprint ? (
                      <div className="mt-1 text-xs text-gray-500 break-all">
                        Content fingerprint {pkg.content_fingerprint}
                      </div>
                    ) : null}
                    {pkg.encryption_status ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Encryption {pkg.encryption_status}
                        {pkg.encryption_algorithm
                          ? ` via ${pkg.encryption_algorithm}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {pkg.signature_status ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Signature {pkg.signature_status}
                        {pkg.signature_algorithm
                          ? ` via ${pkg.signature_algorithm}`
                          : ""}
                        .
                      </div>
                    ) : null}
                    {pkg.activation_backup ? (
                      <div className="mt-1 text-xs text-gray-500">
                        Safety backup: {pkg.activation_backup}
                      </div>
                    ) : null}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-full px-3 py-1 text-xs font-medium ${pkg.status === "activated" ? "bg-emerald-100 text-emerald-800" : pkg.ready ? "bg-sky-100 text-sky-800" : "bg-amber-100 text-amber-800"}`}
                    >
                      {pkg.status}
                    </span>
                    <button
                      disabled={!pkg.ready || busyAction !== ""}
                      onClick={() => void activateReplicationPackage(pkg)}
                      className="rounded-md bg-indigo-700 px-4 py-2 text-sm text-white hover:bg-indigo-800 disabled:opacity-50"
                    >
                      Activate On Standby
                    </button>
                  </div>
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <div className="rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    <div className="font-medium text-slate-900">
                      Schema Version
                    </div>
                    <div className="mt-1">
                      {pkg.manifest?.schema_version ?? "unknown"}
                    </div>
                  </div>
                  <div className="rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    <div className="font-medium text-slate-900">Validation</div>
                    <div className="mt-1">
                      Config {pkg.config_valid ? "OK" : "Failed"}, database{" "}
                      {pkg.database_valid ? "OK" : "Failed"}, network state{" "}
                      {pkg.network_state_present ? "included" : "not included"}
                    </div>
                  </div>
                  <div className="rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    <div className="font-medium text-slate-900">Activation</div>
                    <div className="mt-1">
                      {pkg.activated_at
                        ? `Activated ${pkg.activated_at} by ${pkg.activated_by || "unknown"}`
                        : "Not activated yet"}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Upstream AAA History
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Keep a durable timeline of upstream RADIUS probe outcomes so
              reject storms, timeouts, and fail-over questions are not reduced
              to one live status message.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => void loadUpstreamAAAHistory(true)}
              disabled={loadingUpstreamAAAHistory || busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {loadingUpstreamAAAHistory ? "Refreshing..." : "Refresh"}
            </button>
            <button
              onClick={() => void exportUpstreamAAAHistory("csv")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export CSV
            </button>
            <button
              onClick={() => void exportUpstreamAAAHistory("json")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export JSON
            </button>
          </div>
        </div>

        <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Healthy</div>
            <div className="mt-2">
              {upstreamAAAHistoryStats?.ok_count ?? 0} ok probes
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Degraded</div>
            <div className="mt-2">
              {upstreamAAAHistoryStats?.degraded_count ?? 0} degraded probes
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Down</div>
            <div className="mt-2">
              {upstreamAAAHistoryStats?.down_count ?? 0} down probes
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Disabled</div>
            <div className="mt-2">
              {upstreamAAAHistoryStats?.disabled_count ?? 0} disabled probes
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Last Probe</div>
            <div className="mt-2">
              {upstreamAAAHistoryStats?.last_checked_at || "No data yet"}
            </div>
          </div>
        </div>

        {loadingUpstreamAAAHistory ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading upstream AAA history...
          </div>
        ) : upstreamAAAHistory.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No upstream AAA probe history recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Checked
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Server
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Status
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Response
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Latency
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Message
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {upstreamAAAHistory.map((item) => (
                  <tr key={item.id}>
                    <td className="px-3 py-2 text-gray-600">
                      {item.checked_at}
                    </td>
                    <td className="px-3 py-2 text-gray-900">
                      <div>{item.server_name || item.address}</div>
                      <div className="text-xs text-gray-500">
                        {item.address}:{item.auth_port}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-700">{item.status}</td>
                    <td className="px-3 py-2 text-gray-700">
                      {item.response_code || "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      {item.latency_ms ? `${item.latency_ms} ms` : "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      {item.message || "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Session History
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Review durable session and accounting records with auth method,
              role, byte counts, and session duration so access investigations
              do not depend on the live sessions table alone.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => void loadSessionHistory(true)}
              disabled={loadingSessionHistory || busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {loadingSessionHistory ? "Refreshing..." : "Refresh"}
            </button>
            <button
              onClick={() => void exportSessionHistory("csv")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export CSV
            </button>
            <button
              onClick={() => void exportSessionHistory("json")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export JSON
            </button>
          </div>
        </div>

        <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Records</div>
            <div className="mt-2">
              {sessionHistoryStats?.total_records ?? 0} total,{" "}
              {sessionHistoryStats?.active_count ?? 0} active
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Traffic</div>
            <div className="mt-2">
              {sessionHistoryStats?.traffic_total ?? 0} bytes across{" "}
              {sessionHistoryStats?.accounted_record_count ?? 0} accounted
              records
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Duration</div>
            <div className="mt-2">
              {sessionHistoryStats?.acct_session_seconds_total ?? 0}s total,{" "}
              {sessionHistoryStats?.avg_acct_session_seconds ?? 0}s average
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Latest Start</div>
            <div className="mt-2">
              {sessionHistoryStats?.last_started_at || "No data yet"}
            </div>
          </div>
        </div>

        {loadingSessionHistory ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading session history...
          </div>
        ) : sessionHistory.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No session history recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Started
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    User
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Method
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Role
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Addressing
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Traffic
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Accounting
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Ended
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {sessionHistory.map((item) => (
                  <tr key={item.id}>
                    <td className="px-3 py-2 text-gray-600">
                      <div>{item.start_time}</div>
                      <div className="text-xs text-gray-500">
                        {item.last_activity
                          ? `Last active ${item.last_activity}`
                          : "No activity recorded"}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-900">
                      <div>{item.username || "-"}</div>
                      <div className="text-xs text-gray-500">
                        {item.identity_source || "source unset"}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      <div>{item.auth_method || "-"}</div>
                      <div className="text-xs text-gray-500">
                        {item.radius_session_id || "radius session unset"}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      <div>{item.role || "-"}</div>
                      <div className="text-xs text-gray-500">
                        VLAN {item.vlan || 0}
                        {item.bandwidth_profile
                          ? ` / ${item.bandwidth_profile}`
                          : ""}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      <div>{item.ip || "-"}</div>
                      <div className="text-xs text-gray-500">
                        {item.mac || "-"}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      <div>{item.total_bytes} bytes</div>
                      <div className="text-xs text-gray-500">
                        In {item.bytes_in} / Out {item.bytes_out}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      <div>{item.acct_session_time || 0}s</div>
                      <div className="text-xs text-gray-500">
                        Session {item.session_timeout || 0}s / Idle{" "}
                        {item.idle_timeout || 0}s
                      </div>
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      <div>{item.end_time || "active"}</div>
                      <div className="text-xs text-gray-500">
                        {item.stop_reason || "still active"}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Audit History
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Review exported reports, network applies, HA actions, guest
              approvals, and other operator-visible actions from one durable
              appliance timeline.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => void loadAuditHistory(true)}
              disabled={loadingAuditHistory || busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {loadingAuditHistory ? "Refreshing..." : "Refresh"}
            </button>
            <button
              onClick={() => void exportAuditHistory("csv")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export CSV
            </button>
            <button
              onClick={() => void exportAuditHistory("json")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export JSON
            </button>
          </div>
        </div>

        <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Exports</div>
            <div className="mt-2">
              {auditHistoryStats?.export_action_count ?? 0} recorded downloads
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Network Actions</div>
            <div className="mt-2">
              {auditHistoryStats?.network_action_count ?? 0} network and runtime
              apply actions
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">HA And Upgrade</div>
            <div className="mt-2">
              {auditHistoryStats?.ha_action_count ?? 0} HA,{" "}
              {auditHistoryStats?.upgrade_action_count ?? 0} upgrade actions
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Last Recorded</div>
            <div className="mt-2">
              {auditHistoryStats?.last_recorded_at || "No data yet"}
            </div>
          </div>
        </div>

        {loadingAuditHistory ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading audit history...
          </div>
        ) : auditHistory.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No audit history recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    When
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    User
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Action
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Result
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {auditHistory.map((item) => (
                  <tr key={item.id}>
                    <td className="px-3 py-2 text-gray-600">
                      {item.timestamp}
                    </td>
                    <td className="px-3 py-2 text-gray-900">
                      {item.user || "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-700">{item.action}</td>
                    <td className="px-3 py-2 text-gray-700">
                      {item.result || "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      {item.details || "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Integration History
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Keep durable controller, MDM sync, and posture automation events
              so operator reviews and support handoffs do not depend on the last
              runtime status alone.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => void loadIntegrationHistory(true)}
              disabled={loadingIntegrationHistory || busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              {loadingIntegrationHistory ? "Refreshing..." : "Refresh"}
            </button>
            <button
              onClick={() => void exportIntegrationHistory("csv")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export CSV
            </button>
            <button
              onClick={() => void exportIntegrationHistory("json")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export JSON
            </button>
          </div>
        </div>

        <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Controller Sync</div>
            <div className="mt-2">
              {integrationHistoryStats?.controller_success_count ?? 0}{" "}
              successful /{" "}
              {integrationHistoryStats?.controller_event_count ?? 0} total
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">MDM Sync</div>
            <div className="mt-2">
              {integrationHistoryStats?.mdm_sync_success_count ?? 0} successful
              / {integrationHistoryStats?.mdm_sync_event_count ?? 0} total
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Posture Checks</div>
            <div className="mt-2">
              {integrationHistoryStats?.posture_success_count ?? 0} successful /{" "}
              {integrationHistoryStats?.posture_event_count ?? 0} total
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Last Event</div>
            <div className="mt-2">
              {integrationHistoryStats?.last_event_at || "No data yet"}
            </div>
          </div>
        </div>

        {loadingIntegrationHistory ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading integration history...
          </div>
        ) : integrationHistory.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No integration history recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    When
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Component
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Status
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Summary
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {integrationHistory.map((item) => (
                  <tr key={item.id}>
                    <td className="px-3 py-2 text-gray-600">
                      {item.created_at}
                    </td>
                    <td className="px-3 py-2 text-gray-900">
                      {integrationComponentLabel(item.component)}
                    </td>
                    <td className="px-3 py-2 text-gray-700">{item.status}</td>
                    <td className="px-3 py-2 text-gray-700">{item.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="mt-6 rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">HA History</h3>
            <p className="mt-1 text-sm text-gray-600">
              Track failover promotions, peer health changes, VIP lease actions,
              and replication activity over time.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => void loadHAHistory()}
              disabled={loadingHAHistory || busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Refresh
            </button>
            <button
              onClick={() => void exportHAHistory("csv")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export CSV
            </button>
            <button
              onClick={() => void exportHAHistory("json")}
              disabled={busyAction !== ""}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
            >
              Export JSON
            </button>
          </div>
        </div>

        <div className="mb-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Failover Events</div>
            <div className="mt-2">
              Promotions {haHistoryStats?.failover_promotions ?? 0}, returns{" "}
              {haHistoryStats?.failover_returns ?? 0}
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Peer Health</div>
            <div className="mt-2">
              Failures {haHistoryStats?.peer_failures ?? 0}, recoveries{" "}
              {haHistoryStats?.peer_recoveries ?? 0}
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">VIP Lease</div>
            <div className="mt-2">
              Acquired {haHistoryStats?.vip_acquisitions ?? 0}, preempted{" "}
              {haHistoryStats?.vip_preemptions ?? 0}, released{" "}
              {haHistoryStats?.vip_releases ?? 0}
            </div>
          </div>
          <div className="rounded-md bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <div className="font-medium text-slate-900">Replication</div>
            <div className="mt-2">
              Publishes {haHistoryStats?.replication_publishes ?? 0}, stale
              events {haHistoryStats?.replication_stale_count ?? 0}, activations{" "}
              {haHistoryStats?.activations ?? 0}
            </div>
          </div>
        </div>

        {loadingHAHistory ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            Loading HA history...
          </div>
        ) : haHistory.length === 0 ? (
          <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">
            No HA history recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    When
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Event
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Status
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Role
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Actor
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-gray-600">
                    Summary
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {haHistory.map((item) => (
                  <tr key={item.id}>
                    <td className="px-3 py-2 text-gray-600">
                      {item.created_at}
                    </td>
                    <td className="px-3 py-2 text-gray-900">
                      {item.event_type}
                    </td>
                    <td className="px-3 py-2 text-gray-700">{item.status}</td>
                    <td className="px-3 py-2 text-gray-700">
                      {item.node_role || "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-700">
                      {item.actor || "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-700">{item.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
