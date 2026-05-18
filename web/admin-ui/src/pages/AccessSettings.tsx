import { ChangeEvent, useEffect, useRef, useState } from 'react';
import api from '../api/client';

type JsonMap = Record<string, any>;
type Option = { value: string; label: string };
type DeploymentCapability = {
  key: string;
  label: string;
  state: 'enabled' | 'available' | 'warned' | 'degraded' | 'blocked';
  active: boolean;
  summary: string;
  recommendation?: string;
  dependencies?: string[];
};

type DeploymentPreview = {
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

type DHCPLease = {
  expires_at: string;
  remaining_seconds: number;
  mac: string;
  ip: string;
  hostname: string;
  client_id: string;
  reservation: boolean;
  expired: boolean;
};

type DHCPLeaseHistoryRecord = {
  id: number;
  observed_at: string;
  mac: string;
  ip: string;
  hostname: string;
  client_id: string;
  reservation: boolean;
  expired: boolean;
  expires_at: string;
  remaining_seconds: number;
};

type NetworkSnapshotSummary = {
  id: string;
  created_at: string;
  interfaces: number;
  gateways: number;
  routes: number;
  dnsmasq_enabled: boolean;
  has_firewall: boolean;
  created_by?: string;
  reason?: string;
};

type NetworkDiffSummary = {
  interfaces_added: string[];
  interfaces_removed: string[];
  gateways_added: string[];
  gateways_removed: string[];
  routes_added: string[];
  routes_removed: string[];
};

type NetworkApplyHistoryRecord = {
  id: number;
  action: string;
  status: string;
  summary: string;
  backup_id?: string;
  rollback_id?: string;
  actor?: string;
  created_at: string;
};

type NetworkPreview = {
  desired_state: JsonMap;
  current_state: JsonMap;
  diff: NetworkDiffSummary;
  risk: {
    requires_confirmation: boolean;
    confirmation_phrase?: string;
    summary: string;
    items: Array<{
      level: string;
      code: string;
      message: string;
    }>;
  };
  dnsmasq_enabled: boolean;
  dnsmasq_config: string;
  firewall_rules: string;
  free_site_count: number;
  custom_firewall_rules: number;
  static_reservations: number;
  available_rollback_ids: NetworkSnapshotSummary[];
  recovery?: NetworkRecoveryState | null;
};

type NetworkValidationCheck = {
  name: string;
  status: string;
  detail: string;
};

type NetworkValidationReport = {
  healthy: boolean;
  checks: NetworkValidationCheck[];
};

type NetworkApplyRisk = {
  requires_confirmation: boolean;
  confirmation_phrase?: string;
  summary: string;
  items: Array<{
    level: string;
    code: string;
    message: string;
  }>;
};

type NetworkRecoveryState = {
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

type NetworkApplyStats = {
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

type DHCPLeaseTrendSummary = {
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

type RuntimeStatus = {
  status?: string;
  message?: string;
  updated_at?: string;
  details?: Record<string, any>;
};

type NetworkObservabilityResponse = {
  generated_at: string;
  apply_stats: NetworkApplyStats;
  lease_trends: DHCPLeaseTrendSummary;
  controller_sync?: RuntimeStatus | null;
  recovery?: NetworkRecoveryState | null;
};

const defaultSettings: JsonMap = {
  mode: 'two-nic',
  admin_port: 8083,
  deployment: {
    profile: 'branch',
    form: 'physical',
    hardware: {
      memory_mb: 4096,
      cpu_cores: 2,
      prefer_external_ap: false,
      wireless_passthrough: false,
    },
  },
  wan: { name: '', dhcp: true, address: '', gateway: '', dhcp_range: '' },
  lan: { name: '', dhcp: false, address: '', gateway: '', dhcp_range: '' },
  network: {
    interfaces: [],
    gateways: [],
    dns: {
      upstream_servers: ['8.8.8.8', '8.8.4.4'],
      search_domains: [],
      local_domain: 'aegis.local',
    },
    static_routes: [],
    firewall: {
      rules: [],
      free_sites: [],
      dos_protection: {
        enabled: false,
        syn_rate: '50/second',
        icmp_rate: '25/second',
        conn_rate: '200/second',
        burst: 100,
        log_drops: true,
      },
    },
  },
  dhcp: { enabled: true, lease_time: '12h', authoritative: true, static_leases: [] },
  policy: {
    default_role: '',
    runtime_shaping_enabled: true,
  },
  telemetry: {
    enabled: true,
    prometheus_port: 9090,
    lease_history_poll_seconds: 300,
  },
  ailite: {
    enabled: true,
    mode: 'lite',
    provider: 'local',
    endpoint: '',
    model: '',
    api_key_env: 'AEGIS_AI_API_KEY',
    request_timeout_seconds: 20,
    max_input_events: 200,
    recommendation_limit: 100,
    remote_webhook: '',
  },
  onboarding: {
    device_inventory_enabled: false,
    portal_enabled: false,
    certificate_enrollment_enabled: false,
    eap_tls_enabled: false,
    ca_mode: 'none',
    ca_cert_path: '',
    ca_key_path: '',
    ca_enrollment_url: '',
    ca_enrollment_token_env: '',
  },
  profiling: {
    mac_inventory_enabled: false,
    passive_enabled: false,
    poll_interval_seconds: 300,
    retention_hours: 24,
    posture_enabled: false,
    mdm_sync_enabled: false,
    mdm_provider: '',
    mdm_endpoint: '',
    mdm_api_token_env: '',
    mdm_cache_hours: 12,
    compliance_webhook: '',
    compliance_token_env: '',
    remediation_enabled: false,
  },
  integrations: {
    admin_sso: {
      enabled: false,
      provider: '',
      issuer_url: '',
      client_id: '',
      client_secret_env: '',
      redirect_url: '',
      groups_claim: '',
    },
    siem: {
      enabled: false,
      provider: '',
      endpoint: '',
      api_key_env: 'AEGIS_SIEM_API_KEY',
      batch_size: 100,
    },
    controller: {
      enabled: false,
      platform: '',
      endpoint: '',
      api_token_env: 'AEGIS_CONTROLLER_API_TOKEN',
      sync_mode: 'monitor',
      site: '',
    },
  },
  governance: {
    delegated_admin_enabled: false,
    rbac_mode: 'local',
    external_groups_enabled: false,
    multi_tenant_enabled: false,
    tenant_claim: '',
  },
    high_availability: {
      enabled: false,
      role: 'standby',
      peer_api_url: '',
      virtual_ip: '',
    heartbeat_interval_seconds: 5,
    failover_timeout_seconds: 20,
    replication_interval_seconds: 300,
    replication_stale_after_seconds: 900,
      split_brain_protection_enabled: true,
      auto_stage_shared_package: false,
      auto_activate_on_failover: false,
      replication_signing_key_env: '',
      replication_encryption_key_env: '',
      witness_api_url: '',
      witness_urls: [],
      witness_quorum: 1,
      witness_weights: {},
      witness_weight_threshold: 0,
      witness_groups: {},
      witness_min_distinct_groups: 0,
      witness_sources: {},
      witness_source_confidence: {},
      witness_required_sources: [],
      witness_required_urls: [],
      witness_required_sources_by_tier: {},
      witness_required_urls_by_tier: {},
      witness_required_groups_by_tier: {},
      witness_policy_mode: 'all',
      witness_policy_mode_by_tier: {},
      witness_failure_tolerance: 0,
      witness_failure_weight_tolerance: 0,
      witness_min_approvals_by_tier: {},
      witness_min_weight_by_tier: {},
      witness_min_distinct_groups_by_tier: {},
      witness_min_distinct_sources_by_tier: {},
      witness_max_age_by_tier: {},
      witness_required_node_by_tier: {},
      witness_signature_required_tiers: [],
      witness_replay_required_tiers: [],
      witness_failure_tolerance_by_tier: {},
      witness_failure_weight_tolerance_by_tier: {},
      witness_blocking_tiers: [],
      witness_token_env: '',
      witness_signing_key_env: '',
      witness_max_age_seconds: 0,
      witness_required_node: '',
      witness_replay_protection_enabled: false,
      preempt: false,
      preempt_holdoff_seconds: 0,
      shared_state_dir: '/var/lib/aegisnas/ha',
    },
  portal: {
    enabled: true,
    port: 8081,
    listen_ip: '',
    branding: 'AegisNAS',
    success_url: '',
    logout_url: '',
    radius_auth: false,
    local_fallback: true,
    guest_workflows: {
      self_registration_enabled: false,
      sponsor_approval_enabled: false,
      invite_delivery: 'none',
      approval_delivery: '',
      email_from: '',
      smtp_server: '',
      smtp_port: 587,
      sms_provider: '',
      sms_endpoint: '',
    },
  },
  radius: {
    secret: '',
    auth_port: 1812,
    acct_port: 1813,
    max_sessions: 1024,
    cert_dir: '/etc/freeradius/3.0/certs',
    nas_identifier: 'aegisnas',
    request_timeout_seconds: 5,
    interim_update_seconds: 300,
    dynamic_auth: { enabled: true, port: 3799 },
    vendor: {
      enabled: false,
      name: 'AegisNAS',
      id: 55555,
      attributes: [],
    },
    eap: {
      default_type: 'peap',
      peap_inner: 'mschapv2',
      ttls_inner: 'mschapv2',
      tls_min_version: '1.2',
      tls_max_version: '1.3',
    },
    upstream: {
      enabled: false,
      realm: 'aegis-upstream',
      pool_strategy: 'fail-over',
      status_check: 'status-server',
      response_window: 20,
      zombie_period: 40,
      revive_interval: 120,
      check_interval: 30,
      num_answers_to_alive: 3,
      strip_realm: false,
      servers: [],
    },
  },
  ldap: {
    enabled: false,
    url: '',
    base_dn: '',
    bind_dn: '',
    bind_password: '',
    user_filter: '(uid=%s)',
    group_filter: '(memberUid=%s)',
  },
  wireless: {
    enabled: false,
    country_code: 'US',
    interface: '',
    driver: 'nl80211',
    hw_mode: 'g',
    channel: 6,
    beacon_interval: 100,
    wmm_enabled: true,
    ht_enabled: true,
    ctrl_interface: '/var/run/hostapd',
    hostapd_config_path: '/etc/hostapd/hostapd.conf',
    ssids: [],
  },
};

const clone = <T,>(value: T): T =>
  typeof structuredClone === 'function' ? structuredClone(value) : JSON.parse(JSON.stringify(value));

const deploymentProfileOptions: Option[] = [
  { value: 'lite', label: 'Lite Edge' },
  { value: 'branch', label: 'Branch' },
  { value: 'enterprise', label: 'Enterprise Edge' },
  { value: 'custom', label: 'Custom' },
];

const deploymentFormOptions: Option[] = [
  { value: 'physical', label: 'Physical Appliance' },
  { value: 'virtual', label: 'Virtual Appliance' },
];

const aiModeOptions: Option[] = [
  { value: 'lite', label: 'AI Lite' },
  { value: 'full', label: 'Full AI' },
];

const aiProviderOptions: Option[] = [
  { value: 'local', label: 'Local Rules' },
  { value: 'openai-compatible', label: 'OpenAI Compatible' },
];

const guestDeliveryOptions: Option[] = [
  { value: 'none', label: 'None' },
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
];

const approvalDeliveryOptions: Option[] = [
  { value: '', label: 'Select delivery' },
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
];

const caModeOptions: Option[] = [
  { value: 'none', label: 'No CA Yet' },
  { value: 'internal', label: 'Internal CA Material' },
  { value: 'external', label: 'External Enrollment API' },
];

const adminSSOProviderOptions: Option[] = [
  { value: '', label: 'Select provider' },
  { value: 'oidc', label: 'OIDC' },
  { value: 'saml', label: 'SAML' },
];

const siemProviderOptions: Option[] = [
  { value: '', label: 'Select export type' },
  { value: 'webhook', label: 'Generic Webhook' },
  { value: 'splunk-hec', label: 'Splunk HEC' },
  { value: 'elastic', label: 'Elastic HTTP' },
];

const controllerPlatformOptions: Option[] = [
  { value: '', label: 'Select controller' },
  { value: 'generic', label: 'Generic REST' },
  { value: 'cisco', label: 'Cisco' },
  { value: 'aruba', label: 'Aruba' },
  { value: 'juniper-mist', label: 'Juniper Mist' },
  { value: 'ruckus', label: 'Ruckus' },
  { value: 'fortinet', label: 'Fortinet' },
  { value: 'mikrotik', label: 'MikroTik' },
];

const controllerSyncOptions: Option[] = [
  { value: 'monitor', label: 'Monitor Only' },
  { value: 'push-config', label: 'Push Config' },
  { value: 'coa-only', label: 'CoA Only' },
];

const rbacModeOptions: Option[] = [
  { value: 'local', label: 'Local Roles' },
  { value: 'external-groups', label: 'External Groups' },
  { value: 'hybrid', label: 'Hybrid' },
];

const firewallChainOptions: Option[] = [
  { value: 'input', label: 'Input' },
  { value: 'forward', label: 'Forward' },
];

const firewallActionOptions: Option[] = [
  { value: 'accept', label: 'Accept' },
  { value: 'drop', label: 'Drop' },
  { value: 'reject', label: 'Reject' },
];

const firewallProtocolOptions: Option[] = [
  { value: 'any', label: 'Any' },
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'icmp', label: 'ICMP' },
];

const freeSiteTypeOptions: Option[] = [
  { value: 'domain', label: 'Domain' },
  { value: 'cidr', label: 'CIDR' },
];

const capabilityTone: Record<DeploymentCapability['state'], string> = {
  enabled: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  available: 'border-sky-200 bg-sky-50 text-sky-800',
  warned: 'border-amber-200 bg-amber-50 text-amber-800',
  degraded: 'border-orange-200 bg-orange-50 text-orange-800',
  blocked: 'border-red-200 bg-red-50 text-red-800',
};

function deploymentProfileSummary(profile: string, form: string) {
  if (profile === 'lite') {
    return form === 'virtual'
      ? 'Constrained VM profile. Prefer an external AP, keep AI and telemetry off, and trim shaping on smaller virtual footprints.'
      : 'Constrained appliance profile for very small edge hardware. Keep AI, telemetry, and runtime shaping off unless the box has headroom.';
  }
  if (profile === 'enterprise') {
    return form === 'virtual'
      ? 'Higher-capacity VM profile for central AAA, full AI analysis, and larger virtual edge deployments with external APs.'
      : 'Higher-capacity appliance profile for heavier EAP, full AI analysis, more users, and richer live enforcement.';
  }
  if (profile === 'custom') {
    return 'Operator-managed profile. Use this when you want to keep manual control over every feature knob.';
  }
  return form === 'virtual'
    ? 'Balanced VM profile for gateway, portal, and AAA roles with external APs.'
    : 'Balanced default profile for most branch appliances and pilot production sites.';
}

function applyDeploymentPreset(input: JsonMap): JsonMap {
  const next = clone(input);
  const profile = next.deployment?.profile || 'branch';
  const form = next.deployment?.form || 'physical';

  next.deployment = next.deployment || {};
  next.deployment.hardware = next.deployment.hardware || {};
  next.network = next.network || {};
  next.network.dns = next.network.dns || {};
  next.network.firewall = next.network.firewall || {};
  next.network.firewall.dos_protection = next.network.firewall.dos_protection || {};
  next.policy = next.policy || {};
  next.telemetry = next.telemetry || {};
  next.ailite = next.ailite || {};
  next.onboarding = next.onboarding || {};
  next.profiling = next.profiling || {};
  next.integrations = next.integrations || {};
  next.integrations.admin_sso = next.integrations.admin_sso || {};
  next.integrations.siem = next.integrations.siem || {};
  next.integrations.controller = next.integrations.controller || {};
  next.governance = next.governance || {};
  next.portal = next.portal || {};
  next.portal.guest_workflows = next.portal.guest_workflows || {};
  next.radius = next.radius || {};
  next.radius.upstream = next.radius.upstream || {};
  next.wireless = next.wireless || {};

  if (profile === 'lite') {
    next.ailite.enabled = false;
    next.ailite.mode = 'lite';
    next.ailite.provider = 'local';
    next.ailite.recommendation_limit = 25;
    next.telemetry.enabled = false;
    next.policy.runtime_shaping_enabled = false;
    next.radius.max_sessions = 256;
    next.radius.interim_update_seconds = 600;
    next.radius.upstream.status_check = 'none';
    next.portal.guest_workflows.self_registration_enabled = false;
    next.portal.guest_workflows.sponsor_approval_enabled = false;
    next.portal.guest_workflows.invite_delivery = 'none';
    next.portal.guest_workflows.approval_delivery = '';
    next.onboarding.device_inventory_enabled = false;
    next.onboarding.portal_enabled = false;
    next.onboarding.certificate_enrollment_enabled = false;
    next.onboarding.eap_tls_enabled = false;
    next.onboarding.ca_mode = 'none';
    next.profiling.passive_enabled = false;
    next.profiling.posture_enabled = false;
    next.profiling.mdm_sync_enabled = false;
    next.integrations.admin_sso.enabled = false;
    next.integrations.siem.enabled = false;
    next.integrations.controller.enabled = false;
    next.governance.delegated_admin_enabled = false;
    next.governance.multi_tenant_enabled = false;
  } else if (profile === 'enterprise') {
    next.ailite.enabled = true;
    next.ailite.mode = 'full';
    next.ailite.provider = 'openai-compatible';
    next.ailite.api_key_env = next.ailite.api_key_env || 'AEGIS_AI_API_KEY';
    next.ailite.request_timeout_seconds = next.ailite.request_timeout_seconds || 20;
    next.ailite.max_input_events = next.ailite.max_input_events || 200;
    next.ailite.recommendation_limit = 250;
    next.telemetry.enabled = true;
    next.policy.runtime_shaping_enabled = true;
    next.radius.max_sessions = 4096;
    next.radius.interim_update_seconds = 300;
    next.radius.upstream.status_check = 'status-server';
    next.onboarding.ca_mode = next.onboarding.ca_mode || 'none';
    next.profiling.poll_interval_seconds = next.profiling.poll_interval_seconds || 300;
    next.profiling.retention_hours = next.profiling.retention_hours || 24;
    next.profiling.mdm_cache_hours = next.profiling.mdm_cache_hours || 12;
    next.integrations.siem.batch_size = next.integrations.siem.batch_size || 100;
    next.integrations.controller.sync_mode = next.integrations.controller.sync_mode || 'monitor';
    next.governance.rbac_mode = next.governance.rbac_mode || 'local';
  } else if (profile === 'custom') {
    next.radius.max_sessions = next.radius.max_sessions || 1024;
    next.ailite.mode = next.ailite.mode || 'lite';
    next.ailite.provider = next.ailite.provider || 'local';
    next.ailite.recommendation_limit = next.ailite.recommendation_limit || 100;
  } else {
    next.ailite.enabled = true;
    next.ailite.mode = 'lite';
    next.ailite.provider = 'local';
    next.ailite.recommendation_limit = 100;
    next.telemetry.enabled = true;
    next.policy.runtime_shaping_enabled = true;
    next.radius.max_sessions = 1024;
    next.radius.interim_update_seconds = 300;
    next.radius.upstream.status_check = 'status-server';
  }

  if (form === 'virtual') {
    next.deployment.hardware.prefer_external_ap = true;
    next.wireless.enabled = false;
  }

  return next;
}

function setAtPath(target: JsonMap, path: string[], value: any) {
  let cursor: JsonMap = target;
  for (let index = 0; index < path.length - 1; index += 1) {
    cursor[path[index]] = cursor[path[index]] ?? {};
    cursor = cursor[path[index]];
  }
  cursor[path[path.length - 1]] = value;
}

function TextField({
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
}: {
  label: string;
  value: string | number;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <label className="block text-sm font-medium text-gray-700">
      <span>{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
      />
    </label>
  );
}

function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: Option[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="block text-sm font-medium text-gray-700">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2">
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function ToggleField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label className="flex items-center gap-3 rounded-md border border-gray-200 px-3 py-2 text-sm text-gray-700">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="h-4 w-4" />
      <span>{label}</span>
    </label>
  );
}

export default function AccessSettings() {
  const [settings, setSettings] = useState<JsonMap>(clone(defaultSettings));
  const [deploymentPreview, setDeploymentPreview] = useState<DeploymentPreview | null>(null);
  const [roles, setRoles] = useState<Option[]>([]);
  const [portalProfiles, setPortalProfiles] = useState<Option[]>([]);
  const [identitySources, setIdentitySources] = useState<Option[]>([]);
  const [bandwidthProfiles, setBandwidthProfiles] = useState<Option[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [writingHostapd, setWritingHostapd] = useState(false);
  const [publishingHostapd, setPublishingHostapd] = useState(false);
  const [applyingRadius, setApplyingRadius] = useState(false);
  const [applyingNetwork, setApplyingNetwork] = useState(false);
  const [rollingBackNetwork, setRollingBackNetwork] = useState(false);
  const [leasesLoading, setLeasesLoading] = useState(false);
  const [dhcpLeases, setDhcpLeases] = useState<DHCPLease[]>([]);
  const [dhcpLeaseHistory, setDhcpLeaseHistory] = useState<DHCPLeaseHistoryRecord[]>([]);
  const [networkPreviewLoading, setNetworkPreviewLoading] = useState(false);
  const [networkPreview, setNetworkPreview] = useState<NetworkPreview | null>(null);
  const [networkBackups, setNetworkBackups] = useState<NetworkSnapshotSummary[]>([]);
  const [networkApplyHistory, setNetworkApplyHistory] = useState<NetworkApplyHistoryRecord[]>([]);
  const [lastNetworkValidation, setLastNetworkValidation] = useState<NetworkValidationReport | null>(null);
  const [networkRecovery, setNetworkRecovery] = useState<NetworkRecoveryState | null>(null);
  const [networkObservability, setNetworkObservability] = useState<NetworkObservabilityResponse | null>(null);
  const [confirmingNetworkRecovery, setConfirmingNetworkRecovery] = useState(false);
  const [selectedRollbackId, setSelectedRollbackId] = useState('');
  const [networkConfirmationText, setNetworkConfirmationText] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [previewError, setPreviewError] = useState('');
  const [hostapdPreview, setHostapdPreview] = useState('');
  const [hostapdPath, setHostapdPath] = useState('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const evaluateTimerRef = useRef<number | null>(null);
  const [recoveryTick, setRecoveryTick] = useState(Date.now());

  const updateField = (path: string[], value: any) => {
    setSettings((current) => {
      const next = clone(current);
      setAtPath(next, path, value);
      return next;
    });
  };

  const applyProfileDefaults = () => {
    setSettings((current) => applyDeploymentPreset(current));
    setError('');
    setMessage('Deployment profile defaults applied in the editor. Review the changes, then save when you are ready.');
  };

  const loadReferenceData = async () => {
    const [rolesRes, portalRes, identityRes, bandwidthRes] = await Promise.all([
      api.get('/roles'),
      api.get('/portal-profiles'),
      api.get('/identity-sources'),
      api.get('/bandwidth-profiles'),
    ]);
    setRoles((rolesRes.data || []).map((item: JsonMap) => ({ value: item.name || '', label: item.name || 'Unnamed role' })));
    setPortalProfiles((portalRes.data || []).map((item: JsonMap) => ({ value: item.name || '', label: item.name || 'Unnamed profile' })));
    setIdentitySources((identityRes.data || []).map((item: JsonMap) => ({ value: item.name || '', label: item.name || 'Unnamed source' })));
    setBandwidthProfiles((bandwidthRes.data || []).map((item: JsonMap) => ({ value: item.name || '', label: item.name || 'Unnamed profile' })));
  };

  const loadLeaseReport = async () => {
    setLeasesLoading(true);
    try {
      const [currentRes, historyRes] = await Promise.all([
        api.get('/system/dhcp-leases'),
        api.get('/system/dhcp-lease-history'),
      ]);
      setDhcpLeases(currentRes.data.leases || []);
      setDhcpLeaseHistory(historyRes.data.history || []);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load the DHCP lease report.');
    } finally {
      setLeasesLoading(false);
    }
  };

  const loadNetworkPreview = async () => {
    setNetworkPreviewLoading(true);
    try {
      const [previewRes, backupsRes, historyRes] = await Promise.all([
        api.get('/system/network-preview'),
        api.get('/system/network-backups'),
        api.get('/system/network-apply-history'),
      ]);
      setNetworkPreview(previewRes.data || null);
      setNetworkRecovery(previewRes.data?.recovery || null);
      if (!previewRes.data?.risk?.requires_confirmation) {
        setNetworkConfirmationText('');
      }
      const snapshots = backupsRes.data?.snapshots || previewRes.data?.available_rollback_ids || [];
      setNetworkBackups(snapshots);
      setNetworkApplyHistory(historyRes.data?.history || []);
      if (snapshots.length === 0) {
        setSelectedRollbackId('');
      } else if (!snapshots.some((snapshot: NetworkSnapshotSummary) => snapshot.id === selectedRollbackId)) {
        setSelectedRollbackId(snapshots[0].id || '');
      }
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load the edge network preview.');
    } finally {
      setNetworkPreviewLoading(false);
    }
  };

  const loadNetworkObservability = async () => {
    try {
      const { data } = await api.get('/system/network-observability');
      setNetworkObservability(data || null);
      if (data?.recovery) {
        setNetworkRecovery(data.recovery);
      }
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load network observability.');
    }
  };

  const loadSettings = async () => {
    setLoading(true);
    setError('');
    try {
      const [settingsRes, previewRes] = await Promise.all([
        api.get('/system/settings'),
        api.get('/system/hostapd-preview'),
      ]);
      await loadReferenceData();
      setSettings({ ...clone(defaultSettings), ...settingsRes.data });
      setHostapdPreview(previewRes.data.config || '');
      setHostapdPath(previewRes.data.path || '');
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not load access settings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const evaluateSettings = async (candidate: JsonMap) => {
    try {
      const { data } = await api.post('/system/settings/evaluate', candidate);
      setDeploymentPreview(data.deployment || null);
      setPreviewError(data.valid ? '' : data.validation_error || 'This draft needs more deployment input before it is production-safe.');
    } catch (err: any) {
      setPreviewError(err.response?.data || err.message || 'Could not evaluate deployment capabilities.');
    }
  };

  useEffect(() => {
    if (loading) {
      return;
    }

    if (evaluateTimerRef.current) {
      window.clearTimeout(evaluateTimerRef.current);
    }
    evaluateTimerRef.current = window.setTimeout(() => {
      evaluateSettings(settings);
    }, 250);

    return () => {
      if (evaluateTimerRef.current) {
        window.clearTimeout(evaluateTimerRef.current);
      }
    };
  }, [settings, loading]);

  useEffect(() => {
    if (!networkRecovery?.pending || !networkRecovery.deadline) {
      return;
    }
    setRecoveryTick(Date.now());
    const timer = window.setInterval(() => setRecoveryTick(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [networkRecovery?.pending, networkRecovery?.deadline]);

  const saveSettings = async () => {
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.put('/system/settings', settings);
      setSettings(data.settings || settings);
      setMessage('Settings saved. Use Apply Edge Network for routing, DHCP, DNS, and firewall changes, then restart hostapd or RADIUS only when you change those services.');
      const previewRes = await api.get('/system/hostapd-preview');
      setHostapdPreview(previewRes.data.config || '');
      setHostapdPath(previewRes.data.path || '');
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not save settings.');
    } finally {
      setSaving(false);
    }
  };

  const applyNetworkServices = async () => {
    setApplyingNetwork(true);
    setError('');
    setMessage('');
    try {
      const payload = riskyNetworkApply?.requires_confirmation ? { confirmation_text: networkConfirmationText } : {};
      const { data } = await api.post('/system/network-apply', payload);
      setLastNetworkValidation(data.validation || null);
      setNetworkRecovery(data.recovery || null);
      const backupSuffix = data.backup_id ? ` Backup snapshot ${data.backup_id} was saved first.` : '';
      const validationCount = Array.isArray(data.validation?.checks) ? data.validation.checks.length : 0;
      const validationSuffix =
        data.validation?.healthy && validationCount > 0
          ? ` Post-apply validation passed across ${validationCount} checks.`
          : '';
      const recoverySuffix =
        data.recovery?.pending
          ? ` Confirm management reachability within ${data.recovery?.grace_period_seconds || data.recovery?.remaining_seconds || 0} seconds or snapshot ${data.recovery?.backup_id || data.backup_id} will be restored automatically.`
          : '';
      setMessage(`Interfaces, routes, dnsmasq, and firewall rules were applied on the appliance.${backupSuffix}${validationSuffix}${recoverySuffix}`);
      setNetworkConfirmationText('');
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setLastNetworkValidation(null);
      setError(err.response?.data || err.message || 'Could not apply edge network services.');
    } finally {
      setApplyingNetwork(false);
    }
  };

  const rollbackNetworkServices = async () => {
    setRollingBackNetwork(true);
    setError('');
    setMessage('');
    try {
      const payload = selectedRollbackId ? { id: selectedRollbackId } : {};
      const { data } = await api.post('/system/network-rollback', payload);
      setLastNetworkValidation(null);
      setNetworkRecovery(data.recovery || null);
      setMessage(`Edge network state rolled back to snapshot ${data.rollback_id}.`);
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not roll back edge network services.');
    } finally {
      setRollingBackNetwork(false);
    }
  };

  const confirmNetworkRecovery = async () => {
    if (!networkRecovery?.pending) {
      return;
    }
    setConfirmingNetworkRecovery(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.post('/system/network-recovery/confirm', { backup_id: networkRecovery.backup_id || '' });
      setNetworkRecovery(data.recovery || null);
      setMessage('Management access confirmed. Automatic rollback has been cancelled for the current edge-network change.');
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not confirm management reachability.');
    } finally {
      setConfirmingNetworkRecovery(false);
    }
  };

  const downloadSettings = async () => {
    try {
      const response = await api.get('/system/settings/export', { responseType: 'blob' });
      const href = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = href;
      link.download = 'aegisnas-system-settings.json';
      link.click();
      URL.revokeObjectURL(href);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not export settings.');
    }
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const href = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = href;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(href);
  };

  const exportNetworkHistory = async (kind: 'apply' | 'lease') => {
    try {
      const url = kind === 'apply' ? '/system/network-apply-history/export' : '/system/dhcp-lease-history/export';
      const filename = kind === 'apply' ? 'aegisnas-network-apply-history.csv' : 'aegisnas-dhcp-lease-history.csv';
      const response = await api.get(url, { responseType: 'blob', params: { format: 'csv' } });
      downloadBlob(response.data, filename);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not export network history.');
    }
  };

  const importSettings = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const payload = JSON.parse(text);
      await api.post('/system/settings/import', payload);
      setMessage('Settings imported. Restart the appliance services and hostapd after review.');
      await loadSettings();
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not import settings.');
    } finally {
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const writeHostapdConfig = async () => {
    setWritingHostapd(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.post('/system/hostapd-config');
      setMessage(`hostapd configuration written to ${data.path}. Restart hostapd on the appliance to publish the new SSIDs.`);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not write hostapd configuration.');
    } finally {
      setWritingHostapd(false);
    }
  };

  const publishHostapdConfig = async () => {
    setPublishingHostapd(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.post('/system/hostapd-publish');
      setMessage(`Wireless profile published to ${data.path} and hostapd restarted on the appliance.`);
      const previewRes = await api.get('/system/hostapd-preview');
      setHostapdPreview(previewRes.data.config || '');
      setHostapdPath(previewRes.data.path || '');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not publish hostapd configuration.');
    } finally {
      setPublishingHostapd(false);
    }
  };

  const applyRadiusConfig = async () => {
    setApplyingRadius(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.post('/system/radius-apply');
      setMessage(`FreeRADIUS configuration applied in ${data.config_dir} and the service restarted on the appliance.`);
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not apply RADIUS configuration.');
    } finally {
      setApplyingRadius(false);
    }
  };

  const upstreamServers = settings.radius?.upstream?.servers || [];
  const vendorAttributes = settings.radius?.vendor?.attributes || [];
  const ssids = settings.wireless?.ssids || [];
  const managedInterfaces = settings.network?.interfaces || [];
  const managedGateways = settings.network?.gateways || [];
  const dnsServers = settings.network?.dns?.upstream_servers || [];
  const searchDomains = settings.network?.dns?.search_domains || [];
  const staticRoutes = settings.network?.static_routes || [];
  const firewallRules = settings.network?.firewall?.rules || [];
  const freeSites = settings.network?.firewall?.free_sites || [];
  const staticLeases = settings.dhcp?.static_leases || [];
  const deploymentCapabilities = deploymentPreview?.capabilities || [];
  const deploymentWarnings = deploymentPreview?.warnings || [];
  const rollbackOptions: Option[] =
    networkBackups.length === 0
      ? [{ value: '', label: 'No rollback snapshots yet' }]
      : networkBackups.map((snapshot) => ({
          value: snapshot.id,
          label: `${snapshot.created_at} · ${snapshot.id}`,
        }));

  const riskyNetworkApply: NetworkApplyRisk | null = networkPreview?.risk || null;
  const requiredConfirmationPhrase = riskyNetworkApply?.confirmation_phrase?.trim() || '';
  const networkApplyConfirmed =
    !riskyNetworkApply?.requires_confirmation ||
    (requiredConfirmationPhrase !== '' && networkConfirmationText.trim() === requiredConfirmationPhrase);
  const networkRecoveryDeadlineMs = networkRecovery?.deadline ? new Date(networkRecovery.deadline).getTime() : 0;
  const networkRecoveryRemainingSeconds =
    networkRecovery?.pending && networkRecoveryDeadlineMs > 0
      ? Math.max(0, Math.floor((networkRecoveryDeadlineMs - recoveryTick) / 1000))
      : networkRecovery?.remaining_seconds || 0;

  if (loading) {
    return <div className="text-gray-600">Loading access settings...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Access Settings</h2>
          <p className="mt-1 text-sm text-gray-600">Control the edge appliance, enterprise auth path, and Wi-Fi radio from one place.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={downloadSettings} className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700">
            Export Settings
          </button>
          <button onClick={() => fileInputRef.current?.click()} className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700">
            Import Settings
          </button>
          <button
            onClick={loadLeaseReport}
            disabled={leasesLoading}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 disabled:opacity-60"
          >
            {leasesLoading ? 'Refreshing Leases...' : 'Refresh Lease Report'}
          </button>
          <button
            onClick={applyNetworkServices}
            disabled={applyingNetwork || !networkApplyConfirmed || Boolean(networkRecovery?.pending)}
            className="rounded-md border border-emerald-300 px-4 py-2 text-sm font-medium text-emerald-800 disabled:opacity-60"
          >
            {applyingNetwork
              ? 'Applying Network...'
              : networkRecovery?.pending
                ? 'Awaiting Reachability Confirmation'
              : riskyNetworkApply?.requires_confirmation
                ? 'Confirm And Apply Edge Network'
                : 'Apply Edge Network'}
          </button>
          <button
            onClick={loadNetworkPreview}
            disabled={networkPreviewLoading}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 disabled:opacity-60"
          >
            {networkPreviewLoading ? 'Building Preview...' : 'Preview Edge Network'}
          </button>
          <button
            onClick={rollbackNetworkServices}
            disabled={rollingBackNetwork || networkBackups.length === 0}
            className="rounded-md border border-amber-300 px-4 py-2 text-sm font-medium text-amber-800 disabled:opacity-60"
          >
            {rollingBackNetwork ? 'Rolling Back...' : 'Rollback Edge Network'}
          </button>
          <button
            onClick={writeHostapdConfig}
            disabled={writingHostapd}
            className="rounded-md border border-sky-200 px-4 py-2 text-sm font-medium text-sky-700 disabled:opacity-60"
          >
            {writingHostapd ? 'Writing hostapd...' : 'Write hostapd Config'}
          </button>
          <button
            onClick={publishHostapdConfig}
            disabled={publishingHostapd}
            className="rounded-md border border-sky-300 px-4 py-2 text-sm font-medium text-sky-800 disabled:opacity-60"
          >
            {publishingHostapd ? 'Publishing Wi-Fi...' : 'Write And Restart Wi-Fi'}
          </button>
          <button
            onClick={applyRadiusConfig}
            disabled={applyingRadius}
            className="rounded-md border border-indigo-300 px-4 py-2 text-sm font-medium text-indigo-800 disabled:opacity-60"
          >
            {applyingRadius ? 'Applying RADIUS...' : 'Apply RADIUS Config'}
          </button>
          <button
            onClick={saveSettings}
            disabled={saving}
            className="rounded-md bg-sky-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-60"
          >
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
        <input ref={fileInputRef} type="file" accept="application/json" className="hidden" onChange={importSettings} />
      </div>

      {message && <div className="rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Deployment Profile</h3>
            <p className="mt-1 text-sm text-gray-600">Tune the product for low-power appliances, higher-capacity edge boxes, or VM deployments before you fine-tune the rest.</p>
          </div>
          <button onClick={applyProfileDefaults} className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700">
            Apply Profile Defaults
          </button>
        </div>
        <div className="mb-4 rounded-md border border-sky-100 bg-sky-50 px-4 py-3 text-sm text-sky-900">
          {deploymentPreview?.summary || deploymentProfileSummary(settings.deployment?.profile || 'branch', settings.deployment?.form || 'physical')}
        </div>
        {previewError ? (
          <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            {previewError}
          </div>
        ) : null}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
          <SelectField
            label="Profile"
            value={settings.deployment?.profile || 'branch'}
            onChange={(value) => updateField(['deployment', 'profile'], value)}
            options={deploymentProfileOptions}
          />
          <SelectField
            label="Form"
            value={settings.deployment?.form || 'physical'}
            onChange={(value) => updateField(['deployment', 'form'], value)}
            options={deploymentFormOptions}
          />
          <TextField
            label="Memory MB"
            type="number"
            value={settings.deployment?.hardware?.memory_mb || 0}
            onChange={(value) => updateField(['deployment', 'hardware', 'memory_mb'], Number(value))}
          />
          <TextField
            label="CPU Cores"
            type="number"
            value={settings.deployment?.hardware?.cpu_cores || 0}
            onChange={(value) => updateField(['deployment', 'hardware', 'cpu_cores'], Number(value))}
          />
          <ToggleField
            label="Prefer External AP"
            checked={Boolean(settings.deployment?.hardware?.prefer_external_ap)}
            onChange={(value) => updateField(['deployment', 'hardware', 'prefer_external_ap'], value)}
          />
          <ToggleField
            label="Wi-Fi Passthrough Radio"
            checked={Boolean(settings.deployment?.hardware?.wireless_passthrough)}
            onChange={(value) => updateField(['deployment', 'hardware', 'wireless_passthrough'], value)}
          />
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <ToggleField label="AI Engine Enabled" checked={Boolean(settings.ailite?.enabled)} onChange={(value) => updateField(['ailite', 'enabled'], value)} />
          <ToggleField label="Telemetry Enabled" checked={Boolean(settings.telemetry?.enabled)} onChange={(value) => updateField(['telemetry', 'enabled'], value)} />
          <ToggleField
            label="Runtime Shaping Enabled"
            checked={Boolean(settings.policy?.runtime_shaping_enabled)}
            onChange={(value) => updateField(['policy', 'runtime_shaping_enabled'], value)}
          />
        </div>
        <div className="mt-4 rounded-md border border-gray-200 px-4 py-3 text-sm text-gray-600">
          Production preview: {deploymentPreview?.form || settings.deployment?.form || 'physical'} form,{' '}
          {deploymentPreview?.hardware?.cpu_cores ?? settings.deployment?.hardware?.cpu_cores ?? 'unknown'} cores,{' '}
          {deploymentPreview?.hardware?.memory_mb ?? settings.deployment?.hardware?.memory_mb ?? 'unknown'} MB RAM.
          {deploymentPreview ? (
            <span className="block mt-1 text-xs text-gray-500">
              Recommended floor: {deploymentPreview.recommended_min_cores} cores and {deploymentPreview.recommended_min_memory} MB RAM.
            </span>
          ) : null}
        </div>
        <div className="mt-6">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <h4 className="font-semibold text-gray-900">Phase 1 Capability Preview</h4>
              <p className="mt-1 text-sm text-gray-600">These states are evaluated from the draft in the editor, not just the last saved config.</p>
            </div>
            <div className="text-xs text-gray-500">Production deploy standard</div>
          </div>
          <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
            {deploymentCapabilities.map((capability) => (
              <div key={capability.key} className="rounded-md border border-gray-200 px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-gray-900">{capability.label}</div>
                    <div className="mt-1 text-sm text-gray-600">{capability.summary}</div>
                  </div>
                  <span className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${capabilityTone[capability.state]}`}>{capability.state}</span>
                </div>
                {capability.recommendation ? <div className="mt-3 text-xs text-gray-500">{capability.recommendation}</div> : null}
                {capability.dependencies?.length ? (
                  <div className="mt-2 text-xs text-gray-500">Depends on: {capability.dependencies.join(', ')}</div>
                ) : null}
              </div>
            ))}
          </div>
          <div className="mt-4 space-y-2">
            {deploymentWarnings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-600">
                This draft lines up cleanly with the selected deployment profile.
              </div>
            ) : (
              deploymentWarnings.map((warning, index) => (
                <div key={`deployment-preview-warning-${index}`} className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                  {warning}
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 rounded-md border border-sky-100 bg-sky-50 px-4 py-3 text-sm text-sky-900">
          This page ties together captive portal, EAP, LDAP, upstream AAA, and SSID behavior. Save here first, then write the generated hostapd file when the radio is ready.
        </div>
        <div className="mb-4 grid gap-4 md:grid-cols-3">
          <SelectField
            label="Mode"
            value={settings.mode}
            onChange={(value) => updateField(['mode'], value)}
            options={[
              { value: 'two-nic', label: 'Two NIC Appliance' },
              { value: 'trunk', label: 'Trunk + VLANs' },
            ]}
          />
          <TextField label="Admin Port" type="number" value={settings.admin_port} onChange={(value) => updateField(['admin_port'], Number(value))} />
          <SelectField
            label="Default Role"
            value={settings.policy?.default_role || ''}
            onChange={(value) => updateField(['policy', 'default_role'], value)}
            options={[{ value: '', label: 'No default role' }, ...roles]}
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-3">
            <h3 className="text-lg font-semibold text-gray-900">WAN</h3>
            <TextField label="Interface" value={settings.wan?.name || ''} onChange={(value) => updateField(['wan', 'name'], value)} />
            <ToggleField label="DHCP" checked={Boolean(settings.wan?.dhcp)} onChange={(value) => updateField(['wan', 'dhcp'], value)} />
            <TextField label="Address" value={settings.wan?.address || ''} onChange={(value) => updateField(['wan', 'address'], value)} placeholder="192.168.10.2/24" />
            <TextField label="Gateway" value={settings.wan?.gateway || ''} onChange={(value) => updateField(['wan', 'gateway'], value)} placeholder="192.168.10.1" />
          </div>

          <div className="space-y-3">
            <h3 className="text-lg font-semibold text-gray-900">LAN</h3>
            <TextField label="Interface" value={settings.lan?.name || ''} onChange={(value) => updateField(['lan', 'name'], value)} />
            <ToggleField label="DHCP" checked={Boolean(settings.lan?.dhcp)} onChange={(value) => updateField(['lan', 'dhcp'], value)} />
            <TextField label="Address" value={settings.lan?.address || ''} onChange={(value) => updateField(['lan', 'address'], value)} placeholder="192.168.50.1/24" />
            <TextField label="Gateway" value={settings.lan?.gateway || ''} onChange={(value) => updateField(['lan', 'gateway'], value)} placeholder="192.168.50.1" />
            <TextField label="DHCP Range" value={settings.lan?.dhcp_range || ''} onChange={(value) => updateField(['lan', 'dhcp_range'], value)} placeholder="192.168.50.100,192.168.50.200,12h" />
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">DNS, DHCP, And Lease Report</h3>
            <p className="mt-1 text-sm text-gray-600">Manage resolver behavior, static reservations, and current client leases from the same admin screen.</p>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField label="DHCP Enabled" checked={Boolean(settings.dhcp?.enabled)} onChange={(value) => updateField(['dhcp', 'enabled'], value)} />
          <ToggleField label="Authoritative" checked={Boolean(settings.dhcp?.authoritative)} onChange={(value) => updateField(['dhcp', 'authoritative'], value)} />
          <TextField label="Lease Time" value={settings.dhcp?.lease_time || '12h'} onChange={(value) => updateField(['dhcp', 'lease_time'], value)} placeholder="12h" />
          <TextField label="Local DNS Domain" value={settings.network?.dns?.local_domain || 'aegis.local'} onChange={(value) => updateField(['network', 'dns', 'local_domain'], value)} placeholder="aegis.local" />
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <div>
            <div className="mb-3 flex items-center justify-between">
              <h4 className="font-semibold text-gray-900">Upstream DNS Servers</h4>
              <button
                onClick={() => updateField(['network', 'dns', 'upstream_servers'], [...dnsServers, ''])}
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add DNS Server
              </button>
            </div>
            <div className="space-y-3">
              {dnsServers.length === 0 ? (
                <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Public resolvers or upstream recursive servers go here.</div>
              ) : (
                dnsServers.map((server: string, index: number) => (
                  <div key={`dns-server-${index}`} className="grid gap-3 rounded-lg border border-gray-200 p-3 md:grid-cols-[1fr_auto]">
                    <TextField label={`Server ${index + 1}`} value={server || ''} onChange={(value) => updateField(['network', 'dns', 'upstream_servers', String(index)], value)} placeholder="8.8.8.8" />
                    <div className="flex items-end">
                      <button
                        onClick={() => updateField(['network', 'dns', 'upstream_servers'], dnsServers.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                        className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div>
            <div className="mb-3 flex items-center justify-between">
              <h4 className="font-semibold text-gray-900">Search Domains</h4>
              <button
                onClick={() => updateField(['network', 'dns', 'search_domains'], [...searchDomains, ''])}
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Search Domain
              </button>
            </div>
            <div className="space-y-3">
              {searchDomains.length === 0 ? (
                <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Optional suffixes to hand out with DHCP.</div>
              ) : (
                searchDomains.map((domain: string, index: number) => (
                  <div key={`search-domain-${index}`} className="grid gap-3 rounded-lg border border-gray-200 p-3 md:grid-cols-[1fr_auto]">
                    <TextField label={`Domain ${index + 1}`} value={domain || ''} onChange={(value) => updateField(['network', 'dns', 'search_domains', String(index)], value)} placeholder="corp.example.com" />
                    <div className="flex items-end">
                      <button
                        onClick={() => updateField(['network', 'dns', 'search_domains'], searchDomains.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                        className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h4 className="font-semibold text-gray-900">Static DHCP Reservations</h4>
              <p className="mt-1 text-sm text-gray-600">Pin known clients to fixed addresses with optional hostnames and notes.</p>
            </div>
            <button
              onClick={() =>
                updateField(['dhcp', 'static_leases'], [
                  ...staticLeases,
                  { mac: '', ip: '', hostname: '', enabled: true, description: '' },
                ])
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Reservation
            </button>
          </div>
          <div className="space-y-4">
            {staticLeases.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Create reservations for printers, APs, cameras, or lab clients here.</div>
            ) : (
              staticLeases.map((lease: JsonMap, index: number) => (
                <div key={`static-lease-${index}`} className="rounded-lg border border-gray-200 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">{lease.hostname || lease.mac || `Reservation ${index + 1}`}</h5>
                    <button
                      onClick={() => updateField(['dhcp', 'static_leases'], staticLeases.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                    <TextField label="MAC" value={lease.mac || ''} onChange={(value) => updateField(['dhcp', 'static_leases', String(index), 'mac'], value)} placeholder="aa:bb:cc:dd:ee:ff" />
                    <TextField label="IP" value={lease.ip || ''} onChange={(value) => updateField(['dhcp', 'static_leases', String(index), 'ip'], value)} placeholder="192.168.50.10" />
                    <TextField label="Hostname" value={lease.hostname || ''} onChange={(value) => updateField(['dhcp', 'static_leases', String(index), 'hostname'], value)} placeholder="printer-lobby" />
                    <TextField label="Description" value={lease.description || ''} onChange={(value) => updateField(['dhcp', 'static_leases', String(index), 'description'], value)} placeholder="Lobby printer" />
                    <div className="flex items-end">
                      <ToggleField label="Enabled" checked={Boolean(lease.enabled)} onChange={(value) => updateField(['dhcp', 'static_leases', String(index), 'enabled'], value)} />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-gray-200 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Lease Observations</div>
              <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.lease_trends?.total_records ?? dhcpLeaseHistory.length}</div>
              <div className="mt-1 text-sm text-gray-600">Stored lease-history rows.</div>
            </div>
            <div className="rounded-lg border border-gray-200 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Unique Clients {networkObservability?.lease_trends?.window_hours || 24}h</div>
              <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.lease_trends?.unique_macs_window ?? 0}</div>
              <div className="mt-1 text-sm text-gray-600">Distinct MAC addresses seen recently.</div>
            </div>
            <div className="rounded-lg border border-gray-200 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Peak Concurrent Leases</div>
              <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.lease_trends?.peak_concurrent_leases_window ?? 0}</div>
              <div className="mt-1 text-sm text-gray-600">Highest distinct lease count inside the trend window.</div>
            </div>
            <div className="rounded-lg border border-gray-200 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Reservations In Window</div>
              <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.lease_trends?.reservation_observations_window ?? 0}</div>
              <div className="mt-1 text-sm text-gray-600">Reserved-address lease observations inside the trend window.</div>
            </div>
          </div>
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h4 className="font-semibold text-gray-900">IP Leasing Report</h4>
              <p className="mt-1 text-sm text-gray-600">Live dnsmasq lease data, including reservations and expired clients.</p>
            </div>
            <span className="text-sm text-gray-500">{leasesLoading ? 'Refreshing...' : `${dhcpLeases.length} leases`}</span>
          </div>
          <div className="overflow-x-auto rounded-lg border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">IP</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">MAC</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Hostname</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Lease Ends</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Reservation</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {dhcpLeases.length === 0 ? (
                  <tr>
                    <td className="px-3 py-6 text-gray-500" colSpan={6}>
                      No leases are currently present in dnsmasq.
                    </td>
                  </tr>
                ) : (
                  dhcpLeases.map((lease) => (
                    <tr key={`${lease.ip}-${lease.mac}`}>
                      <td className="px-3 py-2 text-gray-900">{lease.ip || '-'}</td>
                      <td className="px-3 py-2 font-mono text-gray-700">{lease.mac || '-'}</td>
                      <td className="px-3 py-2 text-gray-700">{lease.hostname || '-'}</td>
                      <td className="px-3 py-2 text-gray-700">{lease.expires_at || '-'}</td>
                      <td className="px-3 py-2 text-gray-700">{lease.reservation ? 'Yes' : 'No'}</td>
                      <td className="px-3 py-2 text-gray-700">{lease.expired ? 'Expired' : 'Active'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div className="mt-6">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <h5 className="font-semibold text-gray-900">Recent Lease History</h5>
                <p className="mt-1 text-sm text-gray-600">Recent lease observations captured by the background collector and on-demand refreshes.</p>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-sm text-gray-500">{leasesLoading ? 'Refreshing history...' : `${dhcpLeaseHistory.length} observations`}</span>
                <button
                  onClick={() => exportNetworkHistory('lease')}
                  className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
                >
                  Export Lease CSV
                </button>
              </div>
            </div>
            <div className="overflow-x-auto rounded-lg border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">Observed</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">IP</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">MAC</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">Hostname</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">Reservation</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {dhcpLeaseHistory.length === 0 ? (
                    <tr>
                      <td className="px-3 py-6 text-gray-500" colSpan={6}>
                        No lease history has been captured yet. Refresh the live report to store observations.
                      </td>
                    </tr>
                  ) : (
                    dhcpLeaseHistory.slice(0, 12).map((lease) => (
                      <tr key={`${lease.id}-${lease.observed_at}`}>
                        <td className="px-3 py-2 text-gray-700">{lease.observed_at}</td>
                        <td className="px-3 py-2 text-gray-900">{lease.ip || '-'}</td>
                        <td className="px-3 py-2 font-mono text-gray-700">{lease.mac || '-'}</td>
                        <td className="px-3 py-2 text-gray-700">{lease.hostname || '-'}</td>
                        <td className="px-3 py-2 text-gray-700">{lease.reservation ? 'Yes' : 'No'}</td>
                        <td className="px-3 py-2 text-gray-700">{lease.expired ? 'Expired' : 'Active'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Edge Network Preview And Rollback</h3>
            <p className="mt-1 text-sm text-gray-600">Save first, then preview or apply. The preview reflects the last saved config on the appliance, not unsaved edits still sitting in the browser.</p>
          </div>
          <div className="min-w-[280px]">
            <SelectField label="Rollback Snapshot" value={selectedRollbackId} onChange={setSelectedRollbackId} options={rollbackOptions} />
          </div>
        </div>
        {lastNetworkValidation && (
          <div className={`rounded-lg border p-4 text-sm ${lastNetworkValidation.healthy ? 'border-emerald-200 bg-emerald-50 text-emerald-900' : 'border-red-200 bg-red-50 text-red-900'}`}>
            <div className="font-semibold">{lastNetworkValidation.healthy ? 'Last Apply Validation Passed' : 'Last Apply Validation Failed'}</div>
            <div className="mt-2 space-y-1">
              {lastNetworkValidation.checks.map((check) => (
                <div key={`${check.name}-${check.detail}`} className="flex flex-wrap gap-2">
                  <span className="font-medium">{check.name}</span>
                  <span className="uppercase tracking-wide">{check.status}</span>
                  <span>{check.detail}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {networkRecovery ? (
          <div
            className={`mt-4 rounded-lg border p-4 text-sm ${
              networkRecovery.pending
                ? 'border-amber-300 bg-amber-50 text-amber-950'
                : networkRecovery.status === 'degraded'
                  ? 'border-red-200 bg-red-50 text-red-900'
                  : 'border-sky-200 bg-sky-50 text-sky-900'
            }`}
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="font-semibold">
                  {networkRecovery.pending ? 'Management Reachability Confirmation Pending' : 'Latest Reachability Recovery Status'}
                </div>
                <div className="mt-1">{networkRecovery.message || 'No management-loss recovery state is currently recorded.'}</div>
                {networkRecovery.risk_summary ? <div className="mt-2 text-xs text-gray-700">Risk summary: {networkRecovery.risk_summary}</div> : null}
                {networkRecovery.validation_summary ? <div className="mt-1 text-xs text-gray-700">Validation: {networkRecovery.validation_summary}</div> : null}
                {networkRecovery.backup_id ? <div className="mt-1 text-xs text-gray-700">Protected snapshot: {networkRecovery.backup_id}</div> : null}
                {networkRecovery.deadline ? <div className="mt-1 text-xs text-gray-700">Rollback deadline: {networkRecovery.deadline}</div> : null}
              </div>
              {networkRecovery.pending ? (
                <div className="rounded-md border border-amber-300 bg-white px-3 py-2 text-sm text-amber-950">
                  <div className="text-xs font-semibold uppercase tracking-wide text-amber-800">Time Remaining</div>
                  <div className="mt-1 font-mono text-lg">{networkRecoveryRemainingSeconds}s</div>
                  <button
                    onClick={confirmNetworkRecovery}
                    disabled={confirmingNetworkRecovery}
                    className="mt-3 rounded-md border border-emerald-300 px-3 py-2 text-sm font-medium text-emerald-800 disabled:opacity-60"
                  >
                    {confirmingNetworkRecovery ? 'Confirming Access...' : 'I Still Have Admin Access'}
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        ) : null}
        {riskyNetworkApply && riskyNetworkApply.items.length > 0 ? (
          <div
            className={`mt-4 rounded-lg border p-4 text-sm ${
              riskyNetworkApply.requires_confirmation
                ? 'border-amber-300 bg-amber-50 text-amber-950'
                : 'border-sky-200 bg-sky-50 text-sky-900'
            }`}
          >
            <div className="font-semibold">
              {riskyNetworkApply.requires_confirmation ? 'Management Impact Confirmation Required' : 'Edge Network Warnings'}
            </div>
            <div className="mt-1">{riskyNetworkApply.summary}</div>
            <div className="mt-3 space-y-2">
              {riskyNetworkApply.items.map((item) => (
                <div
                  key={`${item.code}-${item.message}`}
                  className={`rounded-md border px-3 py-2 ${
                    item.level === 'danger'
                      ? 'border-amber-300 bg-white text-amber-950'
                      : 'border-sky-200 bg-white text-sky-900'
                  }`}
                >
                  <div className="text-xs font-semibold uppercase tracking-wide">{item.level}</div>
                  <div className="mt-1">{item.message}</div>
                </div>
              ))}
            </div>
            {riskyNetworkApply.requires_confirmation ? (
              <div className="mt-4 grid gap-3 md:grid-cols-[minmax(0,1fr)_220px] md:items-end">
                <label className="block text-sm font-medium text-gray-700">
                  <span>Type the confirmation phrase to unlock apply</span>
                  <input
                    type="text"
                    value={networkConfirmationText}
                    onChange={(event) => setNetworkConfirmationText(event.target.value)}
                    placeholder={requiredConfirmationPhrase}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 font-mono"
                  />
                </label>
                <div className="rounded-md border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700">
                  <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Confirmation Phrase</div>
                  <div className="mt-1 font-mono text-gray-900">{requiredConfirmationPhrase}</div>
                  <div className="mt-2 text-xs text-gray-500">The apply button stays locked until this phrase matches exactly.</div>
                </div>
              </div>
            ) : null}
          </div>
        ) : null}
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-sm font-semibold text-gray-900">Saved Config Delta</div>
            <div className="mt-2 text-sm text-gray-600">
              {(networkPreview?.diff?.interfaces_added?.length || 0) +
                (networkPreview?.diff?.interfaces_removed?.length || 0) +
                (networkPreview?.diff?.gateways_added?.length || 0) +
                (networkPreview?.diff?.gateways_removed?.length || 0) +
                (networkPreview?.diff?.routes_added?.length || 0) +
                (networkPreview?.diff?.routes_removed?.length || 0)}{' '}
              managed network changes pending between the current live state and the last saved config.
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-sm font-semibold text-gray-900">DNS And DHCP Preview</div>
            <div className="mt-2 text-sm text-gray-600">
              {networkPreview?.dnsmasq_enabled ? 'dnsmasq will run with the generated config below.' : 'dnsmasq is disabled in the saved config and will be stopped on apply.'}
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-sm font-semibold text-gray-900">Rollback Safety Net</div>
            <div className="mt-2 text-sm text-gray-600">
              {networkBackups.length === 0
                ? 'No edge network backups have been captured yet. The first apply will create one automatically.'
                : `${networkBackups.length} rollback snapshot${networkBackups.length === 1 ? '' : 's'} available.`}
            </div>
          </div>
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Apply Successes</div>
            <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.apply_stats?.apply_success_count ?? 0}</div>
            <div className="mt-1 text-sm text-gray-600">Successful edge-network applies recorded so far.</div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Apply Failures</div>
            <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.apply_stats?.apply_failure_count ?? 0}</div>
            <div className="mt-1 text-sm text-gray-600">Pre- or post-apply failures that interrupted a network rollout.</div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Rollback Count</div>
            <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.apply_stats?.rollback_count ?? 0}</div>
            <div className="mt-1 text-sm text-gray-600">Manual rollback operations completed from the UI.</div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Auto-Rollbacks</div>
            <div className="mt-2 text-2xl font-bold text-gray-900">{networkObservability?.apply_stats?.auto_rollback_count ?? 0}</div>
            <div className="mt-1 text-sm text-gray-600">Timed safety restores after risky changes lost confirmation.</div>
          </div>
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <div>
            <h4 className="font-semibold text-gray-900">Change Summary</h4>
            <div className="mt-3 space-y-3 text-sm">
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">Interfaces Added</div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.interfaces_added?.length ? networkPreview.diff.interfaces_added.join(', ') : 'None'}
                </div>
              </div>
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">Interfaces Removed</div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.interfaces_removed?.length ? networkPreview.diff.interfaces_removed.join(', ') : 'None'}
                </div>
              </div>
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">Gateways Added Or Changed</div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.gateways_added?.length ? networkPreview.diff.gateways_added.join(', ') : 'None'}
                </div>
              </div>
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">Routes Added Or Changed</div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.routes_added?.length ? networkPreview.diff.routes_added.join(', ') : 'None'}
                </div>
              </div>
            </div>
          </div>

          <div>
            <h4 className="font-semibold text-gray-900">Rollback Snapshots</h4>
            <div className="mt-3 overflow-x-auto rounded-lg border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">Created</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">By</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">Reason</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">Counts</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {networkBackups.length === 0 ? (
                    <tr>
                      <td className="px-3 py-5 text-gray-500" colSpan={4}>
                        No rollback snapshots captured yet.
                      </td>
                    </tr>
                  ) : (
                    networkBackups.slice(0, 6).map((snapshot) => (
                      <tr key={snapshot.id}>
                        <td className="px-3 py-2 text-gray-700">{snapshot.created_at}</td>
                        <td className="px-3 py-2 text-gray-700">{snapshot.created_by || '-'}</td>
                        <td className="px-3 py-2 text-gray-700">{snapshot.reason || '-'}</td>
                        <td className="px-3 py-2 text-gray-700">
                          {snapshot.interfaces} if / {snapshot.gateways} gw / {snapshot.routes} rt
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="mt-6">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h4 className="font-semibold text-gray-900">Recent Apply History</h4>
              <p className="mt-1 text-sm text-gray-600">This captures applies, confirmations, failures, rollbacks, and auto-recovery events.</p>
            </div>
            <button
              onClick={() => exportNetworkHistory('apply')}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Export Apply CSV
            </button>
          </div>
          <div className="mt-3 overflow-x-auto rounded-lg border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">When</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Action</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Status</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Actor</th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {networkApplyHistory.length === 0 ? (
                  <tr>
                    <td className="px-3 py-6 text-gray-500" colSpan={5}>
                      No network apply history has been captured yet.
                    </td>
                  </tr>
                ) : (
                  networkApplyHistory.slice(0, 12).map((item) => (
                    <tr key={item.id}>
                      <td className="px-3 py-2 text-gray-700">{item.created_at}</td>
                      <td className="px-3 py-2 text-gray-700">{item.action}</td>
                      <td className="px-3 py-2 text-gray-700">{item.status}</td>
                      <td className="px-3 py-2 text-gray-700">{item.actor || '-'}</td>
                      <td className="px-3 py-2 text-gray-700">{item.summary || '-'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {networkObservability?.controller_sync ? (
            <div className="mt-6 rounded-lg border border-gray-200 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h5 className="font-semibold text-gray-900">Controller Sync Health</h5>
                  <p className="mt-1 text-sm text-gray-600">{networkObservability.controller_sync.message || 'No controller sync runtime message recorded yet.'}</p>
                  <div className="mt-3 grid gap-2 text-sm text-gray-700 md:grid-cols-2 xl:grid-cols-4">
                    <div>Sync Count: <span className="font-semibold">{networkObservability.controller_sync.details?.sync_count ?? 0}</span></div>
                    <div>Successes: <span className="font-semibold">{networkObservability.controller_sync.details?.success_count ?? 0}</span></div>
                    <div>Failures: <span className="font-semibold">{networkObservability.controller_sync.details?.failure_count ?? 0}</span></div>
                    <div>Last Duration: <span className="font-semibold">{networkObservability.controller_sync.details?.last_duration_ms ?? 0} ms</span></div>
                  </div>
                </div>
                <span className="rounded-md border border-gray-200 px-2 py-1 text-xs font-semibold uppercase text-gray-700">
                  {networkObservability.controller_sync.status || 'unknown'}
                </span>
              </div>
            </div>
          ) : null}
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <label className="block text-sm font-medium text-gray-700">
            <span>Generated dnsmasq Preview</span>
            <textarea
              value={networkPreview?.dnsmasq_config || (networkPreview?.dnsmasq_enabled ? 'Loading preview...' : '# dnsmasq disabled in saved config')}
              readOnly
              className="mt-1 min-h-[240px] w-full rounded-md border border-gray-300 bg-gray-950 px-4 py-3 font-mono text-sm text-gray-100"
            />
          </label>
          <label className="block text-sm font-medium text-gray-700">
            <span>Generated Firewall Preview</span>
            <textarea
              value={networkPreview?.firewall_rules || 'Loading preview...'}
              readOnly
              className="mt-1 min-h-[240px] w-full rounded-md border border-gray-300 bg-gray-950 px-4 py-3 font-mono text-sm text-gray-100"
            />
          </label>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Interfaces, Gateways, And Static Routes</h3>
            <p className="mt-1 text-sm text-gray-600">Use these objects for extra addresses, default route failover, and downstream network reachability.</p>
          </div>
        </div>

        <div className="mb-6">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Managed Interfaces</h4>
            <button
              onClick={() =>
                updateField(['network', 'interfaces'], [
                  ...managedInterfaces,
                  { name: '', address: '', mtu: 1500, enabled: true, description: '' },
                ])
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Interface
            </button>
          </div>
          <div className="space-y-4">
            {managedInterfaces.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Use this for extra VLAN handoffs, transit links, or loopback-style addresses beyond the primary WAN and LAN.</div>
            ) : (
              managedInterfaces.map((iface: JsonMap, index: number) => (
                <div key={`managed-iface-${index}`} className="rounded-lg border border-gray-200 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">{iface.name || `Interface ${index + 1}`}</h5>
                    <button
                      onClick={() => updateField(['network', 'interfaces'], managedInterfaces.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    <TextField label="Name" value={iface.name || ''} onChange={(value) => updateField(['network', 'interfaces', String(index), 'name'], value)} placeholder="eth2.50" />
                    <TextField label="Address" value={iface.address || ''} onChange={(value) => updateField(['network', 'interfaces', String(index), 'address'], value)} placeholder="10.10.50.1/24" />
                    <TextField label="MTU" type="number" value={iface.mtu || 1500} onChange={(value) => updateField(['network', 'interfaces', String(index), 'mtu'], Number(value))} />
                    <TextField label="Description" value={iface.description || ''} onChange={(value) => updateField(['network', 'interfaces', String(index), 'description'], value)} placeholder="Transit handoff" />
                  </div>
                  <div className="mt-4">
                    <ToggleField label="Enabled" checked={Boolean(iface.enabled)} onChange={(value) => updateField(['network', 'interfaces', String(index), 'enabled'], value)} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="mb-6 border-t border-gray-200 pt-5">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Gateways</h4>
            <button
              onClick={() =>
                updateField(['network', 'gateways'], [
                  ...managedGateways,
                  { name: '', address: '', interface: settings.wan?.name || '', metric: 0, default: true, enabled: true, description: '' },
                ])
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Gateway
            </button>
          </div>
          <div className="space-y-4">
            {managedGateways.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Define alternate default routes and gateway priorities here.</div>
            ) : (
              managedGateways.map((gateway: JsonMap, index: number) => (
                <div key={`gateway-${index}`} className="rounded-lg border border-gray-200 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">{gateway.name || `Gateway ${index + 1}`}</h5>
                    <button
                      onClick={() => updateField(['network', 'gateways'], managedGateways.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                    <TextField label="Name" value={gateway.name || ''} onChange={(value) => updateField(['network', 'gateways', String(index), 'name'], value)} />
                    <TextField label="Address" value={gateway.address || ''} onChange={(value) => updateField(['network', 'gateways', String(index), 'address'], value)} placeholder="192.168.10.1" />
                    <TextField label="Interface" value={gateway.interface || ''} onChange={(value) => updateField(['network', 'gateways', String(index), 'interface'], value)} placeholder={settings.wan?.name || 'eth0'} />
                    <TextField label="Metric" type="number" value={gateway.metric || 0} onChange={(value) => updateField(['network', 'gateways', String(index), 'metric'], Number(value))} />
                    <TextField label="Description" value={gateway.description || ''} onChange={(value) => updateField(['network', 'gateways', String(index), 'description'], value)} placeholder="Primary ISP" />
                  </div>
                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <ToggleField label="Default Route" checked={Boolean(gateway.default)} onChange={(value) => updateField(['network', 'gateways', String(index), 'default'], value)} />
                    <ToggleField label="Enabled" checked={Boolean(gateway.enabled)} onChange={(value) => updateField(['network', 'gateways', String(index), 'enabled'], value)} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="border-t border-gray-200 pt-5">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Static Routes</h4>
            <button
              onClick={() =>
                updateField(['network', 'static_routes'], [
                  ...staticRoutes,
                  { name: '', destination: '', gateway: '', interface: settings.wan?.name || '', metric: 0, enabled: true, description: '' },
                ])
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Route
            </button>
          </div>
          <div className="space-y-4">
            {staticRoutes.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Add static routes for upstream services, site links, or downstream lab networks.</div>
            ) : (
              staticRoutes.map((route: JsonMap, index: number) => (
                <div key={`route-${index}`} className="rounded-lg border border-gray-200 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">{route.name || `Route ${index + 1}`}</h5>
                    <button
                      onClick={() => updateField(['network', 'static_routes'], staticRoutes.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
                    <TextField label="Name" value={route.name || ''} onChange={(value) => updateField(['network', 'static_routes', String(index), 'name'], value)} />
                    <TextField label="Destination" value={route.destination || ''} onChange={(value) => updateField(['network', 'static_routes', String(index), 'destination'], value)} placeholder="172.16.20.0/24" />
                    <TextField label="Gateway" value={route.gateway || ''} onChange={(value) => updateField(['network', 'static_routes', String(index), 'gateway'], value)} placeholder="192.168.10.254" />
                    <TextField label="Interface" value={route.interface || ''} onChange={(value) => updateField(['network', 'static_routes', String(index), 'interface'], value)} placeholder={settings.wan?.name || 'eth0'} />
                    <TextField label="Metric" type="number" value={route.metric || 0} onChange={(value) => updateField(['network', 'static_routes', String(index), 'metric'], Number(value))} />
                    <TextField label="Description" value={route.description || ''} onChange={(value) => updateField(['network', 'static_routes', String(index), 'description'], value)} placeholder="Branch backhaul" />
                  </div>
                  <div className="mt-4">
                    <ToggleField label="Enabled" checked={Boolean(route.enabled)} onChange={(value) => updateField(['network', 'static_routes', String(index), 'enabled'], value)} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Firewall, DoS, And Free Sites</h3>
          <p className="mt-1 text-sm text-gray-600">Blend platform-safe defaults with explicit admin rules, domain/CIDR wall-garden entries, and lightweight DoS controls.</p>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          <ToggleField
            label="DoS Protection Enabled"
            checked={Boolean(settings.network?.firewall?.dos_protection?.enabled)}
            onChange={(value) => updateField(['network', 'firewall', 'dos_protection', 'enabled'], value)}
          />
          <TextField label="SYN Rate" value={settings.network?.firewall?.dos_protection?.syn_rate || '50/second'} onChange={(value) => updateField(['network', 'firewall', 'dos_protection', 'syn_rate'], value)} />
          <TextField label="ICMP Rate" value={settings.network?.firewall?.dos_protection?.icmp_rate || '25/second'} onChange={(value) => updateField(['network', 'firewall', 'dos_protection', 'icmp_rate'], value)} />
          <TextField label="Conn Rate" value={settings.network?.firewall?.dos_protection?.conn_rate || '200/second'} onChange={(value) => updateField(['network', 'firewall', 'dos_protection', 'conn_rate'], value)} />
          <TextField label="Burst" type="number" value={settings.network?.firewall?.dos_protection?.burst || 100} onChange={(value) => updateField(['network', 'firewall', 'dos_protection', 'burst'], Number(value))} />
        </div>
        <div className="mt-3">
          <ToggleField
            label="Log DoS Drops"
            checked={Boolean(settings.network?.firewall?.dos_protection?.log_drops)}
            onChange={(value) => updateField(['network', 'firewall', 'dos_protection', 'log_drops'], value)}
          />
        </div>

        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Free Sites</h4>
            <button
              onClick={() =>
                updateField(['network', 'firewall', 'free_sites'], [
                  ...freeSites,
                  { type: 'domain', value: '', enabled: true, description: '' },
                ])
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Free Site
            </button>
          </div>
          <div className="space-y-4">
            {freeSites.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Allow captive clients to reach health checks, payment portals, or approved public destinations here.</div>
            ) : (
              freeSites.map((site: JsonMap, index: number) => (
                <div key={`free-site-${index}`} className="rounded-lg border border-gray-200 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">{site.value || `Free Site ${index + 1}`}</h5>
                    <button
                      onClick={() => updateField(['network', 'firewall', 'free_sites'], freeSites.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    <SelectField
                      label="Type"
                      value={site.type || 'domain'}
                      onChange={(value) => updateField(['network', 'firewall', 'free_sites', String(index), 'type'], value)}
                      options={freeSiteTypeOptions}
                    />
                    <TextField
                      label="Value"
                      value={site.value || ''}
                      onChange={(value) => updateField(['network', 'firewall', 'free_sites', String(index), 'value'], value)}
                      placeholder={site.type === 'cidr' ? '203.0.113.0/24' : 'example.com'}
                    />
                    <TextField label="Description" value={site.description || ''} onChange={(value) => updateField(['network', 'firewall', 'free_sites', String(index), 'description'], value)} placeholder="Payment provider" />
                    <div className="flex items-end">
                      <ToggleField label="Enabled" checked={Boolean(site.enabled)} onChange={(value) => updateField(['network', 'firewall', 'free_sites', String(index), 'enabled'], value)} />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Custom Firewall Rules</h4>
            <button
              onClick={() =>
                updateField(['network', 'firewall', 'rules'], [
                  ...firewallRules,
                  { name: '', chain: 'forward', action: 'accept', interface: '', source: '', destination: '', protocol: 'any', ports: '', enabled: true, description: '' },
                ])
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Firewall Rule
            </button>
          </div>
          <div className="space-y-4">
            {firewallRules.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Add explicit input or forward rules when the built-in edge policy needs a careful exception.</div>
            ) : (
              firewallRules.map((rule: JsonMap, index: number) => (
                <div key={`firewall-rule-${index}`} className="rounded-lg border border-gray-200 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">{rule.name || `Rule ${index + 1}`}</h5>
                    <button
                      onClick={() => updateField(['network', 'firewall', 'rules'], firewallRules.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                    <TextField label="Name" value={rule.name || ''} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'name'], value)} />
                    <SelectField label="Chain" value={rule.chain || 'forward'} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'chain'], value)} options={firewallChainOptions} />
                    <SelectField label="Action" value={rule.action || 'accept'} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'action'], value)} options={firewallActionOptions} />
                    <SelectField label="Protocol" value={rule.protocol || 'any'} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'protocol'], value)} options={firewallProtocolOptions} />
                    <TextField label="Interface" value={rule.interface || ''} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'interface'], value)} placeholder="ens37" />
                    <TextField label="Source CIDR" value={rule.source || ''} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'source'], value)} placeholder="192.168.50.0/24" />
                    <TextField label="Destination CIDR" value={rule.destination || ''} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'destination'], value)} placeholder="203.0.113.0/24" />
                    <TextField label="Ports" value={rule.ports || ''} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'ports'], value)} placeholder="80,443" />
                    <TextField label="Description" value={rule.description || ''} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'description'], value)} placeholder="Allow support tunnel" />
                  </div>
                  <div className="mt-4">
                    <ToggleField label="Enabled" checked={Boolean(rule.enabled)} onChange={(value) => updateField(['network', 'firewall', 'rules', String(index), 'enabled'], value)} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">Captive Portal And Directory</h3>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <ToggleField label="Portal Enabled" checked={Boolean(settings.portal?.enabled)} onChange={(value) => updateField(['portal', 'enabled'], value)} />
          <ToggleField label="Portal Uses RADIUS Broker" checked={Boolean(settings.portal?.radius_auth)} onChange={(value) => updateField(['portal', 'radius_auth'], value)} />
          <ToggleField label="Local Fallback" checked={Boolean(settings.portal?.local_fallback)} onChange={(value) => updateField(['portal', 'local_fallback'], value)} />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <TextField label="Portal Port" type="number" value={settings.portal?.port || 8081} onChange={(value) => updateField(['portal', 'port'], Number(value))} />
          <TextField label="Portal Listen IP" value={settings.portal?.listen_ip || ''} onChange={(value) => updateField(['portal', 'listen_ip'], value)} />
          <TextField label="Branding" value={settings.portal?.branding || ''} onChange={(value) => updateField(['portal', 'branding'], value)} />
          <TextField label="Success URL" value={settings.portal?.success_url || ''} onChange={(value) => updateField(['portal', 'success_url'], value)} />
          <TextField label="Logout URL" value={settings.portal?.logout_url || ''} onChange={(value) => updateField(['portal', 'logout_url'], value)} />
          <TextField label="LDAP URL" value={settings.ldap?.url || ''} onChange={(value) => updateField(['ldap', 'url'], value)} placeholder="ldaps://ldap.example.com" />
          <TextField label="Base DN" value={settings.ldap?.base_dn || ''} onChange={(value) => updateField(['ldap', 'base_dn'], value)} />
          <TextField label="Bind DN" value={settings.ldap?.bind_dn || ''} onChange={(value) => updateField(['ldap', 'bind_dn'], value)} />
          <TextField label="Bind Password" type="password" value={settings.ldap?.bind_password || ''} onChange={(value) => updateField(['ldap', 'bind_password'], value)} />
          <TextField label="User Filter" value={settings.ldap?.user_filter || ''} onChange={(value) => updateField(['ldap', 'user_filter'], value)} />
          <TextField label="Group Filter" value={settings.ldap?.group_filter || ''} onChange={(value) => updateField(['ldap', 'group_filter'], value)} />
        </div>
        <div className="mt-4">
          <ToggleField label="LDAP Enabled" checked={Boolean(settings.ldap?.enabled)} onChange={(value) => updateField(['ldap', 'enabled'], value)} />
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">Guest Workflow And Delivery</h4>
            <p className="mt-1 text-sm text-gray-600">Phase 2 turns guest self-registration and sponsor approval into production-checked settings instead of free-form toggles.</p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <ToggleField
              label="Self Registration Enabled"
              checked={Boolean(settings.portal?.guest_workflows?.self_registration_enabled)}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'self_registration_enabled'], value)}
            />
            <ToggleField
              label="Sponsor Approval Enabled"
              checked={Boolean(settings.portal?.guest_workflows?.sponsor_approval_enabled)}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'sponsor_approval_enabled'], value)}
            />
            <SelectField
              label="Invite Delivery"
              value={settings.portal?.guest_workflows?.invite_delivery || 'none'}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'invite_delivery'], value)}
              options={guestDeliveryOptions}
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SelectField
              label="Approval Delivery"
              value={settings.portal?.guest_workflows?.approval_delivery || ''}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'approval_delivery'], value)}
              options={approvalDeliveryOptions}
            />
            <TextField
              label="Email From"
              value={settings.portal?.guest_workflows?.email_from || ''}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'email_from'], value)}
              placeholder="guests@example.com"
            />
            <TextField
              label="SMTP Server"
              value={settings.portal?.guest_workflows?.smtp_server || ''}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'smtp_server'], value)}
              placeholder="smtp.example.com"
            />
            <TextField
              label="SMTP Port"
              type="number"
              value={settings.portal?.guest_workflows?.smtp_port || 587}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'smtp_port'], Number(value))}
            />
            <TextField
              label="SMS Provider"
              value={settings.portal?.guest_workflows?.sms_provider || ''}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'sms_provider'], value)}
              placeholder="twilio-like"
            />
            <TextField
              label="SMS Endpoint"
              value={settings.portal?.guest_workflows?.sms_endpoint || ''}
              onChange={(value) => updateField(['portal', 'guest_workflows', 'sms_endpoint'], value)}
              placeholder="https://sms.example.com/send"
            />
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">AI Engine And Runtime Load</h3>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <SelectField
            label="AI Mode"
            value={settings.ailite?.mode || 'lite'}
            onChange={(value) => updateField(['ailite', 'mode'], value)}
            options={aiModeOptions}
          />
          <SelectField
            label="AI Provider"
            value={settings.ailite?.provider || 'local'}
            onChange={(value) => updateField(['ailite', 'provider'], value)}
            options={aiProviderOptions}
          />
          <TextField
            label="Full AI Endpoint"
            value={settings.ailite?.endpoint || ''}
            onChange={(value) => updateField(['ailite', 'endpoint'], value)}
            placeholder="http://127.0.0.1:11434"
          />
          <TextField
            label="Full AI Model"
            value={settings.ailite?.model || ''}
            onChange={(value) => updateField(['ailite', 'model'], value)}
            placeholder="ops-model"
          />
          <TextField
            label="AI API Key Env"
            value={settings.ailite?.api_key_env || 'AEGIS_AI_API_KEY'}
            onChange={(value) => updateField(['ailite', 'api_key_env'], value)}
          />
          <TextField
            label="AI Timeout Seconds"
            type="number"
            value={settings.ailite?.request_timeout_seconds || 20}
            onChange={(value) => updateField(['ailite', 'request_timeout_seconds'], Number(value))}
          />
          <TextField
            label="AI Input Events"
            type="number"
            value={settings.ailite?.max_input_events || 200}
            onChange={(value) => updateField(['ailite', 'max_input_events'], Number(value))}
          />
          <TextField
            label="Prometheus Port"
            type="number"
            value={settings.telemetry?.prometheus_port || 9090}
            onChange={(value) => updateField(['telemetry', 'prometheus_port'], Number(value))}
          />
          <TextField
            label="Lease History Poll Seconds"
            type="number"
            value={settings.telemetry?.lease_history_poll_seconds || 300}
            onChange={(value) => updateField(['telemetry', 'lease_history_poll_seconds'], Number(value))}
          />
          <TextField
            label="Recommendation Limit"
            type="number"
            value={settings.ailite?.recommendation_limit || 100}
            onChange={(value) => updateField(['ailite', 'recommendation_limit'], Number(value))}
          />
          <TextField
            label="AI Webhook"
            value={settings.ailite?.remote_webhook || ''}
            onChange={(value) => updateField(['ailite', 'remote_webhook'], value)}
            placeholder="https://ops.example.com/webhook"
          />
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Onboarding, Inventory, And Profiling</h3>
          <p className="mt-1 text-sm text-gray-600">Phase 3 prepares BYOD-style onboarding, certificate enrollment, and device visibility with production-safe dependency checks.</p>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField
            label="Device Inventory Enabled"
            checked={Boolean(settings.onboarding?.device_inventory_enabled)}
            onChange={(value) => updateField(['onboarding', 'device_inventory_enabled'], value)}
          />
          <ToggleField
            label="Onboarding Portal Enabled"
            checked={Boolean(settings.onboarding?.portal_enabled)}
            onChange={(value) => updateField(['onboarding', 'portal_enabled'], value)}
          />
          <ToggleField
            label="Certificate Enrollment Enabled"
            checked={Boolean(settings.onboarding?.certificate_enrollment_enabled)}
            onChange={(value) => updateField(['onboarding', 'certificate_enrollment_enabled'], value)}
          />
          <ToggleField
            label="EAP-TLS Onboarding Enabled"
            checked={Boolean(settings.onboarding?.eap_tls_enabled)}
            onChange={(value) => updateField(['onboarding', 'eap_tls_enabled'], value)}
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SelectField
            label="CA Mode"
            value={settings.onboarding?.ca_mode || 'none'}
            onChange={(value) => updateField(['onboarding', 'ca_mode'], value)}
            options={caModeOptions}
          />
          <TextField
            label="CA Certificate Path"
            value={settings.onboarding?.ca_cert_path || ''}
            onChange={(value) => updateField(['onboarding', 'ca_cert_path'], value)}
            placeholder="/etc/aegisnas/pki/ca.crt"
          />
          <TextField
            label="CA Private Key Path"
            value={settings.onboarding?.ca_key_path || ''}
            onChange={(value) => updateField(['onboarding', 'ca_key_path'], value)}
            placeholder="/etc/aegisnas/pki/ca.key"
          />
            <TextField
              label="CA Enrollment URL"
              value={settings.onboarding?.ca_enrollment_url || ''}
              onChange={(value) => updateField(['onboarding', 'ca_enrollment_url'], value)}
              placeholder="https://ca.example.com/enroll"
            />
            <TextField
              label="CA Enrollment Token Env"
              value={settings.onboarding?.ca_enrollment_token_env || ''}
              onChange={(value) => updateField(['onboarding', 'ca_enrollment_token_env'], value)}
              placeholder="AEGIS_CA_ENROLLMENT_TOKEN"
            />
          </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">Passive Profiling And Posture</h4>
            <p className="mt-1 text-sm text-gray-600">Use these only when you are ready to support inventory retention, compliance inputs, and remediation decisions.</p>
          </div>
          <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="MAC Inventory Enabled"
              checked={Boolean(settings.profiling?.mac_inventory_enabled)}
              onChange={(value) => updateField(['profiling', 'mac_inventory_enabled'], value)}
            />
            <ToggleField
              label="Passive Profiling Enabled"
              checked={Boolean(settings.profiling?.passive_enabled)}
              onChange={(value) => updateField(['profiling', 'passive_enabled'], value)}
            />
            <ToggleField
              label="Posture Enabled"
              checked={Boolean(settings.profiling?.posture_enabled)}
              onChange={(value) => updateField(['profiling', 'posture_enabled'], value)}
            />
            <ToggleField
              label="MDM/UEM Sync Enabled"
              checked={Boolean(settings.profiling?.mdm_sync_enabled)}
              onChange={(value) => updateField(['profiling', 'mdm_sync_enabled'], value)}
            />
            <ToggleField
              label="Remediation Enabled"
              checked={Boolean(settings.profiling?.remediation_enabled)}
              onChange={(value) => updateField(['profiling', 'remediation_enabled'], value)}
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <TextField
              label="Profiling Poll Interval (s)"
              type="number"
              value={settings.profiling?.poll_interval_seconds || 300}
              onChange={(value) => updateField(['profiling', 'poll_interval_seconds'], Number(value))}
            />
            <TextField
              label="Retention Hours"
              type="number"
              value={settings.profiling?.retention_hours || 24}
              onChange={(value) => updateField(['profiling', 'retention_hours'], Number(value))}
            />
            <TextField
              label="MDM Cache Hours"
              type="number"
              value={settings.profiling?.mdm_cache_hours || 12}
              onChange={(value) => updateField(['profiling', 'mdm_cache_hours'], Number(value))}
            />
            <TextField
              label="MDM Provider"
              value={settings.profiling?.mdm_provider || ''}
              onChange={(value) => updateField(['profiling', 'mdm_provider'], value)}
              placeholder="workspace-one-like"
            />
              <TextField
                label="MDM Endpoint"
                value={settings.profiling?.mdm_endpoint || ''}
                onChange={(value) => updateField(['profiling', 'mdm_endpoint'], value)}
                placeholder="https://mdm.example.com/api"
              />
              <TextField
                label="MDM Token Env"
                value={settings.profiling?.mdm_api_token_env || ''}
                onChange={(value) => updateField(['profiling', 'mdm_api_token_env'], value)}
                placeholder="AEGIS_MDM_API_TOKEN"
              />
              <TextField
                label="Compliance Webhook"
                value={settings.profiling?.compliance_webhook || ''}
                onChange={(value) => updateField(['profiling', 'compliance_webhook'], value)}
                placeholder="https://ops.example.com/compliance"
              />
              <TextField
                label="Compliance Token Env"
                value={settings.profiling?.compliance_token_env || ''}
                onChange={(value) => updateField(['profiling', 'compliance_token_env'], value)}
                placeholder="AEGIS_COMPLIANCE_WEBHOOK_TOKEN"
              />
            </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Integrations, Controller Workflows, And Governance</h3>
          <p className="mt-1 text-sm text-gray-600">Phase 4 turns integration-heavy features into explicit production choices so MDM sync, SIEM export, controller automation, and admin delegation only light up when their dependencies are real.</p>
        </div>
        <div className="mb-4">
          <h4 className="font-semibold text-gray-900">Admin Identity And Governance</h4>
          <p className="mt-1 text-sm text-gray-600">Use this area for SSO-backed admin access, delegated operations, and enterprise tenant boundaries.</p>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField
            label="Admin SSO Enabled"
            checked={Boolean(settings.integrations?.admin_sso?.enabled)}
            onChange={(value) => updateField(['integrations', 'admin_sso', 'enabled'], value)}
          />
          <ToggleField
            label="Delegated Admin Enabled"
            checked={Boolean(settings.governance?.delegated_admin_enabled)}
            onChange={(value) => updateField(['governance', 'delegated_admin_enabled'], value)}
          />
          <ToggleField
            label="External Group Mapping"
            checked={Boolean(settings.governance?.external_groups_enabled)}
            onChange={(value) => updateField(['governance', 'external_groups_enabled'], value)}
          />
          <ToggleField
            label="Multi-Tenant Enabled"
            checked={Boolean(settings.governance?.multi_tenant_enabled)}
            onChange={(value) => updateField(['governance', 'multi_tenant_enabled'], value)}
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SelectField
            label="Admin SSO Provider"
            value={settings.integrations?.admin_sso?.provider || ''}
            onChange={(value) => updateField(['integrations', 'admin_sso', 'provider'], value)}
            options={adminSSOProviderOptions}
          />
          <TextField
            label="Issuer / Metadata URL"
            value={settings.integrations?.admin_sso?.issuer_url || ''}
            onChange={(value) => updateField(['integrations', 'admin_sso', 'issuer_url'], value)}
            placeholder="https://idp.example.com/.well-known/openid-configuration"
          />
          <TextField
            label="Client ID"
            value={settings.integrations?.admin_sso?.client_id || ''}
            onChange={(value) => updateField(['integrations', 'admin_sso', 'client_id'], value)}
            placeholder="aegisnas-admin"
          />
          <TextField
            label="Client Secret Env"
            value={settings.integrations?.admin_sso?.client_secret_env || ''}
            onChange={(value) => updateField(['integrations', 'admin_sso', 'client_secret_env'], value)}
            placeholder="AEGIS_ADMIN_SSO_CLIENT_SECRET"
          />
          <TextField
            label="Redirect URL"
            value={settings.integrations?.admin_sso?.redirect_url || ''}
            onChange={(value) => updateField(['integrations', 'admin_sso', 'redirect_url'], value)}
            placeholder="https://admin.example.com/auth/callback"
          />
          <TextField
            label="Groups Claim"
            value={settings.integrations?.admin_sso?.groups_claim || ''}
            onChange={(value) => updateField(['integrations', 'admin_sso', 'groups_claim'], value)}
            placeholder="groups"
          />
          <SelectField
            label="RBAC Mode"
            value={settings.governance?.rbac_mode || 'local'}
            onChange={(value) => updateField(['governance', 'rbac_mode'], value)}
            options={rbacModeOptions}
          />
          <TextField
            label="Tenant Claim"
            value={settings.governance?.tenant_claim || ''}
            onChange={(value) => updateField(['governance', 'tenant_claim'], value)}
            placeholder="tenant"
          />
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">SIEM And Controller Integrations</h4>
            <p className="mt-1 text-sm text-gray-600">Use these for webhook-grade observability exports and controller-aware Wi-Fi operations in external AP deployments.</p>
          </div>
          <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="SIEM Export Enabled"
              checked={Boolean(settings.integrations?.siem?.enabled)}
              onChange={(value) => updateField(['integrations', 'siem', 'enabled'], value)}
            />
            <ToggleField
              label="Controller Automation Enabled"
              checked={Boolean(settings.integrations?.controller?.enabled)}
              onChange={(value) => updateField(['integrations', 'controller', 'enabled'], value)}
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <SelectField
              label="SIEM Provider"
              value={settings.integrations?.siem?.provider || ''}
              onChange={(value) => updateField(['integrations', 'siem', 'provider'], value)}
              options={siemProviderOptions}
            />
            <TextField
              label="SIEM Endpoint"
              value={settings.integrations?.siem?.endpoint || ''}
              onChange={(value) => updateField(['integrations', 'siem', 'endpoint'], value)}
              placeholder="https://siem.example.com/collect"
            />
            <TextField
              label="SIEM API Key Env"
              value={settings.integrations?.siem?.api_key_env || ''}
              onChange={(value) => updateField(['integrations', 'siem', 'api_key_env'], value)}
              placeholder="AEGIS_SIEM_API_KEY"
            />
            <TextField
              label="SIEM Batch Size"
              type="number"
              value={settings.integrations?.siem?.batch_size || 100}
              onChange={(value) => updateField(['integrations', 'siem', 'batch_size'], Number(value))}
            />
            <SelectField
              label="Controller Platform"
              value={settings.integrations?.controller?.platform || ''}
              onChange={(value) => updateField(['integrations', 'controller', 'platform'], value)}
              options={controllerPlatformOptions}
            />
            <TextField
              label="Controller Endpoint"
              value={settings.integrations?.controller?.endpoint || ''}
              onChange={(value) => updateField(['integrations', 'controller', 'endpoint'], value)}
              placeholder="https://controller.example.com/api"
            />
            <TextField
              label="Controller API Token Env"
              value={settings.integrations?.controller?.api_token_env || ''}
              onChange={(value) => updateField(['integrations', 'controller', 'api_token_env'], value)}
              placeholder="AEGIS_CONTROLLER_API_TOKEN"
            />
            <SelectField
              label="Controller Sync Mode"
              value={settings.integrations?.controller?.sync_mode || 'monitor'}
              onChange={(value) => updateField(['integrations', 'controller', 'sync_mode'], value)}
              options={controllerSyncOptions}
            />
            <TextField
              label="Controller Site"
              value={settings.integrations?.controller?.site || ''}
              onChange={(value) => updateField(['integrations', 'controller', 'site'], value)}
              placeholder="branch-west-01"
            />
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">High Availability And Failover</h3>
          <p className="mt-1 text-sm text-gray-600">Use enterprise deployments for active and standby peer monitoring, shared virtual IP planning, and recovery orchestration groundwork.</p>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-6">
          <ToggleField
            label="High Availability Enabled"
            checked={Boolean(settings.high_availability?.enabled)}
            onChange={(value) => updateField(['high_availability', 'enabled'], value)}
          />
          <ToggleField
            label="Preempt Preferred"
            checked={Boolean(settings.high_availability?.preempt)}
            onChange={(value) => updateField(['high_availability', 'preempt'], value)}
          />
          <ToggleField
            label="Split-Brain Protection"
            checked={Boolean(settings.high_availability?.split_brain_protection_enabled)}
            onChange={(value) => updateField(['high_availability', 'split_brain_protection_enabled'], value)}
          />
          <ToggleField
            label="Auto-Stage Shared Package"
            checked={Boolean(settings.high_availability?.auto_stage_shared_package)}
            onChange={(value) => updateField(['high_availability', 'auto_stage_shared_package'], value)}
          />
          <ToggleField
            label="Auto-Activate On Failover"
            checked={Boolean(settings.high_availability?.auto_activate_on_failover)}
            onChange={(value) => updateField(['high_availability', 'auto_activate_on_failover'], value)}
          />
          <SelectField
            label="Node Role"
            value={settings.high_availability?.role || 'standby'}
            onChange={(value) => updateField(['high_availability', 'role'], value)}
            options={[
              { value: 'active', label: 'Active' },
              { value: 'standby', label: 'Standby' },
            ]}
          />
          <TextField
            label="Virtual IP"
            value={settings.high_availability?.virtual_ip || ''}
            onChange={(value) => updateField(['high_availability', 'virtual_ip'], value)}
            placeholder="192.168.50.2"
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <TextField
            label="Peer API URL"
            value={settings.high_availability?.peer_api_url || ''}
            onChange={(value) => updateField(['high_availability', 'peer_api_url'], value)}
            placeholder="https://peer.example.com:8083"
          />
          <TextField
            label="Heartbeat Interval"
            type="number"
            value={settings.high_availability?.heartbeat_interval_seconds || 5}
            onChange={(value) => updateField(['high_availability', 'heartbeat_interval_seconds'], Number(value))}
          />
          <TextField
            label="Failover Timeout"
            type="number"
            value={settings.high_availability?.failover_timeout_seconds || 20}
            onChange={(value) => updateField(['high_availability', 'failover_timeout_seconds'], Number(value))}
          />
          <TextField
            label="Replication Interval"
            type="number"
            value={settings.high_availability?.replication_interval_seconds || 300}
            onChange={(value) => updateField(['high_availability', 'replication_interval_seconds'], Number(value))}
          />
          <TextField
            label="Replication Stale After"
            type="number"
            value={settings.high_availability?.replication_stale_after_seconds || 900}
            onChange={(value) => updateField(['high_availability', 'replication_stale_after_seconds'], Number(value))}
          />
          <TextField
            label="Preempt Holdoff"
            type="number"
            value={settings.high_availability?.preempt_holdoff_seconds || 0}
            onChange={(value) => updateField(['high_availability', 'preempt_holdoff_seconds'], Number(value))}
          />
          <TextField
            label="Shared State Directory"
            value={settings.high_availability?.shared_state_dir || '/var/lib/aegisnas/ha'}
            onChange={(value) => updateField(['high_availability', 'shared_state_dir'], value)}
            placeholder="/var/lib/aegisnas/ha"
          />
          <TextField
            label="Replication Signing Key Env"
            value={settings.high_availability?.replication_signing_key_env || ''}
            onChange={(value) => updateField(['high_availability', 'replication_signing_key_env'], value)}
            placeholder="AEGIS_HA_REPLICATION_SIGNING_KEY"
          />
          <TextField
            label="Replication Encryption Key Env"
            value={settings.high_availability?.replication_encryption_key_env || ''}
            onChange={(value) => updateField(['high_availability', 'replication_encryption_key_env'], value)}
            placeholder="AEGIS_HA_REPLICATION_ENCRYPTION_KEY"
          />
          <TextField
            label="Witness API URL"
            value={settings.high_availability?.witness_api_url || ''}
            onChange={(value) => updateField(['high_availability', 'witness_api_url'], value)}
            placeholder="https://witness.example.test/ha"
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness URLs</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={(settings.high_availability?.witness_urls || []).join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ['high_availability', 'witness_urls'],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={'https://witness-a.example.test/ha\nhttps://witness-b.example.test/ha'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional multi-witness list. When populated, it overrides the single Witness API URL.</p>
          </div>
          <TextField
            label="Witness Quorum"
            type="number"
            value={settings.high_availability?.witness_quorum || 1}
            onChange={(value) => updateField(['high_availability', 'witness_quorum'], Number(value))}
          />
          <TextField
            label="Witness Weight Threshold"
            type="number"
            value={settings.high_availability?.witness_weight_threshold || 0}
            onChange={(value) => updateField(['high_availability', 'witness_weight_threshold'], Number(value))}
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Weight Overrides</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_weights || {})
                .map(([url, weight]) => `${url}=${weight}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const weights: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const url = parts.slice(0, -1).join('=').trim();
                    const rawWeight = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedWeight = Number(rawWeight);
                    if (url && Number.isFinite(parsedWeight) && parsedWeight > 0) {
                      weights[url] = parsedWeight;
                    }
                  });
                updateField(['high_availability', 'witness_weights'], weights);
              }}
              placeholder={'https://witness-a.example.test/ha=3\nhttps://witness-b.example.test/ha=1'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-witness weights. Unlisted witnesses count as weight 1.</p>
          </div>
          <TextField
            label="Witness Distinct Group Threshold"
            type="number"
            value={settings.high_availability?.witness_min_distinct_groups || 0}
            onChange={(value) => updateField(['high_availability', 'witness_min_distinct_groups'], Number(value))}
          />
          <SelectField
            label="Witness Policy Mode"
            value={settings.high_availability?.witness_policy_mode || 'all'}
            onChange={(value) => updateField(['high_availability', 'witness_policy_mode'], value)}
            options={[
              { value: 'all', label: 'All configured policies' },
              { value: 'any', label: 'Any diversity policy' },
              { value: 'group_only', label: 'Group only' },
              { value: 'source_only', label: 'Source only' },
              { value: 'url_only', label: 'URL only' },
            ]}
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Policy Mode By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_policy_mode_by_tier || {})
                .map(([tier, mode]) => `${tier}=${mode}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const overrides: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawMode = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (tier && rawMode) {
                      overrides[tier] = rawMode;
                    }
                  });
                updateField(['high_availability', 'witness_policy_mode_by_tier'], overrides);
              }}
              placeholder={'critical=all\nadvisory=any'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier policy overrides. Use all, any, group_only, source_only, or url_only. Tiers without an override keep the conservative all-mode behavior.</p>
          </div>
          <TextField
            label="Witness Failure Tolerance"
            type="number"
            value={settings.high_availability?.witness_failure_tolerance || 0}
            onChange={(value) => updateField(['high_availability', 'witness_failure_tolerance'], Number(value))}
          />
          <TextField
            label="Witness Failure Weight Tolerance"
            type="number"
            value={settings.high_availability?.witness_failure_weight_tolerance || 0}
            onChange={(value) => updateField(['high_availability', 'witness_failure_weight_tolerance'], Number(value))}
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Minimum Approvals By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_min_approvals_by_tier || {})
                .map(([tier, approvals]) => `${tier}=${approvals}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawApprovals = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedApprovals = Number(rawApprovals);
                    if (tier && Number.isFinite(parsedApprovals) && parsedApprovals >= 0) {
                      minimums[tier] = parsedApprovals;
                    }
                  });
                updateField(['high_availability', 'witness_min_approvals_by_tier'], minimums);
              }}
              placeholder={'critical=1\nadvisory=1'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier approval floors. Promotion must include at least this many approvals from each listed confidence tier.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Minimum Weight By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_min_weight_by_tier || {})
                .map(([tier, weight]) => `${tier}=${weight}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawWeight = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedWeight = Number(rawWeight);
                    if (tier && Number.isFinite(parsedWeight) && parsedWeight >= 0) {
                      minimums[tier] = parsedWeight;
                    }
                  });
                updateField(['high_availability', 'witness_min_weight_by_tier'], minimums);
              }}
              placeholder={'critical=2\nadvisory=1'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier weight floors. Promotion must include at least this much witness weight from each listed confidence tier.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Minimum Distinct Groups By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_min_distinct_groups_by_tier || {})
                .map(([tier, count]) => `${tier}=${count}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawCount = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedCount = Number(rawCount);
                    if (tier && Number.isFinite(parsedCount) && parsedCount >= 0) {
                      minimums[tier] = parsedCount;
                    }
                  });
                updateField(['high_availability', 'witness_min_distinct_groups_by_tier'], minimums);
              }}
              placeholder={'critical=2\nadvisory=1'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier diversity floors. Promotion must include approvals from at least this many distinct witness groups in each listed confidence tier.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Minimum Distinct Sources By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_min_distinct_sources_by_tier || {})
                .map(([tier, count]) => `${tier}=${count}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawCount = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedCount = Number(rawCount);
                    if (tier && Number.isFinite(parsedCount) && parsedCount >= 0) {
                      minimums[tier] = parsedCount;
                    }
                  });
                updateField(['high_availability', 'witness_min_distinct_sources_by_tier'], minimums);
              }}
              placeholder={'critical=2\nadvisory=1'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier source diversity floors. Promotion must include approvals from at least this many distinct witness sources in each listed confidence tier.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Group Overrides</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_groups || {})
                .map(([url, group]) => `${url}=${group}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const groups: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const url = parts.slice(0, -1).join('=').trim();
                    const rawGroup = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (url && rawGroup) {
                      groups[url] = rawGroup;
                    }
                  });
                updateField(['high_availability', 'witness_groups'], groups);
              }}
              placeholder={'https://witness-a.example.test/ha=dc-a\nhttps://witness-b.example.test/ha=dc-b'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional group mapping for witness diversity. Unlisted witnesses count as their own group.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Source Overrides</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_sources || {})
                .map(([url, source]) => `${url}=${source}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const sources: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const url = parts.slice(0, -1).join('=').trim();
                    const rawSource = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (url && rawSource) {
                      sources[url] = rawSource;
                    }
                  });
                updateField(['high_availability', 'witness_sources'], sources);
              }}
              placeholder={'https://witness-a.example.test/ha=local\nhttps://witness-b.example.test/ha=external'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional source mapping for mixed-source quorum. Unlisted witnesses count as their own source.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Required Sources</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={2}
              value={(settings.high_availability?.witness_required_sources || []).join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ['high_availability', 'witness_required_sources'],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={'local\nexternal'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional source classes that must all be represented in witness approvals before promotion is allowed.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Required URLs</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={2}
              value={(settings.high_availability?.witness_required_urls || []).join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ['high_availability', 'witness_required_urls'],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={'https://witness-a.example.test/ha\nhttps://witness-b.example.test/ha'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional witness endpoints that must all be represented in approvals before promotion is allowed.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Required Sources By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_required_sources_by_tier || {})
                .map(([tier, sources]) => `${tier}=${(Array.isArray(sources) ? sources : []).join(',')}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredByTier: Record<string, string[]> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawSources = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (!tier || !rawSources) {
                      return;
                    }
                    const sources = rawSources
                      .split(',')
                      .map((source) => source.trim())
                      .filter(Boolean);
                    if (sources.length > 0) {
                      requiredByTier[tier] = sources;
                    }
                  });
                updateField(['high_availability', 'witness_required_sources_by_tier'], requiredByTier);
              }}
              placeholder={'critical=local\nadvisory=external,cloud'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier source rules. Each listed tier must include approvals from the named source classes.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Required URLs By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_required_urls_by_tier || {})
                .map(([tier, urls]) => `${tier}=${(Array.isArray(urls) ? urls : []).join(',')}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredByTier: Record<string, string[]> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawURLs = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (!tier || !rawURLs) {
                      return;
                    }
                    const urls = rawURLs
                      .split(',')
                      .map((url) => url.trim())
                      .filter(Boolean);
                    if (urls.length > 0) {
                      requiredByTier[tier] = urls;
                    }
                  });
                updateField(['high_availability', 'witness_required_urls_by_tier'], requiredByTier);
              }}
              placeholder={'critical=https://witness-a.example.test/ha\nadvisory=https://witness-b.example.test/ha,https://witness-c.example.test/ha'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier witness URL rules. Each listed tier must include approvals from the named witness endpoints.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Required Groups By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_required_groups_by_tier || {})
                .map(([tier, groups]) => `${tier}=${(Array.isArray(groups) ? groups : []).join(',')}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredByTier: Record<string, string[]> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawGroups = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (!tier || !rawGroups) {
                      return;
                    }
                    const groups = rawGroups
                      .split(',')
                      .map((group) => group.trim())
                      .filter(Boolean);
                    if (groups.length > 0) {
                      requiredByTier[tier] = groups;
                    }
                  });
                updateField(['high_availability', 'witness_required_groups_by_tier'], requiredByTier);
              }}
              placeholder={'critical=dc-a\nadvisory=dc-b,cloud'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier group rules. Each listed tier must include approvals from the named witness groups.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Source Confidence</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_source_confidence || {})
                .map(([source, tier]) => `${source}=${tier}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const confidence: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const source = parts.slice(0, -1).join('=').trim();
                    const rawTier = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (source && rawTier) {
                      confidence[source] = rawTier;
                    }
                  });
                updateField(['high_availability', 'witness_source_confidence'], confidence);
              }}
              placeholder={'local=critical\nexternal=advisory'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional source-to-tier mapping. Unlisted sources use the standard confidence tier.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Failure Tolerance By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_failure_tolerance_by_tier || {})
                .map(([tier, budget]) => `${tier}=${budget}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const budgets: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawBudget = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedBudget = Number(rawBudget);
                    if (tier && Number.isFinite(parsedBudget) && parsedBudget >= 0) {
                      budgets[tier] = parsedBudget;
                    }
                  });
                updateField(['high_availability', 'witness_failure_tolerance_by_tier'], budgets);
              }}
              placeholder={'advisory=1\nstandard=0'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional tier-specific failed probe count budgets. Any tier without an override falls back to the global failure budget.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Failure Weight Tolerance By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_failure_weight_tolerance_by_tier || {})
                .map(([tier, budget]) => `${tier}=${budget}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const budgets: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawBudget = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedBudget = Number(rawBudget);
                    if (tier && Number.isFinite(parsedBudget) && parsedBudget >= 0) {
                      budgets[tier] = parsedBudget;
                    }
                  });
                updateField(['high_availability', 'witness_failure_weight_tolerance_by_tier'], budgets);
              }}
              placeholder={'advisory=1\nstandard=0'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional tier-specific failed witness weight budgets. Any tier without an override falls back to the global failed-weight budget.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Blocking Tiers</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={2}
              value={(settings.high_availability?.witness_blocking_tiers || []).join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ['high_availability', 'witness_blocking_tiers'],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={'critical'}
            />
            <p className="mt-1 text-xs text-gray-500">If a witness in one of these tiers explicitly denies promotion, standby promotion is blocked immediately.</p>
          </div>
          <TextField
            label="Witness Token Env"
            value={settings.high_availability?.witness_token_env || ''}
            onChange={(value) => updateField(['high_availability', 'witness_token_env'], value)}
            placeholder="AEGIS_HA_WITNESS_TOKEN"
          />
          <TextField
            label="Witness Signing Key Env"
            value={settings.high_availability?.witness_signing_key_env || ''}
            onChange={(value) => updateField(['high_availability', 'witness_signing_key_env'], value)}
            placeholder="AEGIS_HA_WITNESS_SIGNING_KEY"
          />
          <TextField
            label="Witness Max Age (s)"
            type="number"
            value={settings.high_availability?.witness_max_age_seconds || 0}
            onChange={(value) => updateField(['high_availability', 'witness_max_age_seconds'], Number(value))}
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Max Age By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_max_age_by_tier || {})
                .map(([tier, seconds]) => `${tier}=${seconds}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const maximums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawSeconds = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    const parsedSeconds = Number(rawSeconds);
                    if (tier && Number.isFinite(parsedSeconds) && parsedSeconds >= 0) {
                      maximums[tier] = parsedSeconds;
                    }
                  });
                updateField(['high_availability', 'witness_max_age_by_tier'], maximums);
              }}
              placeholder={'critical=10\nadvisory=30'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier freshness overrides in seconds. Any tier without an override falls back to the global witness max age.</p>
          </div>
          <TextField
            label="Witness Required Node"
            value={settings.high_availability?.witness_required_node || ''}
            onChange={(value) => updateField(['high_availability', 'witness_required_node'], value)}
            placeholder="witness-1"
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Required Node By Tier</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(settings.high_availability?.witness_required_node_by_tier || {})
                .map(([tier, node]) => `${tier}=${node}`)
                .join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredNodes: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split('=');
                    const tier = parts.slice(0, -1).join('=').trim();
                    const rawNode = parts.length > 1 ? parts[parts.length - 1].trim() : '';
                    if (tier && rawNode) {
                      requiredNodes[tier] = rawNode;
                    }
                  });
                updateField(['high_availability', 'witness_required_node_by_tier'], requiredNodes);
              }}
              placeholder={'critical=witness-a\nadvisory=witness-b'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional per-tier required witness identities. Tiers without overrides fall back to the global Witness Required Node field.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Signature Required Tiers</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={(settings.high_availability?.witness_signature_required_tiers || []).join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ['high_availability', 'witness_signature_required_tiers'],
                  event.target.value
                    .split(/\r?\n/)
                    .map((line) => line.trim())
                    .filter(Boolean)
                )
              }
              placeholder={'critical\nadvisory'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional confidence tiers that must return signed witness responses even when signature enforcement is not global.</p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Witness Replay Required Tiers</label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={(settings.high_availability?.witness_replay_required_tiers || []).join('\n')}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ['high_availability', 'witness_replay_required_tiers'],
                  event.target.value
                    .split(/\r?\n/)
                    .map((line) => line.trim())
                    .filter(Boolean)
                )
              }
              placeholder={'critical\nadvisory'}
            />
            <p className="mt-1 text-xs text-gray-500">Optional confidence tiers that must satisfy replay challenge verification even when global Witness Replay Protection is off.</p>
          </div>
          <ToggleField
            label="Witness Replay Protection"
            checked={Boolean(settings.high_availability?.witness_replay_protection_enabled)}
            onChange={(checked) => updateField(['high_availability', 'witness_replay_protection_enabled'], checked)}
          />
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <h3 className="mb-4 text-lg font-semibold text-gray-900">FreeRADIUS And EAP</h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <TextField label="NAS Identifier" value={settings.radius?.nas_identifier || ''} onChange={(value) => updateField(['radius', 'nas_identifier'], value)} />
          <TextField label="Shared Secret" type="password" value={settings.radius?.secret || ''} onChange={(value) => updateField(['radius', 'secret'], value)} />
          <TextField label="Auth Port" type="number" value={settings.radius?.auth_port || 1812} onChange={(value) => updateField(['radius', 'auth_port'], Number(value))} />
          <TextField label="Acct Port" type="number" value={settings.radius?.acct_port || 1813} onChange={(value) => updateField(['radius', 'acct_port'], Number(value))} />
          <TextField label="Max Sessions" type="number" value={settings.radius?.max_sessions || 1024} onChange={(value) => updateField(['radius', 'max_sessions'], Number(value))} />
          <TextField label="Request Timeout (s)" type="number" value={settings.radius?.request_timeout_seconds || 5} onChange={(value) => updateField(['radius', 'request_timeout_seconds'], Number(value))} />
          <TextField label="Interim Update (s)" type="number" value={settings.radius?.interim_update_seconds || 300} onChange={(value) => updateField(['radius', 'interim_update_seconds'], Number(value))} />
          <TextField label="Cert Directory" value={settings.radius?.cert_dir || ''} onChange={(value) => updateField(['radius', 'cert_dir'], value)} />
          <SelectField
            label="Default EAP Type"
            value={settings.radius?.eap?.default_type || 'peap'}
            onChange={(value) => updateField(['radius', 'eap', 'default_type'], value)}
            options={[
              { value: 'peap', label: 'PEAP' },
              { value: 'ttls', label: 'TTLS' },
              { value: 'tls', label: 'TLS' },
            ]}
          />
          <SelectField
            label="PEAP Inner"
            value={settings.radius?.eap?.peap_inner || 'mschapv2'}
            onChange={(value) => updateField(['radius', 'eap', 'peap_inner'], value)}
            options={[
              { value: 'mschapv2', label: 'MSCHAPv2' },
              { value: 'gtc', label: 'GTC' },
              { value: 'tls', label: 'TLS' },
            ]}
          />
          <SelectField
            label="TTLS Inner"
            value={settings.radius?.eap?.ttls_inner || 'mschapv2'}
            onChange={(value) => updateField(['radius', 'eap', 'ttls_inner'], value)}
            options={[
              { value: 'mschapv2', label: 'MSCHAPv2' },
              { value: 'pap', label: 'PAP' },
              { value: 'chap', label: 'CHAP' },
              { value: 'gtc', label: 'GTC' },
              { value: 'tls', label: 'TLS' },
            ]}
          />
          <div className="grid grid-cols-2 gap-3">
            <SelectField
              label="TLS Min"
              value={settings.radius?.eap?.tls_min_version || '1.2'}
              onChange={(value) => updateField(['radius', 'eap', 'tls_min_version'], value)}
              options={[
                { value: '1.2', label: '1.2' },
                { value: '1.3', label: '1.3' },
              ]}
            />
            <SelectField
              label="TLS Max"
              value={settings.radius?.eap?.tls_max_version || '1.3'}
              onChange={(value) => updateField(['radius', 'eap', 'tls_max_version'], value)}
              options={[
                { value: '1.2', label: '1.2' },
                { value: '1.3', label: '1.3' },
              ]}
            />
          </div>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <ToggleField label="Dynamic Authorization" checked={Boolean(settings.radius?.dynamic_auth?.enabled)} onChange={(value) => updateField(['radius', 'dynamic_auth', 'enabled'], value)} />
          <TextField label="Dynamic Authorization Port" type="number" value={settings.radius?.dynamic_auth?.port || 3799} onChange={(value) => updateField(['radius', 'dynamic_auth', 'port'], Number(value))} />
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h4 className="font-semibold text-gray-900">AegisNAS Vendor Dictionary</h4>
              <p className="mt-1 text-sm text-gray-600">Built-in attributes come from configs/aegisnas-vendor.dictionery. Add rows here only for local overrides or extensions.</p>
            </div>
            <button
              onClick={() => updateField(['radius', 'vendor', 'attributes'], [...vendorAttributes, { name: '', number: vendorAttributes.length + 20, type: 'string' }])}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Attribute
            </button>
          </div>
          <div className="mb-4 grid gap-4 md:grid-cols-4">
            <ToggleField label="Vendor Attributes Enabled" checked={Boolean(settings.radius?.vendor?.enabled)} onChange={(value) => updateField(['radius', 'vendor', 'enabled'], value)} />
            <TextField label="Vendor Name" value={settings.radius?.vendor?.name || 'AegisNAS'} onChange={(value) => updateField(['radius', 'vendor', 'name'], value)} />
            <TextField label="Vendor ID" type="number" value={settings.radius?.vendor?.id || 0} onChange={(value) => updateField(['radius', 'vendor', 'id'], Number(value))} />
          </div>
          <div className="space-y-3">
            {vendorAttributes.map((attribute: JsonMap, index: number) => (
              <div key={`vendor-attr-${index}`} className="grid gap-3 rounded-lg border border-gray-200 p-3 md:grid-cols-4">
                <TextField label="Name" value={attribute.name || ''} onChange={(value) => updateField(['radius', 'vendor', 'attributes', String(index), 'name'], value)} />
                <TextField label="Number" type="number" value={attribute.number || 0} onChange={(value) => updateField(['radius', 'vendor', 'attributes', String(index), 'number'], Number(value))} />
                <SelectField
                  label="Type"
                  value={attribute.type || 'string'}
                  onChange={(value) => updateField(['radius', 'vendor', 'attributes', String(index), 'type'], value)}
                  options={[
                    { value: 'string', label: 'String' },
                    { value: 'integer', label: 'Integer' },
                    { value: 'ipaddr', label: 'IPv4 Address' },
                    { value: 'octets', label: 'Octets' },
                    { value: 'date', label: 'Date' },
                  ]}
                />
                <div className="flex items-end">
                  <button
                    onClick={() => updateField(['radius', 'vendor', 'attributes'], vendorAttributes.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                    className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">Upstream AAA Servers</h3>
          <button
            onClick={() => updateField(['radius', 'upstream', 'servers'], [...upstreamServers, { name: '', address: '', auth_port: 1812, acct_port: 1813, secret: '' }])}
            className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
          >
            Add Server
          </button>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-4">
          <ToggleField label="Upstream AAA Enabled" checked={Boolean(settings.radius?.upstream?.enabled)} onChange={(value) => updateField(['radius', 'upstream', 'enabled'], value)} />
          <TextField label="Realm" value={settings.radius?.upstream?.realm || ''} onChange={(value) => updateField(['radius', 'upstream', 'realm'], value)} />
          <SelectField
            label="Pool Strategy"
            value={settings.radius?.upstream?.pool_strategy || 'fail-over'}
            onChange={(value) => updateField(['radius', 'upstream', 'pool_strategy'], value)}
            options={[
              { value: 'fail-over', label: 'Fail Over' },
              { value: 'load-balance', label: 'Load Balance' },
              { value: 'client-balance', label: 'Client Balance' },
              { value: 'client-port-balance', label: 'Client + Port Balance' },
              { value: 'keyed-balance', label: 'Keyed Balance' },
            ]}
          />
          <SelectField
            label="Status Check"
            value={settings.radius?.upstream?.status_check || 'status-server'}
            onChange={(value) => updateField(['radius', 'upstream', 'status_check'], value)}
            options={[
              { value: 'status-server', label: 'Status Server' },
              { value: 'none', label: 'None' },
            ]}
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <TextField label="Response Window" type="number" value={settings.radius?.upstream?.response_window || 20} onChange={(value) => updateField(['radius', 'upstream', 'response_window'], Number(value))} />
          <TextField label="Zombie Period" type="number" value={settings.radius?.upstream?.zombie_period || 40} onChange={(value) => updateField(['radius', 'upstream', 'zombie_period'], Number(value))} />
          <TextField label="Revive Interval" type="number" value={settings.radius?.upstream?.revive_interval || 120} onChange={(value) => updateField(['radius', 'upstream', 'revive_interval'], Number(value))} />
          <TextField label="Check Interval" type="number" value={settings.radius?.upstream?.check_interval || 30} onChange={(value) => updateField(['radius', 'upstream', 'check_interval'], Number(value))} />
        </div>
        <div className="mt-3">
          <ToggleField label="Strip Realm" checked={Boolean(settings.radius?.upstream?.strip_realm)} onChange={(value) => updateField(['radius', 'upstream', 'strip_realm'], value)} />
        </div>
        <div className="mt-4 space-y-4">
          {upstreamServers.length === 0 ? (
            <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Primary and secondary AAA servers live here.</div>
          ) : (
            upstreamServers.map((server: JsonMap, index: number) => (
              <div key={`server-${index}`} className="rounded-lg border border-gray-200 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <h4 className="font-semibold text-gray-900">Server {index + 1}</h4>
                  <button
                    onClick={() => updateField(['radius', 'upstream', 'servers'], upstreamServers.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                    className="text-sm font-medium text-red-700"
                  >
                    Remove
                  </button>
                </div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                  <TextField label="Name" value={server.name || ''} onChange={(value) => updateField(['radius', 'upstream', 'servers', String(index), 'name'], value)} />
                  <TextField label="Address" value={server.address || ''} onChange={(value) => updateField(['radius', 'upstream', 'servers', String(index), 'address'], value)} />
                  <TextField label="Auth Port" type="number" value={server.auth_port || 1812} onChange={(value) => updateField(['radius', 'upstream', 'servers', String(index), 'auth_port'], Number(value))} />
                  <TextField label="Acct Port" type="number" value={server.acct_port || 1813} onChange={(value) => updateField(['radius', 'upstream', 'servers', String(index), 'acct_port'], Number(value))} />
                  <TextField label="Secret" type="password" value={server.secret || ''} onChange={(value) => updateField(['radius', 'upstream', 'servers', String(index), 'secret'], value)} />
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Wireless Radio And SSIDs</h3>
            <p className="mt-1 text-sm text-gray-600">Use on appliance radios or passthrough Wi-Fi hardware. The preview below is ready for hostapd.</p>
          </div>
          <button
            onClick={() =>
              updateField(['wireless', 'ssids'], [
                ...ssids,
                {
                  name: '',
                  auth_mode: 'captive-portal',
                  passphrase: '',
                  vlan: 0,
                  bridge: '',
                  hidden: false,
                  client_isolation: true,
                  max_clients: 0,
                  dynamic_vlan: false,
                  portal_profile: '',
                  identity_source: '',
                  bandwidth_profile: '',
                },
              ])
            }
            className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
          >
            Add SSID
          </button>
        </div>
        <div className="mb-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField label="Wireless Enabled" checked={Boolean(settings.wireless?.enabled)} onChange={(value) => updateField(['wireless', 'enabled'], value)} />
          <TextField label="Country Code" value={settings.wireless?.country_code || ''} onChange={(value) => updateField(['wireless', 'country_code'], value)} />
          <TextField label="Radio Interface" value={settings.wireless?.interface || ''} onChange={(value) => updateField(['wireless', 'interface'], value)} placeholder="wlan0" />
          <TextField label="Driver" value={settings.wireless?.driver || ''} onChange={(value) => updateField(['wireless', 'driver'], value)} />
          <SelectField
            label="HW Mode"
            value={settings.wireless?.hw_mode || 'g'}
            onChange={(value) => updateField(['wireless', 'hw_mode'], value)}
            options={[
              { value: 'g', label: '2.4 GHz (802.11g/n)' },
              { value: 'a', label: '5 GHz (802.11a/n/ac)' },
              { value: 'b', label: 'Legacy 802.11b' },
            ]}
          />
          <TextField label="Channel" type="number" value={settings.wireless?.channel || 6} onChange={(value) => updateField(['wireless', 'channel'], Number(value))} />
          <TextField label="Beacon Interval" type="number" value={settings.wireless?.beacon_interval || 100} onChange={(value) => updateField(['wireless', 'beacon_interval'], Number(value))} />
          <TextField label="hostapd Path" value={settings.wireless?.hostapd_config_path || ''} onChange={(value) => updateField(['wireless', 'hostapd_config_path'], value)} />
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <ToggleField label="WMM Enabled" checked={Boolean(settings.wireless?.wmm_enabled)} onChange={(value) => updateField(['wireless', 'wmm_enabled'], value)} />
          <ToggleField label="HT Enabled" checked={Boolean(settings.wireless?.ht_enabled)} onChange={(value) => updateField(['wireless', 'ht_enabled'], value)} />
          <TextField label="Control Socket" value={settings.wireless?.ctrl_interface || ''} onChange={(value) => updateField(['wireless', 'ctrl_interface'], value)} />
        </div>
        <div className="space-y-4">
          {ssids.length === 0 ? (
            <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">Open, captive portal, WPA2, and WPA3 SSIDs can all live on this radio.</div>
          ) : (
            ssids.map((ssid: JsonMap, index: number) => (
              <div key={`ssid-${index}`} className="rounded-lg border border-gray-200 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <h4 className="font-semibold text-gray-900">{ssid.name || `SSID ${index + 1}`}</h4>
                  <button
                    onClick={() => updateField(['wireless', 'ssids'], ssids.filter((_: unknown, itemIndex: number) => itemIndex !== index))}
                    className="text-sm font-medium text-red-700"
                  >
                    Remove
                  </button>
                </div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                  <TextField label="SSID Name" value={ssid.name || ''} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'name'], value)} />
                  <SelectField
                    label="Auth Mode"
                    value={ssid.auth_mode || 'captive-portal'}
                    onChange={(value) => updateField(['wireless', 'ssids', String(index), 'auth_mode'], value)}
                    options={[
                      { value: 'captive-portal', label: 'Captive Portal' },
                      { value: 'open', label: 'Open' },
                      { value: 'wpa2-personal', label: 'WPA2 Personal' },
                      { value: 'wpa2-enterprise', label: 'WPA2 Enterprise' },
                      { value: 'wpa3-personal', label: 'WPA3 Personal' },
                      { value: 'wpa3-enterprise', label: 'WPA3 Enterprise' },
                    ]}
                  />
                  <TextField label="Passphrase" type="password" value={ssid.passphrase || ''} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'passphrase'], value)} />
                  <TextField label="Bridge" value={ssid.bridge || ''} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'bridge'], value)} placeholder="br-guest" />
                  <TextField label="VLAN" type="number" value={ssid.vlan || 0} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'vlan'], Number(value))} />
                  <SelectField
                    label="Portal Profile"
                    value={ssid.portal_profile || ''}
                    onChange={(value) => updateField(['wireless', 'ssids', String(index), 'portal_profile'], value)}
                    options={[{ value: '', label: 'No portal profile override' }, ...portalProfiles]}
                  />
                  <SelectField
                    label="Identity Source"
                    value={ssid.identity_source || ''}
                    onChange={(value) => updateField(['wireless', 'ssids', String(index), 'identity_source'], value)}
                    options={[{ value: '', label: 'Use portal default' }, ...identitySources]}
                  />
                  <SelectField
                    label="Bandwidth Profile"
                    value={ssid.bandwidth_profile || ''}
                    onChange={(value) => updateField(['wireless', 'ssids', String(index), 'bandwidth_profile'], value)}
                    options={[{ value: '', label: 'No bandwidth override' }, ...bandwidthProfiles]}
                  />
                  <TextField label="Max Clients" type="number" value={ssid.max_clients || 0} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'max_clients'], Number(value))} />
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <ToggleField label="Hidden" checked={Boolean(ssid.hidden)} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'hidden'], value)} />
                  <ToggleField label="Client Isolation" checked={Boolean(ssid.client_isolation)} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'client_isolation'], value)} />
                  <ToggleField label="Dynamic VLAN" checked={Boolean(ssid.dynamic_vlan)} onChange={(value) => updateField(['wireless', 'ssids', String(index), 'dynamic_vlan'], value)} />
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">hostapd Preview</h3>
            <p className="mt-1 text-sm text-gray-600">{hostapdPath || 'Choose a path and write the file when the radio is ready.'}</p>
          </div>
          <button onClick={loadSettings} className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700">
            Refresh Preview
          </button>
        </div>
        <textarea
          value={hostapdPreview}
          readOnly
          className="min-h-[320px] w-full rounded-md border border-gray-300 bg-gray-950 px-4 py-3 font-mono text-sm text-gray-100"
        />
      </section>
    </div>
  );
}
