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
  dhcp: { enabled: true, lease_time: '12h', authoritative: true },
  policy: {
    default_role: '',
    runtime_shaping_enabled: true,
  },
  telemetry: {
    enabled: true,
    prometheus_port: 9090,
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
  },
  profiling: {
    mac_inventory_enabled: false,
    passive_enabled: false,
    poll_interval_seconds: 300,
    retention_hours: 24,
    posture_enabled: false,
    mdm_provider: '',
    mdm_endpoint: '',
    compliance_webhook: '',
    remediation_enabled: false,
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
  next.policy = next.policy || {};
  next.telemetry = next.telemetry || {};
  next.ailite = next.ailite || {};
  next.onboarding = next.onboarding || {};
  next.profiling = next.profiling || {};
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
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [previewError, setPreviewError] = useState('');
  const [hostapdPreview, setHostapdPreview] = useState('');
  const [hostapdPath, setHostapdPath] = useState('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const evaluateTimerRef = useRef<number | null>(null);

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

  const saveSettings = async () => {
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const { data } = await api.put('/system/settings', settings);
      setSettings(data.settings || settings);
      setMessage('Settings saved. Restart the appliance services and hostapd to pick up the new access policy.');
      const previewRes = await api.get('/system/hostapd-preview');
      setHostapdPreview(previewRes.data.config || '');
      setHostapdPath(previewRes.data.path || '');
    } catch (err: any) {
      setError(err.response?.data || err.message || 'Could not save settings.');
    } finally {
      setSaving(false);
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
  const deploymentCapabilities = deploymentPreview?.capabilities || [];
  const deploymentWarnings = deploymentPreview?.warnings || [];

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
              label="Compliance Webhook"
              value={settings.profiling?.compliance_webhook || ''}
              onChange={(value) => updateField(['profiling', 'compliance_webhook'], value)}
              placeholder="https://ops.example.com/compliance"
            />
          </div>
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
