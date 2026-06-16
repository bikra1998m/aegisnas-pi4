import { type ReactNode, useEffect, useMemo, useState } from 'react';
import api from '../api/client';

type VendorCompatibilitySummary = {
  product_vendor_id: number;
  product_vendor_name: string;
  product_vendor_id_source?: string;
  product_vendor_id_placeholder?: boolean;
  product_vendor_dictionary_filename?: string;
  product_vendor_dictionary_install_path?: string;
  product_vendor_dictionary_include?: string;
  product_vendor_pen_registry_url?: string;
  product_vendor_pen_apply_url?: string;
  product_attribute_count: number;
  semantic_count: number;
  pack_count: number;
  implemented_count: number;
  planned_count: number;
  hardware_profiles: string[];
};

type VendorProfileSummary = {
  total_clients: number;
  enabled_clients: number;
  profile_counts: Record<string, number>;
  unknown_profiles?: string[];
  global_fallback_client_count: number;
  known_vendor_profile_clients: number;
};

type VendorClientProfile = {
  shortname: string;
  ip: string;
  raw_nas_type?: string;
  nas_type: string;
  enabled: boolean;
  known_pack: boolean;
  uses_global_packs: boolean;
  effective_packs: string[];
  warning?: string;
};

type VendorPack = {
  key: string;
  label: string;
  vendor_name?: string;
  default_enabled: boolean;
  hardware_profiles: string[];
  notes?: string[];
};

type VendorSemanticCapability = {
  key: string;
  label: string;
  compatibility_state: string;
  next_step?: string;
  hardware_scope: string;
};

type VendorDictionaryCoverageRow = {
  pack_key: string;
  pack_label: string;
  active: boolean;
  vendor_name?: string;
  vendor_id?: number;
  dictionary_vendor_found: boolean;
  dictionary_attribute_count: number;
  pack_attribute_count: number;
  radius_attribute_count: number;
  dictionary_matched_attribute_count: number;
  missing_dictionary_attribute_count: number;
  coverage_state: string;
  hardware_profiles: string[];
};

type VendorDictionaryCoverage = {
  source?: string;
  catalog_vendor_count: number;
  catalog_attribute_count: number;
  pack_count: number;
  active_pack_count: number;
  dictionary_backed_pack_count: number;
  partial_dictionary_pack_count: number;
  missing_dictionary_vendor_count: number;
  dictionary_matched_attribute_count: number;
  missing_dictionary_attribute_count: number;
  rows?: VendorDictionaryCoverageRow[];
};

type VendorCompatibilityPayload = {
  summary: VendorCompatibilitySummary;
  active_packs?: string[];
  packs?: VendorPack[];
  client_profiles?: VendorClientProfile[];
  profile_summary?: VendorProfileSummary;
  dictionary_coverage?: VendorDictionaryCoverage;
  semantics?: VendorSemanticCapability[];
  notes?: string[];
};

type VendorReplyPreviewAttribute = {
  name: string;
  value: string;
  quoted: boolean;
};

type VendorReplyPreviewPayload = {
  nas_type: string;
  known_pack: boolean;
  uses_global_packs: boolean;
  effective_packs: string[];
  attributes: VendorReplyPreviewAttribute[];
  freeradius: string;
  warnings?: string[];
};

type VendorReplyPreviewForm = {
  nas_type: string;
  role: string;
  vlan: string;
  download_kbps: string;
  upload_kbps: string;
  session_timeout: string;
  filter_id: string;
  acl_policy_name: string;
  inbound_acl: string;
  outbound_acl: string;
  acl_rules: ACLRuleForm[];
};

type ACLRuleForm = {
  action: string;
  direction: string;
  protocol: string;
  source: string;
  source_port: string;
  destination: string;
  destination_port: string;
  log: boolean;
};

type VendorReplyPreviewTextField = Exclude<keyof VendorReplyPreviewForm, 'acl_rules'>;

const defaultPreviewForm: VendorReplyPreviewForm = {
  nas_type: 'aruba',
  role: 'guest',
  vlan: '20',
  download_kbps: '50000',
  upload_kbps: '20000',
  session_timeout: '3600',
  filter_id: '',
  acl_policy_name: 'guest-internet',
  inbound_acl: '',
  outbound_acl: '',
  acl_rules: [
    {
      action: 'permit',
      direction: 'in',
      protocol: 'tcp',
      source: 'any',
      source_port: '',
      destination: 'any',
      destination_port: '443',
      log: false,
    },
  ],
};

function StatCard({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <div className="rounded-md border border-gray-200 px-4 py-3">
      <div className="text-xs font-semibold uppercase text-gray-500">{label}</div>
      <div className="mt-2 text-2xl font-semibold text-gray-900">{value}</div>
      <div className="mt-1 text-sm text-gray-600">{hint}</div>
    </div>
  );
}

function StatusBadge({ tone, children }: { tone: 'green' | 'amber' | 'gray'; children: ReactNode }) {
  const classes = {
    green: 'bg-emerald-100 text-emerald-800',
    amber: 'bg-amber-100 text-amber-800',
    gray: 'bg-gray-100 text-gray-700',
  };
  return <span className={`rounded-md px-2 py-1 text-xs font-medium ${classes[tone]}`}>{children}</span>;
}

function joinList(values?: string[]) {
  if (!values || values.length === 0) {
    return 'None';
  }
  return values.join(', ');
}

function apiErrorMessage(err: any, fallback: string) {
  const data = err.response?.data;
  if (typeof data === 'string') {
    return data;
  }
  if (data?.error) {
    return String(data.error);
  }
  return err.message || fallback;
}

function numericValue(value: string) {
  if (value.trim() === '') {
    return 0;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function coverageTone(state: string): 'green' | 'amber' | 'gray' {
  switch (state) {
    case 'dictionary-backed':
    case 'standard-radius':
      return 'green';
    case 'partial-dictionary':
    case 'dictionary-missing':
      return 'amber';
    default:
      return 'gray';
  }
}

function coverageLabel(state: string) {
  switch (state) {
    case 'dictionary-backed':
      return 'Dictionary backed';
    case 'standard-radius':
      return 'Standard RADIUS';
    case 'partial-dictionary':
      return 'Partial dictionary';
    case 'dictionary-missing':
      return 'Dictionary missing';
    case 'controller-api':
      return 'Controller API';
    default:
      return 'Metadata only';
  }
}

export default function VendorCompatibility() {
  const [payload, setPayload] = useState<VendorCompatibilityPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [previewForm, setPreviewForm] = useState<VendorReplyPreviewForm>(defaultPreviewForm);
  const [preview, setPreview] = useState<VendorReplyPreviewPayload | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState('');

  const fetchCompatibility = async (announce = false) => {
    if (announce) {
      setError('');
      setMessage('');
    }
    setLoading(true);
    try {
      const { data } = await api.get<VendorCompatibilityPayload>('/system/vendor-compatibility');
      setPayload(data);
      if (announce) {
        setMessage('Vendor compatibility refreshed.');
      }
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Could not load vendor compatibility.'));
    } finally {
      setLoading(false);
    }
  };

  const updatePreviewField = (field: VendorReplyPreviewTextField, value: string) => {
    setPreviewForm((current) => ({ ...current, [field]: value }));
  };

  const updateACLRuleField = (index: number, field: keyof ACLRuleForm, value: string | boolean) => {
    setPreviewForm((current) => ({
      ...current,
      acl_rules: current.acl_rules.map((rule, ruleIndex) => (
        ruleIndex === index ? { ...rule, [field]: value } : rule
      )),
    }));
  };

  const addACLRule = () => {
    setPreviewForm((current) => ({
      ...current,
      acl_rules: [
        ...current.acl_rules,
        {
          action: 'permit',
          direction: 'in',
          protocol: 'ip',
          source: 'any',
          source_port: '',
          destination: 'any',
          destination_port: '',
          log: false,
        },
      ],
    }));
  };

  const removeACLRule = (index: number) => {
    setPreviewForm((current) => ({
      ...current,
      acl_rules: current.acl_rules.filter((_, ruleIndex) => ruleIndex !== index),
    }));
  };

  const runReplyPreview = async () => {
    setPreviewLoading(true);
    setPreviewError('');
    setMessage('');
    try {
      const request = {
        nas_type: previewForm.nas_type,
        role: previewForm.role,
        vlan: numericValue(previewForm.vlan),
        download_kbps: numericValue(previewForm.download_kbps),
        upload_kbps: numericValue(previewForm.upload_kbps),
        session_timeout: numericValue(previewForm.session_timeout),
        filter_id: previewForm.filter_id,
        acl_policy_name: previewForm.acl_policy_name,
        inbound_acl: previewForm.inbound_acl,
        outbound_acl: previewForm.outbound_acl,
        acl_rules: previewForm.acl_rules
          .filter((rule) => [rule.action, rule.direction, rule.protocol, rule.source, rule.source_port, rule.destination, rule.destination_port].some((value) => String(value).trim() !== ''))
          .map((rule) => ({
            action: rule.action,
            direction: rule.direction,
            protocol: rule.protocol,
            source: rule.source,
            source_port: rule.source_port,
            destination: rule.destination,
            destination_port: rule.destination_port,
            log: rule.log,
          })),
        compatibility_packs: activePacks,
      };
      const { data } = await api.post<VendorReplyPreviewPayload>('/system/vendor-reply-preview', request);
      setPreview(data);
      setMessage('Reply preview generated.');
    } catch (err: any) {
      setPreviewError(apiErrorMessage(err, 'Could not preview reply attributes.'));
    } finally {
      setPreviewLoading(false);
    }
  };

  useEffect(() => {
    void fetchCompatibility(false);
  }, []);

  const clientProfiles = payload?.client_profiles || [];
  const profileSummary = payload?.profile_summary;
  const activePacks = payload?.active_packs || [];
  const packs = payload?.packs || [];
  const dictionaryCoverage = payload?.dictionary_coverage;
  const coverageRows = dictionaryCoverage?.rows || [];
  const plannedSemantics = useMemo(
    () => (payload?.semantics || []).filter((item) => item.compatibility_state !== 'implemented'),
    [payload?.semantics],
  );
  const activePackDetails = useMemo(
    () => packs.filter((pack) => activePacks.includes(pack.key)),
    [packs, activePacks],
  );
  const profileCounts = Object.entries(profileSummary?.profile_counts || {}).sort(([left], [right]) => left.localeCompare(right));

  if (loading && !payload) {
    return <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Loading vendor compatibility...</div>;
  }

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Vendor Compatibility</h2>
          <p className="mt-1 text-sm text-gray-600">Confirm deployed NAS profiles, reply packs, and vendor dictionary coverage before changing access policy.</p>
        </div>
        <button
          onClick={() => void fetchCompatibility(true)}
          disabled={loading}
          className="rounded-md bg-sky-700 px-4 py-2 text-sm font-medium text-white hover:bg-sky-800 disabled:opacity-50"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}

      {payload ? (
        <>
          <section>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Vendor"
                value={payload.summary.product_vendor_name || 'AegisNAS'}
                hint={`ID ${payload.summary.product_vendor_id || 0}${payload.summary.product_vendor_id_placeholder ? ' placeholder' : ''}`}
              />
              <StatCard label="Product VSAs" value={payload.summary.product_attribute_count || 0} hint="Built-in dictionary attributes." />
              <StatCard label="Active Packs" value={activePacks.length} hint={joinList(activePacks)} />
              <StatCard label="Client Profiles" value={profileSummary?.enabled_clients || 0} hint={`${profileSummary?.total_clients || 0} registered clients.`} />
              <StatCard label="Known Vendors" value={profileSummary?.known_vendor_profile_clients || 0} hint="Clients using a recognized pack." />
              <StatCard label="Global Fallback" value={profileSummary?.global_fallback_client_count || 0} hint="Clients using default compatibility packs." />
              <StatCard label="Implemented" value={payload.summary.implemented_count || 0} hint="Semantic capabilities ready now." />
              <StatCard label="Planned" value={payload.summary.planned_count || 0} hint="Compatibility capabilities still queued." />
            </div>
          </section>

          <section className="mt-6">
            <div className="rounded-lg bg-white p-5 shadow">
              <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">Product Vendor Identity</h3>
                  <p className="mt-1 text-sm text-gray-600">Use the assigned PEN before enabling AegisNAS product VSAs outside a lab.</p>
                </div>
                <StatusBadge tone={payload.summary.product_vendor_id_placeholder ? 'amber' : 'green'}>
                  {payload.summary.product_vendor_id_placeholder ? 'Placeholder ID' : 'Assigned ID'}
                </StatusBadge>
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <StatCard
                  label="ID Source"
                  value={payload.summary.product_vendor_id_source || 'unknown'}
                  hint={payload.summary.product_vendor_id_placeholder ? 'Set AEGISNAS_VENDOR_ID after IANA assignment.' : 'Ready for production dictionary generation.'}
                />
                <StatCard
                  label="Dictionary"
                  value={payload.summary.product_vendor_dictionary_filename || 'dictionary.aegisnas'}
                  hint={payload.summary.product_vendor_dictionary_include || '$INCLUDE dictionary.aegisnas'}
                />
                <StatCard
                  label="Install Path"
                  value={payload.summary.product_vendor_dictionary_install_path || '/etc/freeradius/3.0/dictionary.aegisnas'}
                  hint="FreeRADIUS local dictionary include target."
                />
              </div>
            </div>
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Reply Preview</h3>
                <p className="mt-1 text-sm text-gray-600">Generate the RADIUS attributes a device profile will receive before testing on APs, controllers, or switches.</p>
              </div>
              {preview ? (
                <StatusBadge tone={preview.known_pack ? 'green' : preview.uses_global_packs ? 'amber' : 'gray'}>
                  {preview.known_pack ? 'Vendor pack' : preview.uses_global_packs ? 'Global fallback' : 'Custom'}
                </StatusBadge>
              ) : null}
            </div>

            <form onSubmit={(event) => { event.preventDefault(); void runReplyPreview(); }} className="rounded-md border border-gray-200 px-4 py-4">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <label className="block text-sm font-medium text-gray-700">
                  NAS Type
                  <input
                    value={previewForm.nas_type}
                    onChange={(event) => updatePreviewField('nas_type', event.target.value)}
                    placeholder="aruba"
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  Role
                  <input
                    value={previewForm.role}
                    onChange={(event) => updatePreviewField('role', event.target.value)}
                    placeholder="guest"
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  VLAN
                  <input
                    type="number"
                    value={previewForm.vlan}
                    onChange={(event) => updatePreviewField('vlan', event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  Session Timeout
                  <input
                    type="number"
                    value={previewForm.session_timeout}
                    onChange={(event) => updatePreviewField('session_timeout', event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  Download Kbps
                  <input
                    type="number"
                    value={previewForm.download_kbps}
                    onChange={(event) => updatePreviewField('download_kbps', event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  Upload Kbps
                  <input
                    type="number"
                    value={previewForm.upload_kbps}
                    onChange={(event) => updatePreviewField('upload_kbps', event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700 xl:col-span-2">
                  Filter ID
                  <input
                    value={previewForm.filter_id}
                    onChange={(event) => updatePreviewField('filter_id', event.target.value)}
                    placeholder="optional vendor policy tag"
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  ACL Policy
                  <input
                    value={previewForm.acl_policy_name}
                    onChange={(event) => updatePreviewField('acl_policy_name', event.target.value)}
                    placeholder="guest-internet"
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  Inbound ACL
                  <input
                    value={previewForm.inbound_acl}
                    onChange={(event) => updatePreviewField('inbound_acl', event.target.value)}
                    placeholder="optional named ACL"
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
                <label className="block text-sm font-medium text-gray-700">
                  Outbound ACL
                  <input
                    value={previewForm.outbound_acl}
                    onChange={(event) => updatePreviewField('outbound_acl', event.target.value)}
                    placeholder="optional named ACL"
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  />
                </label>
              </div>
              <div className="mt-4">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h4 className="text-sm font-semibold text-gray-900">ACL Rules</h4>
                    <p className="mt-1 text-sm text-gray-600">Use single-token addresses such as any, 10.0.0.0/24, or 2001:db8::/64.</p>
                  </div>
                  <button
                    type="button"
                    onClick={addACLRule}
                    className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Add Rule
                  </button>
                </div>
                <div className="space-y-3">
                  {previewForm.acl_rules.length === 0 ? (
                    <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">No ACL rules selected.</div>
                  ) : (
                    previewForm.acl_rules.map((rule, index) => (
                      <div key={`acl-rule-${index}`} className="rounded-md border border-gray-200 px-3 py-3">
                        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                          <label className="block text-xs font-semibold uppercase text-gray-600">
                            Action
                            <select
                              value={rule.action}
                              onChange={(event) => updateACLRuleField(index, 'action', event.target.value)}
                              className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-medium normal-case text-gray-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                            >
                              <option value="permit">permit</option>
                              <option value="deny">deny</option>
                            </select>
                          </label>
                          <label className="block text-xs font-semibold uppercase text-gray-600">
                            Direction
                            <select
                              value={rule.direction}
                              onChange={(event) => updateACLRuleField(index, 'direction', event.target.value)}
                              className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-medium normal-case text-gray-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                            >
                              <option value="in">in</option>
                              <option value="out">out</option>
                            </select>
                          </label>
                          <label className="block text-xs font-semibold uppercase text-gray-600">
                            Protocol
                            <input
                              value={rule.protocol}
                              onChange={(event) => updateACLRuleField(index, 'protocol', event.target.value)}
                              placeholder="tcp"
                              className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm normal-case text-gray-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                            />
                          </label>
                          <label className="block text-xs font-semibold uppercase text-gray-600">
                            Source
                            <input
                              value={rule.source}
                              onChange={(event) => updateACLRuleField(index, 'source', event.target.value)}
                              placeholder="any"
                              className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm normal-case text-gray-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                            />
                          </label>
                          <label className="block text-xs font-semibold uppercase text-gray-600">
                            Source Port
                            <input
                              value={rule.source_port}
                              onChange={(event) => updateACLRuleField(index, 'source_port', event.target.value)}
                              placeholder="optional"
                              className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm normal-case text-gray-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                            />
                          </label>
                          <label className="block text-xs font-semibold uppercase text-gray-600">
                            Destination
                            <input
                              value={rule.destination}
                              onChange={(event) => updateACLRuleField(index, 'destination', event.target.value)}
                              placeholder="any"
                              className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm normal-case text-gray-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                            />
                          </label>
                          <label className="block text-xs font-semibold uppercase text-gray-600">
                            Destination Port
                            <input
                              value={rule.destination_port}
                              onChange={(event) => updateACLRuleField(index, 'destination_port', event.target.value)}
                              placeholder="443"
                              className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm normal-case text-gray-900 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                            />
                          </label>
                          <div className="flex items-end justify-between gap-3">
                            <label className="flex items-center gap-2 pb-2 text-sm font-medium text-gray-700">
                              <input
                                type="checkbox"
                                checked={rule.log}
                                onChange={(event) => updateACLRuleField(index, 'log', event.target.checked)}
                                className="h-4 w-4 rounded border-gray-300 text-sky-700 focus:ring-sky-600"
                              />
                              Log
                            </label>
                            <button
                              type="button"
                              onClick={() => removeACLRule(index)}
                              className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50"
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm text-gray-600">Uses the active reply packs unless the NAS type maps to a more specific vendor profile.</p>
                <button
                  type="submit"
                  disabled={previewLoading}
                  className="rounded-md bg-sky-700 px-4 py-2 text-sm font-medium text-white hover:bg-sky-800 disabled:opacity-50"
                >
                  {previewLoading ? 'Generating...' : 'Preview Reply'}
                </button>
              </div>
            </form>

            {previewError && <div className="mt-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{previewError}</div>}

            {preview ? (
              <div className="mt-4 grid gap-4 xl:grid-cols-2">
                <div className="rounded-md border border-gray-200">
                  <div className="border-b border-gray-200 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge tone="gray">NAS Type: {preview.nas_type || 'other'}</StatusBadge>
                      <StatusBadge tone="gray">Packs: {joinList(preview.effective_packs)}</StatusBadge>
                    </div>
                    {preview.warnings && preview.warnings.length > 0 ? (
                      <div className="mt-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                        {preview.warnings.map((warning) => <div key={warning}>{warning}</div>)}
                      </div>
                    ) : null}
                  </div>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          {['Attribute', 'Value', 'Quoted'].map((label) => (
                            <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {(preview.attributes || []).length === 0 ? (
                          <tr><td className="px-4 py-6 text-sm text-gray-500" colSpan={3}>No reply attributes produced.</td></tr>
                        ) : (
                          preview.attributes.map((attribute) => (
                            <tr key={`${attribute.name}-${attribute.value}`}>
                              <td className="px-4 py-3 text-sm font-medium text-gray-900">{attribute.name}</td>
                              <td className="px-4 py-3 text-sm text-gray-700">{attribute.value}</td>
                              <td className="px-4 py-3 text-sm text-gray-700">{attribute.quoted ? 'Yes' : 'No'}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="rounded-md border border-gray-200">
                  <div className="border-b border-gray-200 px-4 py-3">
                    <h4 className="text-sm font-semibold text-gray-900">FreeRADIUS Reply</h4>
                  </div>
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap px-4 py-3 text-sm text-gray-800">{preview.freeradius || 'No FreeRADIUS reply text generated.'}</pre>
                </div>
              </div>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Dictionary Coverage</h3>
                <p className="mt-1 text-sm text-gray-600">Check which compatibility packs are backed by the parsed FreeRADIUS catalog and which still need vendor dictionary or controller work.</p>
              </div>
              {dictionaryCoverage ? (
                <StatusBadge tone={dictionaryCoverage.missing_dictionary_vendor_count > 0 ? 'amber' : 'green'}>
                  {dictionaryCoverage.missing_dictionary_vendor_count} missing vendors
                </StatusBadge>
              ) : null}
            </div>

            {dictionaryCoverage ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Catalog Vendors" value={dictionaryCoverage.catalog_vendor_count || 0} hint={`${dictionaryCoverage.catalog_attribute_count || 0} parsed attributes.`} />
                  <StatCard label="Backed Packs" value={dictionaryCoverage.dictionary_backed_pack_count || 0} hint={`${dictionaryCoverage.partial_dictionary_pack_count || 0} partial packs.`} />
                  <StatCard label="Matched Attrs" value={dictionaryCoverage.dictionary_matched_attribute_count || 0} hint="Attributes present in the parsed catalog." />
                  <StatCard label="Missing Attrs" value={dictionaryCoverage.missing_dictionary_attribute_count || 0} hint="Mappings that need dictionary or adapter work." />
                </div>

                <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
                  {dictionaryCoverage.source ? (
                    <div className="break-words border-b border-gray-200 px-4 py-3 text-sm text-gray-600">
                      Source: {dictionaryCoverage.source}
                    </div>
                  ) : null}
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        {['Pack', 'Coverage', 'Attributes', 'Hardware'].map((label) => (
                          <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                      {coverageRows.length === 0 ? (
                        <tr><td className="px-4 py-8 text-sm text-gray-500" colSpan={4}>No dictionary coverage rows available.</td></tr>
                      ) : (
                        coverageRows.map((row) => (
                          <tr key={row.pack_key}>
                            <td className="px-4 py-3 text-sm">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-medium text-gray-900">{row.pack_label || row.pack_key}</span>
                                {row.active ? <StatusBadge tone="green">Active</StatusBadge> : <StatusBadge tone="gray">Available</StatusBadge>}
                              </div>
                              <div className="mt-1 text-xs text-gray-500">{row.pack_key}</div>
                            </td>
                            <td className="px-4 py-3 text-sm">
                              <StatusBadge tone={coverageTone(row.coverage_state)}>{coverageLabel(row.coverage_state)}</StatusBadge>
                              <div className="mt-2 text-gray-600">
                                {row.vendor_name || 'Standards-based'}
                                {row.vendor_id ? ` ID ${row.vendor_id}` : ''}
                              </div>
                              {row.vendor_name ? (
                                <div className="text-xs text-gray-500">
                                  {row.dictionary_vendor_found ? `${row.dictionary_attribute_count || 0} dictionary attributes` : 'vendor dictionary not parsed'}
                                </div>
                              ) : null}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-700">
                              <div>{row.dictionary_matched_attribute_count || 0} matched of {row.radius_attribute_count || 0} RADIUS attributes</div>
                              <div className="text-xs text-gray-500">{row.pack_attribute_count || 0} mapped capabilities, {row.missing_dictionary_attribute_count || 0} missing</div>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-700">{joinList(row.hardware_profiles)}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-4 text-sm text-gray-500">Dictionary coverage is unavailable.</div>
            )}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">RADIUS Client Profiles</h3>
                <p className="mt-1 text-sm text-gray-600">Each enabled AP, controller, or switch should use the profile that matches the receiving device.</p>
              </div>
              {profileSummary?.unknown_profiles && profileSummary.unknown_profiles.length > 0 ? (
                <StatusBadge tone="amber">Fallback: {joinList(profileSummary.unknown_profiles)}</StatusBadge>
              ) : (
                <StatusBadge tone="green">Known profiles only</StatusBadge>
              )}
            </div>
            <div className="overflow-x-auto rounded-md border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {['Client', 'IP', 'NAS Type', 'Packs', 'Status', 'Warning'].map((label) => (
                      <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {clientProfiles.length === 0 ? (
                    <tr><td className="px-4 py-8 text-sm text-gray-500" colSpan={6}>No RADIUS clients found.</td></tr>
                  ) : (
                    clientProfiles.map((profile) => (
                      <tr key={`${profile.shortname}-${profile.ip}`}>
                        <td className="px-4 py-3 text-sm">
                          <div className="font-medium text-gray-900">{profile.shortname || 'Unnamed client'}</div>
                          <div className="text-xs text-gray-500">{profile.enabled ? 'Enabled' : 'Disabled'}</div>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-700">{profile.ip || '-'}</td>
                        <td className="px-4 py-3 text-sm">
                          <div className="font-medium text-gray-900">{profile.nas_type || 'other'}</div>
                          {profile.raw_nas_type ? <div className="text-xs text-gray-500">from {profile.raw_nas_type}</div> : null}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-700">{joinList(profile.effective_packs)}</td>
                        <td className="px-4 py-3 text-sm">
                          {profile.known_pack ? (
                            <StatusBadge tone="green">Vendor pack</StatusBadge>
                          ) : profile.uses_global_packs ? (
                            <StatusBadge tone="amber">Global fallback</StatusBadge>
                          ) : (
                            <StatusBadge tone="gray">Custom</StatusBadge>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">{profile.warning || 'Ready'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <div className="mt-6 grid gap-6 xl:grid-cols-2">
            <section>
              <h3 className="text-lg font-semibold text-gray-900">Profile Mix</h3>
              <div className="mt-4 space-y-2">
                {profileCounts.length === 0 ? (
                  <div className="rounded-md border border-dashed border-gray-300 px-4 py-4 text-sm text-gray-500">No profile counts available.</div>
                ) : (
                  profileCounts.map(([profile, count]) => (
                    <div key={profile} className="flex items-center justify-between rounded-md border border-gray-200 px-4 py-3 text-sm">
                      <span className="font-medium text-gray-800">{profile}</span>
                      <span className="text-gray-600">{count}</span>
                    </div>
                  ))
                )}
              </div>
            </section>

            <section>
              <h3 className="text-lg font-semibold text-gray-900">Active Reply Packs</h3>
              <div className="mt-4 space-y-2">
                {activePackDetails.length === 0 ? (
                  <div className="rounded-md border border-dashed border-gray-300 px-4 py-4 text-sm text-gray-500">No active reply packs configured.</div>
                ) : (
                  activePackDetails.map((pack) => (
                    <div key={pack.key} className="rounded-md border border-gray-200 px-4 py-3 text-sm">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-medium text-gray-900">{pack.label}</span>
                        <span className="text-xs uppercase text-gray-500">{pack.key}</span>
                      </div>
                      <div className="mt-1 text-gray-600">{pack.vendor_name || 'Standards-based'} - {joinList(pack.hardware_profiles)}</div>
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>

          <section className="mt-6">
            <h3 className="text-lg font-semibold text-gray-900">Planned Compatibility Work</h3>
            <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {['Capability', 'Scope', 'Next Step'].map((label) => (
                      <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {plannedSemantics.length === 0 ? (
                    <tr><td className="px-4 py-8 text-sm text-gray-500" colSpan={3}>No planned compatibility work listed.</td></tr>
                  ) : (
                    plannedSemantics.map((semantic) => (
                      <tr key={semantic.key}>
                        <td className="px-4 py-3 text-sm">
                          <div className="font-medium text-gray-900">{semantic.label}</div>
                          <div className="text-xs text-gray-500">{semantic.key}</div>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-700">{semantic.hardware_scope}</td>
                        <td className="px-4 py-3 text-sm text-gray-700">{semantic.next_step || 'Queued'}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      ) : (
        <div className="rounded-md border border-dashed border-gray-300 px-4 py-8 text-sm text-gray-500">Vendor compatibility is unavailable.</div>
      )}
    </div>
  );
}
