import { type ReactNode, useEffect, useMemo, useState } from 'react';
import api from '../api/client';
import { useAuth } from '../contexts/AuthContext';

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
  product_vendor_identity_mode?: string;
  product_vendor_assigned_organization?: string;
  product_vendor_assignment_verified?: boolean;
  product_vendor_assignment_record_sha256?: string;
  product_vendor_legacy_ids?: number[];
  product_vendor_legacy_accept_until?: string;
};

type VendorIdentitySnapshot = {
  name: string;
  pen: number;
  identity_mode: string;
  assigned_organization?: string;
  assignment_registry_url?: string;
  registry_last_updated?: string;
  assignment_verified_at?: string;
  assignment_registry_sha256?: string;
  assignment_record_sha256?: string;
  legacy_pens?: number[];
  legacy_accept_until?: string;
};

type VendorIdentityEvidence = {
  pen: number;
  organization: string;
  registry_url: string;
  registry_last_updated: string;
  fetched_at: string;
  registry_sha256: string;
  record_sha256: string;
};

type VendorIdentityMigration = {
  id: string;
  status: string;
  from_pen: number;
  to_pen: number;
  organization: string;
  expires_at: string;
  created_by?: string;
  created_at: string;
  applied_at?: string;
  rolled_back_at?: string;
  failure?: string;
};

type VendorIdentityStatus = {
  status: string;
  ready: boolean;
  current: VendorIdentitySnapshot;
  evidence?: VendorIdentityEvidence;
  config_evidence_valid: boolean;
  legacy_window_active: boolean;
  migrations?: VendorIdentityMigration[];
  metrics: {
    previewed: number;
    applying: number;
    applied: number;
    failed: number;
    rolled_back: number;
    last_event_at?: string;
  };
  warnings?: string[];
};

type VendorIdentityPreview = {
  migration_id: string;
  confirmation_token: string;
  expires_at: string;
  current: VendorIdentitySnapshot;
  target: VendorIdentitySnapshot;
  evidence: VendorIdentityEvidence;
  active_sessions: number;
  affected_systems: string[];
  warnings: string[];
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

type AttributeRegistryEntry = {
  key: string;
  source: string;
  vendor: string;
  pen: number;
  attribute: string;
  number?: number;
  oid?: string;
  wire_type: string;
  capability_family: string;
  dictionary_status: string;
  pack_key?: string;
  semantic?: string;
  directions?: string[];
  decode_kind?: string;
};

type AttributeRegistryPayload = {
  schema_version: number;
  source_release: string;
  source_file_count: number;
  source_attribute_count: number;
  source_sha256: string;
  vendor_count: number;
  attribute_count: number;
  mapped_count: number;
  filtered_count: number;
  entries: AttributeRegistryEntry[];
  next_cursor?: string;
};

type VendorReplyPreviewAttribute = {
  name: string;
  value: string;
  quoted: boolean;
};

type ACLVendorExport = {
  pack_key: string;
  pack_label: string;
  export_mode: string;
  attributes: VendorReplyPreviewAttribute[];
  freeradius: string;
  warnings?: string[];
};

type NormalizedACLRule = {
  action: string;
  direction: string;
  protocol: string;
  source: string;
  source_port?: string;
  destination: string;
  destination_port?: string;
  log?: boolean;
};

type VendorReplyPreviewPayload = {
  nas_type: string;
  known_pack: boolean;
  uses_global_packs: boolean;
  effective_packs: string[];
  attributes: VendorReplyPreviewAttribute[];
  freeradius: string;
  normalized_acl_rules?: NormalizedACLRule[];
  acl_exports?: ACLVendorExport[];
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
    return typeof data.error === 'object' && data.error.message ? String(data.error.message) : String(data.error);
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

function aclExportModeLabel(mode: string) {
  switch (mode) {
    case 'rules':
      return 'Line rules';
    case 'profile':
      return 'Profile hint';
    case 'mixed':
      return 'Profile + rules';
    default:
      return mode || 'ACL intent';
  }
}

export default function VendorCompatibility() {
  const { identity } = useAuth();
  const [payload, setPayload] = useState<VendorCompatibilityPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [previewForm, setPreviewForm] = useState<VendorReplyPreviewForm>(defaultPreviewForm);
  const [preview, setPreview] = useState<VendorReplyPreviewPayload | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState('');
  const [identityStatus, setIdentityStatus] = useState<VendorIdentityStatus | null>(null);
  const [identityBusy, setIdentityBusy] = useState(false);
  const [identityError, setIdentityError] = useState('');
  const [identityPreview, setIdentityPreview] = useState<VendorIdentityPreview | null>(null);
  const [identityForm, setIdentityForm] = useState({ pen: '', organization: '', legacyHours: '168' });
  const [rollbackConfirmations, setRollbackConfirmations] = useState<Record<string, string>>({});
  const [attributeRegistry, setAttributeRegistry] = useState<AttributeRegistryPayload | null>(null);
  const [attributeRegistryBusy, setAttributeRegistryBusy] = useState(false);
  const [attributeRegistryError, setAttributeRegistryError] = useState('');
  const [attributeRegistryFilters, setAttributeRegistryFilters] = useState({ search: '', vendor: '', status: '' });

  const canManageIdentity = identity?.role === 'super_admin';

  const fetchVendorIdentity = async () => {
    try {
      const { data } = await api.get<VendorIdentityStatus>('/system/vendor-identity?limit=25');
      setIdentityStatus(data);
    } catch (err: any) {
      setIdentityError(apiErrorMessage(err, 'Could not load vendor identity status.'));
    }
  };

  const previewIdentityMigration = async () => {
    setIdentityBusy(true);
    setIdentityError('');
    setMessage('');
    try {
      const { data } = await api.post<VendorIdentityPreview>('/system/vendor-identity/migrations/preview', {
        pen: Number(identityForm.pen),
        expected_organization: identityForm.organization.trim(),
        legacy_acceptance_hours: Number(identityForm.legacyHours),
      });
      setIdentityPreview(data);
      setMessage('IANA assignment verified. Review the migration impact before applying.');
      await fetchVendorIdentity();
    } catch (err: any) {
      setIdentityError(apiErrorMessage(err, 'Could not verify the PEN migration.'));
    } finally {
      setIdentityBusy(false);
    }
  };

  const applyIdentityMigration = async () => {
    if (!identityPreview) return;
    setIdentityBusy(true);
    setIdentityError('');
    try {
      await api.post('/system/vendor-identity/migrations/apply', {
        migration_id: identityPreview.migration_id,
        confirmation_token: identityPreview.confirmation_token,
      });
      setIdentityPreview(null);
      setMessage('Production vendor identity applied and FreeRADIUS restarted.');
      await Promise.all([fetchVendorIdentity(), fetchCompatibility(false)]);
    } catch (err: any) {
      setIdentityError(apiErrorMessage(err, 'Could not apply the PEN migration.'));
    } finally {
      setIdentityBusy(false);
    }
  };

  const rollbackIdentityMigration = async (migrationID: string) => {
    setIdentityBusy(true);
    setIdentityError('');
    try {
      await api.post(`/system/vendor-identity/migrations/${migrationID}/rollback`, {
        confirmation_text: rollbackConfirmations[migrationID] || '',
      });
      setMessage('Vendor identity migration rolled back and FreeRADIUS restarted.');
      setRollbackConfirmations((current) => ({ ...current, [migrationID]: '' }));
      await Promise.all([fetchVendorIdentity(), fetchCompatibility(false)]);
    } catch (err: any) {
      setIdentityError(apiErrorMessage(err, 'Could not roll back the PEN migration.'));
    } finally {
      setIdentityBusy(false);
    }
  };

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

  const fetchAttributeRegistry = async (append = false) => {
    setAttributeRegistryBusy(true);
    setAttributeRegistryError('');
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (attributeRegistryFilters.search.trim()) params.set('search', attributeRegistryFilters.search.trim());
      if (attributeRegistryFilters.vendor.trim()) params.set('vendor', attributeRegistryFilters.vendor.trim());
      if (attributeRegistryFilters.status) params.set('status', attributeRegistryFilters.status);
      if (append && attributeRegistry?.next_cursor) params.set('cursor', attributeRegistry.next_cursor);
      const { data } = await api.get<AttributeRegistryPayload>(`/system/attribute-registry?${params.toString()}`);
      setAttributeRegistry((current) => append && current
        ? { ...data, entries: [...current.entries, ...data.entries] }
        : data);
    } catch (err: any) {
      setAttributeRegistryError(apiErrorMessage(err, 'Could not load the generated attribute registry.'));
    } finally {
      setAttributeRegistryBusy(false);
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
    void fetchVendorIdentity();
    void fetchAttributeRegistry(false);
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
          onClick={() => { void fetchCompatibility(true); void fetchVendorIdentity(); void fetchAttributeRegistry(false); }}
          disabled={loading}
          className="rounded-md bg-sky-700 px-4 py-2 text-sm font-medium text-white hover:bg-sky-800 disabled:opacity-50"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {message && <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{message}</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{String(error)}</div>}
      {identityError && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{identityError}</div>}

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
                <StatusBadge tone={identityStatus?.ready ? 'green' : 'amber'}>
                  {identityStatus?.ready ? 'Verified assignment' : payload.summary.product_vendor_id_placeholder ? 'Lab identity' : 'Verification required'}
                </StatusBadge>
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <StatCard
                  label="ID Source"
                  value={payload.summary.product_vendor_id_source || 'unknown'}
                  hint={identityStatus?.ready ? payload.summary.product_vendor_assigned_organization || 'Verified by IANA.' : 'Use the verified migration workflow before production activation.'}
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

              {identityStatus ? (
                <div className="mt-5 border-t border-gray-200 pt-5">
                  <div className="grid gap-3 md:grid-cols-3">
                    <StatCard label="Lifecycle" value={identityStatus.status.split('_').join(' ')} hint={identityStatus.ready ? 'Production identity is active.' : 'Production activation remains blocked.'} />
                    <StatCard label="Legacy Decode" value={identityStatus.legacy_window_active ? 'Active' : 'Inactive'} hint={identityStatus.current.legacy_accept_until || 'No transition window.'} />
                    <StatCard label="Migration Results" value={identityStatus.metrics.applied || 0} hint={`${identityStatus.metrics.failed || 0} failed, ${identityStatus.metrics.rolled_back || 0} rolled back.`} />
                  </div>
                  {(identityStatus.warnings || []).map((warning) => <p key={warning} className="mt-3 text-sm text-amber-800">{warning}</p>)}
                </div>
              ) : null}

              {canManageIdentity ? (
                <form onSubmit={(event) => { event.preventDefault(); void previewIdentityMigration(); }} className="mt-5 border-t border-gray-200 pt-5">
                  <h4 className="font-semibold text-gray-900">Production PEN Migration</h4>
                  <div className="mt-3 grid gap-4 md:grid-cols-3">
                    <label className="text-sm font-medium text-gray-700">
                      Assigned PEN
                      <input type="number" min="1" max="4294967294" required value={identityForm.pen} onChange={(event) => setIdentityForm((current) => ({ ...current, pen: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2" />
                    </label>
                    <label className="text-sm font-medium text-gray-700">
                      Exact IANA organization
                      <input required maxLength={255} value={identityForm.organization} onChange={(event) => setIdentityForm((current) => ({ ...current, organization: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2" />
                    </label>
                    <label className="text-sm font-medium text-gray-700">
                      Legacy decode hours
                      <input type="number" min="0" max="720" required value={identityForm.legacyHours} onChange={(event) => setIdentityForm((current) => ({ ...current, legacyHours: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2" />
                    </label>
                  </div>
                  <button disabled={identityBusy} className="mt-4 rounded-md bg-sky-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
                    {identityBusy ? 'Verifying...' : 'Verify with IANA and Preview'}
                  </button>
                </form>
              ) : null}

              {identityPreview ? (
                <div className="mt-5 border-t border-gray-200 pt-5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h4 className="font-semibold text-gray-900">Verified Migration Preview</h4>
                      <p className="mt-1 text-sm text-gray-600">PEN {identityPreview.current.pen} to {identityPreview.target.pen} for {identityPreview.evidence.organization}</p>
                      <p className="mt-1 text-sm text-gray-600">Registry updated {identityPreview.evidence.registry_last_updated}; confirmation expires {new Date(identityPreview.expires_at).toLocaleString()}.</p>
                    </div>
                    <StatusBadge tone="green">IANA matched</StatusBadge>
                  </div>
                  <p className="mt-3 text-sm text-gray-700">{identityPreview.active_sessions} active sessions; {identityPreview.affected_systems.length} platform surfaces will change.</p>
                  {identityPreview.warnings.map((warning) => <p key={warning} className="mt-2 text-sm text-amber-800">{warning}</p>)}
                  <div className="mt-4 flex gap-3">
                    <button type="button" onClick={() => void applyIdentityMigration()} disabled={identityBusy} className="rounded-md bg-red-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">Apply Verified Migration</button>
                    <button type="button" onClick={() => setIdentityPreview(null)} disabled={identityBusy} className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700">Cancel</button>
                  </div>
                </div>
              ) : null}

              {(identityStatus?.migrations || []).length > 0 ? (
                <div className="mt-5 overflow-x-auto border-t border-gray-200 pt-5">
                  <h4 className="font-semibold text-gray-900">Migration History</h4>
                  <table className="mt-3 min-w-full divide-y divide-gray-200 text-sm">
                    <thead><tr className="text-left text-gray-500"><th className="py-2 pr-4">Created</th><th className="py-2 pr-4">Change</th><th className="py-2 pr-4">Status</th><th className="py-2">Recovery</th></tr></thead>
                    <tbody className="divide-y divide-gray-100">
                      {(identityStatus?.migrations || []).map((migration) => (
                        <tr key={migration.id}>
                          <td className="py-3 pr-4">{new Date(migration.created_at).toLocaleString()}</td>
                          <td className="py-3 pr-4">{migration.from_pen} to {migration.to_pen}<div className="text-xs text-gray-500">{migration.organization}</div></td>
                          <td className="py-3 pr-4">{migration.status}{migration.failure ? <div className="max-w-md text-xs text-red-700">{migration.failure}</div> : null}</td>
                          <td className="py-3">
                            {canManageIdentity && ['applied', 'applying', 'failed'].includes(migration.status) ? (
                              <div className="flex min-w-80 gap-2">
                                <input aria-label={`Rollback confirmation ${migration.id}`} value={rollbackConfirmations[migration.id] || ''} onChange={(event) => setRollbackConfirmations((current) => ({ ...current, [migration.id]: event.target.value }))} placeholder={`ROLLBACK ${migration.id}`} className="min-w-0 flex-1 rounded-md border border-gray-300 px-2 py-1" />
                                <button type="button" disabled={identityBusy} onClick={() => void rollbackIdentityMigration(migration.id)} className="rounded-md border border-red-300 px-3 py-1 text-red-700 disabled:opacity-50">Rollback</button>
                              </div>
                            ) : 'None'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </div>
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Typed Attribute Registry</h3>
                <p className="mt-1 text-sm text-gray-600">Trace wire identifiers, value types, policy semantics, packet decoders, and source provenance from one versioned contract.</p>
              </div>
              {attributeRegistry ? <StatusBadge tone="green">Schema {attributeRegistry.schema_version} / FreeRADIUS {attributeRegistry.source_release}</StatusBadge> : null}
            </div>

            <form className="grid gap-3 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto]" onSubmit={(event) => { event.preventDefault(); void fetchAttributeRegistry(false); }}>
              <label className="text-sm font-medium text-gray-700">Search
                <input value={attributeRegistryFilters.search} onChange={(event) => setAttributeRegistryFilters((current) => ({ ...current, search: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2" placeholder="Attribute, semantic, capability" />
              </label>
              <label className="text-sm font-medium text-gray-700">Vendor
                <input value={attributeRegistryFilters.vendor} onChange={(event) => setAttributeRegistryFilters((current) => ({ ...current, vendor: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2" placeholder="Aruba" />
              </label>
              <label className="text-sm font-medium text-gray-700">Status
                <select value={attributeRegistryFilters.status} onChange={(event) => setAttributeRegistryFilters((current) => ({ ...current, status: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2">
                  <option value="">All states</option><option value="partial">Partial</option><option value="missing">Missing</option><option value="implemented">Implemented</option>
                </select>
              </label>
              <button type="submit" disabled={attributeRegistryBusy} className="self-end rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">{attributeRegistryBusy ? 'Loading...' : 'Filter'}</button>
            </form>

            {attributeRegistryError ? <div className="mt-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{attributeRegistryError}</div> : null}
            {attributeRegistry ? (
              <>
                <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Registry Vendors" value={attributeRegistry.vendor_count} hint={`${attributeRegistry.source_file_count} pinned dictionary files.`} />
                  <StatCard label="Source Attributes" value={attributeRegistry.source_attribute_count} hint={`${attributeRegistry.attribute_count} effective entries.`} />
                  <StatCard label="Mapped Attributes" value={attributeRegistry.mapped_count} hint="Mapped is not device certification." />
                  <StatCard label="Filter Results" value={attributeRegistry.filtered_count} hint={`${attributeRegistry.entries.length} loaded.`} />
                </div>
                <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50"><tr>{['Vendor / Wire', 'Attribute', 'Type / Direction', 'Semantic / State'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                    <tbody className="divide-y divide-gray-200">
                      {attributeRegistry.entries.map((entry) => (
                        <tr key={entry.key}>
                          <td className="px-4 py-3 text-sm"><div className="font-medium text-gray-900">{entry.vendor}</div><div className="text-xs text-gray-500">PEN {entry.pen} / {entry.number || entry.oid || '-'}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-800">{entry.attribute}<div className="text-xs text-gray-500">{entry.source}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{entry.wire_type}<div className="text-xs text-gray-500">{joinList(entry.directions)}{entry.decode_kind ? ` / ${entry.decode_kind}` : ''}</div></td>
                          <td className="px-4 py-3 text-sm"><div>{entry.semantic || entry.capability_family}</div><div className="mt-1"><StatusBadge tone={entry.dictionary_status === 'missing' ? 'gray' : 'amber'}>{entry.dictionary_status}</StatusBadge></div></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {attributeRegistry.next_cursor ? <button type="button" disabled={attributeRegistryBusy} onClick={() => void fetchAttributeRegistry(true)} className="mt-3 rounded-md border border-gray-300 px-4 py-2 text-sm font-semibold text-gray-800 disabled:opacity-50">Load more</button> : null}
                <p className="mt-2 break-all text-xs text-gray-500">Source SHA-256: {attributeRegistry.source_sha256}</p>
              </>
            ) : null}
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
                    <h4 className="text-sm font-semibold text-gray-900">Vendor-Neutral ACL Intent</h4>
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

                <div className="rounded-md border border-gray-200 xl:col-span-2">
                  <div className="border-b border-gray-200 px-4 py-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h4 className="text-sm font-semibold text-gray-900">ACL Vendor Export</h4>
                      <StatusBadge tone="gray">{(preview.normalized_acl_rules || []).length} normalized rules</StatusBadge>
                    </div>
                  </div>
                  {(preview.acl_exports || []).length === 0 ? (
                    <div className="px-4 py-6 text-sm text-gray-500">No ACL export attributes produced.</div>
                  ) : (
                    <div className="divide-y divide-gray-200">
                      {(preview.acl_exports || []).map((aclExport) => (
                        <div key={aclExport.pack_key} className="px-4 py-4">
                          <div className="mb-3 flex flex-wrap items-center gap-2">
                            <span className="text-sm font-semibold text-gray-900">{aclExport.pack_label || aclExport.pack_key}</span>
                            <StatusBadge tone={aclExport.export_mode === 'rules' ? 'green' : aclExport.export_mode === 'mixed' ? 'amber' : 'gray'}>
                              {aclExportModeLabel(aclExport.export_mode)}
                            </StatusBadge>
                          </div>
                          {aclExport.warnings && aclExport.warnings.length > 0 ? (
                            <div className="mb-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                              {aclExport.warnings.map((warning) => <div key={warning}>{warning}</div>)}
                            </div>
                          ) : null}
                          <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                              <thead className="bg-gray-50">
                                <tr>
                                  {['Attribute', 'Value'].map((label) => (
                                    <th key={label} className="px-3 py-2 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-200">
                                {(aclExport.attributes || []).map((attribute) => (
                                  <tr key={`${aclExport.pack_key}-${attribute.name}-${attribute.value}`}>
                                    <td className="px-3 py-2 text-sm font-medium text-gray-900">{attribute.name}</td>
                                    <td className="break-words px-3 py-2 text-sm text-gray-700">{attribute.value}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          {aclExport.freeradius ? (
                            <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap rounded-md bg-gray-950 px-3 py-2 text-sm text-gray-100">{aclExport.freeradius}</pre>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  )}
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
