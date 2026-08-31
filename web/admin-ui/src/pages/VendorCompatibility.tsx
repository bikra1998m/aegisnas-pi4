import { type ReactNode, useEffect, useMemo, useState } from 'react';
import api from '../api/client';
import { useAuth } from '../contexts/AuthContext';

type VendorCompatibilitySummary = {
  product_vendor_id: number;
  product_vendor_name: string;
  dictionary_release_profile_id?: string;
  dictionary_release?: string;
  dictionary_release_source_sha256?: string;
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

type DictionaryVendorAlias = {
  alias: string;
  canonical_vendor: string;
  canonical_pack_key?: string;
  pen?: number;
  scope: string;
};

type DictionaryFirmwareProfile = {
  key: string;
  vendor: string;
  pack_key: string;
  pen?: number;
  product_family: string;
  firmware_scope: string;
  hardware_profiles: string[];
  support_state: string;
  evidence_state: string;
  attribute_scope: string[];
};

type DictionaryReleaseProfile = {
  id: string;
  release: string;
  status: string;
  default: boolean;
  registry_source_sha256?: string;
  source_file_count: number;
  source_attribute_count: number;
  effective_attribute_count: number;
  vendor_count: number;
  mapped_attribute_count: number;
  runtime_decoder_count: number;
  vendor_alias_count: number;
  attribute_alias_count: number;
  firmware_profile_count: number;
  vendor_aliases?: DictionaryVendorAlias[];
  firmware_profiles?: DictionaryFirmwareProfile[];
};

type VendorSemanticCapability = {
  key: string;
  label: string;
  compatibility_state: string;
  evidence?: CompatibilityEvidenceRecord;
  next_step?: string;
  hardware_scope: string;
};

type CompatibilityEvidenceDimension = {
  key: string;
  label: string;
  state: string;
  required: boolean;
  source?: string;
  detail?: string;
  next_step?: string;
};

type CompatibilityEvidenceRecord = {
  id: string;
  subject_type: string;
  pack_key?: string;
  pack_label?: string;
  active: boolean;
  vendor_name?: string;
  vendor_id?: number;
  attribute?: string;
  semantic?: string;
  direction?: string;
  value_type?: string;
  compatibility_state?: string;
  software_state: string;
  certification_state: string;
  claim_state: string;
  software_ready: boolean;
  ready_for_external_validation: boolean;
  external_validation_required: boolean;
  dimensions: CompatibilityEvidenceDimension[];
  blockers?: string[];
  next_steps?: string[];
};

type CompatibilityEvidenceSummary = {
  total_records: number;
  software_ready_count: number;
  software_planned_count: number;
  software_blocked_count: number;
  metadata_only_count: number;
  external_required_count: number;
  externally_certified_count: number;
};

type CompatibilityEvidencePayload = {
  schema_version: number;
  release_profile_id: string;
  source_sha256: string;
  summary: CompatibilityEvidenceSummary;
  filtered_count: number;
  records: CompatibilityEvidenceRecord[];
  next_cursor?: string;
  notes?: string[];
};

type VendorMappingCertificationSummary = {
  baseline_partial_mappings: number;
  certified_mappings: number;
  software_blocked_mappings: number;
  ready_for_external_mappings: number;
  external_required_mappings: number;
  vendor_count: number;
  runtime_decoder_count: number;
  generic_codec_count: number;
  reply_renderer_count: number;
  policy_wired_count: number;
  storage_wired_count: number;
  enforcement_wired_count: number;
  api_ui_wired_count: number;
  observability_wired_count: number;
  current_registry_mapped_count: number;
  current_runtime_mapping_count: number;
  software_completion_percent: number;
  fingerprint: string;
};

type VendorMappingCertificationVendorSummary = {
  vendor: string;
  pen: number;
  pack_key?: string;
  baseline_partial_mappings: number;
  certified_mappings: number;
  software_blocked_mappings: number;
  external_required_mappings: number;
  software_completion_percent: number;
};

type VendorMappingCertificationRecord = {
  id: string;
  vendor: string;
  pen: number;
  pack_key?: string;
  pack_label?: string;
  attribute: string;
  number?: number;
  oid?: string;
  wire_key: string;
  wire_type: string;
  capability_family: string;
  semantic: string;
  primary_semantic: string;
  directions: string[];
  decode_kind?: string;
  software_state: string;
  certification_state: string;
  claim_state: string;
  software_certified: boolean;
  ready_for_external_validation: boolean;
  external_validation_required: boolean;
  dimensions: CompatibilityEvidenceDimension[];
  blockers?: string[];
  next_steps?: string[];
};

type VendorMappingCertificationEvent = {
  event_id: string;
  operation: string;
  status: string;
  release_profile_id: string;
  source_sha256: string;
  baseline_partial_mappings: number;
  certified_mappings: number;
  software_blocked_mappings: number;
  external_required_mappings: number;
  vendor_count: number;
  fingerprint: string;
  actor?: string;
  created_at: string;
};

type VendorMappingCertificationPayload = {
  generated_at: string;
  report: {
    schema_version: number;
    release_profile_id: string;
    source_release: string;
    source_sha256: string;
    baseline_source: string;
    baseline_partial_mappings: number;
    summary: VendorMappingCertificationSummary;
    vendor_summaries: VendorMappingCertificationVendorSummary[];
    records: VendorMappingCertificationRecord[];
    notes?: string[];
  };
  evidence: {
    summary: {
      total_events: number;
      recorded_count: number;
      blocked_count: number;
      failed_count: number;
      last_event_at?: string;
      last_fingerprint?: string;
    };
    recent_events?: VendorMappingCertificationEvent[];
  };
  release_scope: string;
  release_certification_checklist: string;
};

type CiscoFamilyPackSummary = {
  vendor_count: number;
  attribute_count: number;
  native_semantic_mappings: number;
  typed_passthrough_mappings: number;
  grammar_rule_count: number;
  software_certified_mappings: number;
  software_blocked_mappings: number;
  ready_for_external_validation_mappings: number;
  external_required_mappings: number;
  software_completion_percent: number;
  fingerprint: string;
};

type CiscoFamilyVendorSummary = {
  vendor: string;
  pen: number;
  pack_key?: string;
  attribute_count: number;
  native_semantic_mappings: number;
  typed_passthrough_mappings: number;
  software_certified_mappings: number;
  external_required_mappings: number;
  software_completion_percent: number;
};

type CiscoFamilyCapabilitySummary = {
  capability: string;
  attribute_count: number;
  native_semantic_mappings: number;
  typed_passthrough_mappings: number;
  software_certified_mappings: number;
  external_required_mappings: number;
  software_completion_percent: number;
};

type CiscoFamilyGrammarRecord = {
  key: string;
  label: string;
  kind: string;
  semantic: string;
  examples?: string[];
  parser_state: string;
  compiler_state: string;
  inbound_state: string;
  outbound_state: string;
  external_state: string;
  release_scope?: string;
};

type CiscoFamilyAttributeRecord = {
  id: string;
  vendor: string;
  pen: number;
  pack_key?: string;
  attribute: string;
  number?: number;
  oid?: string;
  wire_key: string;
  wire_type: string;
  dictionary_status: string;
  capability: string;
  semantic?: string;
  directions: string[];
  implementation_class: string;
  packet_processing: string;
  policy_engine: string;
  enforcement: string;
  software_state: string;
  external_validation_required: boolean;
  ready_for_external_validation: boolean;
  claim_state: string;
  notes?: string[];
};

type CiscoFamilyPackEvent = {
  event_id: string;
  operation: string;
  status: string;
  release_profile_id: string;
  source_sha256: string;
  attribute_count: number;
  software_certified_mappings: number;
  external_required_mappings: number;
  vendor_count: number;
  fingerprint: string;
  actor?: string;
  created_at: string;
};

type CiscoFamilyPackPayload = {
  generated_at: string;
  report: {
    schema_version: number;
    feature_id: string;
    release_profile_id: string;
    source_release: string;
    source_sha256: string;
    summary: CiscoFamilyPackSummary;
    vendor_summaries: CiscoFamilyVendorSummary[];
    capability_summaries: CiscoFamilyCapabilitySummary[];
    grammar: CiscoFamilyGrammarRecord[];
    records: CiscoFamilyAttributeRecord[];
    notes?: string[];
  };
  evidence: {
    summary: {
      total_events: number;
      recorded_count: number;
      blocked_count: number;
      failed_count: number;
      last_event_at?: string;
      last_fingerprint?: string;
    };
    recent_events?: CiscoFamilyPackEvent[];
  };
  release_scope: string;
  release_certification_checklist: string;
};

type ArubaFamilyPackSummary = CiscoFamilyPackSummary & {
  sensitive_redacted_mappings: number;
};

type ArubaFamilyVendorSummary = CiscoFamilyVendorSummary & {
  sensitive_redacted_mappings: number;
};

type ArubaFamilyCapabilitySummary = CiscoFamilyCapabilitySummary & {
  sensitive_redacted_mappings: number;
};

type ArubaFamilyGrammarRecord = CiscoFamilyGrammarRecord;
type ArubaFamilyAttributeRecord = CiscoFamilyAttributeRecord;
type ArubaFamilyPackEvent = CiscoFamilyPackEvent;

type ArubaFamilyPackPayload = {
  generated_at: string;
  report: {
    schema_version: number;
    feature_id: string;
    release_profile_id: string;
    source_release: string;
    source_sha256: string;
    summary: ArubaFamilyPackSummary;
    vendor_summaries: ArubaFamilyVendorSummary[];
    capability_summaries: ArubaFamilyCapabilitySummary[];
    grammar: ArubaFamilyGrammarRecord[];
    records: ArubaFamilyAttributeRecord[];
    notes?: string[];
  };
  evidence: {
    summary: {
      total_events: number;
      recorded_count: number;
      blocked_count: number;
      failed_count: number;
      last_event_at?: string;
      last_fingerprint?: string;
    };
    recent_events?: ArubaFamilyPackEvent[];
  };
  release_scope: string;
  release_certification_checklist: string;
};

type JuniperExtremePackSummary = ArubaFamilyPackSummary & {
  product_scope_count: number;
};

type JuniperExtremeVendorSummary = ArubaFamilyVendorSummary;
type JuniperExtremeCapabilitySummary = ArubaFamilyCapabilitySummary;
type JuniperExtremeGrammarRecord = ArubaFamilyGrammarRecord;
type JuniperExtremeAttributeRecord = ArubaFamilyAttributeRecord;

type JuniperExtremeProductScope = {
  key: string;
  label: string;
  vendors: string[];
  products: string[];
  dictionary: string;
  software_state: string;
  external_state: string;
  notes?: string[];
};

type JuniperExtremePackEvent = ArubaFamilyPackEvent & {
  product_scope_count?: number;
};

type JuniperExtremePackPayload = {
  generated_at: string;
  report: {
    schema_version: number;
    feature_id: string;
    release_profile_id: string;
    source_release: string;
    source_sha256: string;
    summary: JuniperExtremePackSummary;
    vendor_summaries: JuniperExtremeVendorSummary[];
    capability_summaries: JuniperExtremeCapabilitySummary[];
    product_scopes: JuniperExtremeProductScope[];
    grammar: JuniperExtremeGrammarRecord[];
    records: JuniperExtremeAttributeRecord[];
    notes?: string[];
  };
  evidence: {
    summary: {
      total_events: number;
      recorded_count: number;
      blocked_count: number;
      failed_count: number;
      last_event_at?: string;
      last_fingerprint?: string;
      last_product_scope_count?: number;
    };
    recent_events?: JuniperExtremePackEvent[];
  };
  release_scope: string;
  release_certification_checklist: string;
};

type RuckusICXPackSummary = JuniperExtremePackSummary;
type RuckusICXVendorSummary = JuniperExtremeVendorSummary;
type RuckusICXCapabilitySummary = JuniperExtremeCapabilitySummary;
type RuckusICXGrammarRecord = JuniperExtremeGrammarRecord;
type RuckusICXAttributeRecord = JuniperExtremeAttributeRecord;
type RuckusICXProductScope = JuniperExtremeProductScope;
type RuckusICXPackEvent = JuniperExtremePackEvent;

type RuckusICXPackPayload = {
  generated_at: string;
  report: {
    schema_version: number;
    feature_id: string;
    release_profile_id: string;
    source_release: string;
    source_sha256: string;
    summary: RuckusICXPackSummary;
    vendor_summaries: RuckusICXVendorSummary[];
    capability_summaries: RuckusICXCapabilitySummary[];
    product_scopes: RuckusICXProductScope[];
    grammar: RuckusICXGrammarRecord[];
    records: RuckusICXAttributeRecord[];
    notes?: string[];
  };
  evidence: {
    summary: {
      total_events: number;
      recorded_count: number;
      blocked_count: number;
      failed_count: number;
      last_event_at?: string;
      last_fingerprint?: string;
      last_product_scope_count?: number;
    };
    recent_events?: RuckusICXPackEvent[];
  };
  release_scope: string;
  release_certification_checklist: string;
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
  dictionary_release_profile?: DictionaryReleaseProfile;
  evidence?: CompatibilityEvidencePayload;
  client_profiles?: VendorClientProfile[];
  profile_summary?: VendorProfileSummary;
  dictionary_coverage?: VendorDictionaryCoverage;
  semantics?: VendorSemanticCapability[];
  notes?: string[];
};

type AttributeRegistryEntry = {
  key: string;
  source: string;
  release_profile_id?: string;
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
  semantic_provenance?: string;
  directions?: string[];
  decode_kind?: string;
};

type AttributeRegistryPayload = {
  schema_version: number;
  release_profile_id: string;
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

type VSACodecFormat = {
  type_octets: number;
  length_octets: number;
};

type VSACodecSummary = {
  source_attribute_count: number;
  runtime_decoder_count: number;
  numeric_attribute_count: number;
  oid_attribute_count: number;
  grouped_attribute_count: number;
  repeated_attribute_count: number;
  tagged_attribute_count: number;
  catalog_vendor_count: number;
  formatted_vendor_count: number;
};

type VSACodecLimits = {
  max_radius_packet_bytes: number;
  max_vendor_specific_value_bytes: number;
  max_default_vendor_value_bytes: number;
  max_grouped_depth: number;
  max_decoded_attributes: number;
  max_repeated_values_per_type: number;
  supported_type_octets_max: number;
  supported_length_octets_max: number;
};

type VSACodecPayload = {
  schema_version: number;
  release_profile_id: string;
  source_release: string;
  source_sha256: string;
  status: string;
  summary: VSACodecSummary;
  limits: VSACodecLimits;
  supported_formats: VSACodecFormat[];
  notes?: string[];
};

type OpaquePassThroughRule = {
  direction: string;
  kind: string;
  vendor_id?: number;
  type?: number;
  max_attribute_bytes?: number;
  allow_known?: boolean;
  description?: string;
};

type OpaquePassThroughLimits = {
  max_radius_packet_bytes: number;
  max_attributes_per_packet: number;
  max_attribute_bytes: number;
  max_total_bytes_per_packet: number;
  max_vendor_specific_bytes: number;
  max_standard_value_bytes: number;
  max_replay_records_per_call: number;
};

type OpaquePassThroughPolicy = {
  schema_version: number;
  enabled: boolean;
  default_action: string;
  limits: OpaquePassThroughLimits;
  rules: OpaquePassThroughRule[];
  notes?: string[];
};

type OpaquePassThroughSummary = {
  source_attribute_count: number;
  runtime_decoder_count: number;
  rule_count: number;
  allowed_standard_type_count: number;
  allowed_vendor_count: number;
  allowed_vendor_attribute_count: number;
  registry_missing_attribute_count: number;
  registry_partial_attribute_count: number;
  default_action_drop: boolean;
};

type OpaqueStandardTypeDeny = {
  type: number;
  name: string;
  reason: string;
};

type OpaquePassThroughPayload = {
  schema_version: number;
  release_profile_id: string;
  source_release: string;
  source_sha256: string;
  status: string;
  policy: OpaquePassThroughPolicy;
  summary: OpaquePassThroughSummary;
  limits: OpaquePassThroughLimits;
  sensitive_types: OpaqueStandardTypeDeny[];
  notes?: string[];
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
  compiler_status?: string;
  compiler_version?: string;
  certification_state?: string;
  external_certification_required?: boolean;
  artifact_fingerprint?: string;
  lossless?: boolean;
  decompile_supported?: boolean;
  diagnostics?: Array<{
    severity: string;
    code: string;
    path?: string;
    message: string;
  }>;
  limits?: {
    max_rules: number;
    max_attributes: number;
    max_attribute_value_bytes: number;
    supports_line_rules: boolean;
    supports_profile: boolean;
    supports_decompile: boolean;
  };
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

function formatPercent(value?: number) {
  if (value === undefined || Number.isNaN(value)) {
    return '0%';
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)}%`;
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

function evidenceTone(state: string): 'green' | 'amber' | 'gray' {
  switch (state) {
    case 'ready':
    case 'software_ready':
      return 'green';
    case 'blocked':
    case 'software_ready_external_required':
    case 'external_required':
    case 'planned':
      return 'amber';
    default:
      return 'gray';
  }
}

function evidenceLabel(state: string) {
  return state.replace(/_/g, ' ') || 'unknown';
}

function aclExportModeLabel(mode: string) {
  switch (mode) {
    case 'line_rules':
    case 'rules':
      return 'Line rules';
    case 'profile_reference':
    case 'profile':
      return 'Profile hint';
    case 'mixed':
      return 'Profile + rules';
    default:
      return mode || 'ACL intent';
  }
}

function aclCompilerTone(status?: string): 'green' | 'amber' | 'gray' {
  switch (status) {
    case 'compiled':
    case 'ready':
      return 'green';
    case 'profile_reference':
    case 'degraded':
    case 'blocked':
    case 'unsupported':
      return 'amber';
    default:
      return 'gray';
  }
}

function aclCompilerLabel(status?: string) {
  return (status || 'not compiled').replace(/_/g, ' ');
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
  const [compatibilityEvidence, setCompatibilityEvidence] = useState<CompatibilityEvidencePayload | null>(null);
  const [compatibilityEvidenceBusy, setCompatibilityEvidenceBusy] = useState(false);
  const [compatibilityEvidenceError, setCompatibilityEvidenceError] = useState('');
  const [compatibilityEvidenceFilters, setCompatibilityEvidenceFilters] = useState({ search: '', claim: '' });
  const [mappingCertification, setMappingCertification] = useState<VendorMappingCertificationPayload | null>(null);
  const [mappingCertificationBusy, setMappingCertificationBusy] = useState(false);
  const [mappingCertificationError, setMappingCertificationError] = useState('');
  const [ciscoFamilyPack, setCiscoFamilyPack] = useState<CiscoFamilyPackPayload | null>(null);
  const [ciscoFamilyPackBusy, setCiscoFamilyPackBusy] = useState(false);
  const [ciscoFamilyPackError, setCiscoFamilyPackError] = useState('');
  const [arubaFamilyPack, setArubaFamilyPack] = useState<ArubaFamilyPackPayload | null>(null);
  const [arubaFamilyPackBusy, setArubaFamilyPackBusy] = useState(false);
  const [arubaFamilyPackError, setArubaFamilyPackError] = useState('');
  const [juniperExtremePack, setJuniperExtremePack] = useState<JuniperExtremePackPayload | null>(null);
  const [juniperExtremePackBusy, setJuniperExtremePackBusy] = useState(false);
  const [juniperExtremePackError, setJuniperExtremePackError] = useState('');
  const [ruckusICXPack, setRuckusICXPack] = useState<RuckusICXPackPayload | null>(null);
  const [ruckusICXPackBusy, setRuckusICXPackBusy] = useState(false);
  const [ruckusICXPackError, setRuckusICXPackError] = useState('');
  const [vsaCodec, setVSACodec] = useState<VSACodecPayload | null>(null);
  const [vsaCodecError, setVSACodecError] = useState('');
  const [opaquePassThrough, setOpaquePassThrough] = useState<OpaquePassThroughPayload | null>(null);
  const [opaquePassThroughError, setOpaquePassThroughError] = useState('');

  const canManageIdentity = identity?.role === 'super_admin';
  const canRecordMappingCertification = identity?.role === 'super_admin' || identity?.role === 'ops_admin';
  const canRecordCiscoFamilyPack = identity?.role === 'super_admin' || identity?.role === 'ops_admin';
  const canRecordArubaFamilyPack = identity?.role === 'super_admin' || identity?.role === 'ops_admin';
  const canRecordJuniperExtremePack = identity?.role === 'super_admin' || identity?.role === 'ops_admin';
  const canRecordRuckusICXPack = identity?.role === 'super_admin' || identity?.role === 'ops_admin';

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

  const fetchCompatibilityEvidence = async (append = false) => {
    setCompatibilityEvidenceBusy(true);
    setCompatibilityEvidenceError('');
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (compatibilityEvidenceFilters.search.trim()) params.set('search', compatibilityEvidenceFilters.search.trim());
      if (compatibilityEvidenceFilters.claim) params.set('claim', compatibilityEvidenceFilters.claim);
      if (append && compatibilityEvidence?.next_cursor) params.set('cursor', compatibilityEvidence.next_cursor);
      const { data } = await api.get<CompatibilityEvidencePayload>(`/system/compatibility-evidence?${params.toString()}`);
      setCompatibilityEvidence((current) => append && current
        ? { ...data, records: [...current.records, ...data.records] }
        : data);
    } catch (err: any) {
      setCompatibilityEvidenceError(apiErrorMessage(err, 'Could not load compatibility evidence.'));
    } finally {
      setCompatibilityEvidenceBusy(false);
    }
  };

  const fetchMappingCertification = async () => {
    setMappingCertificationError('');
    try {
      const { data } = await api.get<VendorMappingCertificationPayload>('/system/vendor-mapping-certification?history_limit=5');
      setMappingCertification(data);
    } catch (err: any) {
      setMappingCertificationError(apiErrorMessage(err, 'Could not load NAS-0060 mapping certification.'));
    }
  };

  const recordMappingCertification = async () => {
    setMappingCertificationBusy(true);
    setMappingCertificationError('');
    setMessage('');
    try {
      await api.post('/system/vendor-mapping-certification/record', {});
      setMessage('NAS-0060 mapping certification event recorded.');
      await fetchMappingCertification();
    } catch (err: any) {
      setMappingCertificationError(apiErrorMessage(err, 'Could not record NAS-0060 mapping certification.'));
    } finally {
      setMappingCertificationBusy(false);
    }
  };

  const fetchCiscoFamilyPack = async () => {
    setCiscoFamilyPackError('');
    try {
      const { data } = await api.get<CiscoFamilyPackPayload>('/system/cisco-family-pack?history_limit=5');
      setCiscoFamilyPack(data);
    } catch (err: any) {
      setCiscoFamilyPackError(apiErrorMessage(err, 'Could not load NAS-0061 Cisco family pack.'));
    }
  };

  const recordCiscoFamilyPack = async () => {
    setCiscoFamilyPackBusy(true);
    setCiscoFamilyPackError('');
    setMessage('');
    try {
      await api.post('/system/cisco-family-pack/record', {});
      setMessage('NAS-0061 Cisco family pack event recorded.');
      await fetchCiscoFamilyPack();
    } catch (err: any) {
      setCiscoFamilyPackError(apiErrorMessage(err, 'Could not record NAS-0061 Cisco family pack.'));
    } finally {
      setCiscoFamilyPackBusy(false);
    }
  };

  const fetchArubaFamilyPack = async () => {
    setArubaFamilyPackError('');
    try {
      const { data } = await api.get<ArubaFamilyPackPayload>('/system/aruba-family-pack?history_limit=5');
      setArubaFamilyPack(data);
    } catch (err: any) {
      setArubaFamilyPackError(apiErrorMessage(err, 'Could not load NAS-0062 Aruba/HPE family pack.'));
    }
  };

  const recordArubaFamilyPack = async () => {
    setArubaFamilyPackBusy(true);
    setArubaFamilyPackError('');
    setMessage('');
    try {
      await api.post('/system/aruba-family-pack/record', {});
      setMessage('NAS-0062 Aruba/HPE family pack event recorded.');
      await fetchArubaFamilyPack();
    } catch (err: any) {
      setArubaFamilyPackError(apiErrorMessage(err, 'Could not record NAS-0062 Aruba/HPE family pack.'));
    } finally {
      setArubaFamilyPackBusy(false);
    }
  };

  const fetchJuniperExtremePack = async () => {
    setJuniperExtremePackError('');
    try {
      const { data } = await api.get<JuniperExtremePackPayload>('/system/juniper-extreme-pack?history_limit=5');
      setJuniperExtremePack(data);
    } catch (err: any) {
      setJuniperExtremePackError(apiErrorMessage(err, 'Could not load NAS-0063 Juniper/ERX/Extreme/Mist pack.'));
    }
  };

  const recordJuniperExtremePack = async () => {
    setJuniperExtremePackBusy(true);
    setJuniperExtremePackError('');
    setMessage('');
    try {
      await api.post('/system/juniper-extreme-pack/record', {});
      setMessage('NAS-0063 Juniper/ERX/Extreme/Mist pack event recorded.');
      await fetchJuniperExtremePack();
    } catch (err: any) {
      setJuniperExtremePackError(apiErrorMessage(err, 'Could not record NAS-0063 Juniper/ERX/Extreme/Mist pack.'));
    } finally {
      setJuniperExtremePackBusy(false);
    }
  };

  const fetchRuckusICXPack = async () => {
    setRuckusICXPackError('');
    try {
      const { data } = await api.get<RuckusICXPackPayload>('/system/ruckus-icx-pack?history_limit=5');
      setRuckusICXPack(data);
    } catch (err: any) {
      setRuckusICXPackError(apiErrorMessage(err, 'Could not load NAS-0064 Ruckus/ICX pack.'));
    }
  };

  const recordRuckusICXPack = async () => {
    setRuckusICXPackBusy(true);
    setRuckusICXPackError('');
    setMessage('');
    try {
      await api.post('/system/ruckus-icx-pack/record', {});
      setMessage('NAS-0064 Ruckus/ICX pack event recorded.');
      await fetchRuckusICXPack();
    } catch (err: any) {
      setRuckusICXPackError(apiErrorMessage(err, 'Could not record NAS-0064 Ruckus/ICX pack.'));
    } finally {
      setRuckusICXPackBusy(false);
    }
  };

  const fetchVSACodec = async () => {
    setVSACodecError('');
    try {
      const { data } = await api.get<VSACodecPayload>('/system/vsa-codec');
      setVSACodec(data);
    } catch (err: any) {
      setVSACodecError(apiErrorMessage(err, 'Could not load VSA codec readiness.'));
    }
  };

  const fetchOpaquePassThrough = async () => {
    setOpaquePassThroughError('');
    try {
      const { data } = await api.get<OpaquePassThroughPayload>('/system/opaque-passthrough');
      setOpaquePassThrough(data);
    } catch (err: any) {
      setOpaquePassThroughError(apiErrorMessage(err, 'Could not load opaque pass-through policy.'));
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
    void fetchCompatibilityEvidence(false);
    void fetchMappingCertification();
    void fetchCiscoFamilyPack();
    void fetchArubaFamilyPack();
    void fetchJuniperExtremePack();
    void fetchRuckusICXPack();
    void fetchVSACodec();
    void fetchOpaquePassThrough();
  }, []);

  const clientProfiles = payload?.client_profiles || [];
  const profileSummary = payload?.profile_summary;
  const activePacks = payload?.active_packs || [];
  const packs = payload?.packs || [];
  const dictionaryCoverage = payload?.dictionary_coverage;
  const coverageRows = dictionaryCoverage?.rows || [];
  const releaseProfile = payload?.dictionary_release_profile;
  const firmwareProfiles = releaseProfile?.firmware_profiles || [];
  const vendorAliases = releaseProfile?.vendor_aliases || [];
  const evidenceSummary = compatibilityEvidence?.summary || payload?.evidence?.summary;
  const mappingCertificationSummary = mappingCertification?.report.summary;
  const mappingCertificationComplete = Boolean(mappingCertificationSummary && mappingCertificationSummary.certified_mappings === mappingCertificationSummary.baseline_partial_mappings && mappingCertificationSummary.software_blocked_mappings === 0);
  const mappingCertificationRecords = mappingCertification?.report.records || [];
  const mappingCertificationVendors = mappingCertification?.report.vendor_summaries || [];
  const ciscoFamilyPackSummary = ciscoFamilyPack?.report.summary;
  const ciscoFamilyPackComplete = Boolean(ciscoFamilyPackSummary && ciscoFamilyPackSummary.software_certified_mappings === ciscoFamilyPackSummary.attribute_count && ciscoFamilyPackSummary.software_blocked_mappings === 0);
  const ciscoFamilyPackRecords = ciscoFamilyPack?.report.records || [];
  const ciscoFamilyPackVendors = ciscoFamilyPack?.report.vendor_summaries || [];
  const ciscoFamilyPackCapabilities = ciscoFamilyPack?.report.capability_summaries || [];
  const ciscoFamilyPackGrammar = ciscoFamilyPack?.report.grammar || [];
  const arubaFamilyPackSummary = arubaFamilyPack?.report.summary;
  const arubaFamilyPackComplete = Boolean(arubaFamilyPackSummary && arubaFamilyPackSummary.software_certified_mappings === arubaFamilyPackSummary.attribute_count && arubaFamilyPackSummary.software_blocked_mappings === 0);
  const arubaFamilyPackRecords = arubaFamilyPack?.report.records || [];
  const arubaFamilyPackVendors = arubaFamilyPack?.report.vendor_summaries || [];
  const arubaFamilyPackCapabilities = arubaFamilyPack?.report.capability_summaries || [];
  const arubaFamilyPackGrammar = arubaFamilyPack?.report.grammar || [];
  const juniperExtremePackSummary = juniperExtremePack?.report.summary;
  const juniperExtremePackComplete = Boolean(juniperExtremePackSummary && juniperExtremePackSummary.software_certified_mappings === juniperExtremePackSummary.attribute_count && juniperExtremePackSummary.software_blocked_mappings === 0);
  const juniperExtremePackRecords = juniperExtremePack?.report.records || [];
  const juniperExtremePackVendors = juniperExtremePack?.report.vendor_summaries || [];
  const juniperExtremePackCapabilities = juniperExtremePack?.report.capability_summaries || [];
  const juniperExtremePackGrammar = juniperExtremePack?.report.grammar || [];
  const juniperExtremeProductScopes = juniperExtremePack?.report.product_scopes || [];
  const ruckusICXPackSummary = ruckusICXPack?.report.summary;
  const ruckusICXPackComplete = Boolean(ruckusICXPackSummary && ruckusICXPackSummary.software_certified_mappings === ruckusICXPackSummary.attribute_count && ruckusICXPackSummary.software_blocked_mappings === 0);
  const ruckusICXPackRecords = ruckusICXPack?.report.records || [];
  const ruckusICXPackVendors = ruckusICXPack?.report.vendor_summaries || [];
  const ruckusICXPackCapabilities = ruckusICXPack?.report.capability_summaries || [];
  const ruckusICXPackGrammar = ruckusICXPack?.report.grammar || [];
  const ruckusICXProductScopes = ruckusICXPack?.report.product_scopes || [];
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
          onClick={() => { void fetchCompatibility(true); void fetchVendorIdentity(); void fetchAttributeRegistry(false); void fetchCompatibilityEvidence(false); void fetchMappingCertification(); void fetchCiscoFamilyPack(); void fetchArubaFamilyPack(); void fetchJuniperExtremePack(); void fetchRuckusICXPack(); void fetchVSACodec(); void fetchOpaquePassThrough(); }}
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
                <h3 className="text-lg font-semibold text-gray-900">VSA Codec</h3>
                <p className="mt-1 text-sm text-gray-600">Decode and encode vendor attributes without losing repeated values, grouped OIDs, tags, malformed-length evidence, or release provenance.</p>
              </div>
              {vsaCodec ? <StatusBadge tone={vsaCodec.status === 'ready' ? 'green' : 'amber'}>Codec schema {vsaCodec.schema_version}</StatusBadge> : null}
            </div>
            {vsaCodecError ? <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{vsaCodecError}</div> : null}
            {vsaCodec ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Codec Status" value={vsaCodec.status} hint={`${vsaCodec.summary.runtime_decoder_count} runtime decoders.`} />
                  <StatCard label="Grouped OIDs" value={vsaCodec.summary.grouped_attribute_count} hint={`${vsaCodec.summary.oid_attribute_count} OID-backed attributes.`} />
                  <StatCard label="Repeated Values" value={vsaCodec.summary.repeated_attribute_count} hint={`${vsaCodec.limits.max_repeated_values_per_type} per wire type budget.`} />
                  <StatCard label="Value Limit" value={vsaCodec.limits.max_default_vendor_value_bytes} hint={`${vsaCodec.limits.max_vendor_specific_value_bytes} bytes per vendor payload.`} />
                </div>
                <div className="mt-4 grid gap-4 xl:grid-cols-2">
                  <div className="rounded-md border border-gray-200 p-4">
                    <h4 className="text-sm font-semibold uppercase text-gray-600">Supported Formats</h4>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {vsaCodec.supported_formats.map((format) => (
                        <span key={`${format.type_octets}-${format.length_octets}`} className="rounded-md border border-gray-300 px-3 py-1 text-sm text-gray-700">
                          type {format.type_octets} / length {format.length_octets}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-md border border-gray-200 p-4">
                    <h4 className="text-sm font-semibold uppercase text-gray-600">Codec Limits</h4>
                    <div className="mt-3 grid gap-2 text-sm text-gray-700 sm:grid-cols-2">
                      <div>Packet bytes: {vsaCodec.limits.max_radius_packet_bytes}</div>
                      <div>Grouped depth: {vsaCodec.limits.max_grouped_depth}</div>
                      <div>Decoded attrs: {vsaCodec.limits.max_decoded_attributes}</div>
                      <div>Catalog vendors: {vsaCodec.summary.catalog_vendor_count}</div>
                    </div>
                  </div>
                </div>
                {vsaCodec.notes?.length ? <p className="mt-2 text-xs text-gray-500">{vsaCodec.notes[0]}</p> : null}
                <p className="mt-2 break-all text-xs text-gray-500">Codec source SHA-256: {vsaCodec.source_sha256}</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">NAS-0064 Ruckus/ICX Pack</h3>
                <p className="mt-1 text-sm text-gray-600">Certify Ruckus SmartZone, ZoneDirector, Unleashed, Ruckus One, and ICX software handling while hardware proof stays in release certification.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {ruckusICXPackSummary ? (
                  <StatusBadge tone={ruckusICXPackComplete ? 'green' : 'amber'}>
                    {formatPercent(ruckusICXPackSummary.software_completion_percent)} software
                  </StatusBadge>
                ) : null}
                {canRecordRuckusICXPack ? (
                  <button
                    type="button"
                    onClick={() => void recordRuckusICXPack()}
                    disabled={ruckusICXPackBusy || !ruckusICXPackComplete}
                    className="rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                  >
                    {ruckusICXPackBusy ? 'Recording...' : 'Record Evidence'}
                  </button>
                ) : null}
              </div>
            </div>

            {ruckusICXPackError ? <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{ruckusICXPackError}</div> : null}
            {ruckusICXPackSummary ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Ruckus/ICX Rows" value={ruckusICXPackSummary.attribute_count} hint="Pinned FreeRADIUS 3.2.8 Ruckus and Foundry rows." />
                  <StatCard label="Software Certified" value={ruckusICXPackSummary.software_certified_mappings} hint={`${ruckusICXPackSummary.software_blocked_mappings} software blockers.`} />
                  <StatCard label="Dictionary Vendors" value={ruckusICXPackSummary.vendor_count} hint={`${ruckusICXPackSummary.native_semantic_mappings} native semantic mappings.`} />
                  <StatCard label="Product Scopes" value={ruckusICXPackSummary.product_scope_count} hint="SmartZone, ZoneDirector, Unleashed, Ruckus One, and ICX." />
                  <StatCard label="Policy Grammar" value={ruckusICXPackSummary.grammar_rule_count} hint="FlexAuth, DPSK, WLAN, QoS, guest, and ICX rules." />
                  <StatCard label="Secret Redaction" value={ruckusICXPackSummary.sensitive_redacted_mappings} hint="DPSK, EAPOL, and subscriber identifiers." />
                  <StatCard label="Storage Events" value={ruckusICXPack?.evidence.summary.total_events || 0} hint={ruckusICXPack?.evidence.summary.last_event_at ? `Last ${new Date(ruckusICXPack.evidence.summary.last_event_at).toLocaleString()}` : 'No persisted event yet.'} />
                  <StatCard label="Ready For Lab" value={ruckusICXPackSummary.ready_for_external_validation_mappings} hint="Software-ready rows awaiting release proof." />
                </div>

                <div className="mt-4 rounded-md border border-gray-200 p-4">
                  <div className="text-xs font-semibold uppercase text-gray-500">Ruckus/ICX Fingerprint</div>
                  <div className="mt-2 break-all text-sm font-medium text-gray-900">{ruckusICXPackSummary.fingerprint}</div>
                  <p className="mt-2 text-sm text-gray-600">{ruckusICXPack?.release_scope}</p>
                </div>

                <div className="mt-4 grid gap-4 xl:grid-cols-4">
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Vendor', 'Rows', 'State'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {ruckusICXPackVendors.map((vendor) => (
                          <tr key={`${vendor.vendor}-${vendor.pen}`}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{vendor.vendor}<div className="text-xs text-gray-500">PEN {vendor.pen}{vendor.pack_key ? ` / ${vendor.pack_key}` : ''}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{vendor.software_certified_mappings}/{vendor.attribute_count}<div className="text-xs text-gray-500">{vendor.sensitive_redacted_mappings} redacted</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{formatPercent(vendor.software_completion_percent)}</StatusBadge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Product Scope', 'Dictionary', 'State'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {ruckusICXProductScopes.map((scope) => (
                          <tr key={`${scope.key}-${scope.label}`}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{scope.label}<div className="text-xs text-gray-500">{joinList(scope.products)}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{scope.dictionary}<div className="text-xs text-gray-500">{joinList(scope.vendors)}</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{evidenceLabel(scope.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{evidenceLabel(scope.external_state)}</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Capability', 'Rows', 'Mapping'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {ruckusICXPackCapabilities.slice(0, 8).map((capability) => (
                          <tr key={capability.capability}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{evidenceLabel(capability.capability)}</td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.software_certified_mappings}/{capability.attribute_count}<div className="text-xs text-gray-500">{capability.external_required_mappings} external</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.native_semantic_mappings} native<div className="text-xs text-gray-500">{capability.sensitive_redacted_mappings} redacted</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Grammar', 'State', 'Example'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {ruckusICXPackGrammar.slice(0, 8).map((grammar) => (
                          <tr key={grammar.key}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{grammar.label}<div className="text-xs text-gray-500">{grammar.kind}</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{grammar.parser_state}</StatusBadge><div className="mt-1 text-xs text-gray-500">{grammar.external_state}</div></td>
                            <td className="px-4 py-3 text-xs text-gray-700">{grammar.examples?.[0] || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50"><tr>{['Attribute', 'Capability', 'Software', 'Handling'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                    <tbody className="divide-y divide-gray-200">
                      {ruckusICXPackRecords.slice(0, 10).map((record) => (
                        <tr key={record.id}>
                          <td className="px-4 py-3 text-sm font-medium text-gray-900">{record.attribute}<div className="text-xs text-gray-500">{record.vendor} / {record.wire_key}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.capability)}<div className="text-xs text-gray-500">{joinList(record.directions)}</div></td>
                          <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{evidenceLabel(record.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{record.claim_state}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.implementation_class)}<div className="text-xs text-gray-500">{evidenceLabel(record.packet_processing)}</div></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-xs text-gray-500">{ruckusICXPack?.release_certification_checklist} keeps Ruckus controllers, ICX/FastIron, FreeRADIUS Linux, HA, performance, and customer proof outside engineering completion.</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Opaque Pass-through</h3>
                <p className="mt-1 text-sm text-gray-600">Preserve unknown RADIUS attributes only when an explicit bounded rule allows the value through.</p>
              </div>
              {opaquePassThrough ? (
                <StatusBadge tone={opaquePassThrough.status === 'ready' && opaquePassThrough.summary.default_action_drop ? 'green' : 'amber'}>
                  Policy schema {opaquePassThrough.schema_version}
                </StatusBadge>
              ) : null}
            </div>
            {opaquePassThroughError ? <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{opaquePassThroughError}</div> : null}
            {opaquePassThrough ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Policy Status" value={opaquePassThrough.status} hint={opaquePassThrough.policy.enabled ? 'Configured policy is active.' : 'Pass-through collection is disabled.'} />
                  <StatCard label="Default Action" value={opaquePassThrough.policy.default_action} hint={opaquePassThrough.summary.default_action_drop ? 'Unknown attributes drop unless allowed.' : 'Review policy before proxy use.'} />
                  <StatCard label="Allow Rules" value={opaquePassThrough.summary.rule_count} hint={`${opaquePassThrough.summary.allowed_vendor_attribute_count} exact VSAs, ${opaquePassThrough.summary.allowed_vendor_count} vendors.`} />
                  <StatCard label="Total Budget" value={opaquePassThrough.limits.max_total_bytes_per_packet} hint={`${opaquePassThrough.limits.max_attributes_per_packet} attributes per packet.`} />
                </div>
                <div className="mt-4 grid gap-4 xl:grid-cols-2">
                  <div className="rounded-md border border-gray-200 p-4">
                    <h4 className="text-sm font-semibold uppercase text-gray-600">Effective Rules</h4>
                    <div className="mt-3 space-y-2">
                      {(opaquePassThrough.policy.rules || []).length === 0 ? (
                        <div className="text-sm text-gray-500">No opaque attributes are allowed by the current policy.</div>
                      ) : (
                        opaquePassThrough.policy.rules.map((rule, index) => (
                          <div key={`${rule.direction}-${rule.kind}-${rule.vendor_id || 0}-${rule.type || 0}-${index}`} className="rounded-md border border-gray-200 px-3 py-2 text-sm text-gray-700">
                            <div className="font-medium text-gray-900">{rule.direction || 'any'} / {rule.kind}</div>
                            <div className="mt-1">
                              {rule.vendor_id ? `Vendor ${rule.vendor_id}` : 'Standard RADIUS'}
                              {rule.type ? ` / type ${rule.type}` : ''}
                              {rule.allow_known ? ' / known allowed' : ''}
                            </div>
                            {rule.description ? <div className="mt-1 text-xs text-gray-500">{rule.description}</div> : null}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                  <div className="rounded-md border border-gray-200 p-4">
                    <h4 className="text-sm font-semibold uppercase text-gray-600">Safety Bounds</h4>
                    <div className="mt-3 grid gap-2 text-sm text-gray-700 sm:grid-cols-2">
                      <div>Attribute bytes: {opaquePassThrough.limits.max_attribute_bytes}</div>
                      <div>VSA bytes: {opaquePassThrough.limits.max_vendor_specific_bytes}</div>
                      <div>Standard bytes: {opaquePassThrough.limits.max_standard_value_bytes}</div>
                      <div>Replay records: {opaquePassThrough.limits.max_replay_records_per_call}</div>
                    </div>
                    <div className="mt-4">
                      <h5 className="text-xs font-semibold uppercase text-gray-500">Never Opaque</h5>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {(opaquePassThrough.sensitive_types || []).map((item) => (
                          <span key={item.type} className="rounded-md bg-gray-100 px-2 py-1 text-xs text-gray-700">{item.name}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                {opaquePassThrough.notes?.length ? <p className="mt-2 text-xs text-gray-500">{opaquePassThrough.notes[0]}</p> : null}
                <p className="mt-2 break-all text-xs text-gray-500">Pass-through source SHA-256: {opaquePassThrough.source_sha256}</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Compatibility Evidence</h3>
                <p className="mt-1 text-sm text-gray-600">Separate software readiness from dictionary metadata, packet coverage, policy wiring, reply rendering, and external certification.</p>
              </div>
              {compatibilityEvidence ? <StatusBadge tone="green">Evidence schema {compatibilityEvidence.schema_version}</StatusBadge> : null}
            </div>

            {evidenceSummary ? (
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <StatCard label="Evidence Records" value={evidenceSummary.total_records} hint={`${evidenceSummary.software_ready_count} software ready.`} />
                <StatCard label="Planned" value={evidenceSummary.software_planned_count} hint={`${evidenceSummary.metadata_only_count} metadata only.`} />
                <StatCard label="Blocked" value={evidenceSummary.software_blocked_count} hint="Usually missing dictionary, registry, or decoder evidence." />
                <StatCard label="External Required" value={evidenceSummary.external_required_count} hint={`${evidenceSummary.externally_certified_count} certified in software ledger.`} />
              </div>
            ) : null}

            <form className="mt-4 grid gap-3 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_auto]" onSubmit={(event) => { event.preventDefault(); void fetchCompatibilityEvidence(false); }}>
              <label className="text-sm font-medium text-gray-700">Search
                <input value={compatibilityEvidenceFilters.search} onChange={(event) => setCompatibilityEvidenceFilters((current) => ({ ...current, search: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2" placeholder="Pack, vendor, attribute, semantic" />
              </label>
              <label className="text-sm font-medium text-gray-700">Claim
                <select value={compatibilityEvidenceFilters.claim} onChange={(event) => setCompatibilityEvidenceFilters((current) => ({ ...current, claim: event.target.value }))} className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2">
                  <option value="">All claims</option>
                  <option value="software_ready">Software ready</option>
                  <option value="software_ready_external_required">Software ready, external required</option>
                  <option value="planned">Planned</option>
                  <option value="blocked">Blocked</option>
                  <option value="metadata_only">Metadata only</option>
                </select>
              </label>
              <button type="submit" disabled={compatibilityEvidenceBusy} className="self-end rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">{compatibilityEvidenceBusy ? 'Loading...' : 'Filter'}</button>
            </form>

            {compatibilityEvidenceError ? <div className="mt-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{compatibilityEvidenceError}</div> : null}
            {compatibilityEvidence ? (
              <>
                <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50"><tr>{['Pack / Attribute', 'Software', 'Certification', 'Evidence'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                    <tbody className="divide-y divide-gray-200">
                      {compatibilityEvidence.records.map((record) => (
                        <tr key={record.id}>
                          <td className="px-4 py-3 text-sm"><div className="font-medium text-gray-900">{record.attribute || record.semantic}</div><div className="text-xs text-gray-500">{record.pack_key || 'semantic'}{record.active ? ' / active' : ''}</div></td>
                          <td className="px-4 py-3 text-sm"><StatusBadge tone={evidenceTone(record.software_state)}>{evidenceLabel(record.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{evidenceLabel(record.claim_state)}</div></td>
                          <td className="px-4 py-3 text-sm"><StatusBadge tone={evidenceTone(record.certification_state)}>{evidenceLabel(record.certification_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{record.ready_for_external_validation ? 'ready for lab' : 'not lab-ready'}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">
                            {record.dimensions.slice(0, 3).map((dimension) => (
                              <div key={`${record.id}-${dimension.key}`} className="mb-1"><span className="font-medium">{dimension.label}:</span> {evidenceLabel(dimension.state)}</div>
                            ))}
                            {record.blockers?.length ? <div className="text-xs text-amber-700">{record.blockers[0]}</div> : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {compatibilityEvidence.next_cursor ? <button type="button" disabled={compatibilityEvidenceBusy} onClick={() => void fetchCompatibilityEvidence(true)} className="mt-3 rounded-md border border-gray-300 px-4 py-2 text-sm font-semibold text-gray-800 disabled:opacity-50">Load more evidence</button> : null}
                <p className="mt-2 break-all text-xs text-gray-500">Evidence source SHA-256: {compatibilityEvidence.source_sha256}</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">NAS-0060 Mapping Certification</h3>
                <p className="mt-1 text-sm text-gray-600">Certify the 141 audit-source partial mappings in software while keeping vendor hardware proof in the release checklist.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {mappingCertificationSummary ? (
                  <StatusBadge tone={mappingCertificationComplete ? 'green' : 'amber'}>
                    {formatPercent(mappingCertificationSummary.software_completion_percent)} software
                  </StatusBadge>
                ) : null}
                {canRecordMappingCertification ? (
                  <button
                    type="button"
                    onClick={() => void recordMappingCertification()}
                    disabled={mappingCertificationBusy || !mappingCertificationComplete}
                    className="rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                  >
                    {mappingCertificationBusy ? 'Recording...' : 'Record Evidence'}
                  </button>
                ) : null}
              </div>
            </div>

            {mappingCertificationError ? <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{mappingCertificationError}</div> : null}
            {mappingCertificationSummary ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Baseline Rows" value={mappingCertificationSummary.baseline_partial_mappings} hint="Partial mappings from the pinned audit CSV." />
                  <StatCard label="Software Certified" value={mappingCertificationSummary.certified_mappings} hint={`${mappingCertificationSummary.software_blocked_mappings} software blockers.`} />
                  <StatCard label="Vendors" value={mappingCertificationSummary.vendor_count} hint={`${mappingCertificationSummary.current_runtime_mapping_count} runtime registry mappings.`} />
                  <StatCard label="External Scope" value={mappingCertificationSummary.external_required_mappings} hint="Hardware, firmware, HA, performance, and customer evidence." />
                  <StatCard label="Packet Paths" value={mappingCertificationSummary.runtime_decoder_count} hint="Inbound or accounting packet dimensions passed." />
                  <StatCard label="Reply Paths" value={mappingCertificationSummary.reply_renderer_count} hint="Outbound Access-Accept dimensions passed." />
                  <StatCard label="Storage Events" value={mappingCertification?.evidence.summary.total_events || 0} hint={mappingCertification?.evidence.summary.last_event_at ? `Last ${new Date(mappingCertification.evidence.summary.last_event_at).toLocaleString()}` : 'No persisted event yet.'} />
                  <StatCard label="API/UI Rows" value={mappingCertificationSummary.api_ui_wired_count} hint="Operator-visible certification dimensions." />
                </div>

                <div className="mt-4 rounded-md border border-gray-200 p-4">
                  <div className="text-xs font-semibold uppercase text-gray-500">Certification Fingerprint</div>
                  <div className="mt-2 break-all text-sm font-medium text-gray-900">{mappingCertificationSummary.fingerprint}</div>
                  <p className="mt-2 text-sm text-gray-600">{mappingCertification?.release_scope}</p>
                </div>

                <div className="mt-4 grid gap-4 xl:grid-cols-2">
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Vendor', 'Mappings', 'Status'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {mappingCertificationVendors.slice(0, 8).map((vendor) => (
                          <tr key={`${vendor.vendor}-${vendor.pen}`}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{vendor.vendor}<div className="text-xs text-gray-500">PEN {vendor.pen}{vendor.pack_key ? ` / ${vendor.pack_key}` : ''}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{vendor.certified_mappings}/{vendor.baseline_partial_mappings}<div className="text-xs text-gray-500">{vendor.external_required_mappings} external</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone={vendor.software_blocked_mappings === 0 ? 'green' : 'amber'}>{formatPercent(vendor.software_completion_percent)}</StatusBadge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Attribute', 'Software', 'Evidence'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {mappingCertificationRecords.slice(0, 8).map((record) => (
                          <tr key={record.id}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{record.attribute}<div className="text-xs text-gray-500">{record.vendor} / {record.wire_key}</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone={record.software_certified ? 'green' : 'amber'}>{evidenceLabel(record.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{record.primary_semantic}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">
                              {record.dimensions.slice(0, 3).map((dimension) => (
                                <div key={`${record.id}-${dimension.key}`} className="mb-1"><span className="font-medium">{dimension.label}:</span> {evidenceLabel(dimension.state)}</div>
                              ))}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                <p className="mt-2 text-xs text-gray-500">{mappingCertification?.release_certification_checklist} keeps hardware and production release proof outside engineering completion.</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">NAS-0061 Cisco Family Pack</h3>
                <p className="mt-1 text-sm text-gray-600">Certify Cisco, Airespace/WLC, ASA/VPN, Starent, Meraki, and Cisco-AVPair software handling while keeping device proof in the release checklist.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {ciscoFamilyPackSummary ? (
                  <StatusBadge tone={ciscoFamilyPackComplete ? 'green' : 'amber'}>
                    {formatPercent(ciscoFamilyPackSummary.software_completion_percent)} software
                  </StatusBadge>
                ) : null}
                {canRecordCiscoFamilyPack ? (
                  <button
                    type="button"
                    onClick={() => void recordCiscoFamilyPack()}
                    disabled={ciscoFamilyPackBusy || !ciscoFamilyPackComplete}
                    className="rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                  >
                    {ciscoFamilyPackBusy ? 'Recording...' : 'Record Evidence'}
                  </button>
                ) : null}
              </div>
            </div>

            {ciscoFamilyPackError ? <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{ciscoFamilyPackError}</div> : null}
            {ciscoFamilyPackSummary ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Cisco Rows" value={ciscoFamilyPackSummary.attribute_count} hint="Pinned FreeRADIUS 3.2.8 Cisco-family rows." />
                  <StatCard label="Software Certified" value={ciscoFamilyPackSummary.software_certified_mappings} hint={`${ciscoFamilyPackSummary.software_blocked_mappings} software blockers.`} />
                  <StatCard label="Vendors" value={ciscoFamilyPackSummary.vendor_count} hint={`${ciscoFamilyPackSummary.native_semantic_mappings} native semantic mappings.`} />
                  <StatCard label="Typed Pass-Through" value={ciscoFamilyPackSummary.typed_passthrough_mappings} hint="Visible, bounded, not silently enforced." />
                  <StatCard label="AVPair Grammar" value={ciscoFamilyPackSummary.grammar_rule_count} hint="Parser, compiler, inbound, and outbound states." />
                  <StatCard label="External Scope" value={ciscoFamilyPackSummary.external_required_mappings} hint="Hardware, firmware, HA, performance, and customer evidence." />
                  <StatCard label="Storage Events" value={ciscoFamilyPack?.evidence.summary.total_events || 0} hint={ciscoFamilyPack?.evidence.summary.last_event_at ? `Last ${new Date(ciscoFamilyPack.evidence.summary.last_event_at).toLocaleString()}` : 'No persisted event yet.'} />
                  <StatCard label="Ready For Lab" value={ciscoFamilyPackSummary.ready_for_external_validation_mappings} hint="Software-ready rows awaiting release proof." />
                </div>

                <div className="mt-4 rounded-md border border-gray-200 p-4">
                  <div className="text-xs font-semibold uppercase text-gray-500">Cisco Family Fingerprint</div>
                  <div className="mt-2 break-all text-sm font-medium text-gray-900">{ciscoFamilyPackSummary.fingerprint}</div>
                  <p className="mt-2 text-sm text-gray-600">{ciscoFamilyPack?.release_scope}</p>
                </div>

                <div className="mt-4 grid gap-4 xl:grid-cols-3">
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Vendor', 'Rows', 'State'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {ciscoFamilyPackVendors.map((vendor) => (
                          <tr key={`${vendor.vendor}-${vendor.pen}`}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{vendor.vendor}<div className="text-xs text-gray-500">PEN {vendor.pen}{vendor.pack_key ? ` / ${vendor.pack_key}` : ''}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{vendor.software_certified_mappings}/{vendor.attribute_count}<div className="text-xs text-gray-500">{vendor.typed_passthrough_mappings} pass-through</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{formatPercent(vendor.software_completion_percent)}</StatusBadge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Capability', 'Rows', 'Mapping'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {ciscoFamilyPackCapabilities.slice(0, 8).map((capability) => (
                          <tr key={capability.capability}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{evidenceLabel(capability.capability)}</td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.software_certified_mappings}/{capability.attribute_count}<div className="text-xs text-gray-500">{capability.external_required_mappings} external</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.native_semantic_mappings} native<div className="text-xs text-gray-500">{capability.typed_passthrough_mappings} pass-through</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Grammar', 'State', 'Example'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {ciscoFamilyPackGrammar.slice(0, 8).map((grammar) => (
                          <tr key={grammar.key}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{grammar.label}<div className="text-xs text-gray-500">{grammar.kind}</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{grammar.parser_state}</StatusBadge><div className="mt-1 text-xs text-gray-500">{grammar.external_state}</div></td>
                            <td className="px-4 py-3 text-xs text-gray-700">{grammar.examples?.[0] || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50"><tr>{['Attribute', 'Capability', 'Software', 'Handling'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                    <tbody className="divide-y divide-gray-200">
                      {ciscoFamilyPackRecords.slice(0, 10).map((record) => (
                        <tr key={record.id}>
                          <td className="px-4 py-3 text-sm font-medium text-gray-900">{record.attribute}<div className="text-xs text-gray-500">{record.vendor} / {record.wire_key}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.capability)}<div className="text-xs text-gray-500">{joinList(record.directions)}</div></td>
                          <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{evidenceLabel(record.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{record.claim_state}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.implementation_class)}<div className="text-xs text-gray-500">{evidenceLabel(record.packet_processing)}</div></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-xs text-gray-500">{ciscoFamilyPack?.release_certification_checklist} keeps Cisco hardware, firmware, FreeRADIUS Linux, HA, performance, and customer proof outside engineering completion.</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">NAS-0062 Aruba/HPE Family Pack</h3>
                <p className="mt-1 text-sm text-gray-600">Certify Aruba, HP/ArubaOS-Switch, Aerohive/Extreme, Colubris/MSM, policy grammar, and secret redaction while keeping device proof in the release checklist.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {arubaFamilyPackSummary ? (
                  <StatusBadge tone={arubaFamilyPackComplete ? 'green' : 'amber'}>
                    {formatPercent(arubaFamilyPackSummary.software_completion_percent)} software
                  </StatusBadge>
                ) : null}
                {canRecordArubaFamilyPack ? (
                  <button
                    type="button"
                    onClick={() => void recordArubaFamilyPack()}
                    disabled={arubaFamilyPackBusy || !arubaFamilyPackComplete}
                    className="rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                  >
                    {arubaFamilyPackBusy ? 'Recording...' : 'Record Evidence'}
                  </button>
                ) : null}
              </div>
            </div>

            {arubaFamilyPackError ? <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{arubaFamilyPackError}</div> : null}
            {arubaFamilyPackSummary ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Aruba/HPE Rows" value={arubaFamilyPackSummary.attribute_count} hint="Pinned FreeRADIUS 3.2.8 Aruba/HPE-family rows." />
                  <StatCard label="Software Certified" value={arubaFamilyPackSummary.software_certified_mappings} hint={`${arubaFamilyPackSummary.software_blocked_mappings} software blockers.`} />
                  <StatCard label="Vendors" value={arubaFamilyPackSummary.vendor_count} hint={`${arubaFamilyPackSummary.native_semantic_mappings} native semantic mappings.`} />
                  <StatCard label="Typed Pass-Through" value={arubaFamilyPackSummary.typed_passthrough_mappings} hint="Visible, bounded, not silently enforced." />
                  <StatCard label="Policy Grammar" value={arubaFamilyPackSummary.grammar_rule_count} hint="Parser, compiler, inbound, and outbound states." />
                  <StatCard label="Secret Redaction" value={arubaFamilyPackSummary.sensitive_redacted_mappings} hint="MPSK, DPP, PPSK, PMK, and credential material." />
                  <StatCard label="Storage Events" value={arubaFamilyPack?.evidence.summary.total_events || 0} hint={arubaFamilyPack?.evidence.summary.last_event_at ? `Last ${new Date(arubaFamilyPack.evidence.summary.last_event_at).toLocaleString()}` : 'No persisted event yet.'} />
                  <StatCard label="Ready For Lab" value={arubaFamilyPackSummary.ready_for_external_validation_mappings} hint="Software-ready rows awaiting release proof." />
                </div>

                <div className="mt-4 rounded-md border border-gray-200 p-4">
                  <div className="text-xs font-semibold uppercase text-gray-500">Aruba/HPE Family Fingerprint</div>
                  <div className="mt-2 break-all text-sm font-medium text-gray-900">{arubaFamilyPackSummary.fingerprint}</div>
                  <p className="mt-2 text-sm text-gray-600">{arubaFamilyPack?.release_scope}</p>
                </div>

                <div className="mt-4 grid gap-4 xl:grid-cols-3">
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Vendor', 'Rows', 'State'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {arubaFamilyPackVendors.map((vendor) => (
                          <tr key={`${vendor.vendor}-${vendor.pen}`}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{vendor.vendor}<div className="text-xs text-gray-500">PEN {vendor.pen}{vendor.pack_key ? ` / ${vendor.pack_key}` : ''}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{vendor.software_certified_mappings}/{vendor.attribute_count}<div className="text-xs text-gray-500">{vendor.sensitive_redacted_mappings} redacted</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{formatPercent(vendor.software_completion_percent)}</StatusBadge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Capability', 'Rows', 'Mapping'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {arubaFamilyPackCapabilities.slice(0, 8).map((capability) => (
                          <tr key={capability.capability}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{evidenceLabel(capability.capability)}</td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.software_certified_mappings}/{capability.attribute_count}<div className="text-xs text-gray-500">{capability.external_required_mappings} external</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.native_semantic_mappings} native<div className="text-xs text-gray-500">{capability.sensitive_redacted_mappings} redacted</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Grammar', 'State', 'Example'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {arubaFamilyPackGrammar.slice(0, 8).map((grammar) => (
                          <tr key={grammar.key}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{grammar.label}<div className="text-xs text-gray-500">{grammar.kind}</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{grammar.parser_state}</StatusBadge><div className="mt-1 text-xs text-gray-500">{grammar.external_state}</div></td>
                            <td className="px-4 py-3 text-xs text-gray-700">{grammar.examples?.[0] || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50"><tr>{['Attribute', 'Capability', 'Software', 'Handling'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                    <tbody className="divide-y divide-gray-200">
                      {arubaFamilyPackRecords.slice(0, 10).map((record) => (
                        <tr key={record.id}>
                          <td className="px-4 py-3 text-sm font-medium text-gray-900">{record.attribute}<div className="text-xs text-gray-500">{record.vendor} / {record.wire_key}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.capability)}<div className="text-xs text-gray-500">{joinList(record.directions)}</div></td>
                          <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{evidenceLabel(record.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{record.claim_state}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.implementation_class)}<div className="text-xs text-gray-500">{evidenceLabel(record.packet_processing)}</div></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-xs text-gray-500">{arubaFamilyPack?.release_certification_checklist} keeps Aruba/HPE hardware, controller, FreeRADIUS Linux, HA, performance, and customer proof outside engineering completion.</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">NAS-0063 Juniper/ERX/Extreme/Mist Pack</h3>
                <p className="mt-1 text-sm text-gray-600">Certify Juniper, ERX/E-Series, Extreme, and Mist product-scope software handling while keeping device proof in the release checklist.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {juniperExtremePackSummary ? (
                  <StatusBadge tone={juniperExtremePackComplete ? 'green' : 'amber'}>
                    {formatPercent(juniperExtremePackSummary.software_completion_percent)} software
                  </StatusBadge>
                ) : null}
                {canRecordJuniperExtremePack ? (
                  <button
                    type="button"
                    onClick={() => void recordJuniperExtremePack()}
                    disabled={juniperExtremePackBusy || !juniperExtremePackComplete}
                    className="rounded-md bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
                  >
                    {juniperExtremePackBusy ? 'Recording...' : 'Record Evidence'}
                  </button>
                ) : null}
              </div>
            </div>

            {juniperExtremePackError ? <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{juniperExtremePackError}</div> : null}
            {juniperExtremePackSummary ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Juniper/Extreme Rows" value={juniperExtremePackSummary.attribute_count} hint="Pinned FreeRADIUS 3.2.8 Juniper, ERX, and Extreme rows." />
                  <StatCard label="Software Certified" value={juniperExtremePackSummary.software_certified_mappings} hint={`${juniperExtremePackSummary.software_blocked_mappings} software blockers.`} />
                  <StatCard label="Dictionary Vendors" value={juniperExtremePackSummary.vendor_count} hint={`${juniperExtremePackSummary.native_semantic_mappings} native semantic mappings.`} />
                  <StatCard label="Product Scopes" value={juniperExtremePackSummary.product_scope_count} hint="Junos, ERX/E-Series, Extreme, and Mist tracked separately." />
                  <StatCard label="Policy Grammar" value={juniperExtremePackSummary.grammar_rule_count} hint="Parser, compiler, inbound, and outbound states." />
                  <StatCard label="Secret Redaction" value={juniperExtremePackSummary.sensitive_redacted_mappings} hint="PPP, tunnel, and mobile-IP credentials." />
                  <StatCard label="Storage Events" value={juniperExtremePack?.evidence.summary.total_events || 0} hint={juniperExtremePack?.evidence.summary.last_event_at ? `Last ${new Date(juniperExtremePack.evidence.summary.last_event_at).toLocaleString()}` : 'No persisted event yet.'} />
                  <StatCard label="Ready For Lab" value={juniperExtremePackSummary.ready_for_external_validation_mappings} hint="Software-ready rows awaiting release proof." />
                </div>

                <div className="mt-4 rounded-md border border-gray-200 p-4">
                  <div className="text-xs font-semibold uppercase text-gray-500">Juniper/ERX/Extreme/Mist Fingerprint</div>
                  <div className="mt-2 break-all text-sm font-medium text-gray-900">{juniperExtremePackSummary.fingerprint}</div>
                  <p className="mt-2 text-sm text-gray-600">{juniperExtremePack?.release_scope}</p>
                </div>

                <div className="mt-4 grid gap-4 xl:grid-cols-4">
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Vendor', 'Rows', 'State'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {juniperExtremePackVendors.map((vendor) => (
                          <tr key={`${vendor.vendor}-${vendor.pen}`}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{vendor.vendor}<div className="text-xs text-gray-500">PEN {vendor.pen}{vendor.pack_key ? ` / ${vendor.pack_key}` : ''}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{vendor.software_certified_mappings}/{vendor.attribute_count}<div className="text-xs text-gray-500">{vendor.sensitive_redacted_mappings} redacted</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{formatPercent(vendor.software_completion_percent)}</StatusBadge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Product Scope', 'Dictionary', 'State'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {juniperExtremeProductScopes.map((scope) => (
                          <tr key={scope.key}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{scope.label}<div className="text-xs text-gray-500">{joinList(scope.products)}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{scope.dictionary}<div className="text-xs text-gray-500">{joinList(scope.vendors)}</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{evidenceLabel(scope.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{evidenceLabel(scope.external_state)}</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Capability', 'Rows', 'Mapping'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {juniperExtremePackCapabilities.slice(0, 8).map((capability) => (
                          <tr key={capability.capability}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{evidenceLabel(capability.capability)}</td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.software_certified_mappings}/{capability.attribute_count}<div className="text-xs text-gray-500">{capability.external_required_mappings} external</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{capability.native_semantic_mappings} native<div className="text-xs text-gray-500">{capability.sensitive_redacted_mappings} redacted</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Grammar', 'State', 'Example'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {juniperExtremePackGrammar.slice(0, 8).map((grammar) => (
                          <tr key={grammar.key}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{grammar.label}<div className="text-xs text-gray-500">{grammar.kind}</div></td>
                            <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{grammar.parser_state}</StatusBadge><div className="mt-1 text-xs text-gray-500">{grammar.external_state}</div></td>
                            <td className="px-4 py-3 text-xs text-gray-700">{grammar.examples?.[0] || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="mt-4 overflow-x-auto rounded-md border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50"><tr>{['Attribute', 'Capability', 'Software', 'Handling'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                    <tbody className="divide-y divide-gray-200">
                      {juniperExtremePackRecords.slice(0, 10).map((record) => (
                        <tr key={record.id}>
                          <td className="px-4 py-3 text-sm font-medium text-gray-900">{record.attribute}<div className="text-xs text-gray-500">{record.vendor} / {record.wire_key}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.capability)}<div className="text-xs text-gray-500">{joinList(record.directions)}</div></td>
                          <td className="px-4 py-3 text-sm"><StatusBadge tone="green">{evidenceLabel(record.software_state)}</StatusBadge><div className="mt-1 text-xs text-gray-500">{record.claim_state}</div></td>
                          <td className="px-4 py-3 text-sm text-gray-700">{evidenceLabel(record.implementation_class)}<div className="text-xs text-gray-500">{evidenceLabel(record.packet_processing)}</div></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-xs text-gray-500">{juniperExtremePack?.release_certification_checklist} keeps Junos, ERX/E-Series, Extreme, Mist, FreeRADIUS Linux, HA, performance, and customer proof outside engineering completion.</p>
              </>
            ) : null}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Dictionary Release Profile</h3>
                <p className="mt-1 text-sm text-gray-600">Pin FreeRADIUS dictionary release, vendor aliases, firmware scopes, and registry provenance before enabling vendor packs.</p>
              </div>
              {releaseProfile ? <StatusBadge tone="green">{releaseProfile.id}</StatusBadge> : null}
            </div>
            {releaseProfile ? (
              <>
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="FreeRADIUS Release" value={releaseProfile.release} hint={`${releaseProfile.source_file_count} dictionary files pinned.`} />
                  <StatCard label="Vendor Aliases" value={releaseProfile.vendor_alias_count} hint={`${releaseProfile.attribute_alias_count} attribute aliases.`} />
                  <StatCard label="Firmware Scopes" value={releaseProfile.firmware_profile_count} hint={`${releaseProfile.runtime_decoder_count} runtime decoders.`} />
                  <StatCard label="Effective Attrs" value={releaseProfile.effective_attribute_count} hint={`${releaseProfile.mapped_attribute_count} mapped entries.`} />
                </div>
                <div className="mt-4 grid gap-4 xl:grid-cols-2">
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Alias', 'Canonical', 'Scope'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {vendorAliases.slice(0, 8).map((alias) => (
                          <tr key={`${alias.alias}-${alias.canonical_pack_key}`}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{alias.alias}</td>
                            <td className="px-4 py-3 text-sm text-gray-700">{alias.canonical_vendor}<div className="text-xs text-gray-500">{alias.canonical_pack_key || 'metadata'}{alias.pen ? ` / PEN ${alias.pen}` : ''}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{alias.scope}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="overflow-x-auto rounded-md border border-gray-200">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50"><tr>{['Firmware', 'Vendor', 'Evidence'].map((label) => <th key={label} className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">{label}</th>)}</tr></thead>
                      <tbody className="divide-y divide-gray-200">
                        {firmwareProfiles.slice(0, 8).map((profile) => (
                          <tr key={profile.key}>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">{profile.product_family}<div className="text-xs text-gray-500">{profile.firmware_scope}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{profile.vendor}<div className="text-xs text-gray-500">{profile.pack_key}{profile.pen ? ` / PEN ${profile.pen}` : ''}</div></td>
                            <td className="px-4 py-3 text-sm text-gray-700">{profile.support_state}<div className="text-xs text-gray-500">{profile.evidence_state}</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                <p className="mt-2 break-all text-xs text-gray-500">Registry SHA-256: {releaseProfile.registry_source_sha256 || payload.summary.dictionary_release_source_sha256}</p>
              </>
            ) : (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">Dictionary release profile metadata is unavailable.</div>
            )}
          </section>

          <section className="mt-6">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Typed Attribute Registry</h3>
                <p className="mt-1 text-sm text-gray-600">Trace wire identifiers, value types, policy semantics, packet decoders, and source provenance from one versioned contract.</p>
              </div>
              {attributeRegistry ? <StatusBadge tone="green">{attributeRegistry.release_profile_id} / schema {attributeRegistry.schema_version}</StatusBadge> : null}
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
                          <td className="px-4 py-3 text-sm"><div>{entry.semantic || entry.capability_family}</div><div className="text-xs text-gray-500">{entry.semantic_provenance || entry.release_profile_id || 'metadata'}</div><div className="mt-1"><StatusBadge tone={entry.dictionary_status === 'missing' ? 'gray' : 'amber'}>{entry.dictionary_status}</StatusBadge></div></td>
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
                            <StatusBadge tone={aclExport.export_mode === 'line_rules' || aclExport.export_mode === 'rules' ? 'green' : aclExport.export_mode === 'mixed' ? 'amber' : 'gray'}>
                              {aclExportModeLabel(aclExport.export_mode)}
                            </StatusBadge>
                            <StatusBadge tone={aclCompilerTone(aclExport.compiler_status)}>
                              {aclCompilerLabel(aclExport.compiler_status)}
                            </StatusBadge>
                            {aclExport.certification_state ? (
                              <StatusBadge tone={aclExport.certification_state === 'software-certified' ? 'green' : 'amber'}>
                                {aclExport.certification_state}
                              </StatusBadge>
                            ) : null}
                            {typeof aclExport.lossless === 'boolean' ? (
                              <StatusBadge tone={aclExport.lossless ? 'green' : 'amber'}>{aclExport.lossless ? 'lossless' : 'non-lossless'}</StatusBadge>
                            ) : null}
                          </div>
                          <div className="mb-3 grid gap-2 text-xs text-gray-600 md:grid-cols-2">
                            <div>Compiler: {aclExport.compiler_version || 'not recorded'}</div>
                            <div>Decompile: {aclExport.decompile_supported ? 'supported' : 'not supported'}</div>
                            {aclExport.artifact_fingerprint ? (
                              <div className="break-words md:col-span-2">Artifact fingerprint: {aclExport.artifact_fingerprint}</div>
                            ) : null}
                            {aclExport.external_certification_required ? (
                              <div className="md:col-span-2 text-amber-700">External device certification is required before vendor parity claims.</div>
                            ) : null}
                            {aclExport.limits ? (
                              <div className="md:col-span-2">
                                Limits: {aclExport.limits.max_rules} rules, {aclExport.limits.max_attributes} attributes, {aclExport.limits.max_attribute_value_bytes} bytes per value
                              </div>
                            ) : null}
                          </div>
                          {aclExport.warnings && aclExport.warnings.length > 0 ? (
                            <div className="mb-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                              {aclExport.warnings.map((warning) => <div key={warning}>{warning}</div>)}
                            </div>
                          ) : null}
                          {aclExport.diagnostics && aclExport.diagnostics.length > 0 ? (
                            <div className="mb-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                              {aclExport.diagnostics.map((diagnostic) => (
                                <div key={`${diagnostic.code}-${diagnostic.path || ''}-${diagnostic.message}`}>
                                  {diagnostic.code}: {diagnostic.message}
                                </div>
                              ))}
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
