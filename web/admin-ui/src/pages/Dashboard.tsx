import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api/client";
import { useAuth } from "../contexts/AuthContext";

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

type ControllerSyncPreview = {
  operation: "pull" | "push";
  adapter: string;
  method: string;
  target_url: string;
  desired_state_hash: string;
};

type ControllerSyncResult = {
  operation: string;
  drift_detected: boolean;
  drift_count: number;
  applied_count: number;
  failed_count: number;
  desired_state_hash?: string;
  observed_state_hash?: string;
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

type SecretProviderReport = {
  status: "ready" | "degraded" | "blocked";
  providers: string[];
  summary: {
    total_sources: number;
    reference_count: number;
    inline_count: number;
    missing_count: number;
    unsupported_count: number;
    blocked_count: number;
    provider_ready_count: number;
    provider_error_count: number;
  };
};

type DatabaseStatusReport = {
  status: "ready" | "degraded" | "blocked";
  message: string;
  configured_backend: string;
  ready_for_ha: boolean;
  active: {
    backend: string;
    driver: string;
    dialect: string;
    dsn_ref_set: boolean;
    inline_dsn_set: boolean;
    dsn_fingerprint?: string;
    sslmode?: string;
    tls_required: boolean;
  };
  pool_stats?: {
    OpenConnections?: number;
    InUse?: number;
    Idle?: number;
  };
  warnings?: string[];
};

type RadiusPacketHardeningReport = {
  status?: string;
  message?: string;
  policy?: {
    enabled: boolean;
    fail_closed: boolean;
    require_known_source: boolean;
    require_message_authenticator: string;
  };
  limits?: {
    replay_window_seconds: number;
    per_client_rate_limit_per_second: number;
    per_client_burst: number;
    max_proxy_state_attributes: number;
    max_proxy_state_bytes: number;
  };
  source_trust?: {
    trusted_sources: string[];
  };
  runtime_stats?: {
    total_events: number;
    rejected_count: number;
    replay_reject_count: number;
    rate_limited_reject_count: number;
    message_authenticator_rejects: number;
    unknown_source_rejects: number;
    malformed_rejects: number;
    last_event_at?: string;
  };
};

type RadiusProxyRoutingReport = {
  status?: string;
  message?: string;
  enabled?: boolean;
  summary?: {
    route_count: number;
    explicit_route_count: number;
    default_route_count: number;
    server_count: number;
    radsec_server_count: number;
    default_realm?: string;
  };
  routes?: Array<{
    name: string;
    description?: string;
    realm: string;
    match_realms: string[];
    default: boolean;
    strip_realm: boolean;
    pool_strategy: string;
    status_check: string;
    pool_name: string;
    server_names: string[];
  }>;
  warnings?: string[];
};

type RadiusTransportPolicyReport = {
  status?: string;
  message?: string;
  enabled?: boolean;
  policy?: {
    mode: string;
    fail_closed: boolean;
    default_required_transport: string;
    allow_mixed_transports: boolean;
  };
  summary?: {
    route_count: number;
    explicit_route_policy_count: number;
    radsec_required_routes: number;
    udp_required_routes: number;
    any_transport_routes: number;
    mixed_transport_routes: number;
    violation_count: number;
    udp_server_count: number;
    radsec_server_count: number;
  };
  routes?: Array<{
    name: string;
    required_transport: string;
    observed_transports: string[];
    downgrade_risk: boolean;
    status: string;
    message: string;
  }>;
  warnings?: string[];
};

type RadiusProxyPolicyReport = {
  status?: string;
  message?: string;
  enabled?: boolean;
  summary?: {
    route_policy_count: number;
    implicit_route_policy_count: number;
    allow_standard_count: number;
    deny_standard_count: number;
    allow_vendor_id_count: number;
    deny_vendor_id_count: number;
    allow_vendor_attribute_count: number;
    deny_vendor_attribute_count: number;
    rewrite_rule_count: number;
    trusted_realm_count: number;
  };
  freeradius?: {
    generated_pre_proxy_policy: boolean;
    generated_post_proxy_policy: boolean;
    loop_marker_enforced: boolean;
    sections: string[];
  };
  warnings?: string[];
};

type RadiusAccountingSpoolReport = {
  enabled: boolean;
  status: string;
  message: string;
  summary?: {
    total_records: number;
    queued_count: number;
    retrying_count: number;
    sent_count: number;
    poison_count: number;
    expired_count: number;
    due_count: number;
    attempt_count: number;
    queue_capacity: number;
    queue_utilization_percent: number;
    oldest_queued_at?: string;
    next_attempt_at?: string;
    last_sent_at?: string;
    last_poison_at?: string;
  };
};

type RadiusSQLAccountingReport = {
  enabled: boolean;
  status: string;
  message: string;
  summary?: {
    radacct_rows: number;
    radpostauth_rows: number;
    pending_rows: number;
    stale_pending_rows: number;
    error_rows: number;
    reconciled_rows: number;
    open_sessions: number;
    closed_sessions: number;
  };
};

type RadiusAccountingOrderingReport = {
  enabled: boolean;
  status: string;
  message: string;
  summary?: {
    total_events: number;
    pending_events: number;
    applied_events: number;
    error_events: number;
    duplicate_events: number;
    reordered_events: number;
    late_stop_events: number;
    stale_pending_events: number;
  };
};

type RadiusAccountingCountersReport = {
  enabled: boolean;
  status: string;
  message: string;
  summary?: {
    radacct_rows: number;
    event_rows: number;
    gigaword_rows: number;
    rollover_events: number;
    reset_events: number;
    counter_error_rows: number;
    max_input_octets_64: string;
    max_output_octets_64: string;
  };
};

type RadiusFallbackPolicyReport = {
  enabled: boolean;
  status: string;
  message: string;
  policy?: {
    mode: string;
    fail_closed: boolean;
    allow_portal_local: boolean;
    allow_ldap: boolean;
    require_identity_allowlist: boolean;
    max_outage_seconds: number;
  };
  summary?: {
    allowed_user_count: number;
    allowed_realm_count: number;
    allowed_role_count: number;
    identity_allowlist_set: boolean;
    active_outage: boolean;
    fallback_expires_at?: string;
    current_upstream_status?: string;
  };
  audit_summary?: {
    total_records: number;
    allowed_count: number;
    denied_count: number;
    monitor_count: number;
    last_observed_at?: string;
    last_decision?: string;
    last_reason?: string;
  };
  warnings?: string[];
};

type EAPFrameworkReport = {
  status: string;
  message: string;
  policy?: {
    enabled: boolean;
    mode: string;
    fail_closed: boolean;
    allowed_methods: string[];
    allowed_inner_methods: string[];
    require_message_authenticator: boolean;
    require_identity_binding: boolean;
    effective_max_sessions: number;
    method_timeout_seconds: number;
    fragment_size: number;
  };
  summary?: {
    enabled_method_count: number;
    generated_method_count: number;
    planned_method_count: number;
    blocked_method_count: number;
    identity_source_count: number;
    vendor_profile_count: number;
    recent_event_count: number;
    recent_rejected_count: number;
    recent_unsupported_count: number;
    message_authenticator_mode: string;
  };
  runtime?: {
    total_events: number;
    accepted: number;
    rejected: number;
    monitor_allowed: number;
    unsupported: number;
    last_event_at?: string;
    last_rejected_reason?: string;
  };
  warnings?: string[];
  blocking_issues?: string[];
};

type TEAPReport = {
  status: string;
  message: string;
  policy?: {
    enabled: boolean;
    allowed_by_framework: boolean;
    generated_in_freeradius: boolean;
    framework_mode: string;
    default_inner_method: string;
    chain_mode: string;
    require_crypto_binding: boolean;
    require_channel_binding: boolean;
    require_identity_type: boolean;
    require_machine_identity: boolean;
    require_user_identity: boolean;
    allow_pac: boolean;
    require_pac: boolean;
    pac_provisioning: string;
    max_chain_steps: number;
    session_ttl_seconds: number;
  };
  runtime?: {
    total_events: number;
    accepted: number;
    rejected: number;
    monitor_allowed: number;
    invalid_crypto_binding: number;
    invalid_channel_binding: number;
    missing_machine_identity: number;
    missing_user_identity: number;
    last_rejected_reason?: string;
  };
  warnings?: string[];
  blocking_issues?: string[];
};

type MachineUserReport = {
  status: string;
  message: string;
  policy?: {
    enabled: boolean;
    mode: string;
    fail_closed: boolean;
    framework_enabled: boolean;
    require_teap: boolean;
    teap_generated: boolean;
    correlation_mode: string;
    require_machine_identity: boolean;
    require_user_identity: boolean;
    require_machine_before_user: boolean;
    require_same_calling_station: boolean;
    require_same_nas: boolean;
    require_fresh_machine_auth: boolean;
    machine_auth_ttl_seconds: number;
    user_auth_ttl_seconds: number;
    transition_window_seconds: number;
    allowed_machine_methods: string[];
    allowed_user_methods: string[];
    role_merge_strategy: string;
    conflict_action: string;
    stale_machine_action: string;
  };
  runtime?: {
    total_events: number;
    accepted: number;
    rejected: number;
    monitor_allowed: number;
    quarantined: number;
    active_correlations: number;
    missing_machine_identity: number;
    missing_user_identity: number;
    stale_machine_auth: number;
    role_conflict: number;
    calling_station_mismatch: number;
    nas_mismatch: number;
    machine_before_user_failure: number;
    last_rejected_reason?: string;
  };
  warnings?: string[];
  blocking_issues?: string[];
};

type FASTPWDReport = {
  status: string;
  message: string;
  fast?: {
    enabled: boolean;
    allowed_by_framework: boolean;
    generated_in_freeradius: boolean;
    framework_mode: string;
    default_inner_method: string;
    require_crypto_binding: boolean;
    allow_pac: boolean;
    require_pac: boolean;
    pac_provisioning: string;
    allow_anonymous_provisioning: boolean;
  };
  pwd?: {
    enabled: boolean;
    allowed_by_framework: boolean;
    generated_in_freeradius: boolean;
    framework_mode: string;
    group: number;
    require_strong_group: boolean;
    password_source: string;
    require_password_proof: boolean;
    replay_window_seconds: number;
  };
  runtime?: {
    total_events: number;
    accepted: number;
    rejected: number;
    monitor_allowed: number;
    invalid_crypto_binding: number;
    missing_pac: number;
    missing_password_proof: number;
    weak_pwd_group: number;
    replay_rejected: number;
    last_rejected_reason?: string;
  };
  warnings?: string[];
  blocking_issues?: string[];
};

type SIMAKAReport = {
  status: string;
  message: string;
  policy?: {
    enabled: boolean;
    allowed_by_framework: boolean;
    generated_in_freeradius: boolean;
    framework_mode: string;
    methods: string[];
    generated_methods: string[];
    require_identity: boolean;
    allow_pseudonym_identity: boolean;
    vector_provider: string;
    vector_provider_ref_configured: boolean;
    require_fresh_vectors: boolean;
    max_vector_age_seconds: number;
    min_triplets: number;
    min_quintuplets: number;
    allow_resynchronization: boolean;
    require_network_name: boolean;
    network_name_configured: boolean;
    require_kdf: boolean;
  };
  runtime?: {
    total_events: number;
    accepted: number;
    rejected: number;
    monitor_allowed: number;
    missing_identity: number;
    missing_vector: number;
    stale_vector: number;
    invalid_authenticator: number;
    resync_events: number;
    replay_rejected: number;
    last_rejected_reason?: string;
  };
  warnings?: string[];
  blocking_issues?: string[];
};

type CertificateLifecycleReport = {
  status: string;
  message: string;
  policy?: {
    enabled: boolean;
    mode: string;
    fail_closed: boolean;
    ca_mode: string;
    ca_ready: boolean;
    certificate_enrollment_ready: boolean;
    eap_tls_ready: boolean;
    default_template: string;
    templates: string[];
    active_issuer: string;
    staged_issuer?: string;
    issuer_rotation_mode: string;
    certificate_validity_days: number;
    renewal_window_days: number;
    require_csr: boolean;
    require_proof_of_possession: boolean;
    require_device_binding: boolean;
    require_subject_alt_name: boolean;
    min_rsa_bits: number;
    escrow_policy: string;
    revocation_available: boolean;
    est_enabled: boolean;
    scep_enabled: boolean;
    byod_portal_enabled: boolean;
  };
  runtime?: {
    total_events: number;
    accepted: number;
    rejected: number;
    monitor_allowed: number;
    renewal_due: number;
    revocation_blocked: number;
    weak_key: number;
    missing_csr: number;
    missing_device_binding: number;
    escrow_rejected: number;
    active_inventory: number;
    revoked_inventory: number;
    renewal_due_inventory: number;
    last_event_at?: string;
    last_rejected_reason?: string;
  };
  warnings?: string[];
  blocking_issues?: string[];
  release_checklist?: string;
};

type SupplicantLifecycleReport = {
  status: string;
  message: string;
  policy?: {
    enabled: boolean;
    mode: string;
    fail_closed: boolean;
    ssid: string;
    security: string;
    default_platform: string;
    allowed_platforms: string[];
    default_eap_method: string;
    allowed_eap_methods: string[];
    default_inner_method: string;
    anonymous_identity: string;
    require_trust_anchor_pinning: boolean;
    server_names: string[];
    trust_anchor_pins: string[];
    allow_password_change: boolean;
    require_verifier_compatibility: boolean;
    require_mfa_for_change: boolean;
    require_tls_for_delivery: boolean;
    require_signed_profiles: boolean;
    profile_signing_key_configured: boolean;
    portal_ready: boolean;
    eap_framework_ready: boolean;
    certificate_lifecycle_ready: boolean;
  };
  runtime?: {
    total_events: number;
    accepted: number;
    rejected: number;
    monitor_allowed: number;
    password_change_required: number;
    password_changed: number;
    profiles_delivered: number;
    unsigned_profile_blocked: number;
    trust_pin_failures: number;
    verifier_failures: number;
    tls_failures: number;
    active_profiles: number;
    expired_profiles: number;
    last_rejected_reason?: string;
    last_profile_delivered_at?: string;
  };
  warnings?: string[];
  blocking_issues?: string[];
  release_checklist?: string;
};

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
    analysis_summary?: {
      total_analyses: number;
      last_risk_level?: string;
      last_sample_count: number;
      last_decision_change_count: number;
      last_shadowed_rule_count: number;
      last_ineffective_rule_count: number;
    };
    active?: {
      version: number;
      status: string;
      approval_count: number;
      min_approvals: number;
      policy_sha256: string;
    };
  };
};

type IdentityFailoverReport = {
  enabled: boolean;
  status: string;
  message: string;
  policy?: {
    mode: string;
    fail_closed: boolean;
    cache_credentials: boolean;
    source_order: string[];
    max_failures: number;
    circuit_open_seconds: number;
    stale_cache_seconds: number;
    split_result_policy: string;
  };
  summary?: {
    source_count: number;
    enabled_source_count: number;
    executable_source_count: number;
    open_circuit_count: number;
    cache_enabled: boolean;
    audit_enabled: boolean;
    last_decision?: string;
    last_reason?: string;
  };
  audit_summary?: {
    total_records: number;
    accepted_count: number;
    rejected_count: number;
    failure_count: number;
    stale_accepted_count: number;
    split_denied_count: number;
    last_observed_at?: string;
    last_decision?: string;
    last_reason?: string;
  };
  cache_summary?: {
    total_entries: number;
    expired_entries: number;
    last_success_at?: string;
    next_expires_at?: string;
  };
  sources?: Array<{
    name: string;
    type: string;
    enabled: boolean;
    executable: boolean;
    reason?: string;
    circuit_state?: {
      state: string;
      failure_count: number;
      reopens_at?: string;
    };
  }>;
};

type RadSecCredentialReport = {
  status: string;
  message: string;
  summary?: {
    inbound_enabled: boolean;
    upstream_radsec_peers: number;
    mtls_endpoints: number;
    psk_endpoints: number;
    rotation_staged: number;
    rotation_active: number;
    rotation_expired: number;
    certificate_warnings: number;
    blocking_issues: number;
  };
  upstream?: Array<{
    name: string;
    mode: string;
    status: string;
    rotation_status: string;
    effective_psk_identity?: string;
    using_next_psk?: boolean;
    warnings?: string[];
  }>;
  warnings?: string[];
};

type DynamicNASClientReport = {
  enabled: boolean;
  status: string;
  message: string;
  policy?: {
    discovery_enabled: boolean;
    approval_required: boolean;
    enrollment_token_ref_set: boolean;
    enrollment_ttl_seconds: number;
    max_pending: number;
    discovery_allowed_cidrs: string[];
    default_nas_type: string;
    default_transport: string;
    default_template: string;
  };
  summary?: {
    total_enrollments: number;
    pending_enrollments: number;
    approved_enrollments: number;
    rejected_enrollments: number;
    revoked_enrollments: number;
    expired_enrollments: number;
    dynamic_clients: number;
    static_clients: number;
    capability_templates: number;
    recent_events: number;
    last_event_at?: string;
  };
  warnings?: string[];
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
  database?: DatabaseStatusReport;
  production_readiness?: ProductionReadinessSummary;
  identity?: {
    failover?: IdentityFailoverReport;
    active_directory?: any;
    mfa?: any;
    webauthn?: any;
    mab?: any;
  };
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
    packet_hardening?: RadiusPacketHardeningReport;
    proxy_routes?: RadiusProxyRoutingReport;
    transport_policy?: RadiusTransportPolicyReport;
    proxy_policy?: RadiusProxyPolicyReport;
    accounting_spool?: RadiusAccountingSpoolReport;
    sql_accounting?: RadiusSQLAccountingReport;
    accounting_ordering?: RadiusAccountingOrderingReport;
    accounting_counters?: RadiusAccountingCountersReport;
    fallback_policy?: RadiusFallbackPolicyReport;
    eap_framework?: EAPFrameworkReport;
    eap_teap?: TEAPReport;
    eap_machine_user?: MachineUserReport;
    eap_fast_pwd?: FASTPWDReport;
    eap_sim_aka?: SIMAKAReport;
    policy_engine?: PolicyEngineReport;
    certificate_lifecycle?: CertificateLifecycleReport;
    supplicant_lifecycle?: SupplicantLifecycleReport;
    radsec_credentials?: RadSecCredentialReport;
    dynamic_nas_clients?: DynamicNASClientReport;
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
	const { identity } = useAuth();
	const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [productionReadiness, setProductionReadiness] =
    useState<ProductionReadinessReport | null>(null);
  const [secretProviders, setSecretProviders] =
    useState<SecretProviderReport | null>(null);
  const [loading, setLoading] = useState(true);
	const [error, setError] = useState("");
	const [controllerBusy, setControllerBusy] = useState("");
	const [controllerConfirmation, setControllerConfirmation] = useState("");
	const [controllerPreview, setControllerPreview] =
		useState<ControllerSyncPreview | null>(null);
	const [controllerResult, setControllerResult] =
		useState<ControllerSyncResult | null>(null);
	const [controllerMessage, setControllerMessage] = useState("");
	const [controllerError, setControllerError] = useState("");

  const loadStatus = async (includeReadiness = true) => {
    try {
      const [statusResponse, readinessResponse, secretProviderResponse] =
        await Promise.all([
        api.get("/system/status"),
        includeReadiness
          ? api.get("/system/production-readiness").catch(() => null)
          : Promise.resolve(null),
        includeReadiness
          ? api.get("/system/secret-providers").catch(() => null)
          : Promise.resolve(null),
      ]);
      setSystemStatus(statusResponse.data);
      if (includeReadiness) {
        setProductionReadiness(readinessResponse?.data || null);
        setSecretProviders(secretProviderResponse?.data || null);
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

	const previewControllerSync = async (operation: "pull" | "push") => {
		setControllerBusy(`preview-${operation}`);
		setControllerError("");
		try {
			const { data } = await api.get("/system/controller-sync/preview", {
				params: { operation },
			});
			setControllerPreview(data.preview);
			setControllerMessage(
				`${operation === "pull" ? "Read-only pull" : "Policy push"} preview is ready.`,
			);
		} catch (err: any) {
			setControllerError(
				err.response?.data || err.message || "Could not preview controller synchronization.",
			);
		} finally {
			setControllerBusy("");
		}
	};

	const runControllerSync = async (operation: "pull" | "push") => {
		setControllerBusy(operation);
		setControllerError("");
		try {
			const { data } = await api.post("/system/controller-sync", {
				operation,
				confirmation: operation === "push" ? controllerConfirmation : "",
			});
			setControllerResult(data.result || null);
			setControllerMessage(data.message || `Controller ${operation} completed.`);
			await loadStatus(false);
		} catch (err: any) {
			setControllerError(
				err.response?.data?.message ||
					err.response?.data ||
					err.message ||
					"Controller synchronization failed.",
			);
		} finally {
			setControllerBusy("");
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
  const packetHardening = systemStatus.radius?.packet_hardening;
  const proxyRoutes = systemStatus.radius?.proxy_routes;
  const transportPolicy = systemStatus.radius?.transport_policy;
  const proxyPolicy = systemStatus.radius?.proxy_policy;
  const accountingSpool = systemStatus.radius?.accounting_spool;
  const sqlAccounting = systemStatus.radius?.sql_accounting;
  const accountingOrdering = systemStatus.radius?.accounting_ordering;
  const accountingCounters = systemStatus.radius?.accounting_counters;
  const fallbackPolicy = systemStatus.radius?.fallback_policy;
  const eapFramework = systemStatus.radius?.eap_framework;
  const teapReport = systemStatus.radius?.eap_teap;
  const machineUserReport = systemStatus.radius?.eap_machine_user;
  const fastPWDReport = systemStatus.radius?.eap_fast_pwd;
  const simAKAReport = systemStatus.radius?.eap_sim_aka;
  const policyEngine = systemStatus.radius?.policy_engine;
  const certificateLifecycle =
    systemStatus.radius?.certificate_lifecycle;
  const supplicantLifecycle =
    systemStatus.radius?.supplicant_lifecycle;
  const identityFailover = systemStatus.identity?.failover;
  const identityActiveDirectory = systemStatus.identity?.active_directory;
  const identityMFA = systemStatus.identity?.mfa;
  const identityWebAuthn = systemStatus.identity?.webauthn;
  const identityMAB = systemStatus.identity?.mab;
  const radSecCredentials = systemStatus.radius?.radsec_credentials;
  const dynamicNASClients = systemStatus.radius?.dynamic_nas_clients;
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
  const secretSummary = secretProviders?.summary;
  const databaseStatus = systemStatus.database;
	const highAvailabilityStatus =
    systemStatus.high_availability.replication_runtime?.status === "degraded"
      ? "degraded"
      : systemStatus.high_availability.replication_runtime?.status ===
            "pending" && !systemStatus.high_availability.runtime?.status
        ? "pending"
        : systemStatus.high_availability.runtime?.status ||
		  (systemStatus.high_availability.enabled ? "unknown" : "disabled");
	const canRunControllerSync =
		identity?.role === "super_admin" || identity?.role === "ops_admin";

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

      {secretProviders && secretSummary ? (
        <section
          className={`rounded-md border bg-white p-5 shadow-sm ${
            secretProviders.status === "blocked"
              ? "border-red-300"
              : secretProviders.status === "ready"
                ? "border-emerald-300"
                : "border-amber-300"
          }`}
          aria-labelledby="secret-providers-heading"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <h3
                id="secret-providers-heading"
                className="text-lg font-semibold text-gray-900"
              >
                Secret Providers
              </h3>
              <p className="mt-1 text-sm text-gray-600">
                {secretSummary.inline_count
                  ? `${secretSummary.inline_count} inline source(s) still need references.`
                  : "Configured references are provider-backed."}
              </p>
            </div>
            <StatusBadge status={secretProviders.status} />
          </div>
          <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-6">
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Providers
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {secretProviders.providers.join(", ") || "none"}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Sources
              </div>
              <div className="mt-1 text-2xl font-bold text-gray-900">
                {secretSummary.total_sources}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                References
              </div>
              <div className="mt-1 text-2xl font-bold text-emerald-700">
                {secretSummary.reference_count}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Inline
              </div>
              <div className="mt-1 text-2xl font-bold text-amber-700">
                {secretSummary.inline_count}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Missing
              </div>
              <div className="mt-1 text-2xl font-bold text-red-700">
                {secretSummary.missing_count}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Blocked
              </div>
              <div className="mt-1 text-2xl font-bold text-red-700">
                {secretSummary.blocked_count}
              </div>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            <Link
              to="/radius-clients"
              className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white"
            >
              RADIUS Clients
            </Link>
            <Link
              to="/access-settings"
              className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
            >
              Security Settings
            </Link>
          </div>
        </section>
      ) : null}

      {databaseStatus ? (
        <section
          className={`rounded-md border bg-white p-5 shadow-sm ${
            databaseStatus.status === "blocked"
              ? "border-red-300"
              : databaseStatus.status === "ready"
                ? "border-emerald-300"
                : "border-amber-300"
          }`}
          aria-labelledby="database-heading"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <h3
                id="database-heading"
                className="text-lg font-semibold text-gray-900"
              >
                Database Data Plane
              </h3>
              <p className="mt-1 text-sm text-gray-600">
                {databaseStatus.message}
              </p>
            </div>
            <StatusBadge status={databaseStatus.status} />
          </div>
          <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-6">
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Backend
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {databaseStatus.active?.backend ||
                  databaseStatus.configured_backend ||
                  "unknown"}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                DSN Ref
              </div>
              <div className="mt-1 text-2xl font-bold text-gray-900">
                {databaseStatus.active?.dsn_ref_set ? "Yes" : "No"}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                TLS
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {databaseStatus.active?.sslmode || "n/a"}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                HA Ready
              </div>
              <div className="mt-1 text-2xl font-bold text-gray-900">
                {databaseStatus.ready_for_ha ? "Yes" : "No"}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Open
              </div>
              <div className="mt-1 text-2xl font-bold text-gray-900">
                {databaseStatus.pool_stats?.OpenConnections ?? 0}
              </div>
            </div>
            <div>
              <div className="text-xs font-medium uppercase text-gray-500">
                Inline
              </div>
              <div className="mt-1 text-2xl font-bold text-amber-700">
                {databaseStatus.active?.inline_dsn_set ? "Yes" : "No"}
              </div>
            </div>
          </div>
          {databaseStatus.warnings?.length ? (
            <div className="mt-4 text-sm text-amber-800">
              {databaseStatus.warnings.slice(0, 2).join(" ")}
            </div>
          ) : null}
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
              {proxyRoutes ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Proxy Route Table
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {proxyRoutes.message ||
                          "Proxy route state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-4">
                        <div>
                          Routes {proxyRoutes.summary?.route_count ?? 0}
                        </div>
                        <div>
                          Explicit{" "}
                          {proxyRoutes.summary?.explicit_route_count ?? 0}
                        </div>
                        <div>
                          Default{" "}
                          {proxyRoutes.summary?.default_realm || "none"}
                        </div>
                        <div>
                          Servers {proxyRoutes.summary?.server_count ?? 0}
                        </div>
                      </div>
                      {proxyRoutes.routes?.length ? (
                        <div className="mt-3 divide-y divide-gray-100 text-sm">
                          {proxyRoutes.routes.slice(0, 3).map((route) => (
                            <div key={route.name} className="py-2 first:pt-0">
                              <div className="font-medium text-gray-800">
                                {route.name}
                                {route.default ? " default" : ""}
                              </div>
                              <div className="mt-1 text-xs text-gray-500">
                                {route.realm} via{" "}
                                {route.server_names.join(", ") || "no servers"}
                              </div>
                              {route.match_realms.length > 1 ? (
                                <div className="mt-1 text-xs text-gray-500">
                                  Also matches{" "}
                                  {route.match_realms.slice(1).join(", ")}
                                </div>
                              ) : null}
                            </div>
                          ))}
                          {proxyRoutes.routes.length > 3 ? (
                            <div className="pt-2 text-xs text-gray-500">
                              {proxyRoutes.routes.length - 3} more route(s)
                              available from the proxy routes API.
                            </div>
                          ) : null}
                        </div>
                      ) : null}
                      {proxyRoutes.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {proxyRoutes.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={proxyRoutes.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {transportPolicy ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Transport Downgrade Policy
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {transportPolicy.message ||
                          "Transport policy state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode {transportPolicy.policy?.mode || "monitor"}
                        </div>
                        <div>
                          Required{" "}
                          {transportPolicy.policy
                            ?.default_required_transport || "any"}
                        </div>
                        <div>
                          Mixed{" "}
                          {transportPolicy.summary?.mixed_transport_routes ??
                            0}
                        </div>
                        <div>
                          Violations{" "}
                          {transportPolicy.summary?.violation_count ?? 0}
                        </div>
                        <div>
                          RadSec servers{" "}
                          {transportPolicy.summary?.radsec_server_count ?? 0}
                        </div>
                      </div>
                      {transportPolicy.routes?.length ? (
                        <div className="mt-2 text-xs text-gray-500">
                          {transportPolicy.routes
                            .filter((route) => route.status !== "ready")
                            .slice(0, 2)
                            .map(
                              (route) =>
                                `${route.name}: ${route.observed_transports.join(
                                  "/",
                                )} requires ${route.required_transport}`,
                            )
                            .join("; ") ||
                            "No route transport violations detected."}
                        </div>
                      ) : null}
                      {transportPolicy.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {transportPolicy.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={transportPolicy.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {proxyPolicy ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Proxy Loop And Attribute Policy
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {proxyPolicy.message ||
                          "Proxy policy state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-4">
                        <div>
                          Route policies{" "}
                          {proxyPolicy.summary?.route_policy_count ?? 0}
                        </div>
                        <div>
                          Vendor allows{" "}
                          {(proxyPolicy.summary?.allow_vendor_id_count ?? 0) +
                            (proxyPolicy.summary
                              ?.allow_vendor_attribute_count ?? 0)}
                        </div>
                        <div>
                          Vendor denies{" "}
                          {(proxyPolicy.summary?.deny_vendor_id_count ?? 0) +
                            (proxyPolicy.summary
                              ?.deny_vendor_attribute_count ?? 0)}
                        </div>
                        <div>
                          Rewrites{" "}
                          {proxyPolicy.summary?.rewrite_rule_count ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Loop marker{" "}
                        {proxyPolicy.freeradius?.loop_marker_enforced
                          ? "enforced"
                          : "not enforced"}
                        ; pre-proxy policy{" "}
                        {proxyPolicy.freeradius?.generated_pre_proxy_policy
                          ? "generated"
                          : "not generated"}
                        .
                      </div>
                      {proxyPolicy.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {proxyPolicy.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={proxyPolicy.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {radSecCredentials ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        RadSec Credentials
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {radSecCredentials.message ||
                          "RadSec credential state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          mTLS{" "}
                          {radSecCredentials.summary?.mtls_endpoints ?? 0}
                        </div>
                        <div>
                          TLS-PSK{" "}
                          {radSecCredentials.summary?.psk_endpoints ?? 0}
                        </div>
                        <div>
                          Staged{" "}
                          {radSecCredentials.summary?.rotation_staged ?? 0}
                        </div>
                        <div>
                          Active{" "}
                          {radSecCredentials.summary?.rotation_active ?? 0}
                        </div>
                        <div>
                          Blocked{" "}
                          {radSecCredentials.summary?.blocking_issues ?? 0}
                        </div>
                      </div>
                      {radSecCredentials.upstream?.length ? (
                        <div className="mt-2 text-xs text-gray-500">
                          {radSecCredentials.upstream
                            .slice(0, 2)
                            .map((peer) =>
                              `${peer.name}: ${peer.mode} ${peer.rotation_status}${
                                peer.using_next_psk &&
                                peer.effective_psk_identity
                                  ? ` using ${peer.effective_psk_identity}`
                                  : ""
                              }`,
                            )
                            .join("; ")}
                          {radSecCredentials.upstream.length > 2
                            ? `; ${
                                radSecCredentials.upstream.length - 2
                              } more`
                            : ""}
                          .
                        </div>
                      ) : null}
                      {radSecCredentials.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {radSecCredentials.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge
                      status={radSecCredentials.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {eapFramework ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        EAP Method Framework
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {eapFramework.message ||
                          "EAP method framework state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode {eapFramework.policy?.mode || "monitor"}
                        </div>
                        <div>
                          Enabled{" "}
                          {eapFramework.summary?.enabled_method_count ?? 0}
                        </div>
                        <div>
                          Generated{" "}
                          {eapFramework.summary?.generated_method_count ?? 0}
                        </div>
                        <div>
                          Blocked{" "}
                          {eapFramework.summary?.blocked_method_count ?? 0}
                        </div>
                        <div>
                          Events {eapFramework.runtime?.total_events ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Methods{" "}
                        {eapFramework.policy?.allowed_methods?.join(", ") ||
                          "none"}
                        ; inner{" "}
                        {eapFramework.policy?.allowed_inner_methods?.join(
                          ", ",
                        ) || "none"}
                        ; integrity{" "}
                        {eapFramework.policy?.require_message_authenticator
                          ? "required"
                          : "inherited"}
                        .
                      </div>
                      {eapFramework.runtime?.last_rejected_reason ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last rejection:{" "}
                          {eapFramework.runtime.last_rejected_reason}
                        </div>
                      ) : null}
                      {eapFramework.blocking_issues?.length ? (
                        <div className="mt-2 text-xs text-red-700">
                          {eapFramework.blocking_issues[0]}
                        </div>
                      ) : eapFramework.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {eapFramework.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={eapFramework.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {teapReport ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        TEAP Method Chaining
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {teapReport.message ||
                          "TEAP method-chaining state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode{" "}
                          {teapReport.policy?.framework_mode || "monitor"}
                        </div>
                        <div>
                          Chain{" "}
                          {teapReport.policy?.chain_mode ||
                            "machine_then_user"}
                        </div>
                        <div>
                          Generated{" "}
                          {teapReport.policy?.generated_in_freeradius
                            ? "yes"
                            : "no"}
                        </div>
                        <div>
                          Events {teapReport.runtime?.total_events ?? 0}
                        </div>
                        <div>
                          Rejects {teapReport.runtime?.rejected ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Inner{" "}
                        {teapReport.policy?.default_inner_method ||
                          "mschapv2"}
                        ; cryptobinding{" "}
                        {teapReport.policy?.require_crypto_binding
                          ? "required"
                          : "not required"}
                        ; PAC{" "}
                        {teapReport.policy?.require_pac
                          ? "required"
                          : teapReport.policy?.allow_pac
                            ? "allowed"
                            : "disabled"}
                        .
                      </div>
                      {teapReport.runtime?.last_rejected_reason ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last TEAP rejection:{" "}
                          {teapReport.runtime.last_rejected_reason}
                        </div>
                      ) : null}
                      {teapReport.blocking_issues?.length ? (
                        <div className="mt-2 text-xs text-red-700">
                          {teapReport.blocking_issues[0]}
                        </div>
                      ) : teapReport.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {teapReport.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={teapReport.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {machineUserReport ? (
                  <div className="rounded-md border border-gray-200 px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="font-medium text-gray-900">
                          Machine And User Correlation
                        </div>
                        <div className="mt-1 text-sm text-gray-600">
                          {machineUserReport.message ||
                            "Machine and user correlation state is available."}
                        </div>
                        <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                          <div>
                            Mode {machineUserReport.policy?.mode || "monitor"}
                          </div>
                          <div>
                            Chain{" "}
                            {machineUserReport.policy?.correlation_mode ||
                              "machine_then_user"}
                          </div>
                          <div>
                            Active{" "}
                            {machineUserReport.runtime?.active_correlations ??
                              0}
                          </div>
                          <div>
                            Events{" "}
                            {machineUserReport.runtime?.total_events ?? 0}
                          </div>
                          <div>
                            Quarantine{" "}
                            {machineUserReport.runtime?.quarantined ?? 0}
                          </div>
                        </div>
                        <div className="mt-2 text-xs text-gray-500">
                          TEAP{" "}
                          {machineUserReport.policy?.teap_generated
                            ? "generated"
                            : machineUserReport.policy?.require_teap
                              ? "required"
                              : "optional"}
                          ; same client{" "}
                          {machineUserReport.policy?.require_same_calling_station
                            ? "required"
                            : "not required"}
                          ; machine TTL{" "}
                          {machineUserReport.policy
                            ?.machine_auth_ttl_seconds ?? 28800}
                          s; merge{" "}
                          {machineUserReport.policy?.role_merge_strategy ||
                            "user_primary"}
                          .
                        </div>
                        {machineUserReport.runtime?.last_rejected_reason ? (
                          <div className="mt-2 text-xs text-gray-500">
                            Last correlation rejection:{" "}
                            {machineUserReport.runtime.last_rejected_reason}
                          </div>
                        ) : null}
                        {machineUserReport.blocking_issues?.length ? (
                          <div className="mt-2 text-xs text-red-700">
                            {machineUserReport.blocking_issues[0]}
                          </div>
                        ) : machineUserReport.warnings?.length ? (
                          <div className="mt-2 text-xs text-amber-700">
                            {machineUserReport.warnings[0]}
                          </div>
                        ) : null}
                      </div>
                      <StatusBadge
                        status={machineUserReport.status || "unknown"}
                      />
                    </div>
                  </div>
              ) : null}
              {fastPWDReport ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        EAP-FAST And EAP-PWD
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {fastPWDReport.message ||
                          "EAP-FAST and EAP-PWD state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode{" "}
                          {fastPWDReport.fast?.framework_mode ||
                            fastPWDReport.pwd?.framework_mode ||
                            "monitor"}
                        </div>
                        <div>
                          FAST{" "}
                          {fastPWDReport.fast?.generated_in_freeradius
                            ? "generated"
                            : "off"}
                        </div>
                        <div>
                          PWD{" "}
                          {fastPWDReport.pwd?.generated_in_freeradius
                            ? "generated"
                            : "off"}
                        </div>
                        <div>
                          Events {fastPWDReport.runtime?.total_events ?? 0}
                        </div>
                        <div>
                          Rejects {fastPWDReport.runtime?.rejected ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        FAST inner{" "}
                        {fastPWDReport.fast?.default_inner_method ||
                          "mschapv2"}
                        ; PAC{" "}
                        {fastPWDReport.fast?.require_pac
                          ? "required"
                          : fastPWDReport.fast?.allow_pac
                            ? "allowed"
                            : "disabled"}
                        ; PWD group {fastPWDReport.pwd?.group ?? 19}; proof{" "}
                        {fastPWDReport.pwd?.require_password_proof
                          ? "required"
                          : "not required"}
                        .
                      </div>
                      {fastPWDReport.runtime?.last_rejected_reason ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last FAST/PWD rejection:{" "}
                          {fastPWDReport.runtime.last_rejected_reason}
                        </div>
                      ) : null}
                      {fastPWDReport.blocking_issues?.length ? (
                        <div className="mt-2 text-xs text-red-700">
                          {fastPWDReport.blocking_issues[0]}
                        </div>
                      ) : fastPWDReport.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {fastPWDReport.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={fastPWDReport.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {simAKAReport ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        EAP-SIM And EAP-AKA
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {simAKAReport.message ||
                          "EAP-SIM and EAP-AKA state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode{" "}
                          {simAKAReport.policy?.framework_mode || "monitor"}
                        </div>
                        <div>
                          Methods{" "}
                          {simAKAReport.policy?.generated_methods?.join(", ") ||
                            "off"}
                        </div>
                        <div>
                          Provider{" "}
                          {simAKAReport.policy?.vector_provider || "external"}
                        </div>
                        <div>
                          Events {simAKAReport.runtime?.total_events ?? 0}
                        </div>
                        <div>
                          Rejects {simAKAReport.runtime?.rejected ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Vectors{" "}
                        {simAKAReport.policy?.require_fresh_vectors
                          ? "fresh"
                          : "not freshness-bound"}
                        ; triplets{" "}
                        {simAKAReport.policy?.min_triplets ?? 2}; quintuplets{" "}
                        {simAKAReport.policy?.min_quintuplets ?? 1}; privacy{" "}
                        {simAKAReport.policy?.allow_pseudonym_identity
                          ? "pseudonym"
                          : "permanent-only"}
                        .
                      </div>
                      {simAKAReport.runtime?.last_rejected_reason ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last SIM/AKA rejection:{" "}
                          {simAKAReport.runtime.last_rejected_reason}
                        </div>
                      ) : null}
                      {simAKAReport.blocking_issues?.length ? (
                        <div className="mt-2 text-xs text-red-700">
                          {simAKAReport.blocking_issues[0]}
                        </div>
                      ) : simAKAReport.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {simAKAReport.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={simAKAReport.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {policyEngine ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Typed Policy Engine
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {policyEngine.message ||
                          "Typed authorization policy state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode {policyEngine.config?.mode || "monitor"}
                        </div>
                        <div>
                          Rules{" "}
                          {policyEngine.rules?.filter((rule) => rule.enabled)
                            .length ?? 0}
                        </div>
                        <div>
                          Typed{" "}
                          {policyEngine.rules?.filter(
                            (rule) =>
                              rule.enabled && rule.typed && rule.valid,
                          ).length ?? 0}
                        </div>
                        <div>
                          Legacy{" "}
                          {policyEngine.rules?.filter(
                            (rule) => rule.enabled && rule.legacy,
                          ).length ?? 0}
                        </div>
                        <div>
                          Decisions{" "}
                          {policyEngine.summary?.total_records ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Fields {policyEngine.fields?.length ?? 0}; operators{" "}
                        {policyEngine.operators?.length ?? 0}; audit{" "}
                        {policyEngine.config?.audit_enabled
                          ? "enabled"
                          : "disabled"}
                        ; fail closed{" "}
                        {policyEngine.config?.fail_closed ? "yes" : "no"}.
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Policy sets {policyEngine.policy_sets?.status || "unknown"};
                        active v{policyEngine.policy_sets?.summary?.active_version ?? "none"};
                        pending{" "}
                        {policyEngine.policy_sets?.summary
                          ?.pending_approval_count ?? 0}
                        ; versions{" "}
                        {policyEngine.policy_sets?.summary?.total_versions ??
                          0}
                        .
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Analysis risk{" "}
                        {policyEngine.policy_sets?.analysis_summary
                          ?.last_risk_level || "none"}
                        ; analyses{" "}
                        {policyEngine.policy_sets?.analysis_summary
                          ?.total_analyses ?? 0}
                        ; changes{" "}
                        {policyEngine.policy_sets?.analysis_summary
                          ?.last_decision_change_count ?? 0}
                        /{policyEngine.policy_sets?.analysis_summary
                          ?.last_sample_count ?? 0}
                        ; shadow{" "}
                        {policyEngine.policy_sets?.analysis_summary
                          ?.last_shadowed_rule_count ?? 0}
                        /{policyEngine.policy_sets?.analysis_summary
                          ?.last_ineffective_rule_count ?? 0}
                        .
                      </div>
                      {policyEngine.policy_sets?.active ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Active approval evidence{" "}
                          {policyEngine.policy_sets.active.approval_count}/
                          {policyEngine.policy_sets.active.min_approvals};
                          hash{" "}
                          {policyEngine.policy_sets.active.policy_sha256.slice(
                            0,
                            12,
                          )}
                          .
                        </div>
                      ) : null}
                      {policyEngine.summary?.last_decision ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last decision {policyEngine.summary.last_decision}
                          {policyEngine.summary.last_evaluated_at
                            ? ` at ${policyEngine.summary.last_evaluated_at}`
                            : ""}
                          .
                        </div>
                      ) : null}
                      {policyEngine.rules?.some(
                        (rule) => rule.enabled && !rule.valid,
                      ) ? (
                        <div className="mt-2 text-xs text-red-700">
                          One or more enabled rules have invalid expressions.
                        </div>
                      ) : policyEngine.rules?.some(
                          (rule) => rule.enabled && rule.legacy,
                        ) ? (
                        <div className="mt-2 text-xs text-amber-700">
                          Legacy match conditions are still enabled for
                          migration.
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={policyEngine.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {certificateLifecycle ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Certificate Lifecycle
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {certificateLifecycle.message ||
                          "Certificate lifecycle state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode{" "}
                          {certificateLifecycle.policy?.mode || "monitor"}
                        </div>
                        <div>
                          Issuer{" "}
                          {certificateLifecycle.policy?.active_issuer ||
                            "not set"}
                        </div>
                        <div>
                          Events{" "}
                          {certificateLifecycle.runtime?.total_events ?? 0}
                        </div>
                        <div>
                          Renewal due{" "}
                          {certificateLifecycle.runtime
                            ?.renewal_due_inventory ?? 0}
                        </div>
                        <div>
                          Revocation blocks{" "}
                          {certificateLifecycle.runtime
                            ?.revocation_blocked ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Template{" "}
                        {certificateLifecycle.policy?.default_template ||
                          "device-eap-tls"}
                        ; CA{" "}
                        {certificateLifecycle.policy?.ca_ready
                          ? "ready"
                          : "not ready"}
                        ; enrollment{" "}
                        {certificateLifecycle.policy
                          ?.certificate_enrollment_ready
                          ? "ready"
                          : "not ready"}
                        ; revocation{" "}
                        {certificateLifecycle.policy?.revocation_available
                          ? "available"
                          : "not configured"}
                        ; escrow{" "}
                        {certificateLifecycle.policy?.escrow_policy ||
                          "forbid"}
                        .
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        EST{" "}
                        {certificateLifecycle.policy?.est_enabled
                          ? "on"
                          : "off"}
                        ; SCEP{" "}
                        {certificateLifecycle.policy?.scep_enabled
                          ? "on"
                          : "off"}
                        ; BYOD{" "}
                        {certificateLifecycle.policy?.byod_portal_enabled
                          ? "on"
                          : "off"}
                        ; active inventory{" "}
                        {certificateLifecycle.runtime?.active_inventory ?? 0}.
                      </div>
                      {certificateLifecycle.runtime?.last_rejected_reason ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last certificate rejection:{" "}
                          {certificateLifecycle.runtime.last_rejected_reason}
                        </div>
                      ) : null}
                      {certificateLifecycle.blocking_issues?.length ? (
                        <div className="mt-2 text-xs text-red-700">
                          {certificateLifecycle.blocking_issues[0]}
                        </div>
                      ) : certificateLifecycle.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {certificateLifecycle.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge
                      status={certificateLifecycle.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {supplicantLifecycle ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Password And Supplicant Lifecycle
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {supplicantLifecycle.message ||
                          "Supplicant lifecycle state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode{" "}
                          {supplicantLifecycle.policy?.mode || "monitor"}
                        </div>
                        <div>
                          SSID{" "}
                          {supplicantLifecycle.policy?.ssid || "not set"}
                        </div>
                        <div>
                          Events{" "}
                          {supplicantLifecycle.runtime?.total_events ?? 0}
                        </div>
                        <div>
                          Profiles{" "}
                          {supplicantLifecycle.runtime?.profiles_delivered ??
                            0}
                        </div>
                        <div>
                          Change prompts{" "}
                          {supplicantLifecycle.runtime
                            ?.password_change_required ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Platforms{" "}
                        {supplicantLifecycle.policy?.allowed_platforms?.join(
                          ", ",
                        ) || "none"}
                        ; EAP{" "}
                        {supplicantLifecycle.policy?.allowed_eap_methods?.join(
                          ", ",
                        ) || "none"}
                        ; signing{" "}
                        {supplicantLifecycle.policy
                          ?.profile_signing_key_configured
                          ? "configured"
                          : "missing"}
                        ; trust pins{" "}
                        {supplicantLifecycle.policy?.trust_anchor_pins
                          ?.length ?? 0}
                        .
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Portal{" "}
                        {supplicantLifecycle.policy?.portal_ready
                          ? "ready"
                          : "not ready"}
                        ; EAP framework{" "}
                        {supplicantLifecycle.policy?.eap_framework_ready
                          ? "ready"
                          : "not ready"}
                        ; certificate lifecycle{" "}
                        {supplicantLifecycle.policy
                          ?.certificate_lifecycle_ready
                          ? "ready"
                          : "not ready"}
                        ; active profiles{" "}
                        {supplicantLifecycle.runtime?.active_profiles ?? 0}.
                      </div>
                      {supplicantLifecycle.runtime?.last_rejected_reason ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last supplicant rejection:{" "}
                          {supplicantLifecycle.runtime.last_rejected_reason}
                        </div>
                      ) : null}
                      {supplicantLifecycle.blocking_issues?.length ? (
                        <div className="mt-2 text-xs text-red-700">
                          {supplicantLifecycle.blocking_issues[0]}
                        </div>
                      ) : supplicantLifecycle.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {supplicantLifecycle.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge
                      status={supplicantLifecycle.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {fallbackPolicy ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Outage Fallback Policy
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {fallbackPolicy.message ||
                          "Fallback policy state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>Mode {fallbackPolicy.policy?.mode || "monitor"}</div>
                        <div>
                          Window{" "}
                          {fallbackPolicy.policy?.max_outage_seconds ?? 0}s
                        </div>
                        <div>
                          Users{" "}
                          {fallbackPolicy.summary?.allowed_user_count ?? 0}
                        </div>
                        <div>
                          Realms{" "}
                          {fallbackPolicy.summary?.allowed_realm_count ?? 0}
                        </div>
                        <div>
                          Decisions{" "}
                          {fallbackPolicy.audit_summary?.total_records ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Local{" "}
                        {fallbackPolicy.policy?.allow_portal_local
                          ? "allowed"
                          : "blocked"}
                        ; LDAP{" "}
                        {fallbackPolicy.policy?.allow_ldap
                          ? "allowed"
                          : "blocked"}
                        ; allowlist{" "}
                        {fallbackPolicy.summary?.identity_allowlist_set
                          ? "configured"
                          : "empty"}
                        {fallbackPolicy.summary?.active_outage
                          ? `; outage active${
                              fallbackPolicy.summary?.fallback_expires_at
                                ? ` until ${fallbackPolicy.summary.fallback_expires_at}`
                                : ""
                            }`
                          : ""}
                        .
                      </div>
                      {fallbackPolicy.audit_summary?.last_decision ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last {fallbackPolicy.audit_summary.last_decision}:{" "}
                          {fallbackPolicy.audit_summary.last_reason ||
                            "no reason recorded"}
                        </div>
                      ) : null}
                      {fallbackPolicy.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {fallbackPolicy.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={fallbackPolicy.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {identityFailover ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Identity Source Failover
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {identityFailover.message ||
                          "Identity source failover state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode {identityFailover.policy?.mode || "monitor"}
                        </div>
                        <div>
                          Sources{" "}
                          {identityFailover.summary
                            ?.executable_source_count ?? 0}
                          /{identityFailover.summary?.source_count ?? 0}
                        </div>
                        <div>
                          Open circuits{" "}
                          {identityFailover.summary?.open_circuit_count ?? 0}
                        </div>
                        <div>
                          Cache{" "}
                          {identityFailover.policy?.cache_credentials
                            ? "on"
                            : "off"}
                        </div>
                        <div>
                          Decisions{" "}
                          {identityFailover.audit_summary?.total_records ?? 0}
                        </div>
                      </div>
                      {identityFailover.policy?.source_order?.length ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Order{" "}
                          {identityFailover.policy.source_order.join(" -> ")}.
                        </div>
                      ) : null}
                      {identityFailover.sources?.length ? (
                        <div className="mt-2 text-xs text-gray-500">
                          {identityFailover.sources
                            .slice(0, 3)
                            .map((source) =>
                              `${source.name}: ${
                                source.executable ? "ready" : source.reason || "not ready"
                              }${
                                source.circuit_state?.state === "open"
                                  ? ` until ${source.circuit_state.reopens_at || "later"}`
                                  : ""
                              }`,
                            )
                            .join("; ")}
                          {identityFailover.sources.length > 3
                            ? `; ${identityFailover.sources.length - 3} more`
                            : ""}
                          .
                        </div>
                      ) : null}
                      {identityFailover.audit_summary?.last_decision ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last {identityFailover.audit_summary.last_decision}:{" "}
                          {identityFailover.audit_summary.last_reason ||
                            "no reason recorded"}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge
                      status={identityFailover.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {identityActiveDirectory ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Active Directory
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {identityActiveDirectory.message ||
                          "Active Directory identity state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode{" "}
                          {identityActiveDirectory.policy?.mode || "monitor"}
                        </div>
                        <div>
                          Method{" "}
                          {identityActiveDirectory.policy?.auth_method ||
                            "ldap_bind"}
                        </div>
                        <div>
                          Cache{" "}
                          {identityActiveDirectory.summary?.group_cache_enabled
                            ? "on"
                            : "off"}
                        </div>
                        <div>
                          Decisions{" "}
                          {identityActiveDirectory.audit_summary
                            ?.total_records ?? 0}
                        </div>
                        <div>
                          Health{" "}
                          {identityActiveDirectory.health_summary
                            ?.last_status || "none"}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Domain{" "}
                        {identityActiveDirectory.policy?.domain ||
                          "not configured"}
                        ; realm{" "}
                        {identityActiveDirectory.policy?.realm ||
                          "not configured"}
                        ; source{" "}
                        {identityActiveDirectory.summary?.source_executable
                          ? "ready"
                          : identityActiveDirectory.summary?.source_reason ||
                            "not ready"}
                        .
                      </div>
                      {identityActiveDirectory.audit_summary?.last_decision ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last{" "}
                          {
                            identityActiveDirectory.audit_summary
                              .last_decision
                          }
                          :{" "}
                          {identityActiveDirectory.audit_summary
                            .last_reason || "no reason recorded"}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge
                      status={identityActiveDirectory.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {identityMFA ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        OTP And Challenge MFA
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {identityMFA.message ||
                          "MFA challenge state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>Mode {identityMFA.policy?.mode || "monitor"}</div>
                        <div>
                          Enrolled{" "}
                          {identityMFA.credentials?.enabled_users ?? 0}
                        </div>
                        <div>
                          Pending{" "}
                          {identityMFA.credentials?.pending_challenges ?? 0}
                        </div>
                        <div>
                          Recovery{" "}
                          {identityMFA.credentials
                            ?.recovery_codes_available ?? 0}
                        </div>
                        <div>
                          Decisions{" "}
                          {identityMFA.audit_summary?.total_records ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        OTP {identityMFA.policy?.otp_enabled ? "on" : "off"};
                        challenge{" "}
                        {identityMFA.policy?.challenge_enabled ? "on" : "off"};
                        fail closed{" "}
                        {identityMFA.policy?.fail_closed ? "yes" : "no"}.
                      </div>
                      {identityMFA.audit_summary?.last_decision ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last {identityMFA.audit_summary.last_decision}:{" "}
                          {identityMFA.audit_summary.last_reason ||
                            "no reason recorded"}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={identityMFA.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {identityWebAuthn ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Admin Passkeys
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {identityWebAuthn.message ||
                          "Admin WebAuthn passkey state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Mode {identityWebAuthn.policy?.mode || "monitor"}
                        </div>
                        <div>
                          Credentials{" "}
                          {identityWebAuthn.credentials
                            ?.enabled_credentials ?? 0}
                        </div>
                        <div>
                          Pending{" "}
                          {identityWebAuthn.credentials
                            ?.pending_challenges ?? 0}
                        </div>
                        <div>
                          Origins{" "}
                          {identityWebAuthn.summary?.origin_count ?? 0}
                        </div>
                        <div>
                          Decisions{" "}
                          {identityWebAuthn.audit_summary?.total_records ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        RP{" "}
                        {identityWebAuthn.policy?.rp_id ||
                          "not configured"}
                        ; user verification{" "}
                        {identityWebAuthn.policy?.user_verification ||
                          "preferred"}
                        ; break-glass{" "}
                        {identityWebAuthn.policy?.break_glass_allowed
                          ? "allowed"
                          : "blocked"}
                        .
                      </div>
                      {identityWebAuthn.audit_summary?.last_decision ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last {identityWebAuthn.audit_summary.last_decision}:{" "}
                          {identityWebAuthn.audit_summary.last_reason ||
                            "no reason recorded"}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge
                      status={identityWebAuthn.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {identityMAB ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        MAC Authentication Bypass
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {identityMAB.message ||
                          "MAB endpoint and decision state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>Mode {identityMAB.policy?.mode || "monitor"}</div>
                        <div>
                          Approved{" "}
                          {identityMAB.endpoint_summary?.approved_count ?? 0}
                        </div>
                        <div>
                          Quarantine{" "}
                          {identityMAB.endpoint_summary
                            ?.quarantined_count ?? 0}
                        </div>
                        <div>
                          Unknown{" "}
                          {identityMAB.policy?.unknown_endpoint_policy ||
                            "deny"}
                        </div>
                        <div>
                          Decisions{" "}
                          {identityMAB.audit_summary?.total_records ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Formats{" "}
                        {(identityMAB.policy?.mac_formats || []).join(", ") ||
                          "default"}
                        ; fail closed{" "}
                        {identityMAB.policy?.fail_closed ? "yes" : "no"}.
                      </div>
                      {identityMAB.audit_summary?.last_decision ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last {identityMAB.audit_summary.last_decision}:{" "}
                          {identityMAB.audit_summary.last_reason ||
                            "no reason recorded"}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={identityMAB.status || "unknown"} />
                  </div>
                </div>
              ) : null}
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
              {accountingSpool ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Durable Accounting Spool
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {accountingSpool.message ||
                          "Accounting spool state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Queued{" "}
                          {accountingSpool.summary?.queued_count ?? 0}
                        </div>
                        <div>
                          Retrying{" "}
                          {accountingSpool.summary?.retrying_count ?? 0}
                        </div>
                        <div>
                          Due {accountingSpool.summary?.due_count ?? 0}
                        </div>
                        <div>
                          Poison{" "}
                          {accountingSpool.summary?.poison_count ?? 0}
                        </div>
                        <div>
                          Used{" "}
                          {accountingSpool.summary
                            ?.queue_utilization_percent ?? 0}
                          %
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Sent {accountingSpool.summary?.sent_count ?? 0};
                        expired {accountingSpool.summary?.expired_count ?? 0};
                        attempts{" "}
                        {accountingSpool.summary?.attempt_count ?? 0}
                        {accountingSpool.summary?.next_attempt_at
                          ? `; next ${accountingSpool.summary.next_attempt_at}`
                          : ""}
                      </div>
                    </div>
                    <StatusBadge status={accountingSpool.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {sqlAccounting ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        FreeRADIUS SQL Accounting
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {sqlAccounting.message ||
                          "SQL accounting reconciliation state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-4">
                        <div>
                          radacct {sqlAccounting.summary?.radacct_rows ?? 0}
                        </div>
                        <div>
                          postauth{" "}
                          {sqlAccounting.summary?.radpostauth_rows ?? 0}
                        </div>
                        <div>
                          Pending{" "}
                          {sqlAccounting.summary?.pending_rows ?? 0}
                        </div>
                        <div>
                          Errors {sqlAccounting.summary?.error_rows ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Reconciled{" "}
                        {sqlAccounting.summary?.reconciled_rows ?? 0}; open{" "}
                        {sqlAccounting.summary?.open_sessions ?? 0}; closed{" "}
                        {sqlAccounting.summary?.closed_sessions ?? 0}; stale{" "}
                        {sqlAccounting.summary?.stale_pending_rows ?? 0}
                      </div>
                    </div>
                    <StatusBadge status={sqlAccounting.status || "unknown"} />
                  </div>
                </div>
              ) : null}
              {accountingOrdering ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Accounting Ordering
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {accountingOrdering.message ||
                          "Accounting event ordering state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-4">
                        <div>
                          Events{" "}
                          {accountingOrdering.summary?.total_events ?? 0}
                        </div>
                        <div>
                          Applied{" "}
                          {accountingOrdering.summary?.applied_events ?? 0}
                        </div>
                        <div>
                          Pending{" "}
                          {accountingOrdering.summary?.pending_events ?? 0}
                        </div>
                        <div>
                          Errors{" "}
                          {accountingOrdering.summary?.error_events ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Duplicates{" "}
                        {accountingOrdering.summary?.duplicate_events ?? 0};
                        reordered{" "}
                        {accountingOrdering.summary?.reordered_events ?? 0};
                        late Stop{" "}
                        {accountingOrdering.summary?.late_stop_events ?? 0};
                        stale{" "}
                        {accountingOrdering.summary?.stale_pending_events ?? 0}
                      </div>
                    </div>
                    <StatusBadge
                      status={accountingOrdering.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {accountingCounters ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Accounting Counters
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {accountingCounters.message ||
                          "64-bit counter and gigaword state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-4">
                        <div>
                          Events {accountingCounters.summary?.event_rows ?? 0}
                        </div>
                        <div>
                          Gigawords{" "}
                          {accountingCounters.summary?.gigaword_rows ?? 0}
                        </div>
                        <div>
                          Resets {accountingCounters.summary?.reset_events ?? 0}
                        </div>
                        <div>
                          Errors{" "}
                          {accountingCounters.summary?.counter_error_rows ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Rollover{" "}
                        {accountingCounters.summary?.rollover_events ?? 0};
                        max in{" "}
                        {accountingCounters.summary?.max_input_octets_64 ??
                          "0"};
                        max out{" "}
                        {accountingCounters.summary?.max_output_octets_64 ??
                          "0"}
                      </div>
                    </div>
                    <StatusBadge
                      status={accountingCounters.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {dynamicNASClients ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Dynamic NAS Clients
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {dynamicNASClients.message ||
                          "Dynamic NAS client lifecycle state is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500 sm:grid-cols-5">
                        <div>
                          Pending{" "}
                          {dynamicNASClients.summary?.pending_enrollments ?? 0}
                        </div>
                        <div>
                          Approved{" "}
                          {dynamicNASClients.summary
                            ?.approved_enrollments ?? 0}
                        </div>
                        <div>
                          Dynamic{" "}
                          {dynamicNASClients.summary?.dynamic_clients ?? 0}
                        </div>
                        <div>
                          Static{" "}
                          {dynamicNASClients.summary?.static_clients ?? 0}
                        </div>
                        <div>
                          Templates{" "}
                          {dynamicNASClients.summary
                            ?.capability_templates ?? 0}
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-gray-500">
                        Approval{" "}
                        {dynamicNASClients.policy?.approval_required
                          ? "required"
                          : "automatic"}
                        ; discovery{" "}
                        {dynamicNASClients.policy?.discovery_enabled
                          ? "enabled"
                          : "disabled"}
                        ; token{" "}
                        {dynamicNASClients.policy?.enrollment_token_ref_set
                          ? "configured"
                          : "missing"}
                        .
                        {dynamicNASClients.summary?.last_event_at
                          ? ` Last event ${dynamicNASClients.summary.last_event_at}.`
                          : ""}
                      </div>
                      {dynamicNASClients.warnings?.length ? (
                        <div className="mt-2 text-xs text-amber-700">
                          {dynamicNASClients.warnings[0]}
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge
                      status={dynamicNASClients.status || "unknown"}
                    />
                  </div>
                </div>
              ) : null}
              {packetHardening ? (
                <div className="rounded-md border border-gray-200 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-gray-900">
                        Packet Hardening
                      </div>
                      <div className="mt-1 text-sm text-gray-600">
                        {packetHardening.message ||
                          "Packet hardening policy is available."}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-2 text-xs text-gray-500">
                        <div>
                          Message-Authenticator{" "}
                          {packetHardening.policy
                            ?.require_message_authenticator || "auto"}
                        </div>
                        <div>
                          Fail closed{" "}
                          {packetHardening.policy?.fail_closed ? "yes" : "no"}
                        </div>
                        <div>
                          Replay window{" "}
                          {packetHardening.limits?.replay_window_seconds ?? 0}s
                        </div>
                        <div>
                          Rate{" "}
                          {packetHardening.limits
                            ?.per_client_rate_limit_per_second ?? 0}
                          /s burst{" "}
                          {packetHardening.limits?.per_client_burst ?? 0}
                        </div>
                        <div>
                          Rejects{" "}
                          {packetHardening.runtime_stats?.rejected_count ?? 0}
                        </div>
                        <div>
                          MA rejects{" "}
                          {packetHardening.runtime_stats
                            ?.message_authenticator_rejects ?? 0}
                        </div>
                      </div>
                      {packetHardening.runtime_stats?.last_event_at ? (
                        <div className="mt-2 text-xs text-gray-500">
                          Last hardening event{" "}
                          {packetHardening.runtime_stats.last_event_at}.
                        </div>
                      ) : null}
                    </div>
                    <StatusBadge status={packetHardening.status || "unknown"} />
                  </div>
                </div>
              ) : null}
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
					{systemStatus.integrations.controller.enabled ? (
						<div className="mt-4 border-t border-gray-200 pt-4">
							<div className="flex flex-wrap gap-2">
								<button
									type="button"
									onClick={() => previewControllerSync("pull")}
									disabled={Boolean(controllerBusy)}
									className="rounded-md border border-gray-300 px-3 py-2 text-xs font-medium text-gray-700 disabled:opacity-50"
								>
									Preview Pull
								</button>
								<button
									type="button"
									onClick={() => runControllerSync("pull")}
									disabled={
										Boolean(controllerBusy) ||
										!canRunControllerSync ||
										systemStatus.integrations.controller.ready === false
									}
									className="rounded-md bg-sky-700 px-3 py-2 text-xs font-medium text-white disabled:opacity-50"
								>
									{controllerBusy === "pull" ? "Checking..." : "Pull And Check Drift"}
								</button>
								<button
									type="button"
									onClick={() => previewControllerSync("push")}
									disabled={Boolean(controllerBusy)}
									className="rounded-md border border-gray-300 px-3 py-2 text-xs font-medium text-gray-700 disabled:opacity-50"
								>
									Preview Push
								</button>
							</div>
							{canRunControllerSync ? (
								<div className="mt-3 flex flex-wrap items-end gap-2">
									<label className="min-w-64 flex-1 text-xs font-medium text-gray-700">
										Push confirmation phrase
										<input
											value={controllerConfirmation}
											onChange={(event) => setControllerConfirmation(event.target.value)}
											placeholder="PUSH CONTROLLER POLICY"
											className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm"
										/>
									</label>
									<button
										type="button"
										onClick={() => runControllerSync("push")}
										disabled={
											Boolean(controllerBusy) ||
											controllerConfirmation !== "PUSH CONTROLLER POLICY" ||
											systemStatus.integrations.controller.ready === false
										}
										className="rounded-md bg-red-700 px-3 py-2 text-xs font-medium text-white disabled:opacity-50"
									>
										{controllerBusy === "push" ? "Pushing..." : "Push Controller Policy"}
									</button>
								</div>
							) : null}
							{controllerPreview ? (
								<div className="mt-3 text-xs text-gray-600 break-all">
									{controllerPreview.method} {controllerPreview.target_url}
									<br />Desired state {controllerPreview.desired_state_hash}
								</div>
							) : null}
							{controllerMessage ? (
								<div className="mt-3 text-xs text-emerald-700">{controllerMessage}</div>
							) : null}
							{controllerResult?.drift_detected ? (
								<div className="mt-2 text-xs text-amber-700">
									Detected {controllerResult.drift_count} controller drift item(s).
								</div>
							) : null}
							{controllerError ? (
								<div className="mt-3 text-xs text-red-700">{String(controllerError)}</div>
							) : null}
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
