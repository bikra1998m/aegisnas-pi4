import { ChangeEvent, useEffect, useRef, useState } from "react";
import api from "../api/client";

type JsonMap = Record<string, any>;
type Option = { value: string; label: string };
type DeploymentCapability = {
  key: string;
  label: string;
  state: "enabled" | "available" | "warned" | "degraded" | "blocked";
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

type SubscriberServiceChainSummary = {
  total_chains: number;
  active_chains: number;
  failed_chains: number;
  rolled_back_chains: number;
  total_services: number;
  activated_services: number;
  failed_services: number;
  rolled_back_services: number;
  total_events: number;
  failed_events: number;
  started_accounting: number;
  last_chain_id?: string;
  last_status?: string;
  last_updated_at?: string;
};

type SubscriberServiceChainRecord = {
  chain_id: string;
  session_id: string;
  status: string;
  service_count: number;
  activated_count: number;
  failed_count: number;
  rolled_back_count: number;
  activation_mode: string;
  updated_at: string;
};

type SubscriberServiceChainsReport = {
  schema_version: number;
  status: string;
  message: string;
  config: {
    typed_engine_enabled: boolean;
    fail_closed: boolean;
    audit_enabled: boolean;
    max_service_chain_length: number;
  };
  summary: SubscriberServiceChainSummary;
  recent_chains: SubscriberServiceChainRecord[];
};

type TACACSSummary = {
  configured_clients: number;
  enabled_clients: number;
  effective_sets: number;
  enabled_sets: number;
};

type TACACSDBSummary = {
  authorization_events: number;
  permit_count: number;
  deny_count: number;
  accounting_records: number;
  last_authorization_state?: string;
};

type TACACSReport = {
  schema_version: number;
  enabled: boolean;
  status: string;
  message: string;
  summary: TACACSSummary;
  db_summary: TACACSDBSummary;
  warnings?: string[];
};

type SQLAccountingReport = {
  schema_version: number;
  enabled: boolean;
  status: string;
  message: string;
  summary: {
    radacct_rows: number;
    radpostauth_rows: number;
    pending_rows: number;
    stale_pending_rows: number;
    error_rows: number;
    reconciled_rows: number;
    open_sessions: number;
    closed_sessions: number;
    session_rows: number;
    last_accounting_at?: string;
    last_reconciled_at?: string;
  };
  recent?: Array<{
    radacctid: number;
    acctsessionid: string;
    username?: string;
    nasipaddress?: string;
    acctupdatetime?: string;
    acctstoptime?: string;
    aegis_reconcile_status: string;
  }>;
  warnings?: string[];
};

type AccountingOrderingReport = {
  schema_version: number;
  enabled: boolean;
  status: string;
  message: string;
  summary: {
    total_events: number;
    pending_events: number;
    applied_events: number;
    error_events: number;
    ignored_events: number;
    duplicate_events: number;
    reordered_events: number;
    late_stop_events: number;
    stale_pending_events: number;
    last_event_at?: string;
    last_applied_at?: string;
  };
  warnings?: string[];
};

type AccountingCountersReport = {
  schema_version: number;
  enabled: boolean;
  status: string;
  message: string;
  summary: {
    radacct_rows: number;
    event_rows: number;
    gigaword_rows: number;
    rollover_events: number;
    reset_events: number;
    counter_error_rows: number;
    max_input_octets_64: string;
    max_output_octets_64: string;
    last_counter_event_at?: string;
    last_counter_status?: string;
  };
  warnings?: string[];
};

type AccountingIPReport = {
  schema_version: number;
  enabled: boolean;
  status: string;
  message: string;
  summary: {
    assignment_rows: number;
    active_assignments: number;
    closed_assignments: number;
    ipv4_address_rows: number;
    ipv6_address_rows: number;
    ipv6_prefix_rows: number;
    delegated_prefix_rows: number;
    ipv4_route_rows: number;
    ipv6_route_rows: number;
    invalid_rows: number;
    session_rows_with_ipv6: number;
    session_rows_with_delegated_prefix: number;
    session_rows_with_route: number;
    last_assignment_at?: string;
    last_validation_status?: string;
    last_validation_error?: string;
  };
  warnings?: string[];
};

type AccountingServicesReport = {
  schema_version: number;
  enabled: boolean;
  status: string;
  message: string;
  summary: {
    correlation_rows: number;
    active_correlations: number;
    closed_correlations: number;
    conflict_correlations: number;
    unmatched_correlations: number;
    linked_subscriber_services: number;
    parent_sessions: number;
    child_sessions: number;
    data_services: number;
    voice_services: number;
    bearer_services: number;
    reauth_services: number;
    vpn_services: number;
    primary_services: number;
    acct_multi_session_rows: number;
    call_leg_rows: number;
    bearer_leg_rows: number;
    last_correlation_at?: string;
    last_correlation_status?: string;
    last_correlation_error?: string;
  };
  warnings?: string[];
};

type TenantIsolationReport = {
  schema_version: number;
  status: string;
  message: string;
  config: {
    multi_tenant_enabled: boolean;
    delegated_admin_enabled: boolean;
    isolation_mode: string;
    fail_closed: boolean;
    tenant_profile_required: boolean;
    enforce_policy_set_ownership: boolean;
    enforce_resource_ownership: boolean;
    resource_audit_enabled: boolean;
    resource_retention_limit: number;
    shared_resource_types: string[];
  };
  summary: {
    tenant_count: number;
    active_tenant_count: number;
    resource_binding_count: number;
    policy_set_tenant_count: number;
    denied_event_count: number;
    monitor_event_count: number;
  };
  checks: Array<{
    key: string;
    status: string;
    detail: string;
    required: boolean;
  }>;
};

const certificateLifecycleDefaults: JsonMap = {
  enabled: false,
  mode: "monitor",
  fail_closed: true,
  default_template: "device-eap-tls",
  templates: ["device-eap-tls", "byod-eap-tls"],
  active_issuer: "aegisnas-local",
  staged_issuer: "",
  issuer_rotation_mode: "disabled",
  issuer_overlap_seconds: 2592000,
  certificate_validity_days: 365,
  max_certificate_validity_days: 825,
  renewal_window_days: 30,
  require_csr: true,
  require_proof_of_possession: true,
  require_device_binding: true,
  require_subject_alt_name: true,
  allowed_key_types: ["rsa", "ecdsa", "ed25519"],
  min_rsa_bits: 2048,
  allowed_ecdsa_curves: ["P-256", "P-384", "P-521"],
  allow_server_key_generation: false,
  escrow_policy: "forbid",
  crl_enabled: false,
  crl_publish_path: "/var/lib/aegisnas/pki/crl",
  ocsp_enabled: false,
  ocsp_responder_url: "",
  est_enabled: true,
  scep_enabled: true,
  byod_portal_enabled: true,
  audit_enabled: true,
  event_retention_limit: 6000,
  inventory_retention_limit: 100000,
};

const supplicantLifecycleDefaults: JsonMap = {
  enabled: false,
  mode: "monitor",
  fail_closed: true,
  ssid: "AegisNAS-Enterprise",
  security: "wpa2-enterprise",
  default_platform: "windows",
  allowed_platforms: ["windows", "macos", "ios", "android", "linux"],
  default_eap_method: "tls",
  allowed_eap_methods: ["tls", "peap", "ttls"],
  default_inner_method: "mschapv2",
  allowed_inner_methods: ["mschapv2", "pap", "gtc", "tls"],
  anonymous_identity: "anonymous@aegisnas.local",
  require_anonymous_identity: true,
  domain_suffix: "",
  server_names: [],
  trust_anchor_pins: [],
  require_trust_anchor_pinning: true,
  allow_password_change: true,
  password_change_url: "",
  password_change_providers: ["local", "active-directory", "identity-failover"],
  require_verifier_compatibility: true,
  compatible_verifiers: [
    "local",
    "ldap",
    "active-directory",
    "identity-failover",
    "winbind",
  ],
  max_password_age_days: 90,
  expiry_warning_days: 14,
  grace_period_days: 7,
  min_password_length: 12,
  require_mfa_for_change: true,
  require_tls_for_delivery: true,
  require_signed_profiles: true,
  profile_signing_key_ref: "",
  profile_validity_days: 365,
  delivery_token_ttl_seconds: 900,
  audit_enabled: true,
  event_retention_limit: 6000,
  profile_retention_limit: 100000,
};

const defaultSettings: JsonMap = {
  mode: "two-nic",
  admin_port: 8083,
  deployment: {
    profile: "branch",
    form: "physical",
    hardware: {
      memory_mb: 4096,
      cpu_cores: 2,
      storage_gb: 32,
      prefer_external_ap: false,
      wireless_passthrough: false,
    },
  },
  wan: { name: "", dhcp: true, address: "", gateway: "", dhcp_range: "" },
  lan: { name: "", dhcp: false, address: "", gateway: "", dhcp_range: "" },
  network: {
    interfaces: [],
    gateways: [],
    dns: {
      upstream_servers: ["8.8.8.8", "8.8.4.4"],
      search_domains: [],
      local_domain: "aegis.local",
    },
    static_routes: [],
    firewall: {
      rules: [],
      free_sites: [],
      dos_protection: {
        enabled: false,
        syn_rate: "50/second",
        icmp_rate: "25/second",
        conn_rate: "200/second",
        burst: 100,
        log_drops: true,
      },
    },
  },
  dhcp: {
    enabled: true,
    lease_time: "12h",
    authoritative: true,
    static_leases: [],
  },
  policy: {
    default_role: "",
    runtime_shaping_enabled: true,
    max_service_chain_length: 16,
  },
  tacacs: {
    enabled: false,
    listen_address: "0.0.0.0",
    port: 49,
    mode: "monitor",
    fail_closed: true,
    secret_ref: "",
    max_packet_bytes: 65535,
    max_args: 64,
    max_command_bytes: 512,
    max_connections: 256,
    idle_timeout_seconds: 300,
    read_timeout_seconds: 15,
    audit_enabled: true,
    retention_limit: 10000,
    require_known_client: true,
    allow_unencrypted: false,
    authentication_source: "local",
    clients: [],
    command_sets: [],
  },
  telemetry: {
    enabled: true,
    prometheus_port: 9090,
    lease_history_poll_seconds: 300,
    support_bundle_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/support-bundles",
      interval_minutes: 360,
      retention_count: 7,
    },
    diagnostics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/diagnostics",
      format: "json",
      interval_minutes: 60,
      retention_count: 14,
    },
    audit_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/audit-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    session_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/session-exports",
      format: "both",
      interval_minutes: 60,
      retention_count: 21,
    },
    session_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/session-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    voucher_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/voucher-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    voucher_aging_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/voucher-aging-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    voucher_redemption_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/voucher-redemption-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    voucher_expiry_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/voucher-expiry-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    guest_lifecycle_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/guest-lifecycle-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    guest_invite_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/guest-invite-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    guest_conversion_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/guest-conversion-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    guest_rejection_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/guest-rejection-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    guest_delivery_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/guest-delivery-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    guest_delivery_failures_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/guest-delivery-failures-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    guest_sponsor_analytics_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/guest-sponsor-analytics-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    integration_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/integration-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    ha_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/ha-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    network_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/network-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    upstream_aaa_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/upstream-aaa-exports",
      format: "json",
      interval_minutes: 60,
      retention_count: 21,
    },
    upgrade_readiness_exports: {
      enabled: false,
      directory: "/var/lib/aegisnas/upgrade-readiness-exports",
      format: "json",
      interval_minutes: 240,
      retention_count: 14,
    },
  },
  ailite: {
    enabled: true,
    mode: "lite",
    provider: "local",
    endpoint: "",
    model: "",
    api_key_env: "AEGIS_AI_API_KEY",
    request_timeout_seconds: 20,
    max_input_events: 200,
    recommendation_limit: 100,
    remote_webhook: "",
  },
  onboarding: {
    device_inventory_enabled: false,
    portal_enabled: false,
    certificate_enrollment_enabled: false,
    eap_tls_enabled: false,
    ca_mode: "none",
    ca_cert_path: "",
    ca_key_path: "",
    ca_enrollment_url: "",
    ca_enrollment_token_env: "",
    certificate_lifecycle: { ...certificateLifecycleDefaults },
    supplicant_lifecycle: { ...supplicantLifecycleDefaults },
  },
  profiling: {
    mac_inventory_enabled: false,
    passive_enabled: false,
    poll_interval_seconds: 300,
    retention_hours: 24,
    posture_enabled: false,
    mdm_sync_enabled: false,
    mdm_provider: "",
    mdm_endpoint: "",
    mdm_api_token_env: "",
    mdm_cache_hours: 12,
    compliance_webhook: "",
    compliance_token_env: "",
    remediation_enabled: false,
  },
  integrations: {
    admin_sso: {
      enabled: false,
      provider: "",
      issuer_url: "",
      client_id: "",
      client_secret_env: "",
      redirect_url: "",
      groups_claim: "",
    },
    siem: {
      enabled: false,
      provider: "",
      endpoint: "",
      api_key_env: "AEGIS_SIEM_API_KEY",
      batch_size: 100,
    },
    controller: {
      enabled: false,
      platform: "",
      endpoint: "",
      api_token_env: "AEGIS_CONTROLLER_API_TOKEN",
      api_username_env: "",
      api_password_env: "",
      radius_profile: "",
      radius_server: "",
      radius_secret_env: "",
      sync_mode: "monitor",
      site: "",
    },
  },
  governance: {
    delegated_admin_enabled: false,
    rbac_mode: "local",
    external_groups_enabled: false,
    multi_tenant_enabled: false,
    tenant_claim: "",
    isolation_mode: "monitor",
    fail_closed: true,
    default_tenant: "",
    max_tenants: 256,
    tenant_profile_required: true,
    enforce_policy_set_ownership: true,
    enforce_resource_ownership: true,
    resource_audit_enabled: true,
    resource_retention_limit: 10000,
    shared_resource_types: [
      "system_status",
      "production_readiness",
      "support_bundle",
      "dictionary_catalog",
      "vendor_compatibility",
      "runtime_status",
    ],
  },
  high_availability: {
    enabled: false,
    role: "standby",
    peer_api_url: "",
    virtual_ip: "",
    heartbeat_interval_seconds: 5,
    failover_timeout_seconds: 20,
    replication_interval_seconds: 300,
    replication_stale_after_seconds: 900,
    split_brain_protection_enabled: true,
    auto_stage_shared_package: false,
    auto_activate_on_failover: false,
    replication_signing_key_env: "",
    replication_encryption_key_env: "",
    witness_api_url: "",
    witness_urls: [],
    witness_quorum: 1,
    witness_weights: {},
    witness_weight_threshold: 0,
    witness_groups: {},
    witness_min_distinct_groups: 0,
    witness_required_groups: [],
    witness_sources: {},
    witness_source_confidence: {},
    witness_required_sources: [],
    witness_required_urls: [],
    witness_required_sources_by_tier: {},
    witness_required_urls_by_tier: {},
    witness_required_groups_by_tier: {},
    witness_policy_mode: "all",
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
    witness_token_env: "",
    witness_signing_key_env: "",
    witness_max_age_seconds: 0,
    witness_required_node: "",
    witness_replay_protection_enabled: false,
    preempt: false,
    preempt_holdoff_seconds: 0,
    shared_state_dir: "/var/lib/aegisnas/ha",
  },
  portal: {
    enabled: true,
    port: 8081,
    listen_ip: "",
    branding: "AegisNAS",
    success_url: "",
    logout_url: "",
    radius_auth: false,
    local_fallback: true,
    guest_workflows: {
      self_registration_enabled: false,
      sponsor_approval_enabled: false,
      invite_delivery: "none",
      approval_delivery: "",
      email_from: "",
      smtp_server: "",
      smtp_port: 587,
      sms_provider: "",
      sms_endpoint: "",
    },
  },
  identity: {
    failover: {
      enabled: true,
      mode: "monitor",
      fail_closed: true,
      source_order: ["local", "active-directory", "ldap-primary"],
      max_failures: 3,
      circuit_open_seconds: 300,
      stale_cache_seconds: 3600,
      cache_credentials: false,
      split_result_policy: "deny",
      health_check_interval_seconds: 60,
      audit_enabled: true,
      retention_limit: 6000,
    },
  },
  active_directory: {
    enabled: false,
    mode: "monitor",
    fail_closed: true,
    domain: "",
    realm: "",
    netbios_domain: "",
    ldap_url: "",
    base_dn: "",
    bind_dn: "",
    bind_password: "",
    bind_password_ref: "",
    user_filter: "(|(userPrincipalName=%p)(sAMAccountName=%u))",
    group_filter: "(|(member=%D)(member:1.2.840.113556.1.4.1941:=%D))",
    require_ldaps: true,
    nested_groups: true,
    auth_method: "ldap_bind",
    default_role: "",
    group_role_mappings: {},
    request_timeout_seconds: 5,
    group_cache_ttl_seconds: 3600,
    health_check_interval_seconds: 60,
    clock_skew_seconds: 300,
    audit_enabled: true,
    retention_limit: 6000,
    kerberos: {
      enabled: false,
      kinit_path: "kinit",
      kdestroy_path: "kdestroy",
      krb5_config_path: "",
      keytab_path: "",
      service_principal: "",
      credential_cache_dir: "",
    },
    winbind: {
      enabled: false,
      domain_join_required: true,
      wbinfo_path: "wbinfo",
      ntlm_auth_path: "/usr/bin/ntlm_auth",
      auth_helper_path: "",
    },
  },
  mfa: {
    enabled: false,
    mode: "monitor",
    fail_closed: true,
    otp: {
      enabled: true,
      issuer: "AegisNAS",
      algorithm: "SHA1",
      digits: 6,
      period_seconds: 30,
      window_steps: 1,
      max_attempts: 5,
      sealing_key_ref: "env:AEGIS_MFA_SEALING_KEY",
      step_up_roles: ["admin", "super_admin", "ops_admin"],
      step_up_realms: [],
      required_for_admins: true,
    },
    radius_challenge: {
      enabled: true,
      ttl_seconds: 300,
      max_pending: 10000,
      prompt: "Enter one-time password",
      state_bytes: 32,
      allow_pap_password_append: true,
    },
    recovery: {
      enabled: true,
      code_count: 10,
      code_bytes: 16,
      code_ttl_seconds: 0,
    },
    audit_enabled: true,
    retention_limit: 6000,
  },
  admin_webauthn: {
    enabled: false,
    mode: "monitor",
    fail_closed: true,
    rp_id: "",
    rp_name: "AegisNAS Admin",
    origins: [],
    challenge_ttl_seconds: 300,
    session_ttl_seconds: 28800,
    max_pending: 10000,
    user_verification: "preferred",
    attestation: "none",
    resident_key: "preferred",
    require_for_roles: ["super_admin", "ops_admin"],
    require_for_sso: true,
    require_for_token_login: true,
    break_glass_allowed: true,
    allow_bootstrap_enrollment: false,
    audit_enabled: true,
    retention_limit: 6000,
  },
  mab: {
    enabled: false,
    mode: "monitor",
    fail_closed: true,
    unknown_endpoint_policy: "deny",
    default_role: "",
    guest_role: "guest",
    quarantine_role: "quarantine",
    allowed_nas_port_types: ["ethernet", "wireless-802.11", "wireless80211"],
    mac_formats: ["colon", "hyphen", "plain", "cisco-dot"],
    password_policy: "accept_known_mac",
    profiling_link_enabled: true,
    endpoint_inventory_fallback: true,
    revalidate_interval_seconds: 300,
    cache_ttl_seconds: 300,
    audit_enabled: true,
    retention_limit: 6000,
  },
  radius: {
    secret: "",
    auth_port: 1812,
    acct_port: 1813,
    max_sessions: 1024,
    cert_dir: "/etc/freeradius/3.0/certs",
    nas_identifier: "aegisnas",
    request_timeout_seconds: 5,
    interim_update_seconds: 300,
    dynamic_auth: { enabled: true, port: 3799 },
    dynamic_clients: {
      enabled: false,
      discovery_enabled: false,
      approval_required: true,
      enrollment_token_ref: "",
      enrollment_ttl_seconds: 86400,
      max_pending: 256,
      discovery_allowed_cidrs: [],
      default_nas_type: "other",
      default_transport: "udp",
      default_template: "default",
    },
    radsec: {
      enabled: false,
      listen_address: "0.0.0.0",
      port: 2083,
      certificate_file: "/etc/aegisnas/radsec/server.crt",
      private_key_file: "/etc/aegisnas/radsec/server.key",
      private_key_password_env: "",
      ca_file: "/etc/aegisnas/radsec/ca.crt",
      ca_path: "",
      check_crl: true,
      check_all_crl: true,
      ca_path_reload_interval: 3600,
      tls_min_version: "1.2",
      tls_max_version: "1.3",
      cipher_list: "DEFAULT@SECLEVEL=2",
      radius_v11: "forbid",
      max_connections: 64,
      lifetime_seconds: 86400,
      idle_timeout_seconds: 300,
      probe_interval_seconds: 30,
      certificate_expiry_warning_days: 30,
    },
    vendor: {
      enabled: false,
      name: "AegisNAS",
      id: 55555,
      dictionary_paths: [],
      role_mappings: [],
      extended_vlan_mappings: [],
      avpair_mappings: [],
      portal_status_mappings: [],
      session_action_mappings: [],
      quota_mappings: [],
      service_name_mappings: [],
      attributes: [],
    },
    eap: {
      default_type: "peap",
      peap_inner: "mschapv2",
      ttls_inner: "mschapv2",
      tls_min_version: "1.2",
      tls_max_version: "1.3",
      check_crl: false,
      check_all_crl: false,
      ca_path_reload_interval: 3600,
      ocsp: {
        enabled: false,
        override_cert_url: false,
        url: "",
        use_nonce: true,
        timeout_seconds: 5,
        soft_fail: false,
      },
      teap: {
        enabled: true,
        default_inner_method: "mschapv2",
        chain_mode: "machine_then_user",
        require_crypto_binding: true,
        require_channel_binding: false,
        require_identity_type: true,
        require_machine_identity: true,
        require_user_identity: true,
        allow_pac: true,
        require_pac: false,
        pac_provisioning: "authenticated",
        pac_authority_id: "aegisnas-teap",
        pac_lifetime_seconds: 2592000,
        allow_eap_payload: true,
        allow_basic_password_auth: false,
        max_chain_steps: 2,
        session_ttl_seconds: 900,
        event_retention_limit: 6000,
      },
      machine_user: {
        enabled: true,
        mode: "monitor",
        fail_closed: true,
        correlation_mode: "machine_then_user",
        require_teap: true,
        require_machine_identity: true,
        require_user_identity: true,
        require_machine_before_user: true,
        require_same_calling_station: true,
        require_same_nas: false,
        require_fresh_machine_auth: true,
        machine_auth_ttl_seconds: 28800,
        user_auth_ttl_seconds: 28800,
        transition_window_seconds: 900,
        allowed_machine_methods: ["teap", "tls"],
        allowed_user_methods: ["teap", "peap", "ttls"],
        identity_precedence: "user_over_machine",
        role_merge_strategy: "user_primary",
        conflict_action: "reject",
        stale_machine_action: "reject",
        machine_identity_prefixes: ["host/", "machine/"],
        user_identity_prefixes: [],
        max_active_correlations: 100000,
        audit_enabled: true,
        event_retention_limit: 6000,
      },
      fast: {
        enabled: true,
        default_inner_method: "mschapv2",
        require_crypto_binding: true,
        allow_pac: true,
        require_pac: false,
        pac_provisioning: "authenticated",
        pac_authority_id: "aegisnas-fast",
        pac_lifetime_seconds: 2592000,
        pac_opaque_key_ref: "",
        allow_anonymous_provisioning: false,
        allow_eap_payload: true,
        max_provisioning_attempts: 3,
        session_ttl_seconds: 900,
        event_retention_limit: 6000,
      },
      pwd: {
        enabled: true,
        group: 19,
        server_id: "aegisnas-pwd",
        require_strong_group: true,
        password_source: "identity-failover",
        allow_local_verifier: true,
        require_identity: true,
        require_password_proof: true,
        replay_window_seconds: 30,
        fragment_size: 1020,
        event_retention_limit: 6000,
      },
      sim_aka: {
        enabled: true,
        methods: ["sim", "aka", "aka-prime"],
        require_identity: true,
        require_permanent_identity: true,
        allow_pseudonym_identity: true,
        require_pseudonym_reauth: false,
        pseudonym_ttl_seconds: 86400,
        reauth_ttl_seconds: 43200,
        vector_provider: "external-http",
        vector_provider_ref: "",
        require_fresh_vectors: true,
        max_vector_age_seconds: 300,
        min_triplets: 2,
        min_quintuplets: 1,
        allow_resynchronization: true,
        resync_window_seconds: 300,
        require_network_name: true,
        network_name: "",
        require_kdf: true,
        fail_on_provider_unavailable: true,
        event_retention_limit: 6000,
      },
      framework: {
        enabled: true,
        mode: "monitor",
        fail_closed: true,
        allowed_methods: ["peap", "ttls", "tls"],
        allowed_inner_methods: ["mschapv2", "pap", "chap", "gtc", "tls"],
        default_outer_identity_source: "configured-default",
        default_inner_identity_source: "identity-failover",
        unsupported_method_action: "reject",
        require_message_authenticator: true,
        require_identity_binding: true,
        telemetry_enabled: true,
        event_retention_limit: 6000,
        max_concurrent_sessions: 0,
        method_timeout_seconds: 60,
        fragment_size: 1024,
        nak_unknown_types: true,
        identity_sources: [
          {
            name: "identity-failover",
            source: "identity_failover",
            enabled: true,
            methods: ["peap", "ttls"],
            allow_password_verifier: true,
            allow_certificate_subject: false,
            priority: 10,
          },
          {
            name: "certificate-subject",
            source: "certificate",
            enabled: true,
            methods: ["tls"],
            allow_password_verifier: false,
            allow_certificate_subject: true,
            priority: 20,
          },
        ],
        method_policies: [
          {
            method: "peap",
            enabled: true,
            inner_methods: ["mschapv2", "gtc"],
            identity_source: "identity-failover",
            allow_password_verifier: true,
            min_tls_version: "1.2",
            max_tls_version: "1.3",
          },
          {
            method: "ttls",
            enabled: true,
            inner_methods: ["mschapv2", "pap", "chap", "gtc"],
            identity_source: "identity-failover",
            allow_password_verifier: true,
            min_tls_version: "1.2",
            max_tls_version: "1.3",
          },
          {
            method: "tls",
            enabled: true,
            identity_source: "certificate-subject",
            require_certificate: true,
            require_revocation: false,
            allow_password_verifier: false,
            min_tls_version: "1.2",
            max_tls_version: "1.3",
          },
        ],
        vendor_compatibility_profiles: [
          {
            name: "enterprise-8021x",
            nas_types: [
              "cisco",
              "aruba",
              "ruckus",
              "extreme",
              "juniper",
              "fortinet",
              "unifi",
              "other",
            ],
            allowed_methods: ["peap", "ttls", "tls"],
            required_methods: [],
            notes: "Baseline RFC 3748 EAP policy for enterprise APs and switches.",
          },
        ],
      },
    },
    sql_accounting: {
      enabled: true,
      reconcile_enabled: true,
      reconcile_interval_seconds: 60,
      batch_size: 500,
      stale_after_seconds: 300,
      accounting_retention_days: 365,
      postauth_retention_days: 30,
    },
    accounting_ordering: {
      enabled: true,
      replay_enabled: true,
      sequence_window_seconds: 300,
      late_stop_window_seconds: 86400,
      max_replay_batch: 1000,
      duplicate_retention_days: 365,
    },
    accounting_counters: {
      enabled: true,
      gigawords_enabled: true,
      reset_detection_enabled: true,
      max_counter_bits: 64,
      overflow_policy: "saturate",
      retention_days: 365,
    },
    accounting_ip: {
      enabled: true,
      ipv6_enabled: true,
      route_accounting_enabled: true,
      delegated_prefix_enabled: true,
      reject_invalid: false,
      retention_days: 365,
    },
    accounting_services: {
      enabled: true,
      correlate_subscriber_chains: true,
      derive_from_class: true,
      derive_from_acct_multi_session_id: true,
      retain_unmatched: true,
      retention_days: 365,
      max_recent_services: 25,
    },
    upstream: {
      enabled: false,
      realm: "aegis-upstream",
      pool_strategy: "fail-over",
      status_check: "status-server",
      response_window: 20,
      zombie_period: 40,
      revive_interval: 120,
      check_interval: 30,
      num_answers_to_alive: 3,
      strip_realm: false,
      transport_policy: {
        enabled: true,
        mode: "monitor",
        fail_closed: true,
        default_required_transport: "any",
        allow_mixed_transports: false,
        route_policies: [],
      },
      accounting_spool: {
        enabled: true,
        max_queue_records: 10000,
        max_attempts: 10,
        initial_retry_seconds: 30,
        max_retry_seconds: 3600,
        record_ttl_seconds: 604800,
        replay_interval_seconds: 60,
        batch_size: 100,
        lock_seconds: 120,
        sent_retention_seconds: 604800,
        poison_retention_seconds: 2592000,
      },
      fallback_policy: {
        enabled: true,
        mode: "monitor",
        fail_closed: true,
        allow_portal_local: true,
        allow_ldap: false,
        require_identity_allowlist: true,
        max_outage_seconds: 900,
        stale_policy_seconds: 3600,
        recovery_successes: 2,
        allowed_users: [],
        allowed_realms: [],
        allowed_roles: [],
        audit_enabled: true,
        retention_limit: 6000,
      },
      servers: [],
    },
  },
  ldap: {
    enabled: false,
    url: "",
    base_dn: "",
    bind_dn: "",
    bind_password: "",
    user_filter: "(uid=%s)",
    group_filter: "(memberUid=%s)",
  },
  wireless: {
    enabled: false,
    country_code: "US",
    interface: "",
    driver: "nl80211",
    hw_mode: "g",
    channel: 6,
    beacon_interval: 100,
    wmm_enabled: true,
    ht_enabled: true,
    ctrl_interface: "/var/run/hostapd",
    hostapd_config_path: "/etc/hostapd/hostapd.conf",
    ssids: [],
  },
};

const clone = <T,>(value: T): T =>
  typeof structuredClone === "function"
    ? structuredClone(value)
    : JSON.parse(JSON.stringify(value));

const deploymentProfileOptions: Option[] = [
  { value: "lite", label: "Lite Edge" },
  { value: "branch", label: "Branch" },
  { value: "enterprise", label: "Enterprise Edge" },
  { value: "custom", label: "Custom" },
];

const deploymentFormOptions: Option[] = [
  { value: "physical", label: "Physical Appliance" },
  { value: "virtual", label: "Virtual Appliance" },
];

const aiModeOptions: Option[] = [
  { value: "lite", label: "AI Lite" },
  { value: "full", label: "Full AI" },
];

const aiProviderOptions: Option[] = [
  { value: "local", label: "Local Rules" },
  { value: "openai-compatible", label: "OpenAI Compatible" },
];

const guestDeliveryOptions: Option[] = [
  { value: "none", label: "None" },
  { value: "email", label: "Email" },
  { value: "sms", label: "SMS" },
];

const approvalDeliveryOptions: Option[] = [
  { value: "", label: "Select delivery" },
  { value: "email", label: "Email" },
  { value: "sms", label: "SMS" },
];

const caModeOptions: Option[] = [
  { value: "none", label: "No CA Yet" },
  { value: "internal", label: "Internal CA Material" },
  { value: "external", label: "External Enrollment API" },
];

const certificateLifecycleModeOptions: Option[] = [
  { value: "monitor", label: "Monitor" },
  { value: "enforce", label: "Enforce" },
];

const certificateLifecycleRotationOptions: Option[] = [
  { value: "disabled", label: "No Rotation" },
  { value: "staged", label: "Staged Issuer" },
];

const certificateEscrowOptions: Option[] = [
  { value: "forbid", label: "Forbid Escrow" },
  { value: "admin-approved", label: "Admin Approved" },
  { value: "allow", label: "Allow" },
];

const supplicantSecurityOptions: Option[] = [
  { value: "wpa2-enterprise", label: "WPA2 Enterprise" },
  { value: "wpa3-enterprise", label: "WPA3 Enterprise" },
];

const supplicantPlatformOptions: Option[] = [
  { value: "windows", label: "Windows" },
  { value: "macos", label: "macOS" },
  { value: "ios", label: "iOS" },
  { value: "android", label: "Android" },
  { value: "linux", label: "Linux" },
];

const adminSSOProviderOptions: Option[] = [
  { value: "", label: "Select provider" },
  { value: "oidc", label: "OIDC" },
  { value: "saml", label: "SAML" },
];

const siemProviderOptions: Option[] = [
  { value: "", label: "Select export type" },
  { value: "webhook", label: "Generic Webhook" },
  { value: "splunk-hec", label: "Splunk HEC" },
  { value: "elastic", label: "Elastic HTTP" },
];

const controllerPlatformOptions: Option[] = [
  { value: "", label: "Select controller" },
  { value: "generic", label: "Generic REST" },
  { value: "cisco", label: "Cisco" },
  { value: "aruba", label: "Aruba" },
  { value: "juniper-mist", label: "Juniper Mist" },
  { value: "ruckus", label: "Ruckus" },
  { value: "fortinet", label: "Fortinet" },
  { value: "mikrotik", label: "MikroTik" },
  { value: "unifi", label: "UniFi" },
  { value: "meraki", label: "Cisco Meraki" },
  { value: "openwifi", label: "TIP OpenWiFi" },
];

const controllerSyncOptions: Option[] = [
  { value: "monitor", label: "Monitor Only" },
  { value: "push-config", label: "Push Config" },
  { value: "coa-only", label: "CoA Only" },
];

const transportPolicyModeOptions: Option[] = [
  { value: "monitor", label: "Monitor" },
  { value: "enforce", label: "Enforce" },
];

const splitResultPolicyOptions: Option[] = [
  { value: "deny", label: "Deny Split Result" },
  { value: "prefer_first", label: "Prefer First Result" },
  { value: "prefer_success", label: "Prefer Successful Result" },
];

const activeDirectoryAuthMethodOptions: Option[] = [
  { value: "ldap_bind", label: "LDAP Bind" },
  { value: "kerberos", label: "Kerberos kinit" },
  { value: "winbind_helper", label: "Winbind Helper" },
];

const mabUnknownPolicyOptions: Option[] = [
  { value: "deny", label: "Deny Unknown" },
  { value: "guest", label: "Guest Role" },
  { value: "quarantine", label: "Quarantine Role" },
  { value: "fail_open", label: "Fail Open" },
];

const mabPasswordPolicyOptions: Option[] = [
  { value: "accept_known_mac", label: "Accept Known MAC" },
  { value: "username_equals_password", label: "Username Equals Password" },
  { value: "calling_station_id", label: "Calling-Station-Id" },
];

const requiredTransportOptions: Option[] = [
  { value: "any", label: "Any Explicit Transport" },
  { value: "radsec", label: "Require RadSec" },
  { value: "udp", label: "Require UDP" },
];

const numericVendorRolePackOptions: Option[] = [
  { value: "cambium", label: "Cambium" },
  { value: "aerohive", label: "Aerohive / ExtremeCloud IQ" },
  { value: "dlink", label: "D-Link" },
  { value: "sonicwall", label: "SonicWall" },
  { value: "zte", label: "ZTE" },
];

const extendedVLANPackOptions: Option[] = [
  { value: "extreme", label: "Extreme Networks" },
];

const avPairPackOptions: Option[] = [
  { value: "juniper", label: "Juniper" },
  { value: "huawei", label: "Huawei" },
  { value: "h3c", label: "H3C" },
  { value: "arista", label: "Arista" },
];

const portalStatusPackOptions: Option[] = [
  { value: "tplink", label: "TP-Link Omada" },
];

const sessionActionPackOptions: Option[] = [
  { value: "nomadix", label: "Nomadix" },
];

const sessionActionOptions: Option[] = [
  { value: "allow", label: "Allow" },
  { value: "reauth", label: "Reauthenticate" },
  { value: "disconnect", label: "Disconnect" },
  { value: "quarantine", label: "Quarantine" },
];

const quotaPackOptions: Option[] = [
  { value: "chillispot", label: "ChilliSpot / CoovaChilli" },
];

const serviceNamePackOptions: Option[] = [
  { value: "nokia", label: "Nokia" },
];

const mdmProviderOptions: Option[] = [
  { value: "", label: "Select MDM or UEM" },
  { value: "generic", label: "Generic API" },
  { value: "workspace-one", label: "Workspace ONE" },
  { value: "intune", label: "Microsoft Intune" },
  { value: "jamf", label: "Jamf" },
];

const rbacModeOptions: Option[] = [
  { value: "local", label: "Local Roles" },
  { value: "external-groups", label: "External Groups" },
  { value: "hybrid", label: "Hybrid" },
];

const tenantIsolationModeOptions: Option[] = [
  { value: "monitor", label: "Monitor" },
  { value: "enforce", label: "Enforce" },
];

const firewallChainOptions: Option[] = [
  { value: "input", label: "Input" },
  { value: "forward", label: "Forward" },
];

const firewallActionOptions: Option[] = [
  { value: "accept", label: "Accept" },
  { value: "drop", label: "Drop" },
  { value: "reject", label: "Reject" },
];

const firewallProtocolOptions: Option[] = [
  { value: "any", label: "Any" },
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "icmp", label: "ICMP" },
];

const freeSiteTypeOptions: Option[] = [
  { value: "domain", label: "Domain" },
  { value: "cidr", label: "CIDR" },
];

const capabilityTone: Record<DeploymentCapability["state"], string> = {
  enabled: "border-emerald-200 bg-emerald-50 text-emerald-800",
  available: "border-sky-200 bg-sky-50 text-sky-800",
  warned: "border-amber-200 bg-amber-50 text-amber-800",
  degraded: "border-orange-200 bg-orange-50 text-orange-800",
  blocked: "border-red-200 bg-red-50 text-red-800",
};

function deploymentProfileSummary(profile: string, form: string) {
  if (profile === "lite") {
    return form === "virtual"
      ? "Constrained VM profile. Prefer an external AP, keep AI and telemetry off, and trim shaping on smaller virtual footprints."
      : "Constrained appliance profile for very small edge hardware. Keep AI, telemetry, and runtime shaping off unless the box has headroom.";
  }
  if (profile === "enterprise") {
    return form === "virtual"
      ? "Higher-capacity VM profile for central AAA, full AI analysis, and larger virtual edge deployments with external APs."
      : "Higher-capacity appliance profile for heavier EAP, full AI analysis, more users, and richer live enforcement.";
  }
  if (profile === "custom") {
    return "Operator-managed profile. Use this when you want to keep manual control over every feature knob.";
  }
  return form === "virtual"
    ? "Balanced VM profile for gateway, portal, and AAA roles with external APs."
    : "Balanced default profile for most branch appliances and pilot production sites.";
}

function applyDeploymentPreset(input: JsonMap): JsonMap {
  const next = clone(input);
  const profile = next.deployment?.profile || "branch";
  const form = next.deployment?.form || "physical";

  next.deployment = next.deployment || {};
  next.deployment.hardware = next.deployment.hardware || {};
  next.network = next.network || {};
  next.network.dns = next.network.dns || {};
  next.network.firewall = next.network.firewall || {};
  next.network.firewall.dos_protection =
    next.network.firewall.dos_protection || {};
  next.policy = next.policy || {};
  next.telemetry = next.telemetry || {};
  next.ailite = next.ailite || {};
  next.onboarding = next.onboarding || {};
  next.onboarding.certificate_lifecycle = {
    ...certificateLifecycleDefaults,
    ...(next.onboarding.certificate_lifecycle || {}),
  };
  next.onboarding.supplicant_lifecycle = {
    ...supplicantLifecycleDefaults,
    ...(next.onboarding.supplicant_lifecycle || {}),
  };
  next.profiling = next.profiling || {};
  next.integrations = next.integrations || {};
  next.integrations.admin_sso = next.integrations.admin_sso || {};
  next.integrations.siem = next.integrations.siem || {};
  next.integrations.controller = next.integrations.controller || {};
  next.governance = next.governance || {};
  next.governance.isolation_mode = next.governance.isolation_mode || "monitor";
  next.governance.fail_closed = next.governance.fail_closed ?? true;
  next.governance.default_tenant = next.governance.default_tenant || "";
  next.governance.max_tenants = next.governance.max_tenants || 256;
  next.governance.tenant_profile_required =
    next.governance.tenant_profile_required ?? true;
  next.governance.enforce_policy_set_ownership =
    next.governance.enforce_policy_set_ownership ?? true;
  next.governance.enforce_resource_ownership =
    next.governance.enforce_resource_ownership ?? true;
  next.governance.resource_audit_enabled =
    next.governance.resource_audit_enabled ?? true;
  next.governance.resource_retention_limit =
    next.governance.resource_retention_limit || 10000;
  next.governance.shared_resource_types =
    next.governance.shared_resource_types || [
      "system_status",
      "production_readiness",
      "support_bundle",
      "dictionary_catalog",
      "vendor_compatibility",
      "runtime_status",
    ];
  next.portal = next.portal || {};
  next.portal.guest_workflows = next.portal.guest_workflows || {};
  next.identity = next.identity || {};
  next.identity.failover = next.identity.failover || {};
  next.active_directory = next.active_directory || {};
  next.active_directory.kerberos = next.active_directory.kerberos || {};
  next.active_directory.winbind = next.active_directory.winbind || {};
  next.mfa = next.mfa || {};
  next.mfa.otp = next.mfa.otp || {};
  next.mfa.radius_challenge = next.mfa.radius_challenge || {};
  next.mfa.recovery = next.mfa.recovery || {};
  next.admin_webauthn = next.admin_webauthn || {};
  next.mab = next.mab || {};
  next.radius = next.radius || {};
  next.tacacs = next.tacacs || {};
  next.radius.eap = next.radius.eap || {};
  next.radius.eap.teap = next.radius.eap.teap || {};
  next.radius.eap.machine_user = next.radius.eap.machine_user || {};
  next.radius.eap.fast = next.radius.eap.fast || {};
  next.radius.eap.pwd = next.radius.eap.pwd || {};
  next.radius.eap.sim_aka = next.radius.eap.sim_aka || {};
  next.radius.eap.framework = next.radius.eap.framework || {};
  next.radius.sql_accounting = next.radius.sql_accounting || {};
  next.radius.accounting_ordering = next.radius.accounting_ordering || {};
  next.radius.accounting_counters = next.radius.accounting_counters || {};
  next.radius.accounting_ip = next.radius.accounting_ip || {};
  next.radius.upstream = next.radius.upstream || {};
  next.radius.upstream.fallback_policy =
    next.radius.upstream.fallback_policy || {};
  next.wireless = next.wireless || {};

  if (profile === "lite") {
    next.ailite.enabled = false;
    next.ailite.mode = "lite";
    next.ailite.provider = "local";
    next.ailite.recommendation_limit = 25;
    next.telemetry.enabled = false;
    next.policy.runtime_shaping_enabled = false;
    next.policy.max_service_chain_length = 8;
    next.tacacs.enabled = false;
    next.tacacs.mode = "monitor";
    next.tacacs.max_connections = 32;
    next.tacacs.retention_limit = 1000;
    next.radius.max_sessions = 256;
    next.radius.interim_update_seconds = 600;
    next.radius.sql_accounting.enabled = true;
    next.radius.sql_accounting.reconcile_enabled = true;
    next.radius.sql_accounting.batch_size = 100;
    next.radius.sql_accounting.reconcile_interval_seconds = 120;
    next.radius.sql_accounting.stale_after_seconds = 600;
    next.radius.sql_accounting.accounting_retention_days = 30;
    next.radius.sql_accounting.postauth_retention_days = 7;
    next.radius.accounting_ordering.enabled = true;
    next.radius.accounting_ordering.replay_enabled = true;
    next.radius.accounting_ordering.sequence_window_seconds = 600;
    next.radius.accounting_ordering.late_stop_window_seconds = 86400;
    next.radius.accounting_ordering.max_replay_batch = 250;
    next.radius.accounting_ordering.duplicate_retention_days = 30;
    next.radius.accounting_counters.enabled = true;
    next.radius.accounting_counters.gigawords_enabled = true;
    next.radius.accounting_counters.reset_detection_enabled = true;
    next.radius.accounting_counters.max_counter_bits = 64;
    next.radius.accounting_counters.overflow_policy = "saturate";
    next.radius.accounting_counters.retention_days = 30;
    next.radius.accounting_ip.enabled = true;
    next.radius.accounting_ip.ipv6_enabled = true;
    next.radius.accounting_ip.route_accounting_enabled = true;
    next.radius.accounting_ip.delegated_prefix_enabled = true;
    next.radius.accounting_ip.reject_invalid = false;
    next.radius.accounting_ip.retention_days = 30;
    next.radius.eap.framework.enabled = true;
    next.radius.eap.framework.mode = "monitor";
    next.radius.eap.framework.max_concurrent_sessions = 256;
    next.radius.eap.framework.event_retention_limit = 1000;
    next.radius.eap.teap.enabled = true;
    next.radius.eap.teap.max_chain_steps = 2;
    next.radius.eap.teap.event_retention_limit = 1000;
    next.radius.eap.machine_user.enabled = true;
    next.radius.eap.machine_user.mode = "monitor";
    next.radius.eap.machine_user.max_active_correlations = 10000;
    next.radius.eap.machine_user.event_retention_limit = 1000;
    next.radius.eap.fast.enabled = true;
    next.radius.eap.fast.event_retention_limit = 1000;
    next.radius.eap.pwd.enabled = true;
    next.radius.eap.pwd.event_retention_limit = 1000;
    next.radius.eap.sim_aka.enabled = true;
    next.radius.eap.sim_aka.event_retention_limit = 1000;
    next.radius.upstream.status_check = "none";
    next.portal.guest_workflows.self_registration_enabled = false;
    next.portal.guest_workflows.sponsor_approval_enabled = false;
    next.portal.guest_workflows.invite_delivery = "none";
    next.portal.guest_workflows.approval_delivery = "";
    next.onboarding.device_inventory_enabled = false;
    next.onboarding.portal_enabled = false;
    next.onboarding.certificate_enrollment_enabled = false;
    next.onboarding.eap_tls_enabled = false;
    next.onboarding.ca_mode = "none";
    next.onboarding.certificate_lifecycle.enabled = false;
    next.onboarding.certificate_lifecycle.mode = "monitor";
    next.onboarding.certificate_lifecycle.event_retention_limit = 1000;
    next.onboarding.certificate_lifecycle.inventory_retention_limit = 10000;
    next.onboarding.supplicant_lifecycle.enabled = false;
    next.onboarding.supplicant_lifecycle.mode = "monitor";
    next.onboarding.supplicant_lifecycle.event_retention_limit = 1000;
    next.onboarding.supplicant_lifecycle.profile_retention_limit = 10000;
    next.admin_webauthn.enabled = false;
    next.mab.enabled = false;
    next.profiling.passive_enabled = false;
    next.profiling.posture_enabled = false;
    next.profiling.mdm_sync_enabled = false;
    next.integrations.admin_sso.enabled = false;
    next.integrations.siem.enabled = false;
    next.integrations.controller.enabled = false;
    next.governance.delegated_admin_enabled = false;
    next.governance.multi_tenant_enabled = false;
  } else if (profile === "enterprise") {
    next.ailite.enabled = true;
    next.ailite.mode = "full";
    next.ailite.provider = "openai-compatible";
    next.ailite.api_key_env = next.ailite.api_key_env || "AEGIS_AI_API_KEY";
    next.ailite.request_timeout_seconds =
      next.ailite.request_timeout_seconds || 20;
    next.ailite.max_input_events = next.ailite.max_input_events || 200;
    next.ailite.recommendation_limit = 250;
    next.telemetry.enabled = true;
    next.policy.runtime_shaping_enabled = true;
    next.policy.max_service_chain_length = 32;
    next.tacacs.enabled = next.tacacs.enabled || false;
    next.tacacs.mode = "enforce";
    next.tacacs.max_connections = next.tacacs.max_connections || 2048;
    next.tacacs.retention_limit = next.tacacs.retention_limit || 100000;
    next.radius.max_sessions = 4096;
    next.radius.interim_update_seconds = 300;
    next.radius.sql_accounting.enabled = true;
    next.radius.sql_accounting.reconcile_enabled = true;
    next.radius.sql_accounting.batch_size =
      next.radius.sql_accounting.batch_size || 1000;
    next.radius.sql_accounting.reconcile_interval_seconds =
      next.radius.sql_accounting.reconcile_interval_seconds || 30;
    next.radius.sql_accounting.stale_after_seconds =
      next.radius.sql_accounting.stale_after_seconds || 300;
    next.radius.sql_accounting.accounting_retention_days =
      next.radius.sql_accounting.accounting_retention_days || 730;
    next.radius.sql_accounting.postauth_retention_days =
      next.radius.sql_accounting.postauth_retention_days || 90;
    next.radius.accounting_ordering.enabled = true;
    next.radius.accounting_ordering.replay_enabled = true;
    next.radius.accounting_ordering.sequence_window_seconds =
      next.radius.accounting_ordering.sequence_window_seconds || 300;
    next.radius.accounting_ordering.late_stop_window_seconds =
      next.radius.accounting_ordering.late_stop_window_seconds || 172800;
    next.radius.accounting_ordering.max_replay_batch =
      next.radius.accounting_ordering.max_replay_batch || 2500;
    next.radius.accounting_ordering.duplicate_retention_days =
      next.radius.accounting_ordering.duplicate_retention_days || 730;
    next.radius.accounting_counters.enabled = true;
    next.radius.accounting_counters.gigawords_enabled = true;
    next.radius.accounting_counters.reset_detection_enabled = true;
    next.radius.accounting_counters.max_counter_bits = 64;
    next.radius.accounting_counters.overflow_policy =
      next.radius.accounting_counters.overflow_policy || "saturate";
    next.radius.accounting_counters.retention_days =
      next.radius.accounting_counters.retention_days || 730;
    next.radius.accounting_ip.enabled = true;
    next.radius.accounting_ip.ipv6_enabled = true;
    next.radius.accounting_ip.route_accounting_enabled = true;
    next.radius.accounting_ip.delegated_prefix_enabled = true;
    next.radius.accounting_ip.reject_invalid =
      next.radius.accounting_ip.reject_invalid ?? false;
    next.radius.accounting_ip.retention_days =
      next.radius.accounting_ip.retention_days || 730;
    next.radius.eap.framework.enabled = true;
    next.radius.eap.framework.max_concurrent_sessions =
      next.radius.eap.framework.max_concurrent_sessions || 4096;
    next.radius.eap.framework.event_retention_limit =
      next.radius.eap.framework.event_retention_limit || 12000;
    next.radius.eap.teap.enabled = true;
    next.radius.eap.teap.max_chain_steps =
      next.radius.eap.teap.max_chain_steps || 2;
    next.radius.eap.teap.event_retention_limit =
      next.radius.eap.teap.event_retention_limit || 12000;
    next.radius.eap.machine_user.enabled = true;
    next.radius.eap.machine_user.max_active_correlations =
      next.radius.eap.machine_user.max_active_correlations || 250000;
    next.radius.eap.machine_user.event_retention_limit =
      next.radius.eap.machine_user.event_retention_limit || 12000;
    next.radius.eap.fast.enabled = true;
    next.radius.eap.fast.event_retention_limit =
      next.radius.eap.fast.event_retention_limit || 12000;
    next.radius.eap.pwd.enabled = true;
    next.radius.eap.pwd.event_retention_limit =
      next.radius.eap.pwd.event_retention_limit || 12000;
    next.radius.eap.sim_aka.enabled = true;
    next.radius.eap.sim_aka.event_retention_limit =
      next.radius.eap.sim_aka.event_retention_limit || 12000;
    next.radius.upstream.status_check = "status-server";
    next.admin_webauthn.challenge_ttl_seconds =
      next.admin_webauthn.challenge_ttl_seconds || 300;
    next.admin_webauthn.session_ttl_seconds =
      next.admin_webauthn.session_ttl_seconds || 28800;
    next.mab.cache_ttl_seconds = next.mab.cache_ttl_seconds || 300;
    next.mab.revalidate_interval_seconds =
      next.mab.revalidate_interval_seconds || 300;
    next.onboarding.ca_mode = next.onboarding.ca_mode || "none";
    next.onboarding.certificate_lifecycle.event_retention_limit =
      next.onboarding.certificate_lifecycle.event_retention_limit || 12000;
    next.onboarding.certificate_lifecycle.inventory_retention_limit =
      next.onboarding.certificate_lifecycle.inventory_retention_limit || 500000;
    next.onboarding.supplicant_lifecycle.event_retention_limit =
      next.onboarding.supplicant_lifecycle.event_retention_limit || 12000;
    next.onboarding.supplicant_lifecycle.profile_retention_limit =
      next.onboarding.supplicant_lifecycle.profile_retention_limit || 500000;
    next.profiling.poll_interval_seconds =
      next.profiling.poll_interval_seconds || 300;
    next.profiling.retention_hours = next.profiling.retention_hours || 24;
    next.profiling.mdm_cache_hours = next.profiling.mdm_cache_hours || 12;
    next.integrations.siem.batch_size =
      next.integrations.siem.batch_size || 100;
    next.integrations.controller.sync_mode =
      next.integrations.controller.sync_mode || "monitor";
    next.governance.rbac_mode = next.governance.rbac_mode || "local";
  } else if (profile === "custom") {
    next.radius.max_sessions = next.radius.max_sessions || 1024;
    next.policy.max_service_chain_length =
      next.policy.max_service_chain_length || 16;
    next.tacacs.max_connections = next.tacacs.max_connections || 256;
    next.tacacs.retention_limit = next.tacacs.retention_limit || 10000;
    next.ailite.mode = next.ailite.mode || "lite";
    next.ailite.provider = next.ailite.provider || "local";
    next.ailite.recommendation_limit = next.ailite.recommendation_limit || 100;
    next.radius.sql_accounting.enabled =
      next.radius.sql_accounting.enabled ?? true;
    next.radius.sql_accounting.reconcile_enabled =
      next.radius.sql_accounting.reconcile_enabled ?? true;
    next.radius.sql_accounting.batch_size =
      next.radius.sql_accounting.batch_size || 500;
    next.radius.sql_accounting.reconcile_interval_seconds =
      next.radius.sql_accounting.reconcile_interval_seconds || 60;
    next.radius.sql_accounting.stale_after_seconds =
      next.radius.sql_accounting.stale_after_seconds || 300;
    next.radius.sql_accounting.accounting_retention_days =
      next.radius.sql_accounting.accounting_retention_days || 365;
    next.radius.sql_accounting.postauth_retention_days =
      next.radius.sql_accounting.postauth_retention_days || 30;
    next.radius.accounting_ordering.enabled =
      next.radius.accounting_ordering.enabled ?? true;
    next.radius.accounting_ordering.replay_enabled =
      next.radius.accounting_ordering.replay_enabled ?? true;
    next.radius.accounting_ordering.sequence_window_seconds =
      next.radius.accounting_ordering.sequence_window_seconds || 300;
    next.radius.accounting_ordering.late_stop_window_seconds =
      next.radius.accounting_ordering.late_stop_window_seconds || 86400;
    next.radius.accounting_ordering.max_replay_batch =
      next.radius.accounting_ordering.max_replay_batch || 1000;
    next.radius.accounting_ordering.duplicate_retention_days =
      next.radius.accounting_ordering.duplicate_retention_days || 365;
    next.radius.accounting_counters.enabled =
      next.radius.accounting_counters.enabled ?? true;
    next.radius.accounting_counters.gigawords_enabled =
      next.radius.accounting_counters.gigawords_enabled ?? true;
    next.radius.accounting_counters.reset_detection_enabled =
      next.radius.accounting_counters.reset_detection_enabled ?? true;
    next.radius.accounting_counters.max_counter_bits =
      next.radius.accounting_counters.max_counter_bits || 64;
    next.radius.accounting_counters.overflow_policy =
      next.radius.accounting_counters.overflow_policy || "saturate";
    next.radius.accounting_counters.retention_days =
      next.radius.accounting_counters.retention_days || 365;
    next.radius.accounting_ip.enabled =
      next.radius.accounting_ip.enabled ?? true;
    next.radius.accounting_ip.ipv6_enabled =
      next.radius.accounting_ip.ipv6_enabled ?? true;
    next.radius.accounting_ip.route_accounting_enabled =
      next.radius.accounting_ip.route_accounting_enabled ?? true;
    next.radius.accounting_ip.delegated_prefix_enabled =
      next.radius.accounting_ip.delegated_prefix_enabled ?? true;
    next.radius.accounting_ip.reject_invalid =
      next.radius.accounting_ip.reject_invalid ?? false;
    next.radius.accounting_ip.retention_days =
      next.radius.accounting_ip.retention_days || 365;
  } else {
    next.ailite.enabled = true;
    next.ailite.mode = "lite";
    next.ailite.provider = "local";
    next.ailite.recommendation_limit = 100;
    next.telemetry.enabled = true;
    next.policy.runtime_shaping_enabled = true;
    next.policy.max_service_chain_length = 16;
    next.tacacs.enabled = next.tacacs.enabled || false;
    next.tacacs.mode = next.tacacs.mode || "monitor";
    next.tacacs.max_connections = next.tacacs.max_connections || 256;
    next.tacacs.retention_limit = next.tacacs.retention_limit || 10000;
    next.radius.max_sessions = 1024;
    next.radius.interim_update_seconds = 300;
    next.radius.sql_accounting.enabled = true;
    next.radius.sql_accounting.reconcile_enabled = true;
    next.radius.sql_accounting.batch_size =
      next.radius.sql_accounting.batch_size || 500;
    next.radius.sql_accounting.reconcile_interval_seconds =
      next.radius.sql_accounting.reconcile_interval_seconds || 60;
    next.radius.sql_accounting.stale_after_seconds =
      next.radius.sql_accounting.stale_after_seconds || 300;
    next.radius.sql_accounting.accounting_retention_days =
      next.radius.sql_accounting.accounting_retention_days || 365;
    next.radius.sql_accounting.postauth_retention_days =
      next.radius.sql_accounting.postauth_retention_days || 30;
    next.radius.accounting_ordering.enabled = true;
    next.radius.accounting_ordering.replay_enabled = true;
    next.radius.accounting_ordering.sequence_window_seconds =
      next.radius.accounting_ordering.sequence_window_seconds || 300;
    next.radius.accounting_ordering.late_stop_window_seconds =
      next.radius.accounting_ordering.late_stop_window_seconds || 86400;
    next.radius.accounting_ordering.max_replay_batch =
      next.radius.accounting_ordering.max_replay_batch || 1000;
    next.radius.accounting_ordering.duplicate_retention_days =
      next.radius.accounting_ordering.duplicate_retention_days || 365;
    next.radius.accounting_counters.enabled = true;
    next.radius.accounting_counters.gigawords_enabled = true;
    next.radius.accounting_counters.reset_detection_enabled = true;
    next.radius.accounting_counters.max_counter_bits = 64;
    next.radius.accounting_counters.overflow_policy =
      next.radius.accounting_counters.overflow_policy || "saturate";
    next.radius.accounting_counters.retention_days =
      next.radius.accounting_counters.retention_days || 365;
    next.radius.accounting_ip.enabled = true;
    next.radius.accounting_ip.ipv6_enabled = true;
    next.radius.accounting_ip.route_accounting_enabled = true;
    next.radius.accounting_ip.delegated_prefix_enabled = true;
    next.radius.accounting_ip.reject_invalid =
      next.radius.accounting_ip.reject_invalid ?? false;
    next.radius.accounting_ip.retention_days =
      next.radius.accounting_ip.retention_days || 365;
    next.radius.eap.framework.enabled = true;
    next.radius.eap.framework.max_concurrent_sessions =
      next.radius.eap.framework.max_concurrent_sessions || 1024;
    next.radius.eap.framework.event_retention_limit =
      next.radius.eap.framework.event_retention_limit || 6000;
    next.radius.eap.teap.enabled = true;
    next.radius.eap.teap.max_chain_steps =
      next.radius.eap.teap.max_chain_steps || 2;
    next.radius.eap.teap.event_retention_limit =
      next.radius.eap.teap.event_retention_limit || 6000;
    next.radius.eap.machine_user.enabled = true;
    next.radius.eap.machine_user.max_active_correlations =
      next.radius.eap.machine_user.max_active_correlations || 100000;
    next.radius.eap.machine_user.event_retention_limit =
      next.radius.eap.machine_user.event_retention_limit || 6000;
    next.radius.eap.fast.enabled = true;
    next.radius.eap.fast.event_retention_limit =
      next.radius.eap.fast.event_retention_limit || 6000;
    next.radius.eap.pwd.enabled = true;
    next.radius.eap.pwd.event_retention_limit =
      next.radius.eap.pwd.event_retention_limit || 6000;
    next.radius.eap.sim_aka.enabled = true;
    next.radius.eap.sim_aka.event_retention_limit =
      next.radius.eap.sim_aka.event_retention_limit || 6000;
    next.radius.upstream.status_check = "status-server";
    next.admin_webauthn.challenge_ttl_seconds =
      next.admin_webauthn.challenge_ttl_seconds || 300;
    next.admin_webauthn.session_ttl_seconds =
      next.admin_webauthn.session_ttl_seconds || 28800;
    next.mab.cache_ttl_seconds = next.mab.cache_ttl_seconds || 300;
    next.onboarding.certificate_lifecycle.event_retention_limit =
      next.onboarding.certificate_lifecycle.event_retention_limit || 6000;
    next.onboarding.certificate_lifecycle.inventory_retention_limit =
      next.onboarding.certificate_lifecycle.inventory_retention_limit || 100000;
    next.onboarding.supplicant_lifecycle.event_retention_limit =
      next.onboarding.supplicant_lifecycle.event_retention_limit || 6000;
    next.onboarding.supplicant_lifecycle.profile_retention_limit =
      next.onboarding.supplicant_lifecycle.profile_retention_limit || 100000;
  }

  if (form === "virtual") {
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

function listToCSV(value: any) {
  return Array.isArray(value) ? value.join(", ") : "";
}

function csvToList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function mapToLines(value: any) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "";
  }
  return Object.entries(value)
    .map(([key, mapped]) => `${key}=${String(mapped)}`)
    .join("\n");
}

function linesToMap(value: string) {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .reduce((next: JsonMap, line) => {
      const [key, ...rest] = line.split("=");
      const mapped = rest.join("=").trim();
      if (key.trim() && mapped) {
        next[key.trim()] = mapped;
      }
      return next;
    }, {});
}

function TextField({
  label,
  value,
  onChange,
  type = "text",
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
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function ToggleField({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-3 rounded-md border border-gray-200 px-3 py-2 text-sm text-gray-700">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="h-4 w-4"
      />
      <span>{label}</span>
    </label>
  );
}

export default function AccessSettings() {
  const [settings, setSettings] = useState<JsonMap>(clone(defaultSettings));
  const [deploymentPreview, setDeploymentPreview] =
    useState<DeploymentPreview | null>(null);
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
  const [dhcpLeaseHistory, setDhcpLeaseHistory] = useState<
    DHCPLeaseHistoryRecord[]
  >([]);
  const [networkPreviewLoading, setNetworkPreviewLoading] = useState(false);
  const [networkPreview, setNetworkPreview] = useState<NetworkPreview | null>(
    null,
  );
  const [networkBackups, setNetworkBackups] = useState<
    NetworkSnapshotSummary[]
  >([]);
  const [networkApplyHistory, setNetworkApplyHistory] = useState<
    NetworkApplyHistoryRecord[]
  >([]);
  const [lastNetworkValidation, setLastNetworkValidation] =
    useState<NetworkValidationReport | null>(null);
  const [networkRecovery, setNetworkRecovery] =
    useState<NetworkRecoveryState | null>(null);
  const [networkObservability, setNetworkObservability] =
    useState<NetworkObservabilityResponse | null>(null);
  const [subscriberServiceChains, setSubscriberServiceChains] =
    useState<SubscriberServiceChainsReport | null>(null);
  const [tacacsReport, setTacacsReport] = useState<TACACSReport | null>(null);
  const [sqlAccountingReport, setSQLAccountingReport] =
    useState<SQLAccountingReport | null>(null);
  const [accountingOrderingReport, setAccountingOrderingReport] =
    useState<AccountingOrderingReport | null>(null);
  const [accountingCountersReport, setAccountingCountersReport] =
    useState<AccountingCountersReport | null>(null);
  const [accountingIPReport, setAccountingIPReport] =
    useState<AccountingIPReport | null>(null);
  const [accountingServicesReport, setAccountingServicesReport] =
    useState<AccountingServicesReport | null>(null);
  const [tenantIsolationReport, setTenantIsolationReport] =
    useState<TenantIsolationReport | null>(null);
  const [reconcilingSQLAccounting, setReconcilingSQLAccounting] =
    useState(false);
  const [replayingAccountingOrdering, setReplayingAccountingOrdering] =
    useState(false);
  const [confirmingNetworkRecovery, setConfirmingNetworkRecovery] =
    useState(false);
  const [selectedRollbackId, setSelectedRollbackId] = useState("");
  const [networkConfirmationText, setNetworkConfirmationText] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [previewError, setPreviewError] = useState("");
  const [hostapdPreview, setHostapdPreview] = useState("");
  const [hostapdPath, setHostapdPath] = useState("");
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
    setError("");
    setMessage(
      "Deployment profile defaults applied in the editor. Review the changes, then save when you are ready.",
    );
  };

  const loadReferenceData = async () => {
    const [rolesRes, portalRes, identityRes, bandwidthRes] = await Promise.all([
      api.get("/roles"),
      api.get("/portal-profiles"),
      api.get("/identity-sources"),
      api.get("/bandwidth-profiles"),
    ]);
    setRoles(
      (rolesRes.data || []).map((item: JsonMap) => ({
        value: item.name || "",
        label: item.name || "Unnamed role",
      })),
    );
    setPortalProfiles(
      (portalRes.data || []).map((item: JsonMap) => ({
        value: item.name || "",
        label: item.name || "Unnamed profile",
      })),
    );
    setIdentitySources(
      (identityRes.data || []).map((item: JsonMap) => ({
        value: item.name || "",
        label: item.name || "Unnamed source",
      })),
    );
    setBandwidthProfiles(
      (bandwidthRes.data || []).map((item: JsonMap) => ({
        value: item.name || "",
        label: item.name || "Unnamed profile",
      })),
    );
  };

  const loadLeaseReport = async () => {
    setLeasesLoading(true);
    try {
      const [currentRes, historyRes] = await Promise.all([
        api.get("/system/dhcp-leases"),
        api.get("/system/dhcp-lease-history"),
      ]);
      setDhcpLeases(currentRes.data.leases || []);
      setDhcpLeaseHistory(historyRes.data.history || []);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load the DHCP lease report.",
      );
    } finally {
      setLeasesLoading(false);
    }
  };

  const loadNetworkPreview = async () => {
    setNetworkPreviewLoading(true);
    try {
      const [previewRes, backupsRes, historyRes] = await Promise.all([
        api.get("/system/network-preview"),
        api.get("/system/network-backups"),
        api.get("/system/network-apply-history"),
      ]);
      setNetworkPreview(previewRes.data || null);
      setNetworkRecovery(previewRes.data?.recovery || null);
      if (!previewRes.data?.risk?.requires_confirmation) {
        setNetworkConfirmationText("");
      }
      const snapshots =
        backupsRes.data?.snapshots ||
        previewRes.data?.available_rollback_ids ||
        [];
      setNetworkBackups(snapshots);
      setNetworkApplyHistory(historyRes.data?.history || []);
      if (snapshots.length === 0) {
        setSelectedRollbackId("");
      } else if (
        !snapshots.some(
          (snapshot: NetworkSnapshotSummary) =>
            snapshot.id === selectedRollbackId,
        )
      ) {
        setSelectedRollbackId(snapshots[0].id || "");
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load the edge network preview.",
      );
    } finally {
      setNetworkPreviewLoading(false);
    }
  };

  const loadNetworkObservability = async () => {
    try {
      const { data } = await api.get("/system/network-observability");
      setNetworkObservability(data || null);
      if (data?.recovery) {
        setNetworkRecovery(data.recovery);
      }
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load network observability.",
      );
    }
  };

  const loadSubscriberServiceChains = async () => {
    try {
      const { data } = await api.get("/system/subscriber-service-chains", {
        params: { limit: 5 },
      });
      setSubscriberServiceChains(data || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load subscriber service-chain history.",
      );
    }
  };

  const loadTACACSReport = async () => {
    try {
      const { data } = await api.get("/system/tacacs", {
        params: { limit: 5 },
      });
      setTacacsReport(data || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load TACACS+ command authorization state.",
      );
    }
  };

  const loadSQLAccountingReport = async () => {
    try {
      const { data } = await api.get("/system/sql-accounting", {
        params: { limit: 5 },
      });
      setSQLAccountingReport(data?.report || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load SQL accounting state.",
      );
    }
  };

  const loadAccountingOrderingReport = async () => {
    try {
      const { data } = await api.get("/system/accounting-ordering", {
        params: { limit: 5 },
      });
      setAccountingOrderingReport(data?.report || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load accounting ordering state.",
      );
    }
  };

  const loadAccountingCountersReport = async () => {
    try {
      const { data } = await api.get("/system/accounting-counters");
      setAccountingCountersReport(data?.report || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load accounting counter state.",
      );
    }
  };

  const loadAccountingIPReport = async () => {
    try {
      const { data } = await api.get("/system/accounting-ip");
      setAccountingIPReport(data?.report || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load accounting IP assignment state.",
      );
    }
  };

  const loadAccountingServicesReport = async () => {
    try {
      const { data } = await api.get("/system/accounting-services");
      setAccountingServicesReport(data?.report || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load multi-service accounting state.",
      );
    }
  };

  const loadTenantIsolationReport = async () => {
    try {
      const { data } = await api.get("/system/tenant-isolation", {
        params: { limit: 5 },
      });
      setTenantIsolationReport(data || null);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not load tenant isolation state.",
      );
    }
  };

  const loadSettings = async () => {
    setLoading(true);
    setError("");
    try {
      const [settingsRes, previewRes] = await Promise.all([
        api.get("/system/settings"),
        api.get("/system/hostapd-preview"),
      ]);
      await loadReferenceData();
      setSettings({ ...clone(defaultSettings), ...settingsRes.data });
      setHostapdPreview(previewRes.data.config || "");
      setHostapdPath(previewRes.data.path || "");
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
      await loadSubscriberServiceChains();
      await loadTACACSReport();
      await loadSQLAccountingReport();
      await loadAccountingOrderingReport();
      await loadAccountingCountersReport();
      await loadAccountingIPReport();
      await loadAccountingServicesReport();
      await loadAccountingServicesReport();
      await loadTenantIsolationReport();
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not load access settings.",
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const evaluateSettings = async (candidate: JsonMap) => {
    try {
      const { data } = await api.post("/system/settings/evaluate", candidate);
      setDeploymentPreview(data.deployment || null);
      setPreviewError(
        data.valid
          ? ""
          : data.validation_error ||
              "This draft needs more deployment input before it is production-safe.",
      );
    } catch (err: any) {
      setPreviewError(
        err.response?.data ||
          err.message ||
          "Could not evaluate deployment capabilities.",
      );
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
    setError("");
    setMessage("");
    try {
      const { data } = await api.put("/system/settings", settings);
      setSettings(data.settings || settings);
      setMessage(
        "Settings saved. Use Apply Edge Network for routing, DHCP, DNS, and firewall changes, then restart hostapd or RADIUS only when you change those services.",
      );
      const previewRes = await api.get("/system/hostapd-preview");
      setHostapdPreview(previewRes.data.config || "");
      setHostapdPath(previewRes.data.path || "");
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
      await loadSubscriberServiceChains();
      await loadTACACSReport();
      await loadSQLAccountingReport();
      await loadAccountingOrderingReport();
      await loadAccountingCountersReport();
      await loadAccountingIPReport();
      await loadAccountingServicesReport();
      await loadTenantIsolationReport();
    } catch (err: any) {
      setError(err.response?.data || err.message || "Could not save settings.");
    } finally {
      setSaving(false);
    }
  };

  const applyNetworkServices = async () => {
    setApplyingNetwork(true);
    setError("");
    setMessage("");
    try {
      const payload = riskyNetworkApply?.requires_confirmation
        ? { confirmation_text: networkConfirmationText }
        : {};
      const { data } = await api.post("/system/network-apply", payload);
      setLastNetworkValidation(data.validation || null);
      setNetworkRecovery(data.recovery || null);
      const backupSuffix = data.backup_id
        ? ` Backup snapshot ${data.backup_id} was saved first.`
        : "";
      const validationCount = Array.isArray(data.validation?.checks)
        ? data.validation.checks.length
        : 0;
      const validationSuffix =
        data.validation?.healthy && validationCount > 0
          ? ` Post-apply validation passed across ${validationCount} checks.`
          : "";
      const recoverySuffix = data.recovery?.pending
        ? ` Confirm management reachability within ${data.recovery?.grace_period_seconds || data.recovery?.remaining_seconds || 0} seconds or snapshot ${data.recovery?.backup_id || data.backup_id} will be restored automatically.`
        : "";
      setMessage(
        `Interfaces, routes, dnsmasq, and firewall rules were applied on the appliance.${backupSuffix}${validationSuffix}${recoverySuffix}`,
      );
      setNetworkConfirmationText("");
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setLastNetworkValidation(null);
      setError(
        err.response?.data ||
          err.message ||
          "Could not apply edge network services.",
      );
    } finally {
      setApplyingNetwork(false);
    }
  };

  const rollbackNetworkServices = async () => {
    setRollingBackNetwork(true);
    setError("");
    setMessage("");
    try {
      const payload = selectedRollbackId ? { id: selectedRollbackId } : {};
      const { data } = await api.post("/system/network-rollback", payload);
      setLastNetworkValidation(null);
      setNetworkRecovery(data.recovery || null);
      setMessage(
        `Edge network state rolled back to snapshot ${data.rollback_id}.`,
      );
      await loadLeaseReport();
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not roll back edge network services.",
      );
    } finally {
      setRollingBackNetwork(false);
    }
  };

  const confirmNetworkRecovery = async () => {
    if (!networkRecovery?.pending) {
      return;
    }
    setConfirmingNetworkRecovery(true);
    setError("");
    setMessage("");
    try {
      const { data } = await api.post("/system/network-recovery/confirm", {
        backup_id: networkRecovery.backup_id || "",
      });
      setNetworkRecovery(data.recovery || null);
      setMessage(
        "Management access confirmed. Automatic rollback has been cancelled for the current edge-network change.",
      );
      await loadNetworkPreview();
      await loadNetworkObservability();
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not confirm management reachability.",
      );
    } finally {
      setConfirmingNetworkRecovery(false);
    }
  };

  const downloadSettings = async () => {
    try {
      const response = await api.get("/system/settings/export", {
        responseType: "blob",
      });
      const href = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = href;
      link.download = "aegisnas-system-settings.json";
      link.click();
      URL.revokeObjectURL(href);
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not export settings.",
      );
    }
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(href);
  };

  const exportNetworkHistory = async (kind: "apply" | "lease") => {
    try {
      const url =
        kind === "apply"
          ? "/system/network-apply-history/export"
          : "/system/dhcp-lease-history/export";
      const filename =
        kind === "apply"
          ? "aegisnas-network-apply-history.csv"
          : "aegisnas-dhcp-lease-history.csv";
      const response = await api.get(url, {
        responseType: "blob",
        params: { format: "csv" },
      });
      downloadBlob(response.data, filename);
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not export network history.",
      );
    }
  };

  const importSettings = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const payload = JSON.parse(text);
      await api.post("/system/settings/import", payload);
      setMessage(
        "Settings imported. Restart the appliance services and hostapd after review.",
      );
      await loadSettings();
    } catch (err: any) {
      setError(
        err.response?.data || err.message || "Could not import settings.",
      );
    } finally {
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const writeHostapdConfig = async () => {
    setWritingHostapd(true);
    setError("");
    setMessage("");
    try {
      const { data } = await api.post("/system/hostapd-config");
      setMessage(
        `hostapd configuration written to ${data.path}. Restart hostapd on the appliance to publish the new SSIDs.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not write hostapd configuration.",
      );
    } finally {
      setWritingHostapd(false);
    }
  };

  const publishHostapdConfig = async () => {
    setPublishingHostapd(true);
    setError("");
    setMessage("");
    try {
      const { data } = await api.post("/system/hostapd-publish");
      setMessage(
        `Wireless profile published to ${data.path} and hostapd restarted on the appliance.`,
      );
      const previewRes = await api.get("/system/hostapd-preview");
      setHostapdPreview(previewRes.data.config || "");
      setHostapdPath(previewRes.data.path || "");
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not publish hostapd configuration.",
      );
    } finally {
      setPublishingHostapd(false);
    }
  };

  const reconcileSQLAccounting = async () => {
    setReconcilingSQLAccounting(true);
    setError("");
    setMessage("");
    try {
      const { data } = await api.post("/system/sql-accounting/reconcile", {
        batch_size: settings.radius?.sql_accounting?.batch_size || 500,
      });
      setMessage(
        `SQL accounting reconciled ${data.result?.reconciled || 0} row(s); ${data.result?.error_count || 0} error(s) remain.`,
      );
      await loadSQLAccountingReport();
      await loadAccountingOrderingReport();
      await loadAccountingCountersReport();
      await loadAccountingIPReport();
      await loadAccountingServicesReport();
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not reconcile SQL accounting rows.",
      );
    } finally {
      setReconcilingSQLAccounting(false);
    }
  };

  const replayAccountingOrdering = async () => {
    setReplayingAccountingOrdering(true);
    setError("");
    setMessage("");
    try {
      const { data } = await api.post("/system/accounting-ordering/replay", {
        limit: settings.radius?.accounting_ordering?.max_replay_batch || 1000,
      });
      setMessage(
        `Accounting replay applied ${data.result?.applied || 0} event(s); ${data.result?.error_count || 0} error(s) remain.`,
      );
      await loadAccountingOrderingReport();
      await loadSQLAccountingReport();
      await loadAccountingCountersReport();
      await loadAccountingIPReport();
      await loadAccountingServicesReport();
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not replay accounting events.",
      );
    } finally {
      setReplayingAccountingOrdering(false);
    }
  };

  const applyRadiusConfig = async () => {
    setApplyingRadius(true);
    setError("");
    setMessage("");
    try {
      const { data } = await api.post("/system/radius-apply");
      setMessage(
        `FreeRADIUS configuration applied in ${data.config_dir} and the service restarted on the appliance.`,
      );
    } catch (err: any) {
      setError(
        err.response?.data ||
          err.message ||
          "Could not apply RADIUS configuration.",
      );
    } finally {
      setApplyingRadius(false);
    }
  };

  const upstreamServers = settings.radius?.upstream?.servers || [];
  const vendorAttributes = settings.radius?.vendor?.attributes || [];
  const vendorDictionaryPaths = settings.radius?.vendor?.dictionary_paths || [];
  const vendorRoleMappings = settings.radius?.vendor?.role_mappings || [];
  const vendorExtendedVLANMappings =
    settings.radius?.vendor?.extended_vlan_mappings || [];
  const vendorAVPairMappings = settings.radius?.vendor?.avpair_mappings || [];
  const vendorPortalStatusMappings =
    settings.radius?.vendor?.portal_status_mappings || [];
  const vendorSessionActionMappings =
    settings.radius?.vendor?.session_action_mappings || [];
  const vendorQuotaMappings = settings.radius?.vendor?.quota_mappings || [];
  const vendorServiceNameMappings =
    settings.radius?.vendor?.service_name_mappings || [];
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
  const activeScalingActions =
    deploymentPreview?.scaling?.gating_actions?.filter(
      (action) => action.active && action.state !== "allow",
    ) ||
    [];
  const rollbackOptions: Option[] =
    networkBackups.length === 0
      ? [{ value: "", label: "No rollback snapshots yet" }]
      : networkBackups.map((snapshot) => ({
          value: snapshot.id,
          label: `${snapshot.created_at} · ${snapshot.id}`,
        }));

  const serviceChainSummary = subscriberServiceChains?.summary;
  const serviceChainStatus = subscriberServiceChains?.status || "unknown";
  const serviceChainTone =
    serviceChainStatus === "passed"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : serviceChainStatus === "blocked"
        ? "border-red-200 bg-red-50 text-red-800"
        : "border-amber-200 bg-amber-50 text-amber-800";
  const tacacsStatus = tacacsReport?.status || "unknown";
  const tacacsTone =
    tacacsStatus === "ready"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : tacacsStatus === "blocked"
        ? "border-red-200 bg-red-50 text-red-800"
        : "border-amber-200 bg-amber-50 text-amber-800";
  const tacacsSummary = tacacsReport?.summary;
  const tacacsDBSummary = tacacsReport?.db_summary;
  const tenantIsolationStatus = tenantIsolationReport?.status || "unknown";
  const tenantIsolationTone =
    tenantIsolationStatus === "passed"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : tenantIsolationStatus === "blocked"
        ? "border-red-200 bg-red-50 text-red-800"
        : tenantIsolationStatus === "disabled"
          ? "border-gray-200 bg-gray-50 text-gray-700"
          : "border-amber-200 bg-amber-50 text-amber-800";
  const tenantIsolationSummary = tenantIsolationReport?.summary;

  const riskyNetworkApply: NetworkApplyRisk | null =
    networkPreview?.risk || null;
  const requiredConfirmationPhrase =
    riskyNetworkApply?.confirmation_phrase?.trim() || "";
  const networkApplyConfirmed =
    !riskyNetworkApply?.requires_confirmation ||
    (requiredConfirmationPhrase !== "" &&
      networkConfirmationText.trim() === requiredConfirmationPhrase);
  const networkRecoveryDeadlineMs = networkRecovery?.deadline
    ? new Date(networkRecovery.deadline).getTime()
    : 0;
  const networkRecoveryRemainingSeconds =
    networkRecovery?.pending && networkRecoveryDeadlineMs > 0
      ? Math.max(
          0,
          Math.floor((networkRecoveryDeadlineMs - recoveryTick) / 1000),
        )
      : networkRecovery?.remaining_seconds || 0;

  if (loading) {
    return <div className="text-gray-600">Loading access settings...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Access Settings</h2>
          <p className="mt-1 text-sm text-gray-600">
            Control the edge appliance, enterprise auth path, and Wi-Fi radio
            from one place.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={downloadSettings}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
          >
            Export Settings
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
          >
            Import Settings
          </button>
          <button
            onClick={loadLeaseReport}
            disabled={leasesLoading}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 disabled:opacity-60"
          >
            {leasesLoading ? "Refreshing Leases..." : "Refresh Lease Report"}
          </button>
          <button
            onClick={applyNetworkServices}
            disabled={
              applyingNetwork ||
              !networkApplyConfirmed ||
              Boolean(networkRecovery?.pending)
            }
            className="rounded-md border border-emerald-300 px-4 py-2 text-sm font-medium text-emerald-800 disabled:opacity-60"
          >
            {applyingNetwork
              ? "Applying Network..."
              : networkRecovery?.pending
                ? "Awaiting Reachability Confirmation"
                : riskyNetworkApply?.requires_confirmation
                  ? "Confirm And Apply Edge Network"
                  : "Apply Edge Network"}
          </button>
          <button
            onClick={loadNetworkPreview}
            disabled={networkPreviewLoading}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 disabled:opacity-60"
          >
            {networkPreviewLoading
              ? "Building Preview..."
              : "Preview Edge Network"}
          </button>
          <button
            onClick={rollbackNetworkServices}
            disabled={rollingBackNetwork || networkBackups.length === 0}
            className="rounded-md border border-amber-300 px-4 py-2 text-sm font-medium text-amber-800 disabled:opacity-60"
          >
            {rollingBackNetwork ? "Rolling Back..." : "Rollback Edge Network"}
          </button>
          <button
            onClick={writeHostapdConfig}
            disabled={writingHostapd}
            className="rounded-md border border-sky-200 px-4 py-2 text-sm font-medium text-sky-700 disabled:opacity-60"
          >
            {writingHostapd ? "Writing hostapd..." : "Write hostapd Config"}
          </button>
          <button
            onClick={publishHostapdConfig}
            disabled={publishingHostapd}
            className="rounded-md border border-sky-300 px-4 py-2 text-sm font-medium text-sky-800 disabled:opacity-60"
          >
            {publishingHostapd
              ? "Publishing Wi-Fi..."
              : "Write And Restart Wi-Fi"}
          </button>
          <button
            onClick={applyRadiusConfig}
            disabled={applyingRadius}
            className="rounded-md border border-indigo-300 px-4 py-2 text-sm font-medium text-indigo-800 disabled:opacity-60"
          >
            {applyingRadius ? "Applying RADIUS..." : "Apply RADIUS Config"}
          </button>
          <button
            onClick={saveSettings}
            disabled={saving}
            className="rounded-md bg-sky-700 px-4 py-2 text-sm font-medium text-white disabled:opacity-60"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept="application/json"
          className="hidden"
          onChange={importSettings}
        />
      </div>

      {message && (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          {message}
        </div>
      )}
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {String(error)}
        </div>
      )}

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Deployment Profile
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Tune the product for low-power appliances, higher-capacity edge
              boxes, or VM deployments before you fine-tune the rest.
            </p>
          </div>
          <button
            onClick={applyProfileDefaults}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
          >
            Apply Profile Defaults
          </button>
        </div>
        <div className="mb-4 rounded-md border border-sky-100 bg-sky-50 px-4 py-3 text-sm text-sky-900">
          {deploymentPreview?.summary ||
            deploymentProfileSummary(
              settings.deployment?.profile || "branch",
              settings.deployment?.form || "physical",
            )}
        </div>
        {previewError ? (
          <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            {previewError}
          </div>
        ) : null}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
          <SelectField
            label="Profile"
            value={settings.deployment?.profile || "branch"}
            onChange={(value) => updateField(["deployment", "profile"], value)}
            options={deploymentProfileOptions}
          />
          <SelectField
            label="Form"
            value={settings.deployment?.form || "physical"}
            onChange={(value) => updateField(["deployment", "form"], value)}
            options={deploymentFormOptions}
          />
          <TextField
            label="Memory MB"
            type="number"
            value={settings.deployment?.hardware?.memory_mb || 0}
            onChange={(value) =>
              updateField(
                ["deployment", "hardware", "memory_mb"],
                Number(value),
              )
            }
          />
          <TextField
            label="CPU Cores"
            type="number"
            value={settings.deployment?.hardware?.cpu_cores || 0}
            onChange={(value) =>
              updateField(
                ["deployment", "hardware", "cpu_cores"],
                Number(value),
              )
            }
          />
          <TextField
            label="Storage GB"
            type="number"
            value={settings.deployment?.hardware?.storage_gb || 0}
            onChange={(value) =>
              updateField(
                ["deployment", "hardware", "storage_gb"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Prefer External AP"
            checked={Boolean(settings.deployment?.hardware?.prefer_external_ap)}
            onChange={(value) =>
              updateField(
                ["deployment", "hardware", "prefer_external_ap"],
                value,
              )
            }
          />
          <ToggleField
            label="Wi-Fi Passthrough Radio"
            checked={Boolean(
              settings.deployment?.hardware?.wireless_passthrough,
            )}
            onChange={(value) =>
              updateField(
                ["deployment", "hardware", "wireless_passthrough"],
                value,
              )
            }
          />
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <ToggleField
            label="AI Engine Enabled"
            checked={Boolean(settings.ailite?.enabled)}
            onChange={(value) => updateField(["ailite", "enabled"], value)}
          />
          <ToggleField
            label="Telemetry Enabled"
            checked={Boolean(settings.telemetry?.enabled)}
            onChange={(value) => updateField(["telemetry", "enabled"], value)}
          />
          <ToggleField
            label="Runtime Shaping Enabled"
            checked={Boolean(settings.policy?.runtime_shaping_enabled)}
            onChange={(value) =>
              updateField(["policy", "runtime_shaping_enabled"], value)
            }
          />
        </div>
        <div className="mt-4 rounded-md border border-gray-200 px-4 py-3 text-sm text-gray-600">
          Production preview:{" "}
          {deploymentPreview?.form || settings.deployment?.form || "physical"}{" "}
          form,{" "}
          {deploymentPreview?.hardware?.cpu_cores ??
            settings.deployment?.hardware?.cpu_cores ??
            "unknown"}{" "}
          cores,{" "}
          {deploymentPreview?.hardware?.memory_mb ??
            settings.deployment?.hardware?.memory_mb ??
            "unknown"}{" "}
          MB RAM,{" "}
          {deploymentPreview?.hardware?.storage_gb ??
            settings.deployment?.hardware?.storage_gb ??
            "unknown"}{" "}
          GB storage.
          {deploymentPreview ? (
            <span className="block mt-1 text-xs text-gray-500">
              Recommended floor: {deploymentPreview.recommended_min_cores} cores
              and {deploymentPreview.recommended_min_memory} MB RAM.
            </span>
          ) : null}
          {deploymentPreview?.scaling ? (
            <div className="mt-3 rounded-md border border-gray-200 bg-white px-3 py-2">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-medium text-gray-900">
                  Scaling mode: {deploymentPreview.scaling.mode}
                </span>
                <span
                  className={`rounded-md border px-2 py-1 text-xs font-semibold uppercase ${
                    deploymentPreview.scaling.can_run_selected
                      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                      : "border-amber-200 bg-amber-50 text-amber-800"
                  }`}
                >
                  {deploymentPreview.scaling.can_run_selected
                    ? "fits"
                    : "gated"}
                </span>
              </div>
              <div className="mt-1 text-xs text-gray-600">
                {deploymentPreview.scaling.reason ||
                  deploymentPreview.scaling.summary}
              </div>
              {deploymentPreview.scaling.recommended_limits ? (
                <div className="mt-1 text-xs text-gray-500">
                  Target limits:{" "}
                  {deploymentPreview.scaling.recommended_limits
                    .radius_max_sessions}{" "}
                  RADIUS sessions,{" "}
                  {deploymentPreview.scaling.recommended_limits
                    .recommendation_limit}{" "}
                  AI recommendations, controller sync{" "}
                  {
                    deploymentPreview.scaling.recommended_limits
                      .controller_sync_mode
                  }
                  .
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
        <div className="mt-6">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <h4 className="font-semibold text-gray-900">
                Phase 1 Capability Preview
              </h4>
              <p className="mt-1 text-sm text-gray-600">
                These states are evaluated from the draft in the editor, not
                just the last saved config.
              </p>
            </div>
            <div className="text-xs text-gray-500">
              Production deploy standard
            </div>
          </div>
          <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
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
                  <div className="mt-3 text-xs text-gray-500">
                    {capability.recommendation}
                  </div>
                ) : null}
                {capability.dependencies?.length ? (
                  <div className="mt-2 text-xs text-gray-500">
                    Depends on: {capability.dependencies.join(", ")}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
          <div className="mt-4 space-y-2">
            {deploymentWarnings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-600">
                This draft lines up cleanly with the selected deployment
                profile.
              </div>
            ) : (
              deploymentWarnings.map((warning, index) => (
                <div
                  key={`deployment-preview-warning-${index}`}
                  className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800"
                >
                  {warning}
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Subscriber Service Chains
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Per-session service activation, rollback evidence, and
              service-level accounting for vendor-neutral authorization.
            </p>
          </div>
          <button
            onClick={loadSubscriberServiceChains}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
          >
            Refresh Chains
          </button>
        </div>
        <div className="grid gap-4 lg:grid-cols-4">
          <TextField
            label="Max Chain Length"
            type="number"
            value={settings.policy?.max_service_chain_length || 16}
            onChange={(value) =>
              updateField(["policy", "max_service_chain_length"], Number(value))
            }
          />
          <div className="rounded-md border border-gray-200 px-4 py-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Status
            </div>
            <div
              className={`mt-2 inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${serviceChainTone}`}
            >
              {serviceChainStatus}
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {subscriberServiceChains?.message ||
                "Service-chain history has not loaded yet."}
            </div>
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Chains
            </div>
            <div className="mt-2 text-2xl font-semibold text-gray-900">
              {serviceChainSummary?.total_chains || 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              {serviceChainSummary?.active_chains || 0} active,{" "}
              {serviceChainSummary?.rolled_back_chains || 0} rolled back
            </div>
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Services
            </div>
            <div className="mt-2 text-2xl font-semibold text-gray-900">
              {serviceChainSummary?.activated_services || 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              {serviceChainSummary?.failed_events || 0} failed event(s),{" "}
              {serviceChainSummary?.started_accounting || 0} accounting rows
            </div>
          </div>
        </div>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-gray-500">
              <tr>
                <th className="px-3 py-2">Chain</th>
                <th className="px-3 py-2">Session</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Services</th>
                <th className="px-3 py-2">Updated</th>
              </tr>
            </thead>
            <tbody>
              {(subscriberServiceChains?.recent_chains || []).length === 0 ? (
                <tr>
                  <td className="px-3 py-3 text-gray-500" colSpan={5}>
                    No subscriber service chains have been recorded.
                  </td>
                </tr>
              ) : (
                (subscriberServiceChains?.recent_chains || []).map((chain) => (
                  <tr key={chain.chain_id} className="border-t border-gray-100">
                    <td className="px-3 py-2 font-mono text-xs">
                      {chain.chain_id}
                    </td>
                    <td className="px-3 py-2">{chain.session_id}</td>
                    <td className="px-3 py-2">{chain.status}</td>
                    <td className="px-3 py-2">
                      {chain.activated_count}/{chain.service_count}
                    </td>
                    <td className="px-3 py-2">{chain.updated_at}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              TACACS+ Device Admin
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Command authorization, privilege control, and accounting evidence
              for managed switches, routers, and controllers.
            </p>
          </div>
          <button
            onClick={loadTACACSReport}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
          >
            Refresh TACACS+
          </button>
        </div>
        <div className="grid gap-4 lg:grid-cols-4">
          <ToggleField
            label="Enable TACACS+"
            checked={Boolean(settings.tacacs?.enabled)}
            onChange={(value) => updateField(["tacacs", "enabled"], value)}
          />
          <SelectField
            label="Mode"
            value={settings.tacacs?.mode || "monitor"}
            options={[
              { value: "monitor", label: "Monitor" },
              { value: "enforce", label: "Enforce" },
            ]}
            onChange={(value) => updateField(["tacacs", "mode"], value)}
          />
          <TextField
            label="Listen Address"
            value={settings.tacacs?.listen_address || "0.0.0.0"}
            onChange={(value) =>
              updateField(["tacacs", "listen_address"], value)
            }
          />
          <TextField
            label="Port"
            type="number"
            value={settings.tacacs?.port || 49}
            onChange={(value) => updateField(["tacacs", "port"], Number(value))}
          />
          <TextField
            label="Secret Ref"
            value={settings.tacacs?.secret_ref || ""}
            onChange={(value) =>
              updateField(["tacacs", "secret_ref"], value)
            }
          />
          <TextField
            label="Max Connections"
            type="number"
            value={settings.tacacs?.max_connections || 256}
            onChange={(value) =>
              updateField(["tacacs", "max_connections"], Number(value))
            }
          />
          <TextField
            label="Max Command Bytes"
            type="number"
            value={settings.tacacs?.max_command_bytes || 512}
            onChange={(value) =>
              updateField(["tacacs", "max_command_bytes"], Number(value))
            }
          />
          <TextField
            label="Retention Limit"
            type="number"
            value={settings.tacacs?.retention_limit || 10000}
            onChange={(value) =>
              updateField(["tacacs", "retention_limit"], Number(value))
            }
          />
          <ToggleField
            label="Require Known Clients"
            checked={settings.tacacs?.require_known_client !== false}
            onChange={(value) =>
              updateField(["tacacs", "require_known_client"], value)
            }
          />
          <ToggleField
            label="Fail Closed"
            checked={settings.tacacs?.fail_closed !== false}
            onChange={(value) =>
              updateField(["tacacs", "fail_closed"], value)
            }
          />
          <ToggleField
            label="Audit Decisions"
            checked={settings.tacacs?.audit_enabled !== false}
            onChange={(value) =>
              updateField(["tacacs", "audit_enabled"], value)
            }
          />
          <ToggleField
            label="Allow Unencrypted Lab Packets"
            checked={Boolean(settings.tacacs?.allow_unencrypted)}
            onChange={(value) =>
              updateField(["tacacs", "allow_unencrypted"], value)
            }
          />
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-4">
          <div className="rounded-md border border-gray-200 px-4 py-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Status
            </div>
            <div
              className={`mt-2 inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${tacacsTone}`}
            >
              {tacacsStatus}
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {tacacsReport?.message || "TACACS+ state has not loaded yet."}
            </div>
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Command Sets
            </div>
            <div className="mt-2 text-2xl font-semibold text-gray-900">
              {tacacsSummary?.effective_sets || 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              {tacacsSummary?.enabled_sets || 0} enabled
            </div>
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Clients
            </div>
            <div className="mt-2 text-2xl font-semibold text-gray-900">
              {tacacsSummary?.enabled_clients || 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              {tacacsSummary?.configured_clients || 0} configured
            </div>
          </div>
          <div className="rounded-md border border-gray-200 px-4 py-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Evidence
            </div>
            <div className="mt-2 text-2xl font-semibold text-gray-900">
              {tacacsDBSummary?.authorization_events || 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              {tacacsDBSummary?.permit_count || 0} permit,{" "}
              {tacacsDBSummary?.deny_count || 0} deny,{" "}
              {tacacsDBSummary?.accounting_records || 0} accounting
            </div>
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 rounded-md border border-sky-100 bg-sky-50 px-4 py-3 text-sm text-sky-900">
          This page ties together captive portal, EAP, LDAP, upstream AAA, and
          SSID behavior. Save here first, then write the generated hostapd file
          when the radio is ready.
        </div>
        <div className="mb-4 grid gap-4 md:grid-cols-3">
          <SelectField
            label="Mode"
            value={settings.mode}
            onChange={(value) => updateField(["mode"], value)}
            options={[
              { value: "two-nic", label: "Two NIC Appliance" },
              { value: "trunk", label: "Trunk + VLANs" },
            ]}
          />
          <TextField
            label="Admin Port"
            type="number"
            value={settings.admin_port}
            onChange={(value) => updateField(["admin_port"], Number(value))}
          />
          <SelectField
            label="Default Role"
            value={settings.policy?.default_role || ""}
            onChange={(value) => updateField(["policy", "default_role"], value)}
            options={[{ value: "", label: "No default role" }, ...roles]}
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-3">
            <h3 className="text-lg font-semibold text-gray-900">WAN</h3>
            <TextField
              label="Interface"
              value={settings.wan?.name || ""}
              onChange={(value) => updateField(["wan", "name"], value)}
            />
            <ToggleField
              label="DHCP"
              checked={Boolean(settings.wan?.dhcp)}
              onChange={(value) => updateField(["wan", "dhcp"], value)}
            />
            <TextField
              label="Address"
              value={settings.wan?.address || ""}
              onChange={(value) => updateField(["wan", "address"], value)}
              placeholder="192.168.10.2/24"
            />
            <TextField
              label="Gateway"
              value={settings.wan?.gateway || ""}
              onChange={(value) => updateField(["wan", "gateway"], value)}
              placeholder="192.168.10.1"
            />
          </div>

          <div className="space-y-3">
            <h3 className="text-lg font-semibold text-gray-900">LAN</h3>
            <TextField
              label="Interface"
              value={settings.lan?.name || ""}
              onChange={(value) => updateField(["lan", "name"], value)}
            />
            <ToggleField
              label="DHCP"
              checked={Boolean(settings.lan?.dhcp)}
              onChange={(value) => updateField(["lan", "dhcp"], value)}
            />
            <TextField
              label="Address"
              value={settings.lan?.address || ""}
              onChange={(value) => updateField(["lan", "address"], value)}
              placeholder="192.168.50.1/24"
            />
            <TextField
              label="Gateway"
              value={settings.lan?.gateway || ""}
              onChange={(value) => updateField(["lan", "gateway"], value)}
              placeholder="192.168.50.1"
            />
            <TextField
              label="DHCP Range"
              value={settings.lan?.dhcp_range || ""}
              onChange={(value) => updateField(["lan", "dhcp_range"], value)}
              placeholder="192.168.50.100,192.168.50.200,12h"
            />
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              DNS, DHCP, And Lease Report
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Manage resolver behavior, static reservations, and current client
              leases from the same admin screen.
            </p>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField
            label="DHCP Enabled"
            checked={Boolean(settings.dhcp?.enabled)}
            onChange={(value) => updateField(["dhcp", "enabled"], value)}
          />
          <ToggleField
            label="Authoritative"
            checked={Boolean(settings.dhcp?.authoritative)}
            onChange={(value) => updateField(["dhcp", "authoritative"], value)}
          />
          <TextField
            label="Lease Time"
            value={settings.dhcp?.lease_time || "12h"}
            onChange={(value) => updateField(["dhcp", "lease_time"], value)}
            placeholder="12h"
          />
          <TextField
            label="Local DNS Domain"
            value={settings.network?.dns?.local_domain || "aegis.local"}
            onChange={(value) =>
              updateField(["network", "dns", "local_domain"], value)
            }
            placeholder="aegis.local"
          />
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <div>
            <div className="mb-3 flex items-center justify-between">
              <h4 className="font-semibold text-gray-900">
                Upstream DNS Servers
              </h4>
              <button
                onClick={() =>
                  updateField(
                    ["network", "dns", "upstream_servers"],
                    [...dnsServers, ""],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add DNS Server
              </button>
            </div>
            <div className="space-y-3">
              {dnsServers.length === 0 ? (
                <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                  Public resolvers or upstream recursive servers go here.
                </div>
              ) : (
                dnsServers.map((server: string, index: number) => (
                  <div
                    key={`dns-server-${index}`}
                    className="grid gap-3 rounded-lg border border-gray-200 p-3 md:grid-cols-[1fr_auto]"
                  >
                    <TextField
                      label={`Server ${index + 1}`}
                      value={server || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "dns", "upstream_servers", String(index)],
                          value,
                        )
                      }
                      placeholder="8.8.8.8"
                    />
                    <div className="flex items-end">
                      <button
                        onClick={() =>
                          updateField(
                            ["network", "dns", "upstream_servers"],
                            dnsServers.filter(
                              (_: unknown, itemIndex: number) =>
                                itemIndex !== index,
                            ),
                          )
                        }
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
                onClick={() =>
                  updateField(
                    ["network", "dns", "search_domains"],
                    [...searchDomains, ""],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Search Domain
              </button>
            </div>
            <div className="space-y-3">
              {searchDomains.length === 0 ? (
                <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                  Optional suffixes to hand out with DHCP.
                </div>
              ) : (
                searchDomains.map((domain: string, index: number) => (
                  <div
                    key={`search-domain-${index}`}
                    className="grid gap-3 rounded-lg border border-gray-200 p-3 md:grid-cols-[1fr_auto]"
                  >
                    <TextField
                      label={`Domain ${index + 1}`}
                      value={domain || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "dns", "search_domains", String(index)],
                          value,
                        )
                      }
                      placeholder="corp.example.com"
                    />
                    <div className="flex items-end">
                      <button
                        onClick={() =>
                          updateField(
                            ["network", "dns", "search_domains"],
                            searchDomains.filter(
                              (_: unknown, itemIndex: number) =>
                                itemIndex !== index,
                            ),
                          )
                        }
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
              <h4 className="font-semibold text-gray-900">
                Static DHCP Reservations
              </h4>
              <p className="mt-1 text-sm text-gray-600">
                Pin known clients to fixed addresses with optional hostnames and
                notes.
              </p>
            </div>
            <button
              onClick={() =>
                updateField(
                  ["dhcp", "static_leases"],
                  [
                    ...staticLeases,
                    {
                      mac: "",
                      ip: "",
                      hostname: "",
                      enabled: true,
                      description: "",
                    },
                  ],
                )
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Reservation
            </button>
          </div>
          <div className="space-y-4">
            {staticLeases.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                Create reservations for printers, APs, cameras, or lab clients
                here.
              </div>
            ) : (
              staticLeases.map((lease: JsonMap, index: number) => (
                <div
                  key={`static-lease-${index}`}
                  className="rounded-lg border border-gray-200 p-4"
                >
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">
                      {lease.hostname ||
                        lease.mac ||
                        `Reservation ${index + 1}`}
                    </h5>
                    <button
                      onClick={() =>
                        updateField(
                          ["dhcp", "static_leases"],
                          staticLeases.filter(
                            (_: unknown, itemIndex: number) =>
                              itemIndex !== index,
                          ),
                        )
                      }
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                    <TextField
                      label="MAC"
                      value={lease.mac || ""}
                      onChange={(value) =>
                        updateField(
                          ["dhcp", "static_leases", String(index), "mac"],
                          value,
                        )
                      }
                      placeholder="aa:bb:cc:dd:ee:ff"
                    />
                    <TextField
                      label="IP"
                      value={lease.ip || ""}
                      onChange={(value) =>
                        updateField(
                          ["dhcp", "static_leases", String(index), "ip"],
                          value,
                        )
                      }
                      placeholder="192.168.50.10"
                    />
                    <TextField
                      label="Hostname"
                      value={lease.hostname || ""}
                      onChange={(value) =>
                        updateField(
                          ["dhcp", "static_leases", String(index), "hostname"],
                          value,
                        )
                      }
                      placeholder="printer-lobby"
                    />
                    <TextField
                      label="Description"
                      value={lease.description || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "dhcp",
                            "static_leases",
                            String(index),
                            "description",
                          ],
                          value,
                        )
                      }
                      placeholder="Lobby printer"
                    />
                    <div className="flex items-end">
                      <ToggleField
                        label="Enabled"
                        checked={Boolean(lease.enabled)}
                        onChange={(value) =>
                          updateField(
                            ["dhcp", "static_leases", String(index), "enabled"],
                            value,
                          )
                        }
                      />
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
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                Lease Observations
              </div>
              <div className="mt-2 text-2xl font-bold text-gray-900">
                {networkObservability?.lease_trends?.total_records ??
                  dhcpLeaseHistory.length}
              </div>
              <div className="mt-1 text-sm text-gray-600">
                Stored lease-history rows.
              </div>
            </div>
            <div className="rounded-lg border border-gray-200 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                Unique Clients{" "}
                {networkObservability?.lease_trends?.window_hours || 24}h
              </div>
              <div className="mt-2 text-2xl font-bold text-gray-900">
                {networkObservability?.lease_trends?.unique_macs_window ?? 0}
              </div>
              <div className="mt-1 text-sm text-gray-600">
                Distinct MAC addresses seen recently.
              </div>
            </div>
            <div className="rounded-lg border border-gray-200 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                Peak Concurrent Leases
              </div>
              <div className="mt-2 text-2xl font-bold text-gray-900">
                {networkObservability?.lease_trends
                  ?.peak_concurrent_leases_window ?? 0}
              </div>
              <div className="mt-1 text-sm text-gray-600">
                Highest distinct lease count inside the trend window.
              </div>
            </div>
            <div className="rounded-lg border border-gray-200 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                Reservations In Window
              </div>
              <div className="mt-2 text-2xl font-bold text-gray-900">
                {networkObservability?.lease_trends
                  ?.reservation_observations_window ?? 0}
              </div>
              <div className="mt-1 text-sm text-gray-600">
                Reserved-address lease observations inside the trend window.
              </div>
            </div>
          </div>
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h4 className="font-semibold text-gray-900">IP Leasing Report</h4>
              <p className="mt-1 text-sm text-gray-600">
                Live dnsmasq lease data, including reservations and expired
                clients.
              </p>
            </div>
            <span className="text-sm text-gray-500">
              {leasesLoading ? "Refreshing..." : `${dhcpLeases.length} leases`}
            </span>
          </div>
          <div className="overflow-x-auto rounded-lg border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    IP
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    MAC
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Hostname
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Lease Ends
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Reservation
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Status
                  </th>
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
                      <td className="px-3 py-2 text-gray-900">
                        {lease.ip || "-"}
                      </td>
                      <td className="px-3 py-2 font-mono text-gray-700">
                        {lease.mac || "-"}
                      </td>
                      <td className="px-3 py-2 text-gray-700">
                        {lease.hostname || "-"}
                      </td>
                      <td className="px-3 py-2 text-gray-700">
                        {lease.expires_at || "-"}
                      </td>
                      <td className="px-3 py-2 text-gray-700">
                        {lease.reservation ? "Yes" : "No"}
                      </td>
                      <td className="px-3 py-2 text-gray-700">
                        {lease.expired ? "Expired" : "Active"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div className="mt-6">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <h5 className="font-semibold text-gray-900">
                  Recent Lease History
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Recent lease observations captured by the background collector
                  and on-demand refreshes.
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-sm text-gray-500">
                  {leasesLoading
                    ? "Refreshing history..."
                    : `${dhcpLeaseHistory.length} observations`}
                </span>
                <button
                  onClick={() => exportNetworkHistory("lease")}
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
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      Observed
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      IP
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      MAC
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      Hostname
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      Reservation
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {dhcpLeaseHistory.length === 0 ? (
                    <tr>
                      <td className="px-3 py-6 text-gray-500" colSpan={6}>
                        No lease history has been captured yet. Refresh the live
                        report to store observations.
                      </td>
                    </tr>
                  ) : (
                    dhcpLeaseHistory.slice(0, 12).map((lease) => (
                      <tr key={`${lease.id}-${lease.observed_at}`}>
                        <td className="px-3 py-2 text-gray-700">
                          {lease.observed_at}
                        </td>
                        <td className="px-3 py-2 text-gray-900">
                          {lease.ip || "-"}
                        </td>
                        <td className="px-3 py-2 font-mono text-gray-700">
                          {lease.mac || "-"}
                        </td>
                        <td className="px-3 py-2 text-gray-700">
                          {lease.hostname || "-"}
                        </td>
                        <td className="px-3 py-2 text-gray-700">
                          {lease.reservation ? "Yes" : "No"}
                        </td>
                        <td className="px-3 py-2 text-gray-700">
                          {lease.expired ? "Expired" : "Active"}
                        </td>
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
            <h3 className="text-lg font-semibold text-gray-900">
              Edge Network Preview And Rollback
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Save first, then preview or apply. The preview reflects the last
              saved config on the appliance, not unsaved edits still sitting in
              the browser.
            </p>
          </div>
          <div className="min-w-[280px]">
            <SelectField
              label="Rollback Snapshot"
              value={selectedRollbackId}
              onChange={setSelectedRollbackId}
              options={rollbackOptions}
            />
          </div>
        </div>
        {lastNetworkValidation && (
          <div
            className={`rounded-lg border p-4 text-sm ${lastNetworkValidation.healthy ? "border-emerald-200 bg-emerald-50 text-emerald-900" : "border-red-200 bg-red-50 text-red-900"}`}
          >
            <div className="font-semibold">
              {lastNetworkValidation.healthy
                ? "Last Apply Validation Passed"
                : "Last Apply Validation Failed"}
            </div>
            <div className="mt-2 space-y-1">
              {lastNetworkValidation.checks.map((check) => (
                <div
                  key={`${check.name}-${check.detail}`}
                  className="flex flex-wrap gap-2"
                >
                  <span className="font-medium">{check.name}</span>
                  <span className="uppercase tracking-wide">
                    {check.status}
                  </span>
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
                ? "border-amber-300 bg-amber-50 text-amber-950"
                : networkRecovery.status === "degraded"
                  ? "border-red-200 bg-red-50 text-red-900"
                  : "border-sky-200 bg-sky-50 text-sky-900"
            }`}
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="font-semibold">
                  {networkRecovery.pending
                    ? "Management Reachability Confirmation Pending"
                    : "Latest Reachability Recovery Status"}
                </div>
                <div className="mt-1">
                  {networkRecovery.message ||
                    "No management-loss recovery state is currently recorded."}
                </div>
                {networkRecovery.risk_summary ? (
                  <div className="mt-2 text-xs text-gray-700">
                    Risk summary: {networkRecovery.risk_summary}
                  </div>
                ) : null}
                {networkRecovery.validation_summary ? (
                  <div className="mt-1 text-xs text-gray-700">
                    Validation: {networkRecovery.validation_summary}
                  </div>
                ) : null}
                {networkRecovery.backup_id ? (
                  <div className="mt-1 text-xs text-gray-700">
                    Protected snapshot: {networkRecovery.backup_id}
                  </div>
                ) : null}
                {networkRecovery.deadline ? (
                  <div className="mt-1 text-xs text-gray-700">
                    Rollback deadline: {networkRecovery.deadline}
                  </div>
                ) : null}
              </div>
              {networkRecovery.pending ? (
                <div className="rounded-md border border-amber-300 bg-white px-3 py-2 text-sm text-amber-950">
                  <div className="text-xs font-semibold uppercase tracking-wide text-amber-800">
                    Time Remaining
                  </div>
                  <div className="mt-1 font-mono text-lg">
                    {networkRecoveryRemainingSeconds}s
                  </div>
                  <button
                    onClick={confirmNetworkRecovery}
                    disabled={confirmingNetworkRecovery}
                    className="mt-3 rounded-md border border-emerald-300 px-3 py-2 text-sm font-medium text-emerald-800 disabled:opacity-60"
                  >
                    {confirmingNetworkRecovery
                      ? "Confirming Access..."
                      : "I Still Have Admin Access"}
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
                ? "border-amber-300 bg-amber-50 text-amber-950"
                : "border-sky-200 bg-sky-50 text-sky-900"
            }`}
          >
            <div className="font-semibold">
              {riskyNetworkApply.requires_confirmation
                ? "Management Impact Confirmation Required"
                : "Edge Network Warnings"}
            </div>
            <div className="mt-1">{riskyNetworkApply.summary}</div>
            <div className="mt-3 space-y-2">
              {riskyNetworkApply.items.map((item) => (
                <div
                  key={`${item.code}-${item.message}`}
                  className={`rounded-md border px-3 py-2 ${
                    item.level === "danger"
                      ? "border-amber-300 bg-white text-amber-950"
                      : "border-sky-200 bg-white text-sky-900"
                  }`}
                >
                  <div className="text-xs font-semibold uppercase tracking-wide">
                    {item.level}
                  </div>
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
                    onChange={(event) =>
                      setNetworkConfirmationText(event.target.value)
                    }
                    placeholder={requiredConfirmationPhrase}
                    className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 font-mono"
                  />
                </label>
                <div className="rounded-md border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700">
                  <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                    Confirmation Phrase
                  </div>
                  <div className="mt-1 font-mono text-gray-900">
                    {requiredConfirmationPhrase}
                  </div>
                  <div className="mt-2 text-xs text-gray-500">
                    The apply button stays locked until this phrase matches
                    exactly.
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        ) : null}
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-sm font-semibold text-gray-900">
              Saved Config Delta
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {(networkPreview?.diff?.interfaces_added?.length || 0) +
                (networkPreview?.diff?.interfaces_removed?.length || 0) +
                (networkPreview?.diff?.gateways_added?.length || 0) +
                (networkPreview?.diff?.gateways_removed?.length || 0) +
                (networkPreview?.diff?.routes_added?.length || 0) +
                (networkPreview?.diff?.routes_removed?.length || 0)}{" "}
              managed network changes pending between the current live state and
              the last saved config.
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-sm font-semibold text-gray-900">
              DNS And DHCP Preview
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {networkPreview?.dnsmasq_enabled
                ? "dnsmasq will run with the generated config below."
                : "dnsmasq is disabled in the saved config and will be stopped on apply."}
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-sm font-semibold text-gray-900">
              Rollback Safety Net
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {networkBackups.length === 0
                ? "No edge network backups have been captured yet. The first apply will create one automatically."
                : `${networkBackups.length} rollback snapshot${networkBackups.length === 1 ? "" : "s"} available.`}
            </div>
          </div>
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
              Apply Successes
            </div>
            <div className="mt-2 text-2xl font-bold text-gray-900">
              {networkObservability?.apply_stats?.apply_success_count ?? 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              Successful edge-network applies recorded so far.
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
              Apply Failures
            </div>
            <div className="mt-2 text-2xl font-bold text-gray-900">
              {networkObservability?.apply_stats?.apply_failure_count ?? 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              Pre- or post-apply failures that interrupted a network rollout.
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
              Rollback Count
            </div>
            <div className="mt-2 text-2xl font-bold text-gray-900">
              {networkObservability?.apply_stats?.rollback_count ?? 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              Manual rollback operations completed from the UI.
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 p-4">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">
              Auto-Rollbacks
            </div>
            <div className="mt-2 text-2xl font-bold text-gray-900">
              {networkObservability?.apply_stats?.auto_rollback_count ?? 0}
            </div>
            <div className="mt-1 text-sm text-gray-600">
              Timed safety restores after risky changes lost confirmation.
            </div>
          </div>
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <div>
            <h4 className="font-semibold text-gray-900">Change Summary</h4>
            <div className="mt-3 space-y-3 text-sm">
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">
                  Interfaces Added
                </div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.interfaces_added?.length
                    ? networkPreview.diff.interfaces_added.join(", ")
                    : "None"}
                </div>
              </div>
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">
                  Interfaces Removed
                </div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.interfaces_removed?.length
                    ? networkPreview.diff.interfaces_removed.join(", ")
                    : "None"}
                </div>
              </div>
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">
                  Gateways Added Or Changed
                </div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.gateways_added?.length
                    ? networkPreview.diff.gateways_added.join(", ")
                    : "None"}
                </div>
              </div>
              <div className="rounded-lg border border-gray-200 p-3">
                <div className="font-medium text-gray-900">
                  Routes Added Or Changed
                </div>
                <div className="mt-1 text-gray-600">
                  {networkPreview?.diff?.routes_added?.length
                    ? networkPreview.diff.routes_added.join(", ")
                    : "None"}
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
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      Created
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      By
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      Reason
                    </th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-700">
                      Counts
                    </th>
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
                        <td className="px-3 py-2 text-gray-700">
                          {snapshot.created_at}
                        </td>
                        <td className="px-3 py-2 text-gray-700">
                          {snapshot.created_by || "-"}
                        </td>
                        <td className="px-3 py-2 text-gray-700">
                          {snapshot.reason || "-"}
                        </td>
                        <td className="px-3 py-2 text-gray-700">
                          {snapshot.interfaces} if / {snapshot.gateways} gw /{" "}
                          {snapshot.routes} rt
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
              <h4 className="font-semibold text-gray-900">
                Recent Apply History
              </h4>
              <p className="mt-1 text-sm text-gray-600">
                This captures applies, confirmations, failures, rollbacks, and
                auto-recovery events.
              </p>
            </div>
            <button
              onClick={() => exportNetworkHistory("apply")}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Export Apply CSV
            </button>
          </div>
          <div className="mt-3 overflow-x-auto rounded-lg border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    When
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Action
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Status
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Actor
                  </th>
                  <th className="px-3 py-2 text-left font-semibold text-gray-700">
                    Summary
                  </th>
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
                      <td className="px-3 py-2 text-gray-700">
                        {item.created_at}
                      </td>
                      <td className="px-3 py-2 text-gray-700">{item.action}</td>
                      <td className="px-3 py-2 text-gray-700">{item.status}</td>
                      <td className="px-3 py-2 text-gray-700">
                        {item.actor || "-"}
                      </td>
                      <td className="px-3 py-2 text-gray-700">
                        {item.summary || "-"}
                      </td>
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
                  <h5 className="font-semibold text-gray-900">
                    Controller Sync Health
                  </h5>
                  <p className="mt-1 text-sm text-gray-600">
                    {networkObservability.controller_sync.message ||
                      "No controller sync runtime message recorded yet."}
                  </p>
                  <div className="mt-3 grid gap-2 text-sm text-gray-700 md:grid-cols-2 xl:grid-cols-4">
                    <div>
                      Sync Count:{" "}
                      <span className="font-semibold">
                        {networkObservability.controller_sync.details
                          ?.sync_count ?? 0}
                      </span>
                    </div>
                    <div>
                      Successes:{" "}
                      <span className="font-semibold">
                        {networkObservability.controller_sync.details
                          ?.success_count ?? 0}
                      </span>
                    </div>
                    <div>
                      Failures:{" "}
                      <span className="font-semibold">
                        {networkObservability.controller_sync.details
                          ?.failure_count ?? 0}
                      </span>
                    </div>
                    <div>
                      Last Duration:{" "}
                      <span className="font-semibold">
                        {networkObservability.controller_sync.details
                          ?.last_duration_ms ?? 0}{" "}
                        ms
                      </span>
                    </div>
                    <div>
                      Adapter:{" "}
                      <span className="font-semibold">
                        {String(
                          networkObservability.controller_sync.details
                            ?.adapter || "unknown",
                        )}
                      </span>
                    </div>
                    <div>
                      Auth:{" "}
                      <span className="font-semibold">
                        {String(
                          networkObservability.controller_sync.details
                            ?.auth_scheme || "unknown",
                        )}
                      </span>
                    </div>
                    <div className="md:col-span-2">
                      Target:{" "}
                      <span className="font-semibold break-all">
                        {String(
                          networkObservability.controller_sync.details
                            ?.request_url ||
                            networkObservability.controller_sync.details
                              ?.endpoint ||
                            "n/a",
                        )}
                      </span>
                    </div>
                  </div>
                </div>
                <span className="rounded-md border border-gray-200 px-2 py-1 text-xs font-semibold uppercase text-gray-700">
                  {networkObservability.controller_sync.status || "unknown"}
                </span>
              </div>
            </div>
          ) : null}
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <label className="block text-sm font-medium text-gray-700">
            <span>Generated dnsmasq Preview</span>
            <textarea
              value={
                networkPreview?.dnsmasq_config ||
                (networkPreview?.dnsmasq_enabled
                  ? "Loading preview..."
                  : "# dnsmasq disabled in saved config")
              }
              readOnly
              className="mt-1 min-h-[240px] w-full rounded-md border border-gray-300 bg-gray-950 px-4 py-3 font-mono text-sm text-gray-100"
            />
          </label>
          <label className="block text-sm font-medium text-gray-700">
            <span>Generated Firewall Preview</span>
            <textarea
              value={networkPreview?.firewall_rules || "Loading preview..."}
              readOnly
              className="mt-1 min-h-[240px] w-full rounded-md border border-gray-300 bg-gray-950 px-4 py-3 font-mono text-sm text-gray-100"
            />
          </label>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Interfaces, Gateways, And Static Routes
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Use these objects for extra addresses, default route failover, and
              downstream network reachability.
            </p>
          </div>
        </div>

        <div className="mb-6">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Managed Interfaces</h4>
            <button
              onClick={() =>
                updateField(
                  ["network", "interfaces"],
                  [
                    ...managedInterfaces,
                    {
                      name: "",
                      address: "",
                      mtu: 1500,
                      enabled: true,
                      description: "",
                    },
                  ],
                )
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Interface
            </button>
          </div>
          <div className="space-y-4">
            {managedInterfaces.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                Use this for extra VLAN handoffs, transit links, or
                loopback-style addresses beyond the primary WAN and LAN.
              </div>
            ) : (
              managedInterfaces.map((iface: JsonMap, index: number) => (
                <div
                  key={`managed-iface-${index}`}
                  className="rounded-lg border border-gray-200 p-4"
                >
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">
                      {iface.name || `Interface ${index + 1}`}
                    </h5>
                    <button
                      onClick={() =>
                        updateField(
                          ["network", "interfaces"],
                          managedInterfaces.filter(
                            (_: unknown, itemIndex: number) =>
                              itemIndex !== index,
                          ),
                        )
                      }
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    <TextField
                      label="Name"
                      value={iface.name || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "interfaces", String(index), "name"],
                          value,
                        )
                      }
                      placeholder="eth2.50"
                    />
                    <TextField
                      label="Address"
                      value={iface.address || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "interfaces", String(index), "address"],
                          value,
                        )
                      }
                      placeholder="10.10.50.1/24"
                    />
                    <TextField
                      label="MTU"
                      type="number"
                      value={iface.mtu || 1500}
                      onChange={(value) =>
                        updateField(
                          ["network", "interfaces", String(index), "mtu"],
                          Number(value),
                        )
                      }
                    />
                    <TextField
                      label="Description"
                      value={iface.description || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "interfaces",
                            String(index),
                            "description",
                          ],
                          value,
                        )
                      }
                      placeholder="Transit handoff"
                    />
                  </div>
                  <div className="mt-4">
                    <ToggleField
                      label="Enabled"
                      checked={Boolean(iface.enabled)}
                      onChange={(value) =>
                        updateField(
                          ["network", "interfaces", String(index), "enabled"],
                          value,
                        )
                      }
                    />
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
                updateField(
                  ["network", "gateways"],
                  [
                    ...managedGateways,
                    {
                      name: "",
                      address: "",
                      interface: settings.wan?.name || "",
                      metric: 0,
                      default: true,
                      enabled: true,
                      description: "",
                    },
                  ],
                )
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Gateway
            </button>
          </div>
          <div className="space-y-4">
            {managedGateways.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                Define alternate default routes and gateway priorities here.
              </div>
            ) : (
              managedGateways.map((gateway: JsonMap, index: number) => (
                <div
                  key={`gateway-${index}`}
                  className="rounded-lg border border-gray-200 p-4"
                >
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">
                      {gateway.name || `Gateway ${index + 1}`}
                    </h5>
                    <button
                      onClick={() =>
                        updateField(
                          ["network", "gateways"],
                          managedGateways.filter(
                            (_: unknown, itemIndex: number) =>
                              itemIndex !== index,
                          ),
                        )
                      }
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                    <TextField
                      label="Name"
                      value={gateway.name || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "gateways", String(index), "name"],
                          value,
                        )
                      }
                    />
                    <TextField
                      label="Address"
                      value={gateway.address || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "gateways", String(index), "address"],
                          value,
                        )
                      }
                      placeholder="192.168.10.1"
                    />
                    <TextField
                      label="Interface"
                      value={gateway.interface || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "gateways", String(index), "interface"],
                          value,
                        )
                      }
                      placeholder={settings.wan?.name || "eth0"}
                    />
                    <TextField
                      label="Metric"
                      type="number"
                      value={gateway.metric || 0}
                      onChange={(value) =>
                        updateField(
                          ["network", "gateways", String(index), "metric"],
                          Number(value),
                        )
                      }
                    />
                    <TextField
                      label="Description"
                      value={gateway.description || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "gateways", String(index), "description"],
                          value,
                        )
                      }
                      placeholder="Primary ISP"
                    />
                  </div>
                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <ToggleField
                      label="Default Route"
                      checked={Boolean(gateway.default)}
                      onChange={(value) =>
                        updateField(
                          ["network", "gateways", String(index), "default"],
                          value,
                        )
                      }
                    />
                    <ToggleField
                      label="Enabled"
                      checked={Boolean(gateway.enabled)}
                      onChange={(value) =>
                        updateField(
                          ["network", "gateways", String(index), "enabled"],
                          value,
                        )
                      }
                    />
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
                updateField(
                  ["network", "static_routes"],
                  [
                    ...staticRoutes,
                    {
                      name: "",
                      destination: "",
                      gateway: "",
                      interface: settings.wan?.name || "",
                      metric: 0,
                      enabled: true,
                      description: "",
                    },
                  ],
                )
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Route
            </button>
          </div>
          <div className="space-y-4">
            {staticRoutes.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                Add static routes for upstream services, site links, or
                downstream lab networks.
              </div>
            ) : (
              staticRoutes.map((route: JsonMap, index: number) => (
                <div
                  key={`route-${index}`}
                  className="rounded-lg border border-gray-200 p-4"
                >
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">
                      {route.name || `Route ${index + 1}`}
                    </h5>
                    <button
                      onClick={() =>
                        updateField(
                          ["network", "static_routes"],
                          staticRoutes.filter(
                            (_: unknown, itemIndex: number) =>
                              itemIndex !== index,
                          ),
                        )
                      }
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
                    <TextField
                      label="Name"
                      value={route.name || ""}
                      onChange={(value) =>
                        updateField(
                          ["network", "static_routes", String(index), "name"],
                          value,
                        )
                      }
                    />
                    <TextField
                      label="Destination"
                      value={route.destination || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "static_routes",
                            String(index),
                            "destination",
                          ],
                          value,
                        )
                      }
                      placeholder="172.16.20.0/24"
                    />
                    <TextField
                      label="Gateway"
                      value={route.gateway || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "static_routes",
                            String(index),
                            "gateway",
                          ],
                          value,
                        )
                      }
                      placeholder="192.168.10.254"
                    />
                    <TextField
                      label="Interface"
                      value={route.interface || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "static_routes",
                            String(index),
                            "interface",
                          ],
                          value,
                        )
                      }
                      placeholder={settings.wan?.name || "eth0"}
                    />
                    <TextField
                      label="Metric"
                      type="number"
                      value={route.metric || 0}
                      onChange={(value) =>
                        updateField(
                          ["network", "static_routes", String(index), "metric"],
                          Number(value),
                        )
                      }
                    />
                    <TextField
                      label="Description"
                      value={route.description || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "static_routes",
                            String(index),
                            "description",
                          ],
                          value,
                        )
                      }
                      placeholder="Branch backhaul"
                    />
                  </div>
                  <div className="mt-4">
                    <ToggleField
                      label="Enabled"
                      checked={Boolean(route.enabled)}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "static_routes",
                            String(index),
                            "enabled",
                          ],
                          value,
                        )
                      }
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">
            Firewall, DoS, And Free Sites
          </h3>
          <p className="mt-1 text-sm text-gray-600">
            Blend platform-safe defaults with explicit admin rules, domain/CIDR
            wall-garden entries, and lightweight DoS controls.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
          <ToggleField
            label="DoS Protection Enabled"
            checked={Boolean(
              settings.network?.firewall?.dos_protection?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["network", "firewall", "dos_protection", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="SYN Rate"
            value={
              settings.network?.firewall?.dos_protection?.syn_rate ||
              "50/second"
            }
            onChange={(value) =>
              updateField(
                ["network", "firewall", "dos_protection", "syn_rate"],
                value,
              )
            }
          />
          <TextField
            label="ICMP Rate"
            value={
              settings.network?.firewall?.dos_protection?.icmp_rate ||
              "25/second"
            }
            onChange={(value) =>
              updateField(
                ["network", "firewall", "dos_protection", "icmp_rate"],
                value,
              )
            }
          />
          <TextField
            label="Conn Rate"
            value={
              settings.network?.firewall?.dos_protection?.conn_rate ||
              "200/second"
            }
            onChange={(value) =>
              updateField(
                ["network", "firewall", "dos_protection", "conn_rate"],
                value,
              )
            }
          />
          <TextField
            label="Burst"
            type="number"
            value={settings.network?.firewall?.dos_protection?.burst || 100}
            onChange={(value) =>
              updateField(
                ["network", "firewall", "dos_protection", "burst"],
                Number(value),
              )
            }
          />
        </div>
        <div className="mt-3">
          <ToggleField
            label="Log DoS Drops"
            checked={Boolean(
              settings.network?.firewall?.dos_protection?.log_drops,
            )}
            onChange={(value) =>
              updateField(
                ["network", "firewall", "dos_protection", "log_drops"],
                value,
              )
            }
          />
        </div>

        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Free Sites</h4>
            <button
              onClick={() =>
                updateField(
                  ["network", "firewall", "free_sites"],
                  [
                    ...freeSites,
                    {
                      type: "domain",
                      value: "",
                      enabled: true,
                      description: "",
                    },
                  ],
                )
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Free Site
            </button>
          </div>
          <div className="space-y-4">
            {freeSites.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                Allow captive clients to reach health checks, payment portals,
                or approved public destinations here.
              </div>
            ) : (
              freeSites.map((site: JsonMap, index: number) => (
                <div
                  key={`free-site-${index}`}
                  className="rounded-lg border border-gray-200 p-4"
                >
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">
                      {site.value || `Free Site ${index + 1}`}
                    </h5>
                    <button
                      onClick={() =>
                        updateField(
                          ["network", "firewall", "free_sites"],
                          freeSites.filter(
                            (_: unknown, itemIndex: number) =>
                              itemIndex !== index,
                          ),
                        )
                      }
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    <SelectField
                      label="Type"
                      value={site.type || "domain"}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "free_sites",
                            String(index),
                            "type",
                          ],
                          value,
                        )
                      }
                      options={freeSiteTypeOptions}
                    />
                    <TextField
                      label="Value"
                      value={site.value || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "free_sites",
                            String(index),
                            "value",
                          ],
                          value,
                        )
                      }
                      placeholder={
                        site.type === "cidr" ? "203.0.113.0/24" : "example.com"
                      }
                    />
                    <TextField
                      label="Description"
                      value={site.description || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "free_sites",
                            String(index),
                            "description",
                          ],
                          value,
                        )
                      }
                      placeholder="Payment provider"
                    />
                    <div className="flex items-end">
                      <ToggleField
                        label="Enabled"
                        checked={Boolean(site.enabled)}
                        onChange={(value) =>
                          updateField(
                            [
                              "network",
                              "firewall",
                              "free_sites",
                              String(index),
                              "enabled",
                            ],
                            value,
                          )
                        }
                      />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">
              Custom Firewall Rules
            </h4>
            <button
              onClick={() =>
                updateField(
                  ["network", "firewall", "rules"],
                  [
                    ...firewallRules,
                    {
                      name: "",
                      chain: "forward",
                      action: "accept",
                      interface: "",
                      source: "",
                      destination: "",
                      protocol: "any",
                      ports: "",
                      enabled: true,
                      description: "",
                    },
                  ],
                )
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Firewall Rule
            </button>
          </div>
          <div className="space-y-4">
            {firewallRules.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
                Add explicit input or forward rules when the built-in edge
                policy needs a careful exception.
              </div>
            ) : (
              firewallRules.map((rule: JsonMap, index: number) => (
                <div
                  key={`firewall-rule-${index}`}
                  className="rounded-lg border border-gray-200 p-4"
                >
                  <div className="mb-3 flex items-center justify-between">
                    <h5 className="font-semibold text-gray-900">
                      {rule.name || `Rule ${index + 1}`}
                    </h5>
                    <button
                      onClick={() =>
                        updateField(
                          ["network", "firewall", "rules"],
                          firewallRules.filter(
                            (_: unknown, itemIndex: number) =>
                              itemIndex !== index,
                          ),
                        )
                      }
                      className="text-sm font-medium text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                    <TextField
                      label="Name"
                      value={rule.name || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "name",
                          ],
                          value,
                        )
                      }
                    />
                    <SelectField
                      label="Chain"
                      value={rule.chain || "forward"}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "chain",
                          ],
                          value,
                        )
                      }
                      options={firewallChainOptions}
                    />
                    <SelectField
                      label="Action"
                      value={rule.action || "accept"}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "action",
                          ],
                          value,
                        )
                      }
                      options={firewallActionOptions}
                    />
                    <SelectField
                      label="Protocol"
                      value={rule.protocol || "any"}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "protocol",
                          ],
                          value,
                        )
                      }
                      options={firewallProtocolOptions}
                    />
                    <TextField
                      label="Interface"
                      value={rule.interface || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "interface",
                          ],
                          value,
                        )
                      }
                      placeholder="ens37"
                    />
                    <TextField
                      label="Source CIDR"
                      value={rule.source || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "source",
                          ],
                          value,
                        )
                      }
                      placeholder="192.168.50.0/24"
                    />
                    <TextField
                      label="Destination CIDR"
                      value={rule.destination || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "destination",
                          ],
                          value,
                        )
                      }
                      placeholder="203.0.113.0/24"
                    />
                    <TextField
                      label="Ports"
                      value={rule.ports || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "ports",
                          ],
                          value,
                        )
                      }
                      placeholder="80,443"
                    />
                    <TextField
                      label="Description"
                      value={rule.description || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "description",
                          ],
                          value,
                        )
                      }
                      placeholder="Allow support tunnel"
                    />
                  </div>
                  <div className="mt-4">
                    <ToggleField
                      label="Enabled"
                      checked={Boolean(rule.enabled)}
                      onChange={(value) =>
                        updateField(
                          [
                            "network",
                            "firewall",
                            "rules",
                            String(index),
                            "enabled",
                          ],
                          value,
                        )
                      }
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">
            Captive Portal And Directory
          </h3>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <ToggleField
            label="Portal Enabled"
            checked={Boolean(settings.portal?.enabled)}
            onChange={(value) => updateField(["portal", "enabled"], value)}
          />
          <ToggleField
            label="Portal Uses RADIUS Broker"
            checked={Boolean(settings.portal?.radius_auth)}
            onChange={(value) => updateField(["portal", "radius_auth"], value)}
          />
          <ToggleField
            label="Local Fallback"
            checked={Boolean(settings.portal?.local_fallback)}
            onChange={(value) =>
              updateField(["portal", "local_fallback"], value)
            }
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <TextField
            label="Portal Port"
            type="number"
            value={settings.portal?.port || 8081}
            onChange={(value) => updateField(["portal", "port"], Number(value))}
          />
          <TextField
            label="Portal Listen IP"
            value={settings.portal?.listen_ip || ""}
            onChange={(value) => updateField(["portal", "listen_ip"], value)}
          />
          <TextField
            label="Branding"
            value={settings.portal?.branding || ""}
            onChange={(value) => updateField(["portal", "branding"], value)}
          />
          <TextField
            label="Success URL"
            value={settings.portal?.success_url || ""}
            onChange={(value) => updateField(["portal", "success_url"], value)}
          />
          <TextField
            label="Logout URL"
            value={settings.portal?.logout_url || ""}
            onChange={(value) => updateField(["portal", "logout_url"], value)}
          />
          <TextField
            label="LDAP URL"
            value={settings.ldap?.url || ""}
            onChange={(value) => updateField(["ldap", "url"], value)}
            placeholder="ldaps://ldap.example.com"
          />
          <TextField
            label="Base DN"
            value={settings.ldap?.base_dn || ""}
            onChange={(value) => updateField(["ldap", "base_dn"], value)}
          />
          <TextField
            label="Bind DN"
            value={settings.ldap?.bind_dn || ""}
            onChange={(value) => updateField(["ldap", "bind_dn"], value)}
          />
          <TextField
            label="Bind Password"
            type="password"
            value={settings.ldap?.bind_password || ""}
            onChange={(value) => updateField(["ldap", "bind_password"], value)}
          />
          <TextField
            label="User Filter"
            value={settings.ldap?.user_filter || ""}
            onChange={(value) => updateField(["ldap", "user_filter"], value)}
          />
          <TextField
            label="Group Filter"
            value={settings.ldap?.group_filter || ""}
            onChange={(value) => updateField(["ldap", "group_filter"], value)}
          />
        </div>
        <div className="mt-4">
          <ToggleField
            label="LDAP Enabled"
            checked={Boolean(settings.ldap?.enabled)}
            onChange={(value) => updateField(["ldap", "enabled"], value)}
          />
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              MAC Authentication Bypass
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Known device MACs can receive role, VLAN, ACL, bandwidth, tenant,
              and quarantine decisions when 802.1X is not available.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <ToggleField
              label="MAB Enabled"
              checked={Boolean(settings.mab?.enabled)}
              onChange={(value) => updateField(["mab", "enabled"], value)}
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.mab?.fail_closed !== false}
              onChange={(value) => updateField(["mab", "fail_closed"], value)}
            />
            <ToggleField
              label="Audit Decisions"
              checked={settings.mab?.audit_enabled !== false}
              onChange={(value) =>
                updateField(["mab", "audit_enabled"], value)
              }
            />
            <ToggleField
              label="Link Device Profiles"
              checked={settings.mab?.profiling_link_enabled !== false}
              onChange={(value) =>
                updateField(["mab", "profiling_link_enabled"], value)
              }
            />
            <ToggleField
              label="Inventory Fallback"
              checked={settings.mab?.endpoint_inventory_fallback !== false}
              onChange={(value) =>
                updateField(["mab", "endpoint_inventory_fallback"], value)
              }
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SelectField
              label="Mode"
              value={settings.mab?.mode || "monitor"}
              onChange={(value) => updateField(["mab", "mode"], value)}
              options={transportPolicyModeOptions}
            />
            <SelectField
              label="Unknown Endpoint"
              value={settings.mab?.unknown_endpoint_policy || "deny"}
              onChange={(value) =>
                updateField(["mab", "unknown_endpoint_policy"], value)
              }
              options={mabUnknownPolicyOptions}
            />
            <SelectField
              label="Password Policy"
              value={settings.mab?.password_policy || "accept_known_mac"}
              onChange={(value) =>
                updateField(["mab", "password_policy"], value)
              }
              options={mabPasswordPolicyOptions}
            />
            <TextField
              label="Default Role"
              value={settings.mab?.default_role || ""}
              onChange={(value) => updateField(["mab", "default_role"], value)}
              placeholder="employee"
            />
            <TextField
              label="Guest Role"
              value={settings.mab?.guest_role || "guest"}
              onChange={(value) => updateField(["mab", "guest_role"], value)}
            />
            <TextField
              label="Quarantine Role"
              value={settings.mab?.quarantine_role || "quarantine"}
              onChange={(value) =>
                updateField(["mab", "quarantine_role"], value)
              }
            />
            <TextField
              label="Allowed NAS-Port-Types"
              value={listToCSV(
                settings.mab?.allowed_nas_port_types || [
                  "ethernet",
                  "wireless-802.11",
                  "wireless80211",
                ],
              )}
              onChange={(value) =>
                updateField(["mab", "allowed_nas_port_types"], csvToList(value))
              }
            />
            <TextField
              label="MAC Formats"
              value={listToCSV(
                settings.mab?.mac_formats || [
                  "colon",
                  "hyphen",
                  "plain",
                  "cisco-dot",
                ],
              )}
              onChange={(value) =>
                updateField(["mab", "mac_formats"], csvToList(value))
              }
            />
            <TextField
              label="Revalidate Seconds"
              type="number"
              value={settings.mab?.revalidate_interval_seconds || 300}
              onChange={(value) =>
                updateField(
                  ["mab", "revalidate_interval_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Cache TTL Seconds"
              type="number"
              value={settings.mab?.cache_ttl_seconds || 300}
              onChange={(value) =>
                updateField(["mab", "cache_ttl_seconds"], Number(value))
              }
            />
            <TextField
              label="Audit Retention"
              type="number"
              value={settings.mab?.retention_limit || 6000}
              onChange={(value) =>
                updateField(["mab", "retention_limit"], Number(value))
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              Password And Supplicant Lifecycle
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Deliver signed 802.1X profiles and require password-change,
              verifier, trust-anchor, TLS, and MFA evidence before rollout.
            </p>
          </div>
          <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Supplicant Lifecycle Enabled"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle?.enabled,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle?.fail_closed ?? true,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "fail_closed"],
                  value,
                )
              }
            />
            <ToggleField
              label="Audit Events"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle?.audit_enabled ??
                  true,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "audit_enabled"],
                  value,
                )
              }
            />
            <SelectField
              label="Lifecycle Mode"
              value={
                settings.onboarding?.supplicant_lifecycle?.mode || "monitor"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "mode"],
                  value,
                )
              }
              options={certificateLifecycleModeOptions}
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <TextField
              label="Enterprise SSID"
              value={
                settings.onboarding?.supplicant_lifecycle?.ssid ||
                "AegisNAS-Enterprise"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "ssid"],
                  value,
                )
              }
            />
            <SelectField
              label="Security"
              value={
                settings.onboarding?.supplicant_lifecycle?.security ||
                "wpa2-enterprise"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "security"],
                  value,
                )
              }
              options={supplicantSecurityOptions}
            />
            <SelectField
              label="Default Platform"
              value={
                settings.onboarding?.supplicant_lifecycle?.default_platform ||
                "windows"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "default_platform"],
                  value,
                )
              }
              options={supplicantPlatformOptions}
            />
            <TextField
              label="Allowed Platforms"
              value={listToCSV(
                settings.onboarding?.supplicant_lifecycle?.allowed_platforms ||
                  supplicantLifecycleDefaults.allowed_platforms,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "allowed_platforms"],
                  csvToList(value),
                )
              }
              placeholder="windows, macos, ios, android, linux"
            />
            <TextField
              label="Allowed EAP Methods"
              value={listToCSV(
                settings.onboarding?.supplicant_lifecycle
                  ?.allowed_eap_methods ||
                  supplicantLifecycleDefaults.allowed_eap_methods,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "allowed_eap_methods"],
                  csvToList(value),
                )
              }
              placeholder="tls, peap, ttls"
            />
            <TextField
              label="Default EAP Method"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.default_eap_method || "tls"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "default_eap_method"],
                  value,
                )
              }
            />
            <TextField
              label="Allowed Inner Methods"
              value={listToCSV(
                settings.onboarding?.supplicant_lifecycle
                  ?.allowed_inner_methods ||
                  supplicantLifecycleDefaults.allowed_inner_methods,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "allowed_inner_methods",
                  ],
                  csvToList(value),
                )
              }
              placeholder="mschapv2, pap, gtc, tls"
            />
            <TextField
              label="Default Inner Method"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.default_inner_method || "mschapv2"
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "default_inner_method",
                  ],
                  value,
                )
              }
            />
            <TextField
              label="Anonymous Identity"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.anonymous_identity || "anonymous@aegisnas.local"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "anonymous_identity"],
                  value,
                )
              }
            />
            <TextField
              label="Domain Suffix Match"
              value={
                settings.onboarding?.supplicant_lifecycle?.domain_suffix || ""
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "domain_suffix"],
                  value,
                )
              }
              placeholder="example.com"
            />
            <TextField
              label="Server Names"
              value={listToCSV(
                settings.onboarding?.supplicant_lifecycle?.server_names || [],
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "server_names"],
                  csvToList(value),
                )
              }
              placeholder="radius.example.com"
            />
            <TextField
              label="Trust Anchor Pins"
              value={listToCSV(
                settings.onboarding?.supplicant_lifecycle
                  ?.trust_anchor_pins || [],
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "trust_anchor_pins"],
                  csvToList(value),
                )
              }
              placeholder="sha256:..."
            />
            <TextField
              label="Password Change URL"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.password_change_url || ""
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "password_change_url"],
                  value,
                )
              }
              placeholder="https://portal.example.com/password"
            />
            <TextField
              label="Password Change Providers"
              value={listToCSV(
                settings.onboarding?.supplicant_lifecycle
                  ?.password_change_providers ||
                  supplicantLifecycleDefaults.password_change_providers,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "password_change_providers",
                  ],
                  csvToList(value),
                )
              }
              placeholder="local, active-directory, identity-failover"
            />
            <TextField
              label="Compatible Verifiers"
              value={listToCSV(
                settings.onboarding?.supplicant_lifecycle
                  ?.compatible_verifiers ||
                  supplicantLifecycleDefaults.compatible_verifiers,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "compatible_verifiers",
                  ],
                  csvToList(value),
                )
              }
              placeholder="local, ldap, active-directory, winbind"
            />
            <TextField
              label="Profile Signing Key Ref"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.profile_signing_key_ref || ""
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "profile_signing_key_ref",
                  ],
                  value,
                )
              }
              placeholder="env:AEGIS_SUPPLICANT_PROFILE_SIGNING_KEY"
            />
            <TextField
              label="Max Password Age Days"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.max_password_age_days ?? 90
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "max_password_age_days",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Expiry Warning Days"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.expiry_warning_days ?? 14
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "expiry_warning_days",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Grace Period Days"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.grace_period_days ?? 7
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "grace_period_days"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Min Password Length"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.min_password_length ?? 12
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "supplicant_lifecycle", "min_password_length"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Profile Validity Days"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.profile_validity_days ?? 365
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "profile_validity_days",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Delivery Token TTL Seconds"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.delivery_token_ttl_seconds ?? 900
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "delivery_token_ttl_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Event Retention Limit"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.event_retention_limit ?? 6000
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "event_retention_limit",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Profile Retention Limit"
              type="number"
              value={
                settings.onboarding?.supplicant_lifecycle
                  ?.profile_retention_limit ?? 100000
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "profile_retention_limit",
                  ],
                  Number(value),
                )
              }
            />
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Require Anonymous Identity"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle
                  ?.require_anonymous_identity ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "require_anonymous_identity",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Trust Pinning"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle
                  ?.require_trust_anchor_pinning ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "require_trust_anchor_pinning",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Allow Password Change"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle
                  ?.allow_password_change ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "allow_password_change",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Verifier Compatibility"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle
                  ?.require_verifier_compatibility ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "require_verifier_compatibility",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require MFA For Change"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle
                  ?.require_mfa_for_change ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "require_mfa_for_change",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require TLS Delivery"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle
                  ?.require_tls_for_delivery ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "require_tls_for_delivery",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Signed Profiles"
              checked={Boolean(
                settings.onboarding?.supplicant_lifecycle
                  ?.require_signed_profiles ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "supplicant_lifecycle",
                    "require_signed_profiles",
                  ],
                  value,
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              Active Directory Kerberos And Winbind
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Domain identity uses LDAPS lookup, Kerberos password checks, or a
              winbind helper with bounded group cache and audit history.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <ToggleField
              label="AD Enabled"
              checked={Boolean(settings.active_directory?.enabled)}
              onChange={(value) =>
                updateField(["active_directory", "enabled"], value)
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.active_directory?.fail_closed !== false}
              onChange={(value) =>
                updateField(["active_directory", "fail_closed"], value)
              }
            />
            <ToggleField
              label="Audit Decisions"
              checked={settings.active_directory?.audit_enabled !== false}
              onChange={(value) =>
                updateField(["active_directory", "audit_enabled"], value)
              }
            />
            <ToggleField
              label="Require LDAPS"
              checked={settings.active_directory?.require_ldaps !== false}
              onChange={(value) =>
                updateField(["active_directory", "require_ldaps"], value)
              }
            />
            <ToggleField
              label="Nested Groups"
              checked={settings.active_directory?.nested_groups !== false}
              onChange={(value) =>
                updateField(["active_directory", "nested_groups"], value)
              }
            />
            <ToggleField
              label="Kerberos Enabled"
              checked={Boolean(settings.active_directory?.kerberos?.enabled)}
              onChange={(value) =>
                updateField(["active_directory", "kerberos", "enabled"], value)
              }
            />
            <ToggleField
              label="Winbind Enabled"
              checked={Boolean(settings.active_directory?.winbind?.enabled)}
              onChange={(value) =>
                updateField(["active_directory", "winbind", "enabled"], value)
              }
            />
            <ToggleField
              label="Domain Join Required"
              checked={
                settings.active_directory?.winbind?.domain_join_required !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "winbind", "domain_join_required"],
                  value,
                )
              }
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SelectField
              label="Mode"
              value={settings.active_directory?.mode || "monitor"}
              onChange={(value) =>
                updateField(["active_directory", "mode"], value)
              }
              options={transportPolicyModeOptions}
            />
            <SelectField
              label="Verifier"
              value={settings.active_directory?.auth_method || "ldap_bind"}
              onChange={(value) =>
                updateField(["active_directory", "auth_method"], value)
              }
              options={activeDirectoryAuthMethodOptions}
            />
            <TextField
              label="Domain"
              value={settings.active_directory?.domain || ""}
              onChange={(value) =>
                updateField(["active_directory", "domain"], value)
              }
              placeholder="corp.example.com"
            />
            <TextField
              label="Realm"
              value={settings.active_directory?.realm || ""}
              onChange={(value) =>
                updateField(["active_directory", "realm"], value)
              }
              placeholder="CORP.EXAMPLE.COM"
            />
            <TextField
              label="NetBIOS Domain"
              value={settings.active_directory?.netbios_domain || ""}
              onChange={(value) =>
                updateField(["active_directory", "netbios_domain"], value)
              }
              placeholder="CORP"
            />
            <TextField
              label="AD LDAP URL"
              value={settings.active_directory?.ldap_url || ""}
              onChange={(value) =>
                updateField(["active_directory", "ldap_url"], value)
              }
              placeholder="ldaps://dc1.corp.example.com:636"
            />
            <TextField
              label="AD Base DN"
              value={settings.active_directory?.base_dn || ""}
              onChange={(value) =>
                updateField(["active_directory", "base_dn"], value)
              }
              placeholder="dc=corp,dc=example,dc=com"
            />
            <TextField
              label="AD Bind DN"
              value={settings.active_directory?.bind_dn || ""}
              onChange={(value) =>
                updateField(["active_directory", "bind_dn"], value)
              }
              placeholder="cn=aegisnas,ou=svc,dc=corp,dc=example,dc=com"
            />
            <TextField
              label="AD Bind Password"
              type="password"
              value={settings.active_directory?.bind_password || ""}
              onChange={(value) =>
                updateField(["active_directory", "bind_password"], value)
              }
            />
            <TextField
              label="AD Bind Password Ref"
              value={settings.active_directory?.bind_password_ref || ""}
              onChange={(value) =>
                updateField(["active_directory", "bind_password_ref"], value)
              }
              placeholder="env:AEGIS_AD_BIND_PASSWORD"
            />
            <TextField
              label="AD User Filter"
              value={
                settings.active_directory?.user_filter ||
                "(|(userPrincipalName=%p)(sAMAccountName=%u))"
              }
              onChange={(value) =>
                updateField(["active_directory", "user_filter"], value)
              }
            />
            <TextField
              label="AD Group Filter"
              value={
                settings.active_directory?.group_filter ||
                "(|(member=%D)(member:1.2.840.113556.1.4.1941:=%D))"
              }
              onChange={(value) =>
                updateField(["active_directory", "group_filter"], value)
              }
            />
            <TextField
              label="Default AD Role"
              value={settings.active_directory?.default_role || ""}
              onChange={(value) =>
                updateField(["active_directory", "default_role"], value)
              }
              placeholder="guest-basic"
            />
            <TextField
              label="Request Timeout Seconds"
              type="number"
              value={settings.active_directory?.request_timeout_seconds || 5}
              onChange={(value) =>
                updateField(
                  ["active_directory", "request_timeout_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Group Cache TTL Seconds"
              type="number"
              value={settings.active_directory?.group_cache_ttl_seconds || 3600}
              onChange={(value) =>
                updateField(
                  ["active_directory", "group_cache_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Health Check Seconds"
              type="number"
              value={
                settings.active_directory?.health_check_interval_seconds || 60
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "health_check_interval_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Clock Skew Seconds"
              type="number"
              value={settings.active_directory?.clock_skew_seconds || 300}
              onChange={(value) =>
                updateField(
                  ["active_directory", "clock_skew_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="AD Audit Retention"
              type="number"
              value={settings.active_directory?.retention_limit || 6000}
              onChange={(value) =>
                updateField(
                  ["active_directory", "retention_limit"],
                  Number(value),
                )
              }
            />
            <TextField
              label="kinit Path"
              value={
                settings.active_directory?.kerberos?.kinit_path || "kinit"
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "kerberos", "kinit_path"],
                  value,
                )
              }
            />
            <TextField
              label="kdestroy Path"
              value={
                settings.active_directory?.kerberos?.kdestroy_path ||
                "kdestroy"
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "kerberos", "kdestroy_path"],
                  value,
                )
              }
            />
            <TextField
              label="krb5.conf Path"
              value={
                settings.active_directory?.kerberos?.krb5_config_path || ""
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "kerberos", "krb5_config_path"],
                  value,
                )
              }
            />
            <TextField
              label="Keytab Path"
              value={settings.active_directory?.kerberos?.keytab_path || ""}
              onChange={(value) =>
                updateField(
                  ["active_directory", "kerberos", "keytab_path"],
                  value,
                )
              }
            />
            <TextField
              label="Service Principal"
              value={
                settings.active_directory?.kerberos?.service_principal || ""
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "kerberos", "service_principal"],
                  value,
                )
              }
            />
            <TextField
              label="Credential Cache Dir"
              value={
                settings.active_directory?.kerberos?.credential_cache_dir || ""
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "kerberos", "credential_cache_dir"],
                  value,
                )
              }
            />
            <TextField
              label="wbinfo Path"
              value={settings.active_directory?.winbind?.wbinfo_path || "wbinfo"}
              onChange={(value) =>
                updateField(
                  ["active_directory", "winbind", "wbinfo_path"],
                  value,
                )
              }
            />
            <TextField
              label="ntlm_auth Path"
              value={
                settings.active_directory?.winbind?.ntlm_auth_path ||
                "/usr/bin/ntlm_auth"
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "winbind", "ntlm_auth_path"],
                  value,
                )
              }
            />
            <TextField
              label="Winbind Auth Helper"
              value={
                settings.active_directory?.winbind?.auth_helper_path || ""
              }
              onChange={(value) =>
                updateField(
                  ["active_directory", "winbind", "auth_helper_path"],
                  value,
                )
              }
              placeholder="/usr/local/libexec/aegisnas-ad-auth"
            />
            <label className="block text-sm font-medium text-gray-700 md:col-span-2 lg:col-span-3">
              <span>Group Role Mappings</span>
              <textarea
                value={mapToLines(
                  settings.active_directory?.group_role_mappings || {},
                )}
                onChange={(event) =>
                  updateField(
                    ["active_directory", "group_role_mappings"],
                    linesToMap(event.target.value),
                  )
                }
                rows={4}
                placeholder={"AegisNAS-Employees=employee\nAegisNAS-Admins=admin"}
                className="mt-1 w-full rounded-md border border-gray-300 px-3 py-2"
              />
            </label>
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              Identity Source Failover
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Ordered local and LDAP decisions keep portal authentication
              predictable during source outages.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <ToggleField
              label="Failover Enabled"
              checked={settings.identity?.failover?.enabled !== false}
              onChange={(value) =>
                updateField(["identity", "failover", "enabled"], value)
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.identity?.failover?.fail_closed !== false}
              onChange={(value) =>
                updateField(["identity", "failover", "fail_closed"], value)
              }
            />
            <ToggleField
              label="Audit Decisions"
              checked={settings.identity?.failover?.audit_enabled !== false}
              onChange={(value) =>
                updateField(["identity", "failover", "audit_enabled"], value)
              }
            />
            <ToggleField
              label="Credential Cache"
              checked={Boolean(settings.identity?.failover?.cache_credentials)}
              onChange={(value) =>
                updateField(
                  ["identity", "failover", "cache_credentials"],
                  value,
                )
              }
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SelectField
              label="Mode"
              value={settings.identity?.failover?.mode || "monitor"}
              onChange={(value) =>
                updateField(["identity", "failover", "mode"], value)
              }
              options={transportPolicyModeOptions}
            />
            <SelectField
              label="Split Result Policy"
              value={
                settings.identity?.failover?.split_result_policy || "deny"
              }
              onChange={(value) =>
                updateField(
                  ["identity", "failover", "split_result_policy"],
                  value,
                )
              }
              options={splitResultPolicyOptions}
            />
            <TextField
              label="Source Order"
              value={listToCSV(
                settings.identity?.failover?.source_order || [
                  "local",
                  "active-directory",
                  "ldap-primary",
                ],
              )}
              onChange={(value) =>
                updateField(
                  ["identity", "failover", "source_order"],
                  csvToList(value),
                )
              }
              placeholder="local, active-directory, ldap-primary"
            />
            <TextField
              label="Max Failures"
              type="number"
              value={settings.identity?.failover?.max_failures || 3}
              onChange={(value) =>
                updateField(
                  ["identity", "failover", "max_failures"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Circuit Open Seconds"
              type="number"
              value={settings.identity?.failover?.circuit_open_seconds || 300}
              onChange={(value) =>
                updateField(
                  ["identity", "failover", "circuit_open_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Stale Cache Seconds"
              type="number"
              value={settings.identity?.failover?.stale_cache_seconds || 3600}
              onChange={(value) =>
                updateField(
                  ["identity", "failover", "stale_cache_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Health Check Seconds"
              type="number"
              value={
                settings.identity?.failover?.health_check_interval_seconds || 60
              }
              onChange={(value) =>
                updateField(
                  [
                    "identity",
                    "failover",
                    "health_check_interval_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Audit Retention"
              type="number"
              value={settings.identity?.failover?.retention_limit || 6000}
              onChange={(value) =>
                updateField(
                  ["identity", "failover", "retention_limit"],
                  Number(value),
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              OTP And Challenge MFA
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Step-up verification protects privileged roles and selected
              realms with encrypted TOTP secrets, recovery codes, and bounded
              challenge state.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <ToggleField
              label="MFA Enabled"
              checked={Boolean(settings.mfa?.enabled)}
              onChange={(value) => updateField(["mfa", "enabled"], value)}
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.mfa?.fail_closed !== false}
              onChange={(value) => updateField(["mfa", "fail_closed"], value)}
            />
            <ToggleField
              label="OTP Enabled"
              checked={settings.mfa?.otp?.enabled !== false}
              onChange={(value) =>
                updateField(["mfa", "otp", "enabled"], value)
              }
            />
            <ToggleField
              label="Admin Step-Up"
              checked={settings.mfa?.otp?.required_for_admins !== false}
              onChange={(value) =>
                updateField(["mfa", "otp", "required_for_admins"], value)
              }
            />
            <ToggleField
              label="RADIUS Challenge State"
              checked={settings.mfa?.radius_challenge?.enabled !== false}
              onChange={(value) =>
                updateField(["mfa", "radius_challenge", "enabled"], value)
              }
            />
            <ToggleField
              label="Recovery Codes"
              checked={settings.mfa?.recovery?.enabled !== false}
              onChange={(value) =>
                updateField(["mfa", "recovery", "enabled"], value)
              }
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SelectField
              label="Mode"
              value={settings.mfa?.mode || "monitor"}
              onChange={(value) => updateField(["mfa", "mode"], value)}
              options={transportPolicyModeOptions}
            />
            <TextField
              label="Issuer"
              value={settings.mfa?.otp?.issuer || "AegisNAS"}
              onChange={(value) => updateField(["mfa", "otp", "issuer"], value)}
            />
            <SelectField
              label="Algorithm"
              value={settings.mfa?.otp?.algorithm || "SHA1"}
              onChange={(value) =>
                updateField(["mfa", "otp", "algorithm"], value)
              }
              options={[
                { value: "SHA1", label: "SHA1" },
                { value: "SHA256", label: "SHA256" },
                { value: "SHA512", label: "SHA512" },
              ]}
            />
            <TextField
              label="Digits"
              type="number"
              value={settings.mfa?.otp?.digits || 6}
              onChange={(value) =>
                updateField(["mfa", "otp", "digits"], Number(value))
              }
            />
            <TextField
              label="Period Seconds"
              type="number"
              value={settings.mfa?.otp?.period_seconds || 30}
              onChange={(value) =>
                updateField(["mfa", "otp", "period_seconds"], Number(value))
              }
            />
            <TextField
              label="Window Steps"
              type="number"
              value={settings.mfa?.otp?.window_steps ?? 1}
              onChange={(value) =>
                updateField(["mfa", "otp", "window_steps"], Number(value))
              }
            />
            <TextField
              label="Max Attempts"
              type="number"
              value={settings.mfa?.otp?.max_attempts || 5}
              onChange={(value) =>
                updateField(["mfa", "otp", "max_attempts"], Number(value))
              }
            />
            <TextField
              label="Sealing Key Ref"
              value={
                settings.mfa?.otp?.sealing_key_ref ||
                "env:AEGIS_MFA_SEALING_KEY"
              }
              onChange={(value) =>
                updateField(["mfa", "otp", "sealing_key_ref"], value)
              }
            />
            <TextField
              label="Step-Up Roles"
              value={listToCSV(
                settings.mfa?.otp?.step_up_roles || [
                  "admin",
                  "super_admin",
                  "ops_admin",
                ],
              )}
              onChange={(value) =>
                updateField(["mfa", "otp", "step_up_roles"], csvToList(value))
              }
              placeholder="admin, super_admin, ops_admin"
            />
            <TextField
              label="Step-Up Realms"
              value={listToCSV(settings.mfa?.otp?.step_up_realms || [])}
              onChange={(value) =>
                updateField(["mfa", "otp", "step_up_realms"], csvToList(value))
              }
              placeholder="corp.example, contractors.example"
            />
            <TextField
              label="Challenge TTL Seconds"
              type="number"
              value={settings.mfa?.radius_challenge?.ttl_seconds || 300}
              onChange={(value) =>
                updateField(
                  ["mfa", "radius_challenge", "ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Pending Challenges"
              type="number"
              value={settings.mfa?.radius_challenge?.max_pending || 10000}
              onChange={(value) =>
                updateField(
                  ["mfa", "radius_challenge", "max_pending"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Challenge Prompt"
              value={
                settings.mfa?.radius_challenge?.prompt ||
                "Enter one-time password"
              }
              onChange={(value) =>
                updateField(["mfa", "radius_challenge", "prompt"], value)
              }
            />
            <TextField
              label="State Bytes"
              type="number"
              value={settings.mfa?.radius_challenge?.state_bytes || 32}
              onChange={(value) =>
                updateField(
                  ["mfa", "radius_challenge", "state_bytes"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Recovery Code Count"
              type="number"
              value={settings.mfa?.recovery?.code_count || 10}
              onChange={(value) =>
                updateField(["mfa", "recovery", "code_count"], Number(value))
              }
            />
            <TextField
              label="Recovery Code Bytes"
              type="number"
              value={settings.mfa?.recovery?.code_bytes || 16}
              onChange={(value) =>
                updateField(["mfa", "recovery", "code_bytes"], Number(value))
              }
            />
            <TextField
              label="Recovery TTL Seconds"
              type="number"
              value={settings.mfa?.recovery?.code_ttl_seconds || 0}
              onChange={(value) =>
                updateField(
                  ["mfa", "recovery", "code_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Audit Retention"
              type="number"
              value={settings.mfa?.retention_limit || 6000}
              onChange={(value) =>
                updateField(["mfa", "retention_limit"], Number(value))
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              Admin Passkeys
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Phishing-resistant WebAuthn step-up protects privileged admin
              sessions after token or SSO first factor.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <ToggleField
              label="Passkeys Enabled"
              checked={Boolean(settings.admin_webauthn?.enabled)}
              onChange={(value) =>
                updateField(["admin_webauthn", "enabled"], value)
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.admin_webauthn?.fail_closed !== false}
              onChange={(value) =>
                updateField(["admin_webauthn", "fail_closed"], value)
              }
            />
            <ToggleField
              label="Require For SSO"
              checked={settings.admin_webauthn?.require_for_sso !== false}
              onChange={(value) =>
                updateField(["admin_webauthn", "require_for_sso"], value)
              }
            />
            <ToggleField
              label="Require For Token Login"
              checked={
                settings.admin_webauthn?.require_for_token_login !== false
              }
              onChange={(value) =>
                updateField(
                  ["admin_webauthn", "require_for_token_login"],
                  value,
                )
              }
            />
            <ToggleField
              label="Break-Glass Allowed"
              checked={settings.admin_webauthn?.break_glass_allowed !== false}
              onChange={(value) =>
                updateField(["admin_webauthn", "break_glass_allowed"], value)
              }
            />
            <ToggleField
              label="Audit Enabled"
              checked={settings.admin_webauthn?.audit_enabled !== false}
              onChange={(value) =>
                updateField(["admin_webauthn", "audit_enabled"], value)
              }
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SelectField
              label="Mode"
              value={settings.admin_webauthn?.mode || "monitor"}
              onChange={(value) =>
                updateField(["admin_webauthn", "mode"], value)
              }
              options={transportPolicyModeOptions}
            />
            <TextField
              label="RP ID"
              value={settings.admin_webauthn?.rp_id || ""}
              onChange={(value) =>
                updateField(["admin_webauthn", "rp_id"], value)
              }
              placeholder="admin.example.com"
            />
            <TextField
              label="RP Name"
              value={settings.admin_webauthn?.rp_name || "AegisNAS Admin"}
              onChange={(value) =>
                updateField(["admin_webauthn", "rp_name"], value)
              }
            />
            <TextField
              label="Origins"
              value={listToCSV(settings.admin_webauthn?.origins || [])}
              onChange={(value) =>
                updateField(["admin_webauthn", "origins"], csvToList(value))
              }
              placeholder="https://admin.example.com"
            />
            <SelectField
              label="User Verification"
              value={settings.admin_webauthn?.user_verification || "preferred"}
              onChange={(value) =>
                updateField(["admin_webauthn", "user_verification"], value)
              }
              options={[
                { value: "required", label: "Required" },
                { value: "preferred", label: "Preferred" },
                { value: "discouraged", label: "Discouraged" },
              ]}
            />
            <SelectField
              label="Attestation"
              value={settings.admin_webauthn?.attestation || "none"}
              onChange={(value) =>
                updateField(["admin_webauthn", "attestation"], value)
              }
              options={[
                { value: "none", label: "None" },
                { value: "direct", label: "Direct" },
                { value: "enterprise", label: "Enterprise" },
              ]}
            />
            <SelectField
              label="Resident Key"
              value={settings.admin_webauthn?.resident_key || "preferred"}
              onChange={(value) =>
                updateField(["admin_webauthn", "resident_key"], value)
              }
              options={[
                { value: "required", label: "Required" },
                { value: "preferred", label: "Preferred" },
                { value: "discouraged", label: "Discouraged" },
              ]}
            />
            <TextField
              label="Required Roles"
              value={listToCSV(
                settings.admin_webauthn?.require_for_roles || [
                  "super_admin",
                  "ops_admin",
                ],
              )}
              onChange={(value) =>
                updateField(
                  ["admin_webauthn", "require_for_roles"],
                  csvToList(value),
                )
              }
              placeholder="super_admin, ops_admin"
            />
            <TextField
              label="Challenge TTL Seconds"
              type="number"
              value={settings.admin_webauthn?.challenge_ttl_seconds || 300}
              onChange={(value) =>
                updateField(
                  ["admin_webauthn", "challenge_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Session TTL Seconds"
              type="number"
              value={settings.admin_webauthn?.session_ttl_seconds || 28800}
              onChange={(value) =>
                updateField(
                  ["admin_webauthn", "session_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Pending Challenges"
              type="number"
              value={settings.admin_webauthn?.max_pending || 10000}
              onChange={(value) =>
                updateField(
                  ["admin_webauthn", "max_pending"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Audit Retention"
              type="number"
              value={settings.admin_webauthn?.retention_limit || 6000}
              onChange={(value) =>
                updateField(
                  ["admin_webauthn", "retention_limit"],
                  Number(value),
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              Guest Workflow And Delivery
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Phase 2 turns guest self-registration and sponsor approval into
              production-checked settings instead of free-form toggles.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <ToggleField
              label="Self Registration Enabled"
              checked={Boolean(
                settings.portal?.guest_workflows?.self_registration_enabled,
              )}
              onChange={(value) =>
                updateField(
                  ["portal", "guest_workflows", "self_registration_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Sponsor Approval Enabled"
              checked={Boolean(
                settings.portal?.guest_workflows?.sponsor_approval_enabled,
              )}
              onChange={(value) =>
                updateField(
                  ["portal", "guest_workflows", "sponsor_approval_enabled"],
                  value,
                )
              }
            />
            <SelectField
              label="Invite Delivery"
              value={
                settings.portal?.guest_workflows?.invite_delivery || "none"
              }
              onChange={(value) =>
                updateField(
                  ["portal", "guest_workflows", "invite_delivery"],
                  value,
                )
              }
              options={guestDeliveryOptions}
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SelectField
              label="Approval Delivery"
              value={settings.portal?.guest_workflows?.approval_delivery || ""}
              onChange={(value) =>
                updateField(
                  ["portal", "guest_workflows", "approval_delivery"],
                  value,
                )
              }
              options={approvalDeliveryOptions}
            />
            <TextField
              label="Email From"
              value={settings.portal?.guest_workflows?.email_from || ""}
              onChange={(value) =>
                updateField(["portal", "guest_workflows", "email_from"], value)
              }
              placeholder="guests@example.com"
            />
            <TextField
              label="SMTP Server"
              value={settings.portal?.guest_workflows?.smtp_server || ""}
              onChange={(value) =>
                updateField(["portal", "guest_workflows", "smtp_server"], value)
              }
              placeholder="smtp.example.com"
            />
            <TextField
              label="SMTP Port"
              type="number"
              value={settings.portal?.guest_workflows?.smtp_port || 587}
              onChange={(value) =>
                updateField(
                  ["portal", "guest_workflows", "smtp_port"],
                  Number(value),
                )
              }
            />
            <TextField
              label="SMS Provider"
              value={settings.portal?.guest_workflows?.sms_provider || ""}
              onChange={(value) =>
                updateField(
                  ["portal", "guest_workflows", "sms_provider"],
                  value,
                )
              }
              placeholder="twilio-like"
            />
            <TextField
              label="SMS Endpoint"
              value={settings.portal?.guest_workflows?.sms_endpoint || ""}
              onChange={(value) =>
                updateField(
                  ["portal", "guest_workflows", "sms_endpoint"],
                  value,
                )
              }
              placeholder="https://sms.example.com/send"
            />
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">
            AI Engine And Runtime Load
          </h3>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <SelectField
            label="AI Mode"
            value={settings.ailite?.mode || "lite"}
            onChange={(value) => updateField(["ailite", "mode"], value)}
            options={aiModeOptions}
          />
          <SelectField
            label="AI Provider"
            value={settings.ailite?.provider || "local"}
            onChange={(value) => updateField(["ailite", "provider"], value)}
            options={aiProviderOptions}
          />
          <TextField
            label="Full AI Endpoint"
            value={settings.ailite?.endpoint || ""}
            onChange={(value) => updateField(["ailite", "endpoint"], value)}
            placeholder="http://127.0.0.1:11434"
          />
          <TextField
            label="Full AI Model"
            value={settings.ailite?.model || ""}
            onChange={(value) => updateField(["ailite", "model"], value)}
            placeholder="ops-model"
          />
          <TextField
            label="AI API Key Env"
            value={settings.ailite?.api_key_env || "AEGIS_AI_API_KEY"}
            onChange={(value) => updateField(["ailite", "api_key_env"], value)}
          />
          <TextField
            label="AI Timeout Seconds"
            type="number"
            value={settings.ailite?.request_timeout_seconds || 20}
            onChange={(value) =>
              updateField(["ailite", "request_timeout_seconds"], Number(value))
            }
          />
          <TextField
            label="AI Input Events"
            type="number"
            value={settings.ailite?.max_input_events || 200}
            onChange={(value) =>
              updateField(["ailite", "max_input_events"], Number(value))
            }
          />
          <TextField
            label="Prometheus Port"
            type="number"
            value={settings.telemetry?.prometheus_port || 9090}
            onChange={(value) =>
              updateField(["telemetry", "prometheus_port"], Number(value))
            }
          />
          <TextField
            label="Lease History Poll Seconds"
            type="number"
            value={settings.telemetry?.lease_history_poll_seconds || 300}
            onChange={(value) =>
              updateField(
                ["telemetry", "lease_history_poll_seconds"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Support Bundle Exports"
            checked={Boolean(
              settings.telemetry?.support_bundle_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "support_bundle_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Support Bundle Export Directory"
            value={
              settings.telemetry?.support_bundle_exports?.directory ||
              "/var/lib/aegisnas/support-bundles"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "support_bundle_exports", "directory"],
                value,
              )
            }
          />
          <TextField
            label="Support Bundle Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.support_bundle_exports?.interval_minutes ||
              360
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "support_bundle_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Support Bundle Export Retention"
            type="number"
            value={
              settings.telemetry?.support_bundle_exports?.retention_count || 7
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "support_bundle_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Diagnostics Exports"
            checked={Boolean(settings.telemetry?.diagnostics_exports?.enabled)}
            onChange={(value) =>
              updateField(
                ["telemetry", "diagnostics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Diagnostics Export Directory"
            value={
              settings.telemetry?.diagnostics_exports?.directory ||
              "/var/lib/aegisnas/diagnostics"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "diagnostics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Diagnostics Export Format"
            value={settings.telemetry?.diagnostics_exports?.format || "json"}
            onChange={(value) =>
              updateField(["telemetry", "diagnostics_exports", "format"], value)
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Diagnostics Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.diagnostics_exports?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "diagnostics_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Diagnostics Export Retention"
            type="number"
            value={
              settings.telemetry?.diagnostics_exports?.retention_count || 14
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "diagnostics_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Audit Exports"
            checked={Boolean(settings.telemetry?.audit_exports?.enabled)}
            onChange={(value) =>
              updateField(["telemetry", "audit_exports", "enabled"], value)
            }
          />
          <TextField
            label="Audit Export Directory"
            value={
              settings.telemetry?.audit_exports?.directory ||
              "/var/lib/aegisnas/audit-exports"
            }
            onChange={(value) =>
              updateField(["telemetry", "audit_exports", "directory"], value)
            }
          />
          <SelectField
            label="Audit Export Format"
            value={settings.telemetry?.audit_exports?.format || "json"}
            onChange={(value) =>
              updateField(["telemetry", "audit_exports", "format"], value)
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Audit Export Interval Minutes"
            type="number"
            value={settings.telemetry?.audit_exports?.interval_minutes || 60}
            onChange={(value) =>
              updateField(
                ["telemetry", "audit_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Audit Export Retention"
            type="number"
            value={settings.telemetry?.audit_exports?.retention_count || 21}
            onChange={(value) =>
              updateField(
                ["telemetry", "audit_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Session Exports"
            checked={Boolean(settings.telemetry?.session_exports?.enabled)}
            onChange={(value) =>
              updateField(["telemetry", "session_exports", "enabled"], value)
            }
          />
          <TextField
            label="Session Export Directory"
            value={
              settings.telemetry?.session_exports?.directory ||
              "/var/lib/aegisnas/session-exports"
            }
            onChange={(value) =>
              updateField(["telemetry", "session_exports", "directory"], value)
            }
          />
          <SelectField
            label="Session Export Format"
            value={settings.telemetry?.session_exports?.format || "both"}
            onChange={(value) =>
              updateField(["telemetry", "session_exports", "format"], value)
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Session Export Interval"
            type="number"
            value={settings.telemetry?.session_exports?.interval_minutes || 60}
            onChange={(value) =>
              updateField(
                ["telemetry", "session_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Session Export Retention"
            type="number"
            value={settings.telemetry?.session_exports?.retention_count || 21}
            onChange={(value) =>
              updateField(
                ["telemetry", "session_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Session Analytics Exports"
            checked={Boolean(
              settings.telemetry?.session_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "session_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Session Analytics Export Directory"
            value={
              settings.telemetry?.session_analytics_exports?.directory ||
              "/var/lib/aegisnas/session-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "session_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Session Analytics Export Format"
            value={
              settings.telemetry?.session_analytics_exports?.format || "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "session_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Session Analytics Export Interval"
            type="number"
            value={
              settings.telemetry?.session_analytics_exports?.interval_minutes ||
              60
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "session_analytics_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Session Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.session_analytics_exports?.retention_count ||
              21
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "session_analytics_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Voucher Analytics Exports"
            checked={Boolean(
              settings.telemetry?.voucher_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Voucher Analytics Export Directory"
            value={
              settings.telemetry?.voucher_analytics_exports?.directory ||
              "/var/lib/aegisnas/voucher-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Voucher Analytics Export Format"
            value={
              settings.telemetry?.voucher_analytics_exports?.format || "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Voucher Analytics Export Interval"
            type="number"
            value={
              settings.telemetry?.voucher_analytics_exports?.interval_minutes ||
              60
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_analytics_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Voucher Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.voucher_analytics_exports?.retention_count ||
              21
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_analytics_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Voucher Aging Analytics Exports"
            checked={Boolean(
              settings.telemetry?.voucher_aging_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_aging_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Voucher Aging Analytics Export Directory"
            value={
              settings.telemetry?.voucher_aging_analytics_exports?.directory ||
              "/var/lib/aegisnas/voucher-aging-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_aging_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Voucher Aging Analytics Export Format"
            value={
              settings.telemetry?.voucher_aging_analytics_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_aging_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Voucher Aging Analytics Export Interval"
            type="number"
            value={
              settings.telemetry?.voucher_aging_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_aging_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Voucher Aging Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.voucher_aging_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_aging_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Voucher Redemption Analytics Exports"
            checked={Boolean(
              settings.telemetry?.voucher_redemption_analytics_exports
                ?.enabled,
            )}
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_redemption_analytics_exports",
                  "enabled",
                ],
                value,
              )
            }
          />
          <TextField
            label="Voucher Redemption Analytics Export Directory"
            value={
              settings.telemetry?.voucher_redemption_analytics_exports
                ?.directory ||
              "/var/lib/aegisnas/voucher-redemption-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_redemption_analytics_exports",
                  "directory",
                ],
                value,
              )
            }
          />
          <SelectField
            label="Voucher Redemption Analytics Export Format"
            value={
              settings.telemetry?.voucher_redemption_analytics_exports
                ?.format || "json"
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_redemption_analytics_exports",
                  "format",
                ],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Voucher Redemption Analytics Export Interval"
            type="number"
            value={
              settings.telemetry?.voucher_redemption_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_redemption_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Voucher Redemption Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.voucher_redemption_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_redemption_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Voucher Expiry Analytics Exports"
            checked={Boolean(
              settings.telemetry?.voucher_expiry_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_expiry_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Voucher Expiry Analytics Export Directory"
            value={
              settings.telemetry?.voucher_expiry_analytics_exports?.directory ||
              "/var/lib/aegisnas/voucher-expiry-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_expiry_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Voucher Expiry Analytics Export Format"
            value={
              settings.telemetry?.voucher_expiry_analytics_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "voucher_expiry_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Voucher Expiry Analytics Export Interval"
            type="number"
            value={
              settings.telemetry?.voucher_expiry_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_expiry_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Voucher Expiry Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.voucher_expiry_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "voucher_expiry_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Guest Lifecycle Exports"
            checked={Boolean(
              settings.telemetry?.guest_lifecycle_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_lifecycle_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Guest Lifecycle Export Directory"
            value={
              settings.telemetry?.guest_lifecycle_exports?.directory ||
              "/var/lib/aegisnas/guest-lifecycle-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_lifecycle_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Guest Lifecycle Export Format"
            value={
              settings.telemetry?.guest_lifecycle_exports?.format || "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_lifecycle_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Guest Lifecycle Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.guest_lifecycle_exports?.interval_minutes ||
              60
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_lifecycle_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Guest Lifecycle Export Retention"
            type="number"
            value={
              settings.telemetry?.guest_lifecycle_exports?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_lifecycle_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Guest Invite Analytics Exports"
            checked={Boolean(
              settings.telemetry?.guest_invite_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_invite_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Guest Invite Analytics Export Directory"
            value={
              settings.telemetry?.guest_invite_analytics_exports?.directory ||
              "/var/lib/aegisnas/guest-invite-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_invite_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Guest Invite Analytics Export Format"
            value={
              settings.telemetry?.guest_invite_analytics_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_invite_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Guest Invite Analytics Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.guest_invite_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_invite_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Guest Invite Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.guest_invite_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_invite_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Guest Conversion Analytics Exports"
            checked={Boolean(
              settings.telemetry?.guest_conversion_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_conversion_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Guest Conversion Analytics Export Directory"
            value={
              settings.telemetry?.guest_conversion_analytics_exports
                ?.directory ||
              "/var/lib/aegisnas/guest-conversion-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_conversion_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Guest Conversion Analytics Export Format"
            value={
              settings.telemetry?.guest_conversion_analytics_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_conversion_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Guest Conversion Analytics Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.guest_conversion_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_conversion_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Guest Conversion Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.guest_conversion_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_conversion_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Guest Rejection Analytics Exports"
            checked={Boolean(
              settings.telemetry?.guest_rejection_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_rejection_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Guest Rejection Analytics Export Directory"
            value={
              settings.telemetry?.guest_rejection_analytics_exports
                ?.directory || "/var/lib/aegisnas/guest-rejection-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_rejection_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Guest Rejection Analytics Export Format"
            value={
              settings.telemetry?.guest_rejection_analytics_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_rejection_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Guest Rejection Analytics Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.guest_rejection_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_rejection_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Guest Rejection Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.guest_rejection_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_rejection_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Guest Delivery Analytics Exports"
            checked={Boolean(
              settings.telemetry?.guest_delivery_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_delivery_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Guest Delivery Analytics Export Directory"
            value={
              settings.telemetry?.guest_delivery_analytics_exports?.directory ||
              "/var/lib/aegisnas/guest-delivery-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_delivery_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Guest Delivery Analytics Export Format"
            value={
              settings.telemetry?.guest_delivery_analytics_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_delivery_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Guest Delivery Analytics Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.guest_delivery_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_delivery_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Guest Delivery Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.guest_delivery_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_delivery_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Guest Delivery Failure Exports"
            checked={Boolean(
              settings.telemetry?.guest_delivery_failures_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_delivery_failures_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Guest Delivery Failure Export Directory"
            value={
              settings.telemetry?.guest_delivery_failures_exports?.directory ||
              "/var/lib/aegisnas/guest-delivery-failures-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_delivery_failures_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Guest Delivery Failure Export Format"
            value={
              settings.telemetry?.guest_delivery_failures_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_delivery_failures_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Guest Delivery Failure Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.guest_delivery_failures_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_delivery_failures_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Guest Delivery Failure Export Retention"
            type="number"
            value={
              settings.telemetry?.guest_delivery_failures_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_delivery_failures_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Guest Sponsor Analytics Exports"
            checked={Boolean(
              settings.telemetry?.guest_sponsor_analytics_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_sponsor_analytics_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Guest Sponsor Analytics Export Directory"
            value={
              settings.telemetry?.guest_sponsor_analytics_exports?.directory ||
              "/var/lib/aegisnas/guest-sponsor-analytics-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_sponsor_analytics_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Guest Sponsor Analytics Export Format"
            value={
              settings.telemetry?.guest_sponsor_analytics_exports?.format ||
              "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "guest_sponsor_analytics_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Guest Sponsor Analytics Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.guest_sponsor_analytics_exports
                ?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_sponsor_analytics_exports",
                  "interval_minutes",
                ],
                Number(value),
              )
            }
          />
          <TextField
            label="Guest Sponsor Analytics Export Retention"
            type="number"
            value={
              settings.telemetry?.guest_sponsor_analytics_exports
                ?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                [
                  "telemetry",
                  "guest_sponsor_analytics_exports",
                  "retention_count",
                ],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Integration Exports"
            checked={Boolean(settings.telemetry?.integration_exports?.enabled)}
            onChange={(value) =>
              updateField(
                ["telemetry", "integration_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Integration Export Directory"
            value={
              settings.telemetry?.integration_exports?.directory ||
              "/var/lib/aegisnas/integration-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "integration_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Integration Export Format"
            value={settings.telemetry?.integration_exports?.format || "json"}
            onChange={(value) =>
              updateField(["telemetry", "integration_exports", "format"], value)
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Integration Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.integration_exports?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "integration_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Integration Export Retention"
            type="number"
            value={
              settings.telemetry?.integration_exports?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "integration_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled HA Exports"
            checked={Boolean(settings.telemetry?.ha_exports?.enabled)}
            onChange={(value) =>
              updateField(["telemetry", "ha_exports", "enabled"], value)
            }
          />
          <TextField
            label="HA Export Directory"
            value={
              settings.telemetry?.ha_exports?.directory ||
              "/var/lib/aegisnas/ha-exports"
            }
            onChange={(value) =>
              updateField(["telemetry", "ha_exports", "directory"], value)
            }
          />
          <SelectField
            label="HA Export Format"
            value={settings.telemetry?.ha_exports?.format || "json"}
            onChange={(value) =>
              updateField(["telemetry", "ha_exports", "format"], value)
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="HA Export Interval Minutes"
            type="number"
            value={settings.telemetry?.ha_exports?.interval_minutes || 60}
            onChange={(value) =>
              updateField(
                ["telemetry", "ha_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="HA Export Retention"
            type="number"
            value={settings.telemetry?.ha_exports?.retention_count || 21}
            onChange={(value) =>
              updateField(
                ["telemetry", "ha_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Network Exports"
            checked={Boolean(settings.telemetry?.network_exports?.enabled)}
            onChange={(value) =>
              updateField(["telemetry", "network_exports", "enabled"], value)
            }
          />
          <TextField
            label="Network Export Directory"
            value={
              settings.telemetry?.network_exports?.directory ||
              "/var/lib/aegisnas/network-exports"
            }
            onChange={(value) =>
              updateField(["telemetry", "network_exports", "directory"], value)
            }
          />
          <SelectField
            label="Network Export Format"
            value={settings.telemetry?.network_exports?.format || "json"}
            onChange={(value) =>
              updateField(["telemetry", "network_exports", "format"], value)
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Network Export Interval Minutes"
            type="number"
            value={settings.telemetry?.network_exports?.interval_minutes || 60}
            onChange={(value) =>
              updateField(
                ["telemetry", "network_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Network Export Retention"
            type="number"
            value={settings.telemetry?.network_exports?.retention_count || 21}
            onChange={(value) =>
              updateField(
                ["telemetry", "network_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Upstream AAA Exports"
            checked={Boolean(settings.telemetry?.upstream_aaa_exports?.enabled)}
            onChange={(value) =>
              updateField(
                ["telemetry", "upstream_aaa_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Upstream AAA Export Directory"
            value={
              settings.telemetry?.upstream_aaa_exports?.directory ||
              "/var/lib/aegisnas/upstream-aaa-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "upstream_aaa_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Upstream AAA Export Format"
            value={settings.telemetry?.upstream_aaa_exports?.format || "json"}
            onChange={(value) =>
              updateField(
                ["telemetry", "upstream_aaa_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Upstream AAA Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.upstream_aaa_exports?.interval_minutes || 60
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "upstream_aaa_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Upstream AAA Export Retention"
            type="number"
            value={
              settings.telemetry?.upstream_aaa_exports?.retention_count || 21
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "upstream_aaa_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <ToggleField
            label="Scheduled Upgrade Readiness Exports"
            checked={Boolean(
              settings.telemetry?.upgrade_readiness_exports?.enabled,
            )}
            onChange={(value) =>
              updateField(
                ["telemetry", "upgrade_readiness_exports", "enabled"],
                value,
              )
            }
          />
          <TextField
            label="Upgrade Readiness Export Directory"
            value={
              settings.telemetry?.upgrade_readiness_exports?.directory ||
              "/var/lib/aegisnas/upgrade-readiness-exports"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "upgrade_readiness_exports", "directory"],
                value,
              )
            }
          />
          <SelectField
            label="Upgrade Readiness Export Format"
            value={
              settings.telemetry?.upgrade_readiness_exports?.format || "json"
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "upgrade_readiness_exports", "format"],
                value,
              )
            }
            options={[
              { value: "json", label: "JSON" },
              { value: "csv", label: "CSV" },
              { value: "both", label: "JSON + CSV" },
            ]}
          />
          <TextField
            label="Upgrade Readiness Export Interval Minutes"
            type="number"
            value={
              settings.telemetry?.upgrade_readiness_exports?.interval_minutes ||
              240
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "upgrade_readiness_exports", "interval_minutes"],
                Number(value),
              )
            }
          />
          <TextField
            label="Upgrade Readiness Export Retention"
            type="number"
            value={
              settings.telemetry?.upgrade_readiness_exports?.retention_count ||
              14
            }
            onChange={(value) =>
              updateField(
                ["telemetry", "upgrade_readiness_exports", "retention_count"],
                Number(value),
              )
            }
          />
          <TextField
            label="Recommendation Limit"
            type="number"
            value={settings.ailite?.recommendation_limit || 100}
            onChange={(value) =>
              updateField(["ailite", "recommendation_limit"], Number(value))
            }
          />
          <TextField
            label="AI Webhook"
            value={settings.ailite?.remote_webhook || ""}
            onChange={(value) =>
              updateField(["ailite", "remote_webhook"], value)
            }
            placeholder="https://ops.example.com/webhook"
          />
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">
            Onboarding, Inventory, And Profiling
          </h3>
          <p className="mt-1 text-sm text-gray-600">
            Phase 3 prepares BYOD-style onboarding, certificate enrollment, and
            device visibility with production-safe dependency checks.
          </p>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField
            label="Device Inventory Enabled"
            checked={Boolean(settings.onboarding?.device_inventory_enabled)}
            onChange={(value) =>
              updateField(["onboarding", "device_inventory_enabled"], value)
            }
          />
          <ToggleField
            label="Onboarding Portal Enabled"
            checked={Boolean(settings.onboarding?.portal_enabled)}
            onChange={(value) =>
              updateField(["onboarding", "portal_enabled"], value)
            }
          />
          <ToggleField
            label="Certificate Enrollment Enabled"
            checked={Boolean(
              settings.onboarding?.certificate_enrollment_enabled,
            )}
            onChange={(value) =>
              updateField(
                ["onboarding", "certificate_enrollment_enabled"],
                value,
              )
            }
          />
          <ToggleField
            label="EAP-TLS Onboarding Enabled"
            checked={Boolean(settings.onboarding?.eap_tls_enabled)}
            onChange={(value) =>
              updateField(["onboarding", "eap_tls_enabled"], value)
            }
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SelectField
            label="CA Mode"
            value={settings.onboarding?.ca_mode || "none"}
            onChange={(value) => updateField(["onboarding", "ca_mode"], value)}
            options={caModeOptions}
          />
          <TextField
            label="CA Certificate Path"
            value={settings.onboarding?.ca_cert_path || ""}
            onChange={(value) =>
              updateField(["onboarding", "ca_cert_path"], value)
            }
            placeholder="/etc/aegisnas/pki/ca.crt"
          />
          <TextField
            label="CA Private Key Path"
            value={settings.onboarding?.ca_key_path || ""}
            onChange={(value) =>
              updateField(["onboarding", "ca_key_path"], value)
            }
            placeholder="/etc/aegisnas/pki/ca.key"
          />
          <TextField
            label="CA Enrollment URL"
            value={settings.onboarding?.ca_enrollment_url || ""}
            onChange={(value) =>
              updateField(["onboarding", "ca_enrollment_url"], value)
            }
            placeholder="https://ca.example.com/enroll"
          />
          <TextField
            label="CA Enrollment Token Env"
            value={settings.onboarding?.ca_enrollment_token_env || ""}
            onChange={(value) =>
              updateField(["onboarding", "ca_enrollment_token_env"], value)
            }
            placeholder="AEGIS_CA_ENROLLMENT_TOKEN"
          />
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              Certificate Lifecycle
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Govern EAP-TLS certificate templates, EST/SCEP/BYOD enrollment,
              revocation evidence, renewal windows, and issuer rollover.
            </p>
          </div>
          <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Lifecycle Enabled"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.enabled,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.fail_closed ??
                  true,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "fail_closed"],
                  value,
                )
              }
            />
            <ToggleField
              label="Audit Events"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.audit_enabled ??
                  true,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "audit_enabled"],
                  value,
                )
              }
            />
            <SelectField
              label="Lifecycle Mode"
              value={
                settings.onboarding?.certificate_lifecycle?.mode || "monitor"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "mode"],
                  value,
                )
              }
              options={certificateLifecycleModeOptions}
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <TextField
              label="Templates"
              value={listToCSV(
                settings.onboarding?.certificate_lifecycle?.templates ||
                  certificateLifecycleDefaults.templates,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "templates"],
                  csvToList(value),
                )
              }
              placeholder="device-eap-tls, byod-eap-tls"
            />
            <TextField
              label="Default Template"
              value={
                settings.onboarding?.certificate_lifecycle?.default_template ||
                "device-eap-tls"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "default_template"],
                  value,
                )
              }
            />
            <TextField
              label="Active Issuer"
              value={
                settings.onboarding?.certificate_lifecycle?.active_issuer ||
                "aegisnas-local"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "active_issuer"],
                  value,
                )
              }
            />
            <TextField
              label="Staged Issuer"
              value={
                settings.onboarding?.certificate_lifecycle?.staged_issuer || ""
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "staged_issuer"],
                  value,
                )
              }
            />
            <SelectField
              label="Issuer Rotation"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.issuer_rotation_mode || "disabled"
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "issuer_rotation_mode",
                  ],
                  value,
                )
              }
              options={certificateLifecycleRotationOptions}
            />
            <TextField
              label="Issuer Overlap Seconds"
              type="number"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.issuer_overlap_seconds ?? 2592000
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "issuer_overlap_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Validity Days"
              type="number"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.certificate_validity_days ?? 365
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "certificate_validity_days",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Validity Days"
              type="number"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.max_certificate_validity_days ?? 825
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "max_certificate_validity_days",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Renewal Window Days"
              type="number"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.renewal_window_days ?? 30
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "renewal_window_days",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Allowed Key Types"
              value={listToCSV(
                settings.onboarding?.certificate_lifecycle
                  ?.allowed_key_types ||
                  certificateLifecycleDefaults.allowed_key_types,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "allowed_key_types"],
                  csvToList(value),
                )
              }
              placeholder="rsa, ecdsa, ed25519"
            />
            <TextField
              label="Minimum RSA Bits"
              type="number"
              value={
                settings.onboarding?.certificate_lifecycle?.min_rsa_bits ??
                2048
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "min_rsa_bits"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Allowed ECDSA Curves"
              value={listToCSV(
                settings.onboarding?.certificate_lifecycle
                  ?.allowed_ecdsa_curves ||
                  certificateLifecycleDefaults.allowed_ecdsa_curves,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "allowed_ecdsa_curves",
                  ],
                  csvToList(value),
                )
              }
              placeholder="P-256, P-384, P-521"
            />
            <SelectField
              label="Escrow Policy"
              value={
                settings.onboarding?.certificate_lifecycle?.escrow_policy ||
                "forbid"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "escrow_policy"],
                  value,
                )
              }
              options={certificateEscrowOptions}
            />
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Require CSR"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.require_csr ??
                  true,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "require_csr"],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Proof Of Possession"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle
                  ?.require_proof_of_possession ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "require_proof_of_possession",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Device Binding"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle
                  ?.require_device_binding ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "require_device_binding",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require subjectAltName"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle
                  ?.require_subject_alt_name ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "require_subject_alt_name",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Allow Server Key Generation"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle
                  ?.allow_server_key_generation,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "allow_server_key_generation",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="EST Enabled"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.est_enabled ??
                  true,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "est_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="SCEP Enabled"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.scep_enabled ??
                  true,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "scep_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="BYOD Portal Enabled"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle
                  ?.byod_portal_enabled ?? true,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "byod_portal_enabled",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="CRL Enabled"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.crl_enabled,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "crl_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="OCSP Enabled"
              checked={Boolean(
                settings.onboarding?.certificate_lifecycle?.ocsp_enabled,
              )}
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "ocsp_enabled"],
                  value,
                )
              }
            />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <TextField
              label="CRL Publish Path"
              value={
                settings.onboarding?.certificate_lifecycle?.crl_publish_path ||
                "/var/lib/aegisnas/pki/crl"
              }
              onChange={(value) =>
                updateField(
                  ["onboarding", "certificate_lifecycle", "crl_publish_path"],
                  value,
                )
              }
            />
            <TextField
              label="OCSP Responder URL"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.ocsp_responder_url || ""
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "ocsp_responder_url",
                  ],
                  value,
                )
              }
              placeholder="https://ocsp.example.com"
            />
            <TextField
              label="Event Retention Limit"
              type="number"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.event_retention_limit ?? 6000
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "event_retention_limit",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Inventory Retention Limit"
              type="number"
              value={
                settings.onboarding?.certificate_lifecycle
                  ?.inventory_retention_limit ?? 100000
              }
              onChange={(value) =>
                updateField(
                  [
                    "onboarding",
                    "certificate_lifecycle",
                    "inventory_retention_limit",
                  ],
                  Number(value),
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              Passive Profiling And Posture
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Use these only when you are ready to support inventory retention,
              compliance inputs, and remediation decisions.
            </p>
          </div>
          <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="MAC Inventory Enabled"
              checked={Boolean(settings.profiling?.mac_inventory_enabled)}
              onChange={(value) =>
                updateField(["profiling", "mac_inventory_enabled"], value)
              }
            />
            <ToggleField
              label="Passive Profiling Enabled"
              checked={Boolean(settings.profiling?.passive_enabled)}
              onChange={(value) =>
                updateField(["profiling", "passive_enabled"], value)
              }
            />
            <ToggleField
              label="Posture Enabled"
              checked={Boolean(settings.profiling?.posture_enabled)}
              onChange={(value) =>
                updateField(["profiling", "posture_enabled"], value)
              }
            />
            <ToggleField
              label="MDM/UEM Sync Enabled"
              checked={Boolean(settings.profiling?.mdm_sync_enabled)}
              onChange={(value) =>
                updateField(["profiling", "mdm_sync_enabled"], value)
              }
            />
            <ToggleField
              label="Remediation Enabled"
              checked={Boolean(settings.profiling?.remediation_enabled)}
              onChange={(value) =>
                updateField(["profiling", "remediation_enabled"], value)
              }
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <TextField
              label="Profiling Poll Interval (s)"
              type="number"
              value={settings.profiling?.poll_interval_seconds || 300}
              onChange={(value) =>
                updateField(
                  ["profiling", "poll_interval_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Retention Hours"
              type="number"
              value={settings.profiling?.retention_hours || 24}
              onChange={(value) =>
                updateField(["profiling", "retention_hours"], Number(value))
              }
            />
            <TextField
              label="MDM Cache Hours"
              type="number"
              value={settings.profiling?.mdm_cache_hours || 12}
              onChange={(value) =>
                updateField(["profiling", "mdm_cache_hours"], Number(value))
              }
            />
            <SelectField
              label="MDM Provider"
              value={settings.profiling?.mdm_provider || ""}
              onChange={(value) =>
                updateField(["profiling", "mdm_provider"], value)
              }
              options={mdmProviderOptions}
            />
            <TextField
              label="MDM Endpoint"
              value={settings.profiling?.mdm_endpoint || ""}
              onChange={(value) =>
                updateField(["profiling", "mdm_endpoint"], value)
              }
              placeholder="https://mdm.example.com/api"
            />
            <TextField
              label="MDM Token Env"
              value={settings.profiling?.mdm_api_token_env || ""}
              onChange={(value) =>
                updateField(["profiling", "mdm_api_token_env"], value)
              }
              placeholder="AEGIS_MDM_API_TOKEN"
            />
            <TextField
              label="Compliance Webhook"
              value={settings.profiling?.compliance_webhook || ""}
              onChange={(value) =>
                updateField(["profiling", "compliance_webhook"], value)
              }
              placeholder="https://ops.example.com/compliance"
            />
            <TextField
              label="Compliance Token Env"
              value={settings.profiling?.compliance_token_env || ""}
              onChange={(value) =>
                updateField(["profiling", "compliance_token_env"], value)
              }
              placeholder="AEGIS_COMPLIANCE_WEBHOOK_TOKEN"
            />
          </div>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">
            Integrations, Controller Workflows, And Governance
          </h3>
          <p className="mt-1 text-sm text-gray-600">
            Phase 4 turns integration-heavy features into explicit production
            choices so MDM sync, SIEM export, controller automation, and admin
            delegation only light up when their dependencies are real.
          </p>
        </div>
        <div className="mb-4">
          <h4 className="font-semibold text-gray-900">
            Admin Identity And Governance
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            Use this area for SSO-backed admin access, delegated operations, and
            enterprise tenant boundaries.
          </p>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField
            label="Admin SSO Enabled"
            checked={Boolean(settings.integrations?.admin_sso?.enabled)}
            onChange={(value) =>
              updateField(["integrations", "admin_sso", "enabled"], value)
            }
          />
          <ToggleField
            label="Delegated Admin Enabled"
            checked={Boolean(settings.governance?.delegated_admin_enabled)}
            onChange={(value) =>
              updateField(["governance", "delegated_admin_enabled"], value)
            }
          />
          <ToggleField
            label="External Group Mapping"
            checked={Boolean(settings.governance?.external_groups_enabled)}
            onChange={(value) =>
              updateField(["governance", "external_groups_enabled"], value)
            }
          />
          <ToggleField
            label="Multi-Tenant Enabled"
            checked={Boolean(settings.governance?.multi_tenant_enabled)}
            onChange={(value) =>
              updateField(["governance", "multi_tenant_enabled"], value)
            }
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SelectField
            label="Admin SSO Provider"
            value={settings.integrations?.admin_sso?.provider || ""}
            onChange={(value) =>
              updateField(["integrations", "admin_sso", "provider"], value)
            }
            options={adminSSOProviderOptions}
          />
          <TextField
            label="Issuer / Metadata URL"
            value={settings.integrations?.admin_sso?.issuer_url || ""}
            onChange={(value) =>
              updateField(["integrations", "admin_sso", "issuer_url"], value)
            }
            placeholder="https://idp.example.com/.well-known/openid-configuration"
          />
          <TextField
            label="Client ID"
            value={settings.integrations?.admin_sso?.client_id || ""}
            onChange={(value) =>
              updateField(["integrations", "admin_sso", "client_id"], value)
            }
            placeholder="aegisnas-admin"
          />
          <TextField
            label="Client Secret Env"
            value={settings.integrations?.admin_sso?.client_secret_env || ""}
            onChange={(value) =>
              updateField(
                ["integrations", "admin_sso", "client_secret_env"],
                value,
              )
            }
            placeholder="AEGIS_ADMIN_SSO_CLIENT_SECRET"
          />
          <TextField
            label="Redirect URL"
            value={settings.integrations?.admin_sso?.redirect_url || ""}
            onChange={(value) =>
              updateField(["integrations", "admin_sso", "redirect_url"], value)
            }
            placeholder="https://admin.example.com/auth/callback"
          />
          <TextField
            label="Groups Claim"
            value={settings.integrations?.admin_sso?.groups_claim || ""}
            onChange={(value) =>
              updateField(["integrations", "admin_sso", "groups_claim"], value)
            }
            placeholder="groups"
          />
          <SelectField
            label="RBAC Mode"
            value={settings.governance?.rbac_mode || "local"}
            onChange={(value) =>
              updateField(["governance", "rbac_mode"], value)
            }
            options={rbacModeOptions}
          />
          <TextField
            label="Tenant Claim"
            value={settings.governance?.tenant_claim || ""}
            onChange={(value) =>
              updateField(["governance", "tenant_claim"], value)
            }
            placeholder="tenant"
          />
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <h4 className="font-semibold text-gray-900">
                Tenant Isolation
              </h4>
              <p className="mt-1 text-sm text-gray-600">
                Keep tenant policy trees, resource ownership, and delegated
                administration bounded before enforcement is enabled.
              </p>
            </div>
            <button
              onClick={loadTenantIsolationReport}
              className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700"
            >
              Refresh Isolation
            </button>
          </div>
          <div className="grid gap-4 lg:grid-cols-4">
            <SelectField
              label="Isolation Mode"
              value={settings.governance?.isolation_mode || "monitor"}
              onChange={(value) =>
                updateField(["governance", "isolation_mode"], value)
              }
              options={tenantIsolationModeOptions}
            />
            <TextField
              label="Default Tenant"
              value={settings.governance?.default_tenant || ""}
              onChange={(value) =>
                updateField(["governance", "default_tenant"], value)
              }
              placeholder="tenant-a"
            />
            <TextField
              label="Max Tenants"
              type="number"
              value={settings.governance?.max_tenants || 256}
              onChange={(value) =>
                updateField(["governance", "max_tenants"], Number(value))
              }
            />
            <TextField
              label="Isolation Event Retention"
              type="number"
              value={settings.governance?.resource_retention_limit || 10000}
              onChange={(value) =>
                updateField(
                  ["governance", "resource_retention_limit"],
                  Number(value),
                )
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.governance?.fail_closed !== false}
              onChange={(value) =>
                updateField(["governance", "fail_closed"], value)
              }
            />
            <ToggleField
              label="Require Tenant Profiles"
              checked={settings.governance?.tenant_profile_required !== false}
              onChange={(value) =>
                updateField(["governance", "tenant_profile_required"], value)
              }
            />
            <ToggleField
              label="Policy Ownership"
              checked={
                settings.governance?.enforce_policy_set_ownership !== false
              }
              onChange={(value) =>
                updateField(
                  ["governance", "enforce_policy_set_ownership"],
                  value,
                )
              }
            />
            <ToggleField
              label="Resource Ownership"
              checked={settings.governance?.enforce_resource_ownership !== false}
              onChange={(value) =>
                updateField(["governance", "enforce_resource_ownership"], value)
              }
            />
            <ToggleField
              label="Audit Isolation Decisions"
              checked={settings.governance?.resource_audit_enabled !== false}
              onChange={(value) =>
                updateField(["governance", "resource_audit_enabled"], value)
              }
            />
            <TextField
              label="Shared Resource Types"
              value={listToCSV(settings.governance?.shared_resource_types)}
              onChange={(value) =>
                updateField(
                  ["governance", "shared_resource_types"],
                  csvToList(value),
                )
              }
              placeholder="system_status, production_readiness"
            />
            <div className="rounded-md border border-gray-200 px-4 py-3">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Status
              </div>
              <div
                className={`mt-2 inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${tenantIsolationTone}`}
              >
                {tenantIsolationStatus}
              </div>
              <div className="mt-2 text-sm text-gray-600">
                {tenantIsolationReport?.message ||
                  "Tenant isolation state has not loaded yet."}
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-4 py-3">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Active Tenants
              </div>
              <div className="mt-2 text-2xl font-semibold text-gray-900">
                {tenantIsolationSummary?.active_tenant_count || 0}
              </div>
              <div className="mt-1 text-sm text-gray-600">
                {tenantIsolationSummary?.tenant_count || 0} total profiles
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-4 py-3">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Owned Resources
              </div>
              <div className="mt-2 text-2xl font-semibold text-gray-900">
                {tenantIsolationSummary?.resource_binding_count || 0}
              </div>
              <div className="mt-1 text-sm text-gray-600">
                {tenantIsolationSummary?.policy_set_tenant_count || 0} policy
                scope(s)
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-4 py-3">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Decision Evidence
              </div>
              <div className="mt-2 text-2xl font-semibold text-gray-900">
                {tenantIsolationSummary?.denied_event_count || 0}
              </div>
              <div className="mt-1 text-sm text-gray-600">
                {tenantIsolationSummary?.monitor_event_count || 0} monitor
                event(s)
              </div>
            </div>
          </div>
          {tenantIsolationReport?.checks?.length ? (
            <div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-3">
              {tenantIsolationReport.checks.map((check) => (
                <div
                  key={check.key}
                  className={`rounded-md border px-3 py-2 text-sm ${
                    check.status === "passed"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                      : check.status === "blocked"
                        ? "border-red-200 bg-red-50 text-red-900"
                        : "border-amber-200 bg-amber-50 text-amber-900"
                  }`}
                >
                  <div className="font-semibold">{check.key}</div>
                  <div className="mt-1">{check.detail}</div>
                </div>
              ))}
            </div>
          ) : null}
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4">
            <h4 className="font-semibold text-gray-900">
              SIEM And Controller Integrations
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              Use these for webhook-grade observability exports and
              controller-aware Wi-Fi operations in external AP deployments.
            </p>
          </div>
          <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="SIEM Export Enabled"
              checked={Boolean(settings.integrations?.siem?.enabled)}
              onChange={(value) =>
                updateField(["integrations", "siem", "enabled"], value)
              }
            />
            <ToggleField
              label="Controller Automation Enabled"
              checked={Boolean(settings.integrations?.controller?.enabled)}
              onChange={(value) =>
                updateField(["integrations", "controller", "enabled"], value)
              }
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <SelectField
              label="SIEM Provider"
              value={settings.integrations?.siem?.provider || ""}
              onChange={(value) =>
                updateField(["integrations", "siem", "provider"], value)
              }
              options={siemProviderOptions}
            />
            <TextField
              label="SIEM Endpoint"
              value={settings.integrations?.siem?.endpoint || ""}
              onChange={(value) =>
                updateField(["integrations", "siem", "endpoint"], value)
              }
              placeholder="https://siem.example.com/collect"
            />
            <TextField
              label="SIEM API Key Env"
              value={settings.integrations?.siem?.api_key_env || ""}
              onChange={(value) =>
                updateField(["integrations", "siem", "api_key_env"], value)
              }
              placeholder="AEGIS_SIEM_API_KEY"
            />
            <TextField
              label="SIEM Batch Size"
              type="number"
              value={settings.integrations?.siem?.batch_size || 100}
              onChange={(value) =>
                updateField(
                  ["integrations", "siem", "batch_size"],
                  Number(value),
                )
              }
            />
            <SelectField
              label="Controller Platform"
              value={settings.integrations?.controller?.platform || ""}
              onChange={(value) =>
                updateField(["integrations", "controller", "platform"], value)
              }
              options={controllerPlatformOptions}
            />
            <TextField
              label="Controller Endpoint"
              value={settings.integrations?.controller?.endpoint || ""}
              onChange={(value) =>
                updateField(["integrations", "controller", "endpoint"], value)
              }
              placeholder="https://controller.example.com/api"
            />
            <TextField
              label="Controller API Token Env"
              value={settings.integrations?.controller?.api_token_env || ""}
              onChange={(value) =>
                updateField(
                  ["integrations", "controller", "api_token_env"],
                  value,
                )
              }
              placeholder="AEGIS_CONTROLLER_API_TOKEN"
            />
            <TextField
              label="Controller API Username Env"
              value={settings.integrations?.controller?.api_username_env || ""}
              onChange={(value) =>
                updateField(
                  ["integrations", "controller", "api_username_env"],
                  value,
                )
              }
              placeholder="AEGIS_CISCO_ISE_USERNAME"
            />
            <TextField
              label="Controller API Password Env"
              value={settings.integrations?.controller?.api_password_env || ""}
              onChange={(value) =>
                updateField(
                  ["integrations", "controller", "api_password_env"],
                  value,
                )
              }
              placeholder="AEGIS_CISCO_ISE_PASSWORD"
            />
            <TextField
              label="Controller RADIUS Profile"
              value={settings.integrations?.controller?.radius_profile || ""}
              onChange={(value) =>
                updateField(
                  ["integrations", "controller", "radius_profile"],
                  value,
                )
              }
              placeholder="aegisnas-radius"
            />
            <TextField
              label="Controller RADIUS Server"
              value={settings.integrations?.controller?.radius_server || ""}
              onChange={(value) =>
                updateField(
                  ["integrations", "controller", "radius_server"],
                  value,
                )
              }
              placeholder="192.0.2.10"
            />
            <TextField
              label="Controller RADIUS Secret Env"
              value={settings.integrations?.controller?.radius_secret_env || ""}
              onChange={(value) =>
                updateField(
                  ["integrations", "controller", "radius_secret_env"],
                  value,
                )
              }
              placeholder="AEGIS_MIST_RADIUS_SECRET"
            />
            <SelectField
              label="Controller Sync Mode"
              value={settings.integrations?.controller?.sync_mode || "monitor"}
              onChange={(value) =>
                updateField(["integrations", "controller", "sync_mode"], value)
              }
              options={controllerSyncOptions}
            />
            <TextField
              label="Controller Site / Zone / Network"
              value={settings.integrations?.controller?.site || ""}
              onChange={(value) =>
                updateField(["integrations", "controller", "site"], value)
              }
              placeholder="branch-west-01"
            />
          </div>
          <p className="mt-3 text-xs text-gray-500">
            Vendor-native controller adapters use this field as the site, zone,
            or network identifier. Generic REST mode can leave it blank.
          </p>
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-900">
            High Availability And Failover
          </h3>
          <p className="mt-1 text-sm text-gray-600">
            Use enterprise deployments for active and standby peer monitoring,
            shared virtual IP planning, and recovery orchestration groundwork.
          </p>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-6">
          <ToggleField
            label="High Availability Enabled"
            checked={Boolean(settings.high_availability?.enabled)}
            onChange={(value) =>
              updateField(["high_availability", "enabled"], value)
            }
          />
          <ToggleField
            label="Preempt Preferred"
            checked={Boolean(settings.high_availability?.preempt)}
            onChange={(value) =>
              updateField(["high_availability", "preempt"], value)
            }
          />
          <ToggleField
            label="Split-Brain Protection"
            checked={Boolean(
              settings.high_availability?.split_brain_protection_enabled,
            )}
            onChange={(value) =>
              updateField(
                ["high_availability", "split_brain_protection_enabled"],
                value,
              )
            }
          />
          <ToggleField
            label="Auto-Stage Shared Package"
            checked={Boolean(
              settings.high_availability?.auto_stage_shared_package,
            )}
            onChange={(value) =>
              updateField(
                ["high_availability", "auto_stage_shared_package"],
                value,
              )
            }
          />
          <ToggleField
            label="Auto-Activate On Failover"
            checked={Boolean(
              settings.high_availability?.auto_activate_on_failover,
            )}
            onChange={(value) =>
              updateField(
                ["high_availability", "auto_activate_on_failover"],
                value,
              )
            }
          />
          <SelectField
            label="Node Role"
            value={settings.high_availability?.role || "standby"}
            onChange={(value) =>
              updateField(["high_availability", "role"], value)
            }
            options={[
              { value: "active", label: "Active" },
              { value: "standby", label: "Standby" },
            ]}
          />
          <TextField
            label="Virtual IP"
            value={settings.high_availability?.virtual_ip || ""}
            onChange={(value) =>
              updateField(["high_availability", "virtual_ip"], value)
            }
            placeholder="192.168.50.2"
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <TextField
            label="Peer API URL"
            value={settings.high_availability?.peer_api_url || ""}
            onChange={(value) =>
              updateField(["high_availability", "peer_api_url"], value)
            }
            placeholder="https://peer.example.com:8083"
          />
          <TextField
            label="Heartbeat Interval"
            type="number"
            value={settings.high_availability?.heartbeat_interval_seconds || 5}
            onChange={(value) =>
              updateField(
                ["high_availability", "heartbeat_interval_seconds"],
                Number(value),
              )
            }
          />
          <TextField
            label="Failover Timeout"
            type="number"
            value={settings.high_availability?.failover_timeout_seconds || 20}
            onChange={(value) =>
              updateField(
                ["high_availability", "failover_timeout_seconds"],
                Number(value),
              )
            }
          />
          <TextField
            label="Replication Interval"
            type="number"
            value={
              settings.high_availability?.replication_interval_seconds || 300
            }
            onChange={(value) =>
              updateField(
                ["high_availability", "replication_interval_seconds"],
                Number(value),
              )
            }
          />
          <TextField
            label="Replication Stale After"
            type="number"
            value={
              settings.high_availability?.replication_stale_after_seconds || 900
            }
            onChange={(value) =>
              updateField(
                ["high_availability", "replication_stale_after_seconds"],
                Number(value),
              )
            }
          />
          <TextField
            label="Preempt Holdoff"
            type="number"
            value={settings.high_availability?.preempt_holdoff_seconds || 0}
            onChange={(value) =>
              updateField(
                ["high_availability", "preempt_holdoff_seconds"],
                Number(value),
              )
            }
          />
          <TextField
            label="Shared State Directory"
            value={
              settings.high_availability?.shared_state_dir ||
              "/var/lib/aegisnas/ha"
            }
            onChange={(value) =>
              updateField(["high_availability", "shared_state_dir"], value)
            }
            placeholder="/var/lib/aegisnas/ha"
          />
          <TextField
            label="Replication Signing Key Env"
            value={
              settings.high_availability?.replication_signing_key_env || ""
            }
            onChange={(value) =>
              updateField(
                ["high_availability", "replication_signing_key_env"],
                value,
              )
            }
            placeholder="AEGIS_HA_REPLICATION_SIGNING_KEY"
          />
          <TextField
            label="Replication Encryption Key Env"
            value={
              settings.high_availability?.replication_encryption_key_env || ""
            }
            onChange={(value) =>
              updateField(
                ["high_availability", "replication_encryption_key_env"],
                value,
              )
            }
            placeholder="AEGIS_HA_REPLICATION_ENCRYPTION_KEY"
          />
          <TextField
            label="Witness API URL"
            value={settings.high_availability?.witness_api_url || ""}
            onChange={(value) =>
              updateField(["high_availability", "witness_api_url"], value)
            }
            placeholder="https://witness.example.test/ha"
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness URLs
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={(settings.high_availability?.witness_urls || []).join(
                "\n",
              )}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["high_availability", "witness_urls"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={
                "https://witness-a.example.test/ha\nhttps://witness-b.example.test/ha"
              }
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional multi-witness list. When populated, it overrides the
              single Witness API URL.
            </p>
          </div>
          <TextField
            label="Witness Quorum"
            type="number"
            value={settings.high_availability?.witness_quorum || 1}
            onChange={(value) =>
              updateField(
                ["high_availability", "witness_quorum"],
                Number(value),
              )
            }
          />
          <TextField
            label="Witness Weight Threshold"
            type="number"
            value={settings.high_availability?.witness_weight_threshold || 0}
            onChange={(value) =>
              updateField(
                ["high_availability", "witness_weight_threshold"],
                Number(value),
              )
            }
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Weight Overrides
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_weights || {},
              )
                .map(([url, weight]) => `${url}=${weight}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const weights: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const url = parts.slice(0, -1).join("=").trim();
                    const rawWeight =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedWeight = Number(rawWeight);
                    if (
                      url &&
                      Number.isFinite(parsedWeight) &&
                      parsedWeight > 0
                    ) {
                      weights[url] = parsedWeight;
                    }
                  });
                updateField(["high_availability", "witness_weights"], weights);
              }}
              placeholder={
                "https://witness-a.example.test/ha=3\nhttps://witness-b.example.test/ha=1"
              }
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-witness weights. Unlisted witnesses count as weight
              1.
            </p>
          </div>
          <TextField
            label="Witness Distinct Group Threshold"
            type="number"
            value={settings.high_availability?.witness_min_distinct_groups || 0}
            onChange={(value) =>
              updateField(
                ["high_availability", "witness_min_distinct_groups"],
                Number(value),
              )
            }
          />
          <SelectField
            label="Witness Policy Mode"
            value={settings.high_availability?.witness_policy_mode || "all"}
            onChange={(value) =>
              updateField(["high_availability", "witness_policy_mode"], value)
            }
            options={[
              { value: "all", label: "All configured policies" },
              { value: "any", label: "Any diversity policy" },
              { value: "group_only", label: "Group only" },
              { value: "source_only", label: "Source only" },
              { value: "url_only", label: "URL only" },
            ]}
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Policy Mode By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_policy_mode_by_tier || {},
              )
                .map(([tier, mode]) => `${tier}=${mode}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const overrides: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawMode =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (tier && rawMode) {
                      overrides[tier] = rawMode;
                    }
                  });
                updateField(
                  ["high_availability", "witness_policy_mode_by_tier"],
                  overrides,
                );
              }}
              placeholder={"critical=all\nadvisory=any"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier policy overrides. Use all, any, group_only,
              source_only, or url_only. Tiers without an override keep the
              conservative all-mode behavior.
            </p>
          </div>
          <TextField
            label="Witness Failure Tolerance"
            type="number"
            value={settings.high_availability?.witness_failure_tolerance || 0}
            onChange={(value) =>
              updateField(
                ["high_availability", "witness_failure_tolerance"],
                Number(value),
              )
            }
          />
          <TextField
            label="Witness Failure Weight Tolerance"
            type="number"
            value={
              settings.high_availability?.witness_failure_weight_tolerance || 0
            }
            onChange={(value) =>
              updateField(
                ["high_availability", "witness_failure_weight_tolerance"],
                Number(value),
              )
            }
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Minimum Approvals By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_min_approvals_by_tier || {},
              )
                .map(([tier, approvals]) => `${tier}=${approvals}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawApprovals =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedApprovals = Number(rawApprovals);
                    if (
                      tier &&
                      Number.isFinite(parsedApprovals) &&
                      parsedApprovals >= 0
                    ) {
                      minimums[tier] = parsedApprovals;
                    }
                  });
                updateField(
                  ["high_availability", "witness_min_approvals_by_tier"],
                  minimums,
                );
              }}
              placeholder={"critical=1\nadvisory=1"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier approval floors. Promotion must include at least
              this many approvals from each listed confidence tier.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Minimum Weight By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_min_weight_by_tier || {},
              )
                .map(([tier, weight]) => `${tier}=${weight}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawWeight =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedWeight = Number(rawWeight);
                    if (
                      tier &&
                      Number.isFinite(parsedWeight) &&
                      parsedWeight >= 0
                    ) {
                      minimums[tier] = parsedWeight;
                    }
                  });
                updateField(
                  ["high_availability", "witness_min_weight_by_tier"],
                  minimums,
                );
              }}
              placeholder={"critical=2\nadvisory=1"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier weight floors. Promotion must include at least
              this much witness weight from each listed confidence tier.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Minimum Distinct Groups By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability
                  ?.witness_min_distinct_groups_by_tier || {},
              )
                .map(([tier, count]) => `${tier}=${count}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawCount =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedCount = Number(rawCount);
                    if (
                      tier &&
                      Number.isFinite(parsedCount) &&
                      parsedCount >= 0
                    ) {
                      minimums[tier] = parsedCount;
                    }
                  });
                updateField(
                  ["high_availability", "witness_min_distinct_groups_by_tier"],
                  minimums,
                );
              }}
              placeholder={"critical=2\nadvisory=1"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier diversity floors. Promotion must include
              approvals from at least this many distinct witness groups in each
              listed confidence tier.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Minimum Distinct Sources By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability
                  ?.witness_min_distinct_sources_by_tier || {},
              )
                .map(([tier, count]) => `${tier}=${count}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const minimums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawCount =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedCount = Number(rawCount);
                    if (
                      tier &&
                      Number.isFinite(parsedCount) &&
                      parsedCount >= 0
                    ) {
                      minimums[tier] = parsedCount;
                    }
                  });
                updateField(
                  ["high_availability", "witness_min_distinct_sources_by_tier"],
                  minimums,
                );
              }}
              placeholder={"critical=2\nadvisory=1"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier source diversity floors. Promotion must include
              approvals from at least this many distinct witness sources in each
              listed confidence tier.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Group Overrides
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_groups || {},
              )
                .map(([url, group]) => `${url}=${group}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const groups: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const url = parts.slice(0, -1).join("=").trim();
                    const rawGroup =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (url && rawGroup) {
                      groups[url] = rawGroup;
                    }
                  });
                updateField(["high_availability", "witness_groups"], groups);
              }}
              placeholder={
                "https://witness-a.example.test/ha=dc-a\nhttps://witness-b.example.test/ha=dc-b"
              }
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional group mapping for witness diversity. Unlisted witnesses
              count as their own group.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Source Overrides
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_sources || {},
              )
                .map(([url, source]) => `${url}=${source}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const sources: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const url = parts.slice(0, -1).join("=").trim();
                    const rawSource =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (url && rawSource) {
                      sources[url] = rawSource;
                    }
                  });
                updateField(["high_availability", "witness_sources"], sources);
              }}
              placeholder={
                "https://witness-a.example.test/ha=local\nhttps://witness-b.example.test/ha=external"
              }
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional source mapping for mixed-source quorum. Unlisted
              witnesses count as their own source.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Required Groups
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={2}
              value={(
                settings.high_availability?.witness_required_groups || []
              ).join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["high_availability", "witness_required_groups"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={"dc-a\ndc-b"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional witness groups that must all be represented in approvals
              before promotion is allowed.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Required Sources
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={2}
              value={(
                settings.high_availability?.witness_required_sources || []
              ).join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["high_availability", "witness_required_sources"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={"local\nexternal"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional source classes that must all be represented in witness
              approvals before promotion is allowed.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Required URLs
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={2}
              value={(
                settings.high_availability?.witness_required_urls || []
              ).join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["high_availability", "witness_required_urls"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={
                "https://witness-a.example.test/ha\nhttps://witness-b.example.test/ha"
              }
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional witness endpoints that must all be represented in
              approvals before promotion is allowed.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Required Sources By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_required_sources_by_tier ||
                  {},
              )
                .map(
                  ([tier, sources]) =>
                    `${tier}=${(Array.isArray(sources) ? sources : []).join(",")}`,
                )
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredByTier: Record<string, string[]> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawSources =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (!tier || !rawSources) {
                      return;
                    }
                    const sources = rawSources
                      .split(",")
                      .map((source) => source.trim())
                      .filter(Boolean);
                    if (sources.length > 0) {
                      requiredByTier[tier] = sources;
                    }
                  });
                updateField(
                  ["high_availability", "witness_required_sources_by_tier"],
                  requiredByTier,
                );
              }}
              placeholder={"critical=local\nadvisory=external,cloud"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier source rules. Each listed tier must include
              approvals from the named source classes.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Required URLs By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_required_urls_by_tier || {},
              )
                .map(
                  ([tier, urls]) =>
                    `${tier}=${(Array.isArray(urls) ? urls : []).join(",")}`,
                )
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredByTier: Record<string, string[]> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawURLs =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (!tier || !rawURLs) {
                      return;
                    }
                    const urls = rawURLs
                      .split(",")
                      .map((url) => url.trim())
                      .filter(Boolean);
                    if (urls.length > 0) {
                      requiredByTier[tier] = urls;
                    }
                  });
                updateField(
                  ["high_availability", "witness_required_urls_by_tier"],
                  requiredByTier,
                );
              }}
              placeholder={
                "critical=https://witness-a.example.test/ha\nadvisory=https://witness-b.example.test/ha,https://witness-c.example.test/ha"
              }
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier witness URL rules. Each listed tier must include
              approvals from the named witness endpoints.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Required Groups By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_required_groups_by_tier ||
                  {},
              )
                .map(
                  ([tier, groups]) =>
                    `${tier}=${(Array.isArray(groups) ? groups : []).join(",")}`,
                )
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredByTier: Record<string, string[]> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawGroups =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (!tier || !rawGroups) {
                      return;
                    }
                    const groups = rawGroups
                      .split(",")
                      .map((group) => group.trim())
                      .filter(Boolean);
                    if (groups.length > 0) {
                      requiredByTier[tier] = groups;
                    }
                  });
                updateField(
                  ["high_availability", "witness_required_groups_by_tier"],
                  requiredByTier,
                );
              }}
              placeholder={"critical=dc-a\nadvisory=dc-b,cloud"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier group rules. Each listed tier must include
              approvals from the named witness groups.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Source Confidence
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_source_confidence || {},
              )
                .map(([source, tier]) => `${source}=${tier}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const confidence: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const source = parts.slice(0, -1).join("=").trim();
                    const rawTier =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (source && rawTier) {
                      confidence[source] = rawTier;
                    }
                  });
                updateField(
                  ["high_availability", "witness_source_confidence"],
                  confidence,
                );
              }}
              placeholder={"local=critical\nexternal=advisory"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional source-to-tier mapping. Unlisted sources use the standard
              confidence tier.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Failure Tolerance By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_failure_tolerance_by_tier ||
                  {},
              )
                .map(([tier, budget]) => `${tier}=${budget}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const budgets: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawBudget =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedBudget = Number(rawBudget);
                    if (
                      tier &&
                      Number.isFinite(parsedBudget) &&
                      parsedBudget >= 0
                    ) {
                      budgets[tier] = parsedBudget;
                    }
                  });
                updateField(
                  ["high_availability", "witness_failure_tolerance_by_tier"],
                  budgets,
                );
              }}
              placeholder={"advisory=1\nstandard=0"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional tier-specific failed probe count budgets. Any tier
              without an override falls back to the global failure budget.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Failure Weight Tolerance By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability
                  ?.witness_failure_weight_tolerance_by_tier || {},
              )
                .map(([tier, budget]) => `${tier}=${budget}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const budgets: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawBudget =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedBudget = Number(rawBudget);
                    if (
                      tier &&
                      Number.isFinite(parsedBudget) &&
                      parsedBudget >= 0
                    ) {
                      budgets[tier] = parsedBudget;
                    }
                  });
                updateField(
                  [
                    "high_availability",
                    "witness_failure_weight_tolerance_by_tier",
                  ],
                  budgets,
                );
              }}
              placeholder={"advisory=1\nstandard=0"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional tier-specific failed witness weight budgets. Any tier
              without an override falls back to the global failed-weight budget.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Blocking Tiers
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={2}
              value={(
                settings.high_availability?.witness_blocking_tiers || []
              ).join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["high_availability", "witness_blocking_tiers"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((value) => value.trim())
                    .filter(Boolean),
                )
              }
              placeholder={"critical"}
            />
            <p className="mt-1 text-xs text-gray-500">
              If a witness in one of these tiers explicitly denies promotion,
              standby promotion is blocked immediately.
            </p>
          </div>
          <TextField
            label="Witness Token Env"
            value={settings.high_availability?.witness_token_env || ""}
            onChange={(value) =>
              updateField(["high_availability", "witness_token_env"], value)
            }
            placeholder="AEGIS_HA_WITNESS_TOKEN"
          />
          <TextField
            label="Witness Signing Key Env"
            value={settings.high_availability?.witness_signing_key_env || ""}
            onChange={(value) =>
              updateField(
                ["high_availability", "witness_signing_key_env"],
                value,
              )
            }
            placeholder="AEGIS_HA_WITNESS_SIGNING_KEY"
          />
          <TextField
            label="Witness Max Age (s)"
            type="number"
            value={settings.high_availability?.witness_max_age_seconds || 0}
            onChange={(value) =>
              updateField(
                ["high_availability", "witness_max_age_seconds"],
                Number(value),
              )
            }
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Max Age By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_max_age_by_tier || {},
              )
                .map(([tier, seconds]) => `${tier}=${seconds}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const maximums: Record<string, number> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawSeconds =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    const parsedSeconds = Number(rawSeconds);
                    if (
                      tier &&
                      Number.isFinite(parsedSeconds) &&
                      parsedSeconds >= 0
                    ) {
                      maximums[tier] = parsedSeconds;
                    }
                  });
                updateField(
                  ["high_availability", "witness_max_age_by_tier"],
                  maximums,
                );
              }}
              placeholder={"critical=10\nadvisory=30"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier freshness overrides in seconds. Any tier without
              an override falls back to the global witness max age.
            </p>
          </div>
          <TextField
            label="Witness Required Node"
            value={settings.high_availability?.witness_required_node || ""}
            onChange={(value) =>
              updateField(["high_availability", "witness_required_node"], value)
            }
            placeholder="witness-1"
          />
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Required Node By Tier
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={Object.entries(
                settings.high_availability?.witness_required_node_by_tier || {},
              )
                .map(([tier, node]) => `${tier}=${node}`)
                .join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) => {
                const requiredNodes: Record<string, string> = {};
                event.target.value
                  .split(/\r?\n/)
                  .map((line) => line.trim())
                  .filter(Boolean)
                  .forEach((line) => {
                    const parts = line.split("=");
                    const tier = parts.slice(0, -1).join("=").trim();
                    const rawNode =
                      parts.length > 1 ? parts[parts.length - 1].trim() : "";
                    if (tier && rawNode) {
                      requiredNodes[tier] = rawNode;
                    }
                  });
                updateField(
                  ["high_availability", "witness_required_node_by_tier"],
                  requiredNodes,
                );
              }}
              placeholder={"critical=witness-a\nadvisory=witness-b"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional per-tier required witness identities. Tiers without
              overrides fall back to the global Witness Required Node field.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Signature Required Tiers
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={(
                settings.high_availability?.witness_signature_required_tiers ||
                []
              ).join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["high_availability", "witness_signature_required_tiers"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((line) => line.trim())
                    .filter(Boolean),
                )
              }
              placeholder={"critical\nadvisory"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional confidence tiers that must return signed witness
              responses even when signature enforcement is not global.
            </p>
          </div>
          <div className="md:col-span-2 lg:col-span-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">
              Witness Replay Required Tiers
            </label>
            <textarea
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              rows={3}
              value={(
                settings.high_availability?.witness_replay_required_tiers || []
              ).join("\n")}
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["high_availability", "witness_replay_required_tiers"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((line) => line.trim())
                    .filter(Boolean),
                )
              }
              placeholder={"critical\nadvisory"}
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional confidence tiers that must satisfy replay challenge
              verification even when global Witness Replay Protection is off.
            </p>
          </div>
          <ToggleField
            label="Witness Replay Protection"
            checked={Boolean(
              settings.high_availability?.witness_replay_protection_enabled,
            )}
            onChange={(checked) =>
              updateField(
                ["high_availability", "witness_replay_protection_enabled"],
                checked,
              )
            }
          />
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <h3 className="mb-4 text-lg font-semibold text-gray-900">
          FreeRADIUS And EAP
        </h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <TextField
            label="NAS Identifier"
            value={settings.radius?.nas_identifier || ""}
            onChange={(value) =>
              updateField(["radius", "nas_identifier"], value)
            }
          />
          <TextField
            label="Shared Secret"
            type="password"
            value={settings.radius?.secret || ""}
            onChange={(value) => updateField(["radius", "secret"], value)}
          />
          <TextField
            label="Auth Port"
            type="number"
            value={settings.radius?.auth_port || 1812}
            onChange={(value) =>
              updateField(["radius", "auth_port"], Number(value))
            }
          />
          <TextField
            label="Acct Port"
            type="number"
            value={settings.radius?.acct_port || 1813}
            onChange={(value) =>
              updateField(["radius", "acct_port"], Number(value))
            }
          />
          <TextField
            label="Max Sessions"
            type="number"
            value={settings.radius?.max_sessions || 1024}
            onChange={(value) =>
              updateField(["radius", "max_sessions"], Number(value))
            }
          />
          <TextField
            label="Request Timeout (s)"
            type="number"
            value={settings.radius?.request_timeout_seconds || 5}
            onChange={(value) =>
              updateField(["radius", "request_timeout_seconds"], Number(value))
            }
          />
          <TextField
            label="Interim Update (s)"
            type="number"
            value={settings.radius?.interim_update_seconds || 300}
            onChange={(value) =>
              updateField(["radius", "interim_update_seconds"], Number(value))
            }
          />
          <TextField
            label="Cert Directory"
            value={settings.radius?.cert_dir || ""}
            onChange={(value) => updateField(["radius", "cert_dir"], value)}
          />
          <SelectField
            label="Default EAP Type"
            value={settings.radius?.eap?.default_type || "peap"}
            onChange={(value) =>
              updateField(["radius", "eap", "default_type"], value)
            }
            options={[
              { value: "peap", label: "PEAP" },
              { value: "ttls", label: "TTLS" },
              { value: "tls", label: "TLS" },
              { value: "teap", label: "TEAP" },
              { value: "fast", label: "FAST" },
              { value: "pwd", label: "PWD" },
              { value: "sim", label: "SIM" },
              { value: "aka", label: "AKA" },
              { value: "aka-prime", label: "AKA-prime" },
            ]}
          />
          <SelectField
            label="PEAP Inner"
            value={settings.radius?.eap?.peap_inner || "mschapv2"}
            onChange={(value) =>
              updateField(["radius", "eap", "peap_inner"], value)
            }
            options={[
              { value: "mschapv2", label: "MSCHAPv2" },
              { value: "gtc", label: "GTC" },
              { value: "tls", label: "TLS" },
            ]}
          />
          <SelectField
            label="TTLS Inner"
            value={settings.radius?.eap?.ttls_inner || "mschapv2"}
            onChange={(value) =>
              updateField(["radius", "eap", "ttls_inner"], value)
            }
            options={[
              { value: "mschapv2", label: "MSCHAPv2" },
              { value: "pap", label: "PAP" },
              { value: "chap", label: "CHAP" },
              { value: "gtc", label: "GTC" },
              { value: "tls", label: "TLS" },
            ]}
          />
          <div className="grid grid-cols-2 gap-3">
            <SelectField
              label="TLS Min"
              value={settings.radius?.eap?.tls_min_version || "1.2"}
              onChange={(value) =>
                updateField(["radius", "eap", "tls_min_version"], value)
              }
              options={[
                { value: "1.2", label: "1.2" },
                { value: "1.3", label: "1.3" },
              ]}
            />
            <SelectField
              label="TLS Max"
              value={settings.radius?.eap?.tls_max_version || "1.3"}
              onChange={(value) =>
                updateField(["radius", "eap", "tls_max_version"], value)
              }
              options={[
                { value: "1.2", label: "1.2" },
                { value: "1.3", label: "1.3" },
              ]}
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <h4 className="font-semibold text-gray-900">
            EAP Method Framework
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            Bind 802.1X methods to explicit identity sources and packet
            integrity checks before enforcing production access.
          </p>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Framework Enabled"
              checked={settings.radius?.eap?.framework?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "framework", "enabled"], value)
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.radius?.eap?.framework?.fail_closed !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "fail_closed"],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Message-Authenticator"
              checked={
                settings.radius?.eap?.framework
                  ?.require_message_authenticator !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "framework",
                    "require_message_authenticator",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Identity Binding"
              checked={
                settings.radius?.eap?.framework?.require_identity_binding !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "require_identity_binding"],
                  value,
                )
              }
            />
            <SelectField
              label="Framework Mode"
              value={settings.radius?.eap?.framework?.mode || "monitor"}
              onChange={(value) =>
                updateField(["radius", "eap", "framework", "mode"], value)
              }
              options={[
                { value: "monitor", label: "Monitor" },
                { value: "enforce", label: "Enforce" },
              ]}
            />
            <SelectField
              label="Unsupported Method"
              value={
                settings.radius?.eap?.framework?.unsupported_method_action ||
                "reject"
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "framework",
                    "unsupported_method_action",
                  ],
                  value,
                )
              }
              options={[
                { value: "reject", label: "Reject" },
                { value: "nak", label: "NAK" },
                { value: "monitor", label: "Monitor" },
              ]}
            />
            <TextField
              label="Allowed Methods"
              value={listToCSV(
                settings.radius?.eap?.framework?.allowed_methods || [
                  "peap",
                  "ttls",
                  "tls",
                ],
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "allowed_methods"],
                  csvToList(value),
                )
              }
            />
            <TextField
              label="Allowed Inner Methods"
              value={listToCSV(
                settings.radius?.eap?.framework?.allowed_inner_methods || [
                  "mschapv2",
                  "pap",
                  "chap",
                  "gtc",
                  "tls",
                ],
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "allowed_inner_methods"],
                  csvToList(value),
                )
              }
            />
            <TextField
              label="Outer Identity Source"
              value={
                settings.radius?.eap?.framework
                  ?.default_outer_identity_source || "configured-default"
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "framework",
                    "default_outer_identity_source",
                  ],
                  value,
                )
              }
            />
            <TextField
              label="Inner Identity Source"
              value={
                settings.radius?.eap?.framework
                  ?.default_inner_identity_source || "identity-failover"
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "framework",
                    "default_inner_identity_source",
                  ],
                  value,
                )
              }
            />
            <TextField
              label="Method Timeout (s)"
              type="number"
              value={
                settings.radius?.eap?.framework?.method_timeout_seconds ?? 60
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "method_timeout_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Fragment Size"
              type="number"
              value={settings.radius?.eap?.framework?.fragment_size ?? 1024}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "fragment_size"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max EAP Sessions"
              type="number"
              value={
                settings.radius?.eap?.framework?.max_concurrent_sessions ?? 0
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "max_concurrent_sessions"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Telemetry Retention"
              type="number"
              value={
                settings.radius?.eap?.framework?.event_retention_limit ?? 6000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "event_retention_limit"],
                  Number(value),
                )
              }
            />
            <ToggleField
              label="Telemetry Enabled"
              checked={
                settings.radius?.eap?.framework?.telemetry_enabled !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "telemetry_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="NAK Unknown Types"
              checked={
                settings.radius?.eap?.framework?.nak_unknown_types !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "framework", "nak_unknown_types"],
                  value,
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <h4 className="font-semibold text-gray-900">
            TEAP Method Chaining
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            Gate RFC 7170 TEAP with machine and user identity chaining,
            cryptobinding, PAC policy, and bounded audit history.
          </p>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="TEAP Available"
              checked={settings.radius?.eap?.teap?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "teap", "enabled"], value)
              }
            />
            <ToggleField
              label="Require Cryptobinding"
              checked={
                settings.radius?.eap?.teap?.require_crypto_binding !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "require_crypto_binding"],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Channel Binding"
              checked={Boolean(
                settings.radius?.eap?.teap?.require_channel_binding,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "require_channel_binding"],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Identity Type"
              checked={
                settings.radius?.eap?.teap?.require_identity_type !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "require_identity_type"],
                  value,
                )
              }
            />
            <ToggleField
              label="Machine Identity"
              checked={
                settings.radius?.eap?.teap?.require_machine_identity !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "require_machine_identity"],
                  value,
                )
              }
            />
            <ToggleField
              label="User Identity"
              checked={
                settings.radius?.eap?.teap?.require_user_identity !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "require_user_identity"],
                  value,
                )
              }
            />
            <ToggleField
              label="Allow PAC"
              checked={settings.radius?.eap?.teap?.allow_pac !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "teap", "allow_pac"], value)
              }
            />
            <ToggleField
              label="Require PAC"
              checked={Boolean(settings.radius?.eap?.teap?.require_pac)}
              onChange={(value) =>
                updateField(["radius", "eap", "teap", "require_pac"], value)
              }
            />
            <SelectField
              label="TEAP Inner"
              value={
                settings.radius?.eap?.teap?.default_inner_method || "mschapv2"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "default_inner_method"],
                  value,
                )
              }
              options={[
                { value: "mschapv2", label: "MSCHAPv2" },
                { value: "pap", label: "PAP" },
                { value: "chap", label: "CHAP" },
                { value: "gtc", label: "GTC" },
                { value: "tls", label: "TLS" },
              ]}
            />
            <SelectField
              label="Chain Mode"
              value={
                settings.radius?.eap?.teap?.chain_mode ||
                "machine_then_user"
              }
              onChange={(value) =>
                updateField(["radius", "eap", "teap", "chain_mode"], value)
              }
              options={[
                { value: "machine_then_user", label: "Machine Then User" },
                { value: "machine_only", label: "Machine Only" },
                { value: "user_only", label: "User Only" },
                { value: "either", label: "Either" },
              ]}
            />
            <SelectField
              label="PAC Provisioning"
              value={
                settings.radius?.eap?.teap?.pac_provisioning ||
                "authenticated"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "pac_provisioning"],
                  value,
                )
              }
              options={[
                { value: "disabled", label: "Disabled" },
                { value: "authenticated", label: "Authenticated" },
                { value: "optional", label: "Optional" },
              ]}
            />
            <TextField
              label="PAC Authority ID"
              value={
                settings.radius?.eap?.teap?.pac_authority_id ||
                "aegisnas-teap"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "pac_authority_id"],
                  value,
                )
              }
            />
            <TextField
              label="PAC Lifetime (s)"
              type="number"
              value={
                settings.radius?.eap?.teap?.pac_lifetime_seconds ?? 2592000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "pac_lifetime_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Chain Steps"
              type="number"
              value={settings.radius?.eap?.teap?.max_chain_steps ?? 2}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "max_chain_steps"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Chain TTL (s)"
              type="number"
              value={settings.radius?.eap?.teap?.session_ttl_seconds ?? 900}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "session_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="TEAP Retention"
              type="number"
              value={
                settings.radius?.eap?.teap?.event_retention_limit ?? 6000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "event_retention_limit"],
                  Number(value),
                )
              }
            />
            <ToggleField
              label="Allow EAP Payload"
              checked={settings.radius?.eap?.teap?.allow_eap_payload !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "allow_eap_payload"],
                  value,
                )
              }
            />
            <ToggleField
              label="Basic Password Auth"
              checked={Boolean(
                settings.radius?.eap?.teap?.allow_basic_password_auth,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "teap", "allow_basic_password_auth"],
                  value,
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <h4 className="font-semibold text-gray-900">
            Machine And User Correlation
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            Bind managed device authentication to user logon with fresh machine
            evidence, same-client checks, deterministic role merge, and bounded
            history.
          </p>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Correlation Enabled"
              checked={settings.radius?.eap?.machine_user?.enabled !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Fail Closed"
              checked={settings.radius?.eap?.machine_user?.fail_closed !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "fail_closed"],
                  value,
                )
              }
            />
            <ToggleField
              label="Require TEAP"
              checked={settings.radius?.eap?.machine_user?.require_teap !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "require_teap"],
                  value,
                )
              }
            />
            <ToggleField
              label="Machine Identity"
              checked={
                settings.radius?.eap?.machine_user
                  ?.require_machine_identity !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "require_machine_identity",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="User Identity"
              checked={
                settings.radius?.eap?.machine_user?.require_user_identity !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "require_user_identity"],
                  value,
                )
              }
            />
            <ToggleField
              label="Machine Before User"
              checked={
                settings.radius?.eap?.machine_user
                  ?.require_machine_before_user !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "require_machine_before_user",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Same Client"
              checked={
                settings.radius?.eap?.machine_user
                  ?.require_same_calling_station !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "require_same_calling_station",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Same NAS"
              checked={Boolean(
                settings.radius?.eap?.machine_user?.require_same_nas,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "require_same_nas"],
                  value,
                )
              }
            />
            <ToggleField
              label="Fresh Machine Auth"
              checked={
                settings.radius?.eap?.machine_user
                  ?.require_fresh_machine_auth !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "require_fresh_machine_auth",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Audit Decisions"
              checked={settings.radius?.eap?.machine_user?.audit_enabled !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "audit_enabled"],
                  value,
                )
              }
            />
            <SelectField
              label="Correlation Mode"
              value={
                settings.radius?.eap?.machine_user?.correlation_mode ||
                "machine_then_user"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "correlation_mode"],
                  value,
                )
              }
              options={[
                { value: "machine_then_user", label: "Machine Then User" },
                { value: "same_session", label: "Same Session" },
                { value: "either", label: "Either" },
                { value: "machine_only", label: "Machine Only" },
                { value: "user_only", label: "User Only" },
              ]}
            />
            <SelectField
              label="Mode"
              value={settings.radius?.eap?.machine_user?.mode || "monitor"}
              onChange={(value) =>
                updateField(["radius", "eap", "machine_user", "mode"], value)
              }
              options={[
                { value: "monitor", label: "Monitor" },
                { value: "enforce", label: "Enforce" },
              ]}
            />
            <SelectField
              label="Identity Precedence"
              value={
                settings.radius?.eap?.machine_user?.identity_precedence ||
                "user_over_machine"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "identity_precedence"],
                  value,
                )
              }
              options={[
                { value: "user_over_machine", label: "User Over Machine" },
                { value: "machine_over_user", label: "Machine Over User" },
                { value: "deny_conflict", label: "Deny Conflict" },
              ]}
            />
            <SelectField
              label="Role Merge"
              value={
                settings.radius?.eap?.machine_user?.role_merge_strategy ||
                "user_primary"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "role_merge_strategy"],
                  value,
                )
              }
              options={[
                { value: "user_primary", label: "User Primary" },
                { value: "machine_primary", label: "Machine Primary" },
                { value: "intersection", label: "Intersection" },
                { value: "deny_conflict", label: "Deny Conflict" },
              ]}
            />
            <SelectField
              label="Conflict Action"
              value={
                settings.radius?.eap?.machine_user?.conflict_action || "reject"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "conflict_action"],
                  value,
                )
              }
              options={[
                { value: "reject", label: "Reject" },
                { value: "monitor", label: "Monitor" },
                { value: "quarantine", label: "Quarantine" },
              ]}
            />
            <SelectField
              label="Stale Machine"
              value={
                settings.radius?.eap?.machine_user?.stale_machine_action ||
                "reject"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "stale_machine_action"],
                  value,
                )
              }
              options={[
                { value: "reject", label: "Reject" },
                { value: "monitor", label: "Monitor" },
                { value: "allow", label: "Allow" },
              ]}
            />
            <TextField
              label="Machine Methods"
              value={listToCSV(
                settings.radius?.eap?.machine_user
                  ?.allowed_machine_methods || ["teap", "tls"],
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "allowed_machine_methods"],
                  csvToList(value),
                )
              }
            />
            <TextField
              label="User Methods"
              value={listToCSV(
                settings.radius?.eap?.machine_user?.allowed_user_methods || [
                  "teap",
                  "peap",
                  "ttls",
                ],
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "allowed_user_methods"],
                  csvToList(value),
                )
              }
            />
            <TextField
              label="Machine Prefixes"
              value={listToCSV(
                settings.radius?.eap?.machine_user
                  ?.machine_identity_prefixes || ["host/", "machine/"],
              )}
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "machine_identity_prefixes",
                  ],
                  csvToList(value),
                )
              }
            />
            <TextField
              label="User Prefixes"
              value={listToCSV(
                settings.radius?.eap?.machine_user?.user_identity_prefixes ||
                  [],
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "user_identity_prefixes"],
                  csvToList(value),
                )
              }
            />
            <TextField
              label="Machine TTL (s)"
              type="number"
              value={
                settings.radius?.eap?.machine_user
                  ?.machine_auth_ttl_seconds ?? 28800
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "machine_auth_ttl_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="User TTL (s)"
              type="number"
              value={
                settings.radius?.eap?.machine_user?.user_auth_ttl_seconds ??
                28800
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "user_auth_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Transition Window (s)"
              type="number"
              value={
                settings.radius?.eap?.machine_user
                  ?.transition_window_seconds ?? 900
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "transition_window_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Correlations"
              type="number"
              value={
                settings.radius?.eap?.machine_user
                  ?.max_active_correlations ?? 100000
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "machine_user",
                    "max_active_correlations",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Correlation Retention"
              type="number"
              value={
                settings.radius?.eap?.machine_user?.event_retention_limit ??
                6000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "machine_user", "event_retention_limit"],
                  Number(value),
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <h4 className="font-semibold text-gray-900">
            EAP-FAST And EAP-PWD
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            Govern PAC-backed EAP-FAST and password-authenticated EAP-PWD with
            cryptobinding, replay protection, strong groups, and bounded audit
            history.
          </p>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="FAST Available"
              checked={settings.radius?.eap?.fast?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "fast", "enabled"], value)
              }
            />
            <ToggleField
              label="FAST Cryptobinding"
              checked={
                settings.radius?.eap?.fast?.require_crypto_binding !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "require_crypto_binding"],
                  value,
                )
              }
            />
            <ToggleField
              label="Allow FAST PAC"
              checked={settings.radius?.eap?.fast?.allow_pac !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "fast", "allow_pac"], value)
              }
            />
            <ToggleField
              label="Require FAST PAC"
              checked={Boolean(settings.radius?.eap?.fast?.require_pac)}
              onChange={(value) =>
                updateField(["radius", "eap", "fast", "require_pac"], value)
              }
            />
            <ToggleField
              label="Anonymous PAC"
              checked={Boolean(
                settings.radius?.eap?.fast?.allow_anonymous_provisioning,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "fast",
                    "allow_anonymous_provisioning",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="FAST EAP Payload"
              checked={settings.radius?.eap?.fast?.allow_eap_payload !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "allow_eap_payload"],
                  value,
                )
              }
            />
            <SelectField
              label="FAST Inner"
              value={
                settings.radius?.eap?.fast?.default_inner_method ||
                "mschapv2"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "default_inner_method"],
                  value,
                )
              }
              options={[
                { value: "mschapv2", label: "MSCHAPv2" },
                { value: "pap", label: "PAP" },
                { value: "chap", label: "CHAP" },
                { value: "gtc", label: "GTC" },
                { value: "tls", label: "TLS" },
              ]}
            />
            <SelectField
              label="FAST PAC Mode"
              value={
                settings.radius?.eap?.fast?.pac_provisioning ||
                "authenticated"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "pac_provisioning"],
                  value,
                )
              }
              options={[
                { value: "disabled", label: "Disabled" },
                { value: "authenticated", label: "Authenticated" },
                { value: "anonymous", label: "Anonymous" },
                { value: "optional", label: "Optional" },
              ]}
            />
            <TextField
              label="FAST Authority ID"
              value={
                settings.radius?.eap?.fast?.pac_authority_id ||
                "aegisnas-fast"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "pac_authority_id"],
                  value,
                )
              }
            />
            <TextField
              label="PAC Key Ref"
              value={settings.radius?.eap?.fast?.pac_opaque_key_ref || ""}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "pac_opaque_key_ref"],
                  value,
                )
              }
            />
            <TextField
              label="PAC Lifetime (s)"
              type="number"
              value={
                settings.radius?.eap?.fast?.pac_lifetime_seconds ?? 2592000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "pac_lifetime_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="PAC Attempts"
              type="number"
              value={
                settings.radius?.eap?.fast?.max_provisioning_attempts ?? 3
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "max_provisioning_attempts"],
                  Number(value),
                )
              }
            />
            <TextField
              label="FAST TTL (s)"
              type="number"
              value={settings.radius?.eap?.fast?.session_ttl_seconds ?? 900}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "session_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="FAST Retention"
              type="number"
              value={
                settings.radius?.eap?.fast?.event_retention_limit ?? 6000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "fast", "event_retention_limit"],
                  Number(value),
                )
              }
            />
            <ToggleField
              label="PWD Available"
              checked={settings.radius?.eap?.pwd?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "pwd", "enabled"], value)
              }
            />
            <ToggleField
              label="PWD Strong Group"
              checked={
                settings.radius?.eap?.pwd?.require_strong_group !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "require_strong_group"],
                  value,
                )
              }
            />
            <ToggleField
              label="PWD Identity"
              checked={settings.radius?.eap?.pwd?.require_identity !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "require_identity"],
                  value,
                )
              }
            />
            <ToggleField
              label="PWD Proof"
              checked={
                settings.radius?.eap?.pwd?.require_password_proof !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "require_password_proof"],
                  value,
                )
              }
            />
            <ToggleField
              label="PWD Local Verifier"
              checked={settings.radius?.eap?.pwd?.allow_local_verifier !== false}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "allow_local_verifier"],
                  value,
                )
              }
            />
            <TextField
              label="PWD Group"
              type="number"
              value={settings.radius?.eap?.pwd?.group ?? 19}
              onChange={(value) =>
                updateField(["radius", "eap", "pwd", "group"], Number(value))
              }
            />
            <TextField
              label="PWD Server ID"
              value={settings.radius?.eap?.pwd?.server_id || "aegisnas-pwd"}
              onChange={(value) =>
                updateField(["radius", "eap", "pwd", "server_id"], value)
              }
            />
            <TextField
              label="PWD Source"
              value={
                settings.radius?.eap?.pwd?.password_source ||
                "identity-failover"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "password_source"],
                  value,
                )
              }
            />
            <TextField
              label="Replay Window (s)"
              type="number"
              value={settings.radius?.eap?.pwd?.replay_window_seconds ?? 30}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "replay_window_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="PWD Fragment"
              type="number"
              value={settings.radius?.eap?.pwd?.fragment_size ?? 1020}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "fragment_size"],
                  Number(value),
                )
              }
            />
            <TextField
              label="PWD Retention"
              type="number"
              value={settings.radius?.eap?.pwd?.event_retention_limit ?? 6000}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "pwd", "event_retention_limit"],
                  Number(value),
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <h4 className="font-semibold text-gray-900">
            EAP-SIM And EAP-AKA
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            Gate carrier offload and roaming with vector-provider health,
            pseudonym privacy, resync policy, and AKA-prime network binding.
          </p>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="SIM/AKA Available"
              checked={settings.radius?.eap?.sim_aka?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "sim_aka", "enabled"], value)
              }
            />
            <ToggleField
              label="Require Identity"
              checked={
                settings.radius?.eap?.sim_aka?.require_identity !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "require_identity"],
                  value,
                )
              }
            />
            <ToggleField
              label="Permanent Identity"
              checked={
                settings.radius?.eap?.sim_aka
                  ?.require_permanent_identity !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "sim_aka",
                    "require_permanent_identity",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Pseudonym Privacy"
              checked={
                settings.radius?.eap?.sim_aka
                  ?.allow_pseudonym_identity !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "sim_aka",
                    "allow_pseudonym_identity",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Pseudonym Reauth"
              checked={Boolean(
                settings.radius?.eap?.sim_aka?.require_pseudonym_reauth,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "sim_aka",
                    "require_pseudonym_reauth",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Fresh Vectors"
              checked={
                settings.radius?.eap?.sim_aka?.require_fresh_vectors !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "require_fresh_vectors"],
                  value,
                )
              }
            />
            <ToggleField
              label="Allow Resync"
              checked={
                settings.radius?.eap?.sim_aka?.allow_resynchronization !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "allow_resynchronization"],
                  value,
                )
              }
            />
            <ToggleField
              label="AKA-prime Network"
              checked={
                settings.radius?.eap?.sim_aka?.require_network_name !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "require_network_name"],
                  value,
                )
              }
            />
            <ToggleField
              label="AKA-prime KDF"
              checked={settings.radius?.eap?.sim_aka?.require_kdf !== false}
              onChange={(value) =>
                updateField(["radius", "eap", "sim_aka", "require_kdf"], value)
              }
            />
            <ToggleField
              label="Fail Provider Down"
              checked={
                settings.radius?.eap?.sim_aka
                  ?.fail_on_provider_unavailable !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "eap",
                    "sim_aka",
                    "fail_on_provider_unavailable",
                  ],
                  value,
                )
              }
            />
            <TextField
              label="SIM/AKA Methods"
              value={listToCSV(
                settings.radius?.eap?.sim_aka?.methods || [
                  "sim",
                  "aka",
                  "aka-prime",
                ],
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "methods"],
                  csvToList(value),
                )
              }
            />
            <SelectField
              label="Vector Provider"
              value={
                settings.radius?.eap?.sim_aka?.vector_provider ||
                "external-http"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "vector_provider"],
                  value,
                )
              }
              options={[
                { value: "external-http", label: "External HTTP" },
                { value: "hss-http", label: "HSS HTTP" },
                { value: "udm-http", label: "UDM HTTP" },
                { value: "static-file", label: "Static File" },
                { value: "identity-failover", label: "Identity Failover" },
              ]}
            />
            <TextField
              label="Provider Ref"
              value={settings.radius?.eap?.sim_aka?.vector_provider_ref || ""}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "vector_provider_ref"],
                  value,
                )
              }
            />
            <TextField
              label="Pseudonym TTL (s)"
              type="number"
              value={
                settings.radius?.eap?.sim_aka?.pseudonym_ttl_seconds ?? 86400
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "pseudonym_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Reauth TTL (s)"
              type="number"
              value={settings.radius?.eap?.sim_aka?.reauth_ttl_seconds ?? 43200}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "reauth_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Vector Age (s)"
              type="number"
              value={settings.radius?.eap?.sim_aka?.max_vector_age_seconds ?? 300}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "max_vector_age_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Min Triplets"
              type="number"
              value={settings.radius?.eap?.sim_aka?.min_triplets ?? 2}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "min_triplets"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Min Quintuplets"
              type="number"
              value={settings.radius?.eap?.sim_aka?.min_quintuplets ?? 1}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "min_quintuplets"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Resync Window (s)"
              type="number"
              value={settings.radius?.eap?.sim_aka?.resync_window_seconds ?? 300}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "resync_window_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="AKA-prime Network Name"
              value={settings.radius?.eap?.sim_aka?.network_name || ""}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "network_name"],
                  value,
                )
              }
            />
            <TextField
              label="SIM/AKA Retention"
              type="number"
              value={
                settings.radius?.eap?.sim_aka?.event_retention_limit ?? 6000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "sim_aka", "event_retention_limit"],
                  Number(value),
                )
              }
            />
          </div>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <ToggleField
            label="Dynamic Authorization"
            checked={Boolean(settings.radius?.dynamic_auth?.enabled)}
            onChange={(value) =>
              updateField(["radius", "dynamic_auth", "enabled"], value)
            }
          />
          <TextField
            label="Dynamic Authorization Port"
            type="number"
            value={settings.radius?.dynamic_auth?.port || 3799}
            onChange={(value) =>
              updateField(["radius", "dynamic_auth", "port"], Number(value))
            }
          />
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <h4 className="font-semibold text-gray-900">
            Dynamic NAS Clients
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            New APs, switches, and controllers can request enrollment, stay
            pending until approved, and inherit capability templates.
          </p>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <ToggleField
              label="Enable Enrollment"
              checked={Boolean(settings.radius?.dynamic_clients?.enabled)}
              onChange={(value) =>
                updateField(["radius", "dynamic_clients", "enabled"], value)
              }
            />
            <ToggleField
              label="Packet Discovery"
              checked={Boolean(
                settings.radius?.dynamic_clients?.discovery_enabled,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "discovery_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Approval"
              checked={
                settings.radius?.dynamic_clients?.approval_required !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "approval_required"],
                  value,
                )
              }
            />
            <TextField
              label="Enrollment Token Ref"
              value={
                settings.radius?.dynamic_clients?.enrollment_token_ref || ""
              }
              placeholder="env:AEGIS_NAS_ENROLLMENT_TOKEN"
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "enrollment_token_ref"],
                  value,
                )
              }
            />
            <TextField
              label="Enrollment TTL (s)"
              type="number"
              value={
                settings.radius?.dynamic_clients?.enrollment_ttl_seconds ||
                86400
              }
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "enrollment_ttl_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Pending"
              type="number"
              value={settings.radius?.dynamic_clients?.max_pending || 256}
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "max_pending"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Default NAS Type"
              value={
                settings.radius?.dynamic_clients?.default_nas_type || "other"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "default_nas_type"],
                  value,
                )
              }
            />
            <SelectField
              label="Default Transport"
              value={
                settings.radius?.dynamic_clients?.default_transport || "udp"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "default_transport"],
                  value,
                )
              }
              options={[
                { value: "udp", label: "RADIUS / UDP" },
                { value: "radsec", label: "RadSec / TLS" },
              ]}
            />
            <TextField
              label="Default Template"
              value={
                settings.radius?.dynamic_clients?.default_template || "default"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "dynamic_clients", "default_template"],
                  value,
                )
              }
            />
          </div>
          <label className="mt-4 block text-sm font-medium text-gray-700">
            <span>Discovery Allowed CIDRs</span>
            <textarea
              value={
                Array.isArray(
                  settings.radius?.dynamic_clients?.discovery_allowed_cidrs,
                )
                  ? settings.radius.dynamic_clients.discovery_allowed_cidrs.join(
                      "\n",
                    )
                  : ""
              }
              onChange={(event: ChangeEvent<HTMLTextAreaElement>) =>
                updateField(
                  ["radius", "dynamic_clients", "discovery_allowed_cidrs"],
                  event.target.value
                    .split(/\r?\n/)
                    .map((line) => line.trim())
                    .filter(Boolean),
                )
              }
              className="mt-1 min-h-[96px] w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-sm"
              placeholder={"10.20.0.0/24\n2001:db8:10::/64"}
            />
          </label>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <h4 className="font-semibold text-gray-900">
            EAP-TLS Certificate Revocation
          </h4>
          <p className="mt-1 text-sm text-gray-600">
            EAP-TLS onboarding requires CRL or OCSP validation. Keep OCSP
            soft-fail disabled unless CRL checking provides a fallback.
          </p>
          <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Check Client CRL"
              checked={Boolean(settings.radius?.eap?.check_crl)}
              onChange={(checked) =>
                updateField(["radius", "eap", "check_crl"], checked)
              }
            />
            <ToggleField
              label="Check Full CRL Chain"
              checked={Boolean(settings.radius?.eap?.check_all_crl)}
              onChange={(checked) =>
                updateField(["radius", "eap", "check_all_crl"], checked)
              }
            />
            <TextField
              label="CA/CRL Reload (s)"
              type="number"
              value={settings.radius?.eap?.ca_path_reload_interval ?? 3600}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "ca_path_reload_interval"],
                  Number(value),
                )
              }
            />
            <ToggleField
              label="Enable OCSP"
              checked={Boolean(settings.radius?.eap?.ocsp?.enabled)}
              onChange={(checked) =>
                updateField(["radius", "eap", "ocsp", "enabled"], checked)
              }
            />
            <ToggleField
              label="Override Certificate OCSP URL"
              checked={Boolean(
                settings.radius?.eap?.ocsp?.override_cert_url,
              )}
              onChange={(checked) =>
                updateField(
                  ["radius", "eap", "ocsp", "override_cert_url"],
                  checked,
                )
              }
            />
            <TextField
              label="OCSP Responder URL"
              value={settings.radius?.eap?.ocsp?.url || ""}
              onChange={(value) =>
                updateField(["radius", "eap", "ocsp", "url"], value)
              }
            />
            <ToggleField
              label="OCSP Nonce"
              checked={settings.radius?.eap?.ocsp?.use_nonce !== false}
              onChange={(checked) =>
                updateField(
                  ["radius", "eap", "ocsp", "use_nonce"],
                  checked,
                )
              }
            />
            <TextField
              label="OCSP Timeout (s)"
              type="number"
              value={settings.radius?.eap?.ocsp?.timeout_seconds ?? 5}
              onChange={(value) =>
                updateField(
                  ["radius", "eap", "ocsp", "timeout_seconds"],
                  Number(value),
                )
              }
            />
            <ToggleField
              label="OCSP Soft Fail"
              checked={Boolean(settings.radius?.eap?.ocsp?.soft_fail)}
              onChange={(checked) =>
                updateField(
                  ["radius", "eap", "ocsp", "soft_fail"],
                  checked,
                )
              }
            />
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 pt-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h4 className="font-semibold text-gray-900">
                AegisNAS Vendor Dictionary
              </h4>
              <p className="mt-1 text-sm text-gray-600">
                Built-in attributes come from
                configs/dictionary.aegisnas. Add rows here only for local
                overrides or extensions.
              </p>
            </div>
            <button
              onClick={() =>
                updateField(
                  ["radius", "vendor", "attributes"],
                  [
                    ...vendorAttributes,
                    {
                      name: "",
                      number: vendorAttributes.length + 20,
                      type: "string",
                    },
                  ],
                )
              }
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Add Attribute
            </button>
          </div>
          <div className="mb-4 grid gap-4 md:grid-cols-4">
            <ToggleField
              label="Vendor Attributes Enabled"
              checked={Boolean(settings.radius?.vendor?.enabled)}
              onChange={(value) =>
                updateField(["radius", "vendor", "enabled"], value)
              }
            />
            <TextField
              label="Vendor Name"
              value={settings.radius?.vendor?.name || "AegisNAS"}
              onChange={(value) =>
                updateField(["radius", "vendor", "name"], value)
              }
            />
            <TextField
              label="Vendor ID"
              type="number"
              value={settings.radius?.vendor?.id || 0}
              onChange={(value) =>
                updateField(["radius", "vendor", "id"], Number(value))
              }
            />
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  Dictionary Import Paths
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Import FreeRADIUS dictionary files or directories for the
                  Vendor Compatibility coverage matrix.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "dictionary_paths"],
                    [...vendorDictionaryPaths, ""],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Path
              </button>
            </div>
            {vendorDictionaryPaths.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No custom dictionary paths configured. The appliance will
                auto-detect standard FreeRADIUS paths when they exist.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorDictionaryPaths.map((path: string, index: number) => (
                  <div
                    key={`vendor-dictionary-path-${index}`}
                    className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-[1fr_auto]"
                  >
                    <TextField
                      label="Path"
                      value={path || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "radius",
                            "vendor",
                            "dictionary_paths",
                            String(index),
                          ],
                          value,
                        )
                      }
                      placeholder="/usr/share/freeradius"
                    />
                    <div className="flex items-end">
                      <button
                        onClick={() =>
                          updateField(
                            ["radius", "vendor", "dictionary_paths"],
                            vendorDictionaryPaths.filter(
                              (_: unknown, itemIndex: number) =>
                                itemIndex !== index,
                            ),
                          )
                        }
                        className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  Numeric Vendor Roles
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Use values certified for the target dictionary and device
                  profile.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "role_mappings"],
                    [
                      ...vendorRoleMappings,
                      { pack: "cambium", role: "", value: 0 },
                    ],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Role Mapping
              </button>
            </div>
            {vendorRoleMappings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No numeric vendor roles configured.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorRoleMappings.map((mapping: JsonMap, index: number) => (
                  <div
                    key={`vendor-role-mapping-${index}`}
                    className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-4"
                  >
                    <SelectField
                      label="Vendor Pack"
                      value={mapping.pack || "cambium"}
                      onChange={(value) =>
                        updateField(
                          [
                            "radius",
                            "vendor",
                            "role_mappings",
                            String(index),
                            "pack",
                          ],
                          value,
                        )
                      }
                      options={numericVendorRolePackOptions}
                    />
                    <TextField
                      label="Local Role"
                      value={mapping.role || ""}
                      onChange={(value) =>
                        updateField(
                          [
                            "radius",
                            "vendor",
                            "role_mappings",
                            String(index),
                            "role",
                          ],
                          value,
                        )
                      }
                      placeholder="network-admin"
                    />
                    <TextField
                      label="Vendor Value"
                      type="number"
                      value={mapping.value ?? 0}
                      onChange={(value) =>
                        updateField(
                          [
                            "radius",
                            "vendor",
                            "role_mappings",
                            String(index),
                            "value",
                          ],
                          Number(value),
                        )
                      }
                    />
                    <div className="flex items-end">
                      <button
                        onClick={() =>
                          updateField(
                            ["radius", "vendor", "role_mappings"],
                            vendorRoleMappings.filter(
                              (_: unknown, itemIndex: number) =>
                                itemIndex !== index,
                            ),
                          )
                        }
                        className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  Extreme Extended VLANs
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Assign one optional untagged VLAN and up to ten total VLANs
                  to a local role.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "extended_vlan_mappings"],
                    [
                      ...vendorExtendedVLANMappings,
                      {
                        pack: "extreme",
                        role: "",
                        untagged_vlan: 0,
                        tagged_vlans: [],
                      },
                    ],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add VLAN Mapping
              </button>
            </div>
            {vendorExtendedVLANMappings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No Extreme extended VLAN mappings configured.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorExtendedVLANMappings.map(
                  (mapping: JsonMap, index: number) => (
                    <div
                      key={`vendor-extended-vlan-${index}`}
                      className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-5"
                    >
                      <SelectField
                        label="Vendor Pack"
                        value={mapping.pack || "extreme"}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "extended_vlan_mappings",
                              String(index),
                              "pack",
                            ],
                            value,
                          )
                        }
                        options={extendedVLANPackOptions}
                      />
                      <TextField
                        label="Local Role"
                        value={mapping.role || ""}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "extended_vlan_mappings",
                              String(index),
                              "role",
                            ],
                            value,
                          )
                        }
                        placeholder="voice-device"
                      />
                      <TextField
                        label="Untagged VLAN"
                        type="number"
                        value={mapping.untagged_vlan ?? 0}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "extended_vlan_mappings",
                              String(index),
                              "untagged_vlan",
                            ],
                            Number(value),
                          )
                        }
                      />
                      <TextField
                        label="Tagged VLANs"
                        value={(mapping.tagged_vlans || []).join(", ")}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "extended_vlan_mappings",
                              String(index),
                              "tagged_vlans",
                            ],
                            value
                              .split(",")
                              .map((item) => item.trim())
                              .filter(Boolean)
                              .map(Number),
                          )
                        }
                        placeholder="30, 40"
                      />
                      <div className="flex items-end">
                        <button
                          onClick={() =>
                            updateField(
                              [
                                "radius",
                                "vendor",
                                "extended_vlan_mappings",
                              ],
                              vendorExtendedVLANMappings.filter(
                                (_: unknown, itemIndex: number) =>
                                  itemIndex !== index,
                              ),
                            )
                          }
                          className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ),
                )}
              </div>
            )}
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  Vendor AVPair Templates
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Add one certified value per line for each local role.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "avpair_mappings"],
                    [
                      ...vendorAVPairMappings,
                      { pack: "juniper", role: "", values: [] },
                    ],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add AVPair Mapping
              </button>
            </div>
            <p className="mb-3 text-xs text-gray-500">
              Placeholders: ${"{role}"}, ${"{acl_policy}"}, ${"{inbound_acl}"},
              ${"{outbound_acl}"}, ${"{vlan}"}, ${"{policy_tag}"},
              ${"{device_group}"}, ${"{tenant}"}
            </p>
            {vendorAVPairMappings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No vendor AVPair templates configured.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorAVPairMappings.map(
                  (mapping: JsonMap, index: number) => (
                    <div
                      key={`vendor-avpair-${index}`}
                      className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-[1fr_1fr_2fr_auto]"
                    >
                      <SelectField
                        label="Vendor Pack"
                        value={mapping.pack || "juniper"}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "avpair_mappings",
                              String(index),
                              "pack",
                            ],
                            value,
                          )
                        }
                        options={avPairPackOptions}
                      />
                      <TextField
                        label="Local Role"
                        value={mapping.role || ""}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "avpair_mappings",
                              String(index),
                              "role",
                            ],
                            value,
                          )
                        }
                        placeholder="network-admin"
                      />
                      <label className="text-sm text-gray-700">
                        <span className="mb-1 block">AVPair Values</span>
                        <textarea
                          rows={3}
                          value={(mapping.values || []).join("\n")}
                          onChange={(event) =>
                            updateField(
                              [
                                "radius",
                                "vendor",
                                "avpair_mappings",
                                String(index),
                                "values",
                              ],
                              event.target.value
                                .split("\n")
                                .map((item) => item.trim())
                                .filter(Boolean),
                            )
                          }
                          placeholder="shell:roles=${role}"
                          className="w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-sm"
                        />
                      </label>
                      <div className="flex items-end">
                        <button
                          onClick={() =>
                            updateField(
                              ["radius", "vendor", "avpair_mappings"],
                              vendorAVPairMappings.filter(
                                (_: unknown, itemIndex: number) =>
                                  itemIndex !== index,
                              ),
                            )
                          }
                          className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ),
                )}
              </div>
            )}
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  TP-Link Portal Status
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Use integer values certified for the deployed Omada release.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "portal_status_mappings"],
                    [
                      ...vendorPortalStatusMappings,
                      {
                        pack: "tplink",
                        portal_profile: "",
                        value: 0,
                      },
                    ],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Portal Status
              </button>
            </div>
            {vendorPortalStatusMappings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No TP-Link portal status mappings configured.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorPortalStatusMappings.map(
                  (mapping: JsonMap, index: number) => (
                    <div
                      key={`vendor-portal-status-${index}`}
                      className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-4"
                    >
                      <SelectField
                        label="Vendor Pack"
                        value={mapping.pack || "tplink"}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "portal_status_mappings",
                              String(index),
                              "pack",
                            ],
                            value,
                          )
                        }
                        options={portalStatusPackOptions}
                      />
                      <TextField
                        label="Portal Profile"
                        value={mapping.portal_profile || ""}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "portal_status_mappings",
                              String(index),
                              "portal_profile",
                            ],
                            value,
                          )
                        }
                        placeholder="https://portal.example.test/guest"
                      />
                      <TextField
                        label="Vendor Value"
                        type="number"
                        value={mapping.value ?? 0}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "portal_status_mappings",
                              String(index),
                              "value",
                            ],
                            Number(value),
                          )
                        }
                      />
                      <div className="flex items-end">
                        <button
                          onClick={() =>
                            updateField(
                              [
                                "radius",
                                "vendor",
                                "portal_status_mappings",
                              ],
                              vendorPortalStatusMappings.filter(
                                (_: unknown, itemIndex: number) =>
                                  itemIndex !== index,
                              ),
                            )
                          }
                          className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ),
                )}
              </div>
            )}
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  Nomadix Session Actions
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Bind certified EndofSession values to local roles and actions.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "session_action_mappings"],
                    [
                      ...vendorSessionActionMappings,
                      {
                        pack: "nomadix",
                        role: "",
                        action: "disconnect",
                        value: 0,
                      },
                    ],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Session Action
              </button>
            </div>
            {vendorSessionActionMappings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No Nomadix session action mappings configured.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorSessionActionMappings.map(
                  (mapping: JsonMap, index: number) => (
                    <div
                      key={`vendor-session-action-${index}`}
                      className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-5"
                    >
                      <SelectField
                        label="Vendor Pack"
                        value={mapping.pack || "nomadix"}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "session_action_mappings",
                              String(index),
                              "pack",
                            ],
                            value,
                          )
                        }
                        options={sessionActionPackOptions}
                      />
                      <TextField
                        label="Local Role"
                        value={mapping.role || ""}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "session_action_mappings",
                              String(index),
                              "role",
                            ],
                            value,
                          )
                        }
                        placeholder="expired-guest"
                      />
                      <SelectField
                        label="Local Action"
                        value={mapping.action || "disconnect"}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "session_action_mappings",
                              String(index),
                              "action",
                            ],
                            value,
                          )
                        }
                        options={sessionActionOptions}
                      />
                      <TextField
                        label="Vendor Value"
                        type="number"
                        value={mapping.value ?? 0}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "session_action_mappings",
                              String(index),
                              "value",
                            ],
                            Number(value),
                          )
                        }
                      />
                      <div className="flex items-end">
                        <button
                          onClick={() =>
                            updateField(
                              [
                                "radius",
                                "vendor",
                                "session_action_mappings",
                              ],
                              vendorSessionActionMappings.filter(
                                (_: unknown, itemIndex: number) =>
                                  itemIndex !== index,
                              ),
                            )
                          }
                          className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ),
                )}
              </div>
            )}
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  ChilliSpot Data Quotas
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Limit combined input and output bytes for each local role.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "quota_mappings"],
                    [
                      ...vendorQuotaMappings,
                      {
                        pack: "chillispot",
                        role: "",
                        max_total_octets: 1073741824,
                      },
                    ],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Data Quota
              </button>
            </div>
            {vendorQuotaMappings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No ChilliSpot data quotas configured.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorQuotaMappings.map(
                  (mapping: JsonMap, index: number) => (
                    <div
                      key={`vendor-quota-${index}`}
                      className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-4"
                    >
                      <SelectField
                        label="Vendor Pack"
                        value={mapping.pack || "chillispot"}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "quota_mappings",
                              String(index),
                              "pack",
                            ],
                            value,
                          )
                        }
                        options={quotaPackOptions}
                      />
                      <TextField
                        label="Local Role"
                        value={mapping.role || ""}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "quota_mappings",
                              String(index),
                              "role",
                            ],
                            value,
                          )
                        }
                        placeholder="guest-1g"
                      />
                      <TextField
                        label="Maximum Total Octets"
                        type="number"
                        value={mapping.max_total_octets ?? 1073741824}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "quota_mappings",
                              String(index),
                              "max_total_octets",
                            ],
                            Number(value),
                          )
                        }
                      />
                      <div className="flex items-end">
                        <button
                          onClick={() =>
                            updateField(
                              ["radius", "vendor", "quota_mappings"],
                              vendorQuotaMappings.filter(
                                (_: unknown, itemIndex: number) =>
                                  itemIndex !== index,
                              ),
                            )
                          }
                          className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ),
                )}
              </div>
            )}
          </div>
          <div className="mb-4 border-t border-gray-100 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-gray-900">
                  Nokia Service Names
                </h5>
                <p className="mt-1 text-sm text-gray-600">
                  Map local roles to decimal service names encoded as Nokia BCD.
                </p>
              </div>
              <button
                onClick={() =>
                  updateField(
                    ["radius", "vendor", "service_name_mappings"],
                    [
                      ...vendorServiceNameMappings,
                      {
                        pack: "nokia",
                        role: "",
                        service_name: "",
                      },
                    ],
                  )
                }
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Add Service Name
              </button>
            </div>
            {vendorServiceNameMappings.length === 0 ? (
              <div className="rounded-md border border-dashed border-gray-300 px-4 py-3 text-sm text-gray-500">
                No Nokia service name mappings configured.
              </div>
            ) : (
              <div className="space-y-3">
                {vendorServiceNameMappings.map(
                  (mapping: JsonMap, index: number) => (
                    <div
                      key={`vendor-service-name-${index}`}
                      className="grid gap-3 rounded-md border border-gray-200 p-3 md:grid-cols-4"
                    >
                      <SelectField
                        label="Vendor Pack"
                        value={mapping.pack || "nokia"}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "service_name_mappings",
                              String(index),
                              "pack",
                            ],
                            value,
                          )
                        }
                        options={serviceNamePackOptions}
                      />
                      <TextField
                        label="Local Role"
                        value={mapping.role || ""}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "service_name_mappings",
                              String(index),
                              "role",
                            ],
                            value,
                          )
                        }
                        placeholder="mobile-data"
                      />
                      <TextField
                        label="Decimal Service Name"
                        value={mapping.service_name || ""}
                        onChange={(value) =>
                          updateField(
                            [
                              "radius",
                              "vendor",
                              "service_name_mappings",
                              String(index),
                              "service_name",
                            ],
                            value,
                          )
                        }
                        placeholder="00123"
                      />
                      <div className="flex items-end">
                        <button
                          onClick={() =>
                            updateField(
                              [
                                "radius",
                                "vendor",
                                "service_name_mappings",
                              ],
                              vendorServiceNameMappings.filter(
                                (_: unknown, itemIndex: number) =>
                                  itemIndex !== index,
                              ),
                            )
                          }
                          className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ),
                )}
              </div>
            )}
          </div>
          <div className="space-y-3">
            {vendorAttributes.map((attribute: JsonMap, index: number) => (
              <div
                key={`vendor-attr-${index}`}
                className="grid gap-3 rounded-lg border border-gray-200 p-3 md:grid-cols-4"
              >
                <TextField
                  label="Name"
                  value={attribute.name || ""}
                  onChange={(value) =>
                    updateField(
                      ["radius", "vendor", "attributes", String(index), "name"],
                      value,
                    )
                  }
                />
                <TextField
                  label="Number"
                  type="number"
                  value={attribute.number || 0}
                  onChange={(value) =>
                    updateField(
                      [
                        "radius",
                        "vendor",
                        "attributes",
                        String(index),
                        "number",
                      ],
                      Number(value),
                    )
                  }
                />
                <SelectField
                  label="Type"
                  value={attribute.type || "string"}
                  onChange={(value) =>
                    updateField(
                      ["radius", "vendor", "attributes", String(index), "type"],
                      value,
                    )
                  }
                  options={[
                    { value: "string", label: "String" },
                    { value: "integer", label: "Integer" },
                    { value: "ipaddr", label: "IPv4 Address" },
                    { value: "octets", label: "Octets" },
                    { value: "date", label: "Date" },
                  ]}
                />
                <div className="flex items-end">
                  <button
                    onClick={() =>
                      updateField(
                        ["radius", "vendor", "attributes"],
                        vendorAttributes.filter(
                          (_: unknown, itemIndex: number) =>
                            itemIndex !== index,
                        ),
                      )
                    }
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
        <h3 className="mb-4 text-lg font-semibold text-gray-900">RadSec</h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField label="Inbound RadSec" checked={Boolean(settings.radius?.radsec?.enabled)} onChange={(value) => updateField(["radius", "radsec", "enabled"], value)} />
          <TextField label="Listen Address" value={settings.radius?.radsec?.listen_address || "0.0.0.0"} onChange={(value) => updateField(["radius", "radsec", "listen_address"], value)} />
          <TextField label="Port" type="number" value={settings.radius?.radsec?.port || 2083} onChange={(value) => updateField(["radius", "radsec", "port"], Number(value))} />
          <SelectField label="RADIUS Version" value={settings.radius?.radsec?.radius_v11 || "forbid"} onChange={(value) => updateField(["radius", "radsec", "radius_v11"], value)} options={[{ value: "forbid", label: "RADIUS/1.0" }, { value: "allow", label: "Allow RADIUS/1.1" }, { value: "require", label: "Require RADIUS/1.1" }]} />
          <TextField label="Server Certificate" value={settings.radius?.radsec?.certificate_file || ""} onChange={(value) => updateField(["radius", "radsec", "certificate_file"], value)} />
          <TextField label="Server Private Key" value={settings.radius?.radsec?.private_key_file || ""} onChange={(value) => updateField(["radius", "radsec", "private_key_file"], value)} />
          <TextField label="Key Password Environment" value={settings.radius?.radsec?.private_key_password_env || ""} onChange={(value) => updateField(["radius", "radsec", "private_key_password_env"], value)} />
          <TextField label="Trusted CA File" value={settings.radius?.radsec?.ca_file || ""} onChange={(value) => updateField(["radius", "radsec", "ca_file"], value)} />
          <TextField label="Trusted CA Path" value={settings.radius?.radsec?.ca_path || ""} onChange={(value) => updateField(["radius", "radsec", "ca_path"], value)} />
          <SelectField label="TLS Minimum" value={settings.radius?.radsec?.tls_min_version || "1.2"} onChange={(value) => updateField(["radius", "radsec", "tls_min_version"], value)} options={[{ value: "1.2", label: "TLS 1.2" }, { value: "1.3", label: "TLS 1.3" }]} />
          <SelectField label="TLS Maximum" value={settings.radius?.radsec?.tls_max_version || "1.3"} onChange={(value) => updateField(["radius", "radsec", "tls_max_version"], value)} options={[{ value: "1.2", label: "TLS 1.2" }, { value: "1.3", label: "TLS 1.3" }]} />
          <TextField label="OpenSSL Cipher List" value={settings.radius?.radsec?.cipher_list || "DEFAULT@SECLEVEL=2"} onChange={(value) => updateField(["radius", "radsec", "cipher_list"], value)} />
          <TextField label="Connection Limit" type="number" value={settings.radius?.radsec?.max_connections || 64} onChange={(value) => updateField(["radius", "radsec", "max_connections"], Number(value))} />
          <TextField label="Connection Lifetime (s)" type="number" value={settings.radius?.radsec?.lifetime_seconds || 86400} onChange={(value) => updateField(["radius", "radsec", "lifetime_seconds"], Number(value))} />
          <TextField label="Idle Timeout (s)" type="number" value={settings.radius?.radsec?.idle_timeout_seconds || 300} onChange={(value) => updateField(["radius", "radsec", "idle_timeout_seconds"], Number(value))} />
          <TextField label="Probe Interval (s)" type="number" value={settings.radius?.radsec?.probe_interval_seconds || 30} onChange={(value) => updateField(["radius", "radsec", "probe_interval_seconds"], Number(value))} />
          <TextField label="Certificate Warning (days)" type="number" value={settings.radius?.radsec?.certificate_expiry_warning_days || 30} onChange={(value) => updateField(["radius", "radsec", "certificate_expiry_warning_days"], Number(value))} />
          <ToggleField label="CRL Validation" checked={Boolean(settings.radius?.radsec?.check_crl)} onChange={(value) => updateField(["radius", "radsec", "check_crl"], value)} />
          <ToggleField label="Full Chain CRL Validation" checked={Boolean(settings.radius?.radsec?.check_all_crl)} onChange={(value) => updateField(["radius", "radsec", "check_all_crl"], value)} />
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">
            Upstream AAA Servers
          </h3>
          <button
            onClick={() =>
              updateField(
                ["radius", "upstream", "servers"],
                [
                  ...upstreamServers,
                  {
                    name: "",
                    address: "",
                    transport: "udp",
                    auth_port: 1812,
                    acct_port: 1813,
                    secret: "",
                    radsec: {
                      port: 2083,
                      server_name: "",
                      psk: {
                        enabled: false,
                        identity: "",
                        secret_ref: "",
                        next_identity: "",
                        next_secret_ref: "",
                        next_not_before: "",
                        next_not_after: "",
                        overlap_seconds: 86400,
                        warning_days: 30,
                      },
                      certificate_file: "/etc/aegisnas/radsec/client.crt",
                      private_key_file: "/etc/aegisnas/radsec/client.key",
                      private_key_password_env: "",
                      ca_file: "/etc/aegisnas/radsec/ca.crt",
                      ca_path: "",
                      check_crl: true,
                      tls_min_version: "1.2",
                      tls_max_version: "1.3",
                      cipher_list: "DEFAULT@SECLEVEL=2",
                      radius_v11: "forbid",
                      max_connections: 16,
                      max_requests: 0,
                      lifetime_seconds: 86400,
                      idle_timeout_seconds: 300,
                    },
                  },
                ],
              )
            }
            className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
          >
            Add Server
          </button>
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-4">
          <ToggleField
            label="Upstream AAA Enabled"
            checked={Boolean(settings.radius?.upstream?.enabled)}
            onChange={(value) =>
              updateField(["radius", "upstream", "enabled"], value)
            }
          />
          <TextField
            label="Realm"
            value={settings.radius?.upstream?.realm || ""}
            onChange={(value) =>
              updateField(["radius", "upstream", "realm"], value)
            }
          />
          <SelectField
            label="Pool Strategy"
            value={settings.radius?.upstream?.pool_strategy || "fail-over"}
            onChange={(value) =>
              updateField(["radius", "upstream", "pool_strategy"], value)
            }
            options={[
              { value: "fail-over", label: "Fail Over" },
              { value: "load-balance", label: "Load Balance" },
              { value: "client-balance", label: "Client Balance" },
              { value: "client-port-balance", label: "Client + Port Balance" },
              { value: "keyed-balance", label: "Keyed Balance" },
            ]}
          />
          <SelectField
            label="Status Check"
            value={settings.radius?.upstream?.status_check || "status-server"}
            onChange={(value) =>
              updateField(["radius", "upstream", "status_check"], value)
            }
            options={[
              { value: "status-server", label: "Status Server" },
              { value: "none", label: "None" },
            ]}
          />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <TextField
            label="Response Window"
            type="number"
            value={settings.radius?.upstream?.response_window || 20}
            onChange={(value) =>
              updateField(
                ["radius", "upstream", "response_window"],
                Number(value),
              )
            }
          />
          <TextField
            label="Zombie Period"
            type="number"
            value={settings.radius?.upstream?.zombie_period || 40}
            onChange={(value) =>
              updateField(
                ["radius", "upstream", "zombie_period"],
                Number(value),
              )
            }
          />
          <TextField
            label="Revive Interval"
            type="number"
            value={settings.radius?.upstream?.revive_interval || 120}
            onChange={(value) =>
              updateField(
                ["radius", "upstream", "revive_interval"],
                Number(value),
              )
            }
          />
          <TextField
            label="Check Interval"
            type="number"
            value={settings.radius?.upstream?.check_interval || 30}
            onChange={(value) =>
              updateField(
                ["radius", "upstream", "check_interval"],
                Number(value),
              )
            }
          />
        </div>
        <div className="mt-3">
          <ToggleField
            label="Strip Realm"
            checked={Boolean(settings.radius?.upstream?.strip_realm)}
            onChange={(value) =>
              updateField(["radius", "upstream", "strip_realm"], value)
            }
          />
        </div>
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-gray-900">
            Transport Downgrade Policy
          </h4>
          <div className="mt-3 grid gap-3 md:grid-cols-2 lg:grid-cols-5">
            <ToggleField
              label="Policy Enabled"
              checked={
                settings.radius?.upstream?.transport_policy?.enabled !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "transport_policy", "enabled"],
                  value,
                )
              }
            />
            <SelectField
              label="Mode"
              value={
                settings.radius?.upstream?.transport_policy?.mode || "monitor"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "transport_policy", "mode"],
                  value,
                )
              }
              options={transportPolicyModeOptions}
            />
            <ToggleField
              label="Fail Closed"
              checked={
                settings.radius?.upstream?.transport_policy?.fail_closed !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "transport_policy", "fail_closed"],
                  value,
                )
              }
            />
            <SelectField
              label="Required Transport"
              value={
                settings.radius?.upstream?.transport_policy
                  ?.default_required_transport || "any"
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "transport_policy",
                    "default_required_transport",
                  ],
                  value,
                )
              }
              options={requiredTransportOptions}
            />
            <ToggleField
              label="Allow Mixed Pools"
              checked={Boolean(
                settings.radius?.upstream?.transport_policy
                  ?.allow_mixed_transports,
              )}
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "transport_policy",
                    "allow_mixed_transports",
                  ],
                  value,
                )
              }
            />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Enforce mode blocks proxy generation when a route can silently
            downgrade from RadSec to UDP.
          </p>
        </div>
        <div className="mt-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <h4 className="text-sm font-semibold text-gray-900">
                FreeRADIUS SQL Accounting
              </h4>
              <p className="mt-1 text-xs text-gray-500">
                Keep radacct, radpostauth, and AegisNAS sessions aligned.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={loadSQLAccountingReport}
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Refresh SQL
              </button>
              <button
                type="button"
                onClick={reconcileSQLAccounting}
                disabled={reconcilingSQLAccounting}
                className="rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
              >
                {reconcilingSQLAccounting ? "Reconciling..." : "Reconcile"}
              </button>
            </div>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="SQL Accounting"
              checked={settings.radius?.sql_accounting?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "sql_accounting", "enabled"], value)
              }
            />
            <ToggleField
              label="Auto Reconcile"
              checked={
                settings.radius?.sql_accounting?.reconcile_enabled !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "sql_accounting", "reconcile_enabled"],
                  value,
                )
              }
            />
            <TextField
              label="Batch Size"
              type="number"
              value={settings.radius?.sql_accounting?.batch_size || 500}
              onChange={(value) =>
                updateField(
                  ["radius", "sql_accounting", "batch_size"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Reconcile Interval (s)"
              type="number"
              value={
                settings.radius?.sql_accounting
                  ?.reconcile_interval_seconds || 60
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "sql_accounting",
                    "reconcile_interval_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Stale After (s)"
              type="number"
              value={settings.radius?.sql_accounting?.stale_after_seconds || 300}
              onChange={(value) =>
                updateField(
                  ["radius", "sql_accounting", "stale_after_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Accounting Retention (d)"
              type="number"
              value={
                settings.radius?.sql_accounting
                  ?.accounting_retention_days || 365
              }
              onChange={(value) =>
                updateField(
                  ["radius", "sql_accounting", "accounting_retention_days"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Post-Auth Retention (d)"
              type="number"
              value={
                settings.radius?.sql_accounting?.postauth_retention_days || 30
              }
              onChange={(value) =>
                updateField(
                  ["radius", "sql_accounting", "postauth_retention_days"],
                  Number(value),
                )
              }
            />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Status
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {sqlAccountingReport?.status || "unknown"}
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Rows
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {sqlAccountingReport?.summary?.radacct_rows || 0} radacct /{" "}
                {sqlAccountingReport?.summary?.radpostauth_rows || 0} postauth
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Pending
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {sqlAccountingReport?.summary?.pending_rows || 0} pending,{" "}
                {sqlAccountingReport?.summary?.stale_pending_rows || 0} stale
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Errors
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {sqlAccountingReport?.summary?.error_rows || 0} error(s),{" "}
                {sqlAccountingReport?.summary?.reconciled_rows || 0} reconciled
              </div>
            </div>
          </div>
          {sqlAccountingReport?.message && (
            <p className="mt-2 text-xs text-gray-500">
              {sqlAccountingReport.message}
            </p>
          )}
        </div>
        <div className="mt-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <h4 className="text-sm font-semibold text-gray-900">
                Accounting Ordering
              </h4>
              <p className="mt-1 text-xs text-gray-500">
                Apply each accounting packet once, then merge reordered packets
                safely.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={loadAccountingOrderingReport}
                className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
              >
                Refresh Ordering
              </button>
              <button
                type="button"
                onClick={replayAccountingOrdering}
                disabled={replayingAccountingOrdering}
                className="rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
              >
                {replayingAccountingOrdering ? "Replaying..." : "Replay Events"}
              </button>
            </div>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Ordering Engine"
              checked={settings.radius?.accounting_ordering?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "accounting_ordering", "enabled"], value)
              }
            />
            <ToggleField
              label="Replay Enabled"
              checked={
                settings.radius?.accounting_ordering?.replay_enabled !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_ordering", "replay_enabled"],
                  value,
                )
              }
            />
            <TextField
              label="Sequence Window (s)"
              type="number"
              value={
                settings.radius?.accounting_ordering
                  ?.sequence_window_seconds || 300
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_ordering", "sequence_window_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Late Stop Window (s)"
              type="number"
              value={
                settings.radius?.accounting_ordering
                  ?.late_stop_window_seconds || 86400
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_ordering", "late_stop_window_seconds"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Replay Batch"
              type="number"
              value={settings.radius?.accounting_ordering?.max_replay_batch || 1000}
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_ordering", "max_replay_batch"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Duplicate Retention (d)"
              type="number"
              value={
                settings.radius?.accounting_ordering
                  ?.duplicate_retention_days || 365
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "accounting_ordering",
                    "duplicate_retention_days",
                  ],
                  Number(value),
                )
              }
            />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Status
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingOrderingReport?.status || "unknown"}
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Events
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingOrderingReport?.summary?.total_events || 0} total,{" "}
                {accountingOrderingReport?.summary?.applied_events || 0} applied
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Pending
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingOrderingReport?.summary?.pending_events || 0} pending,{" "}
                {accountingOrderingReport?.summary?.stale_pending_events || 0} stale
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Recovery
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingOrderingReport?.summary?.duplicate_events || 0} dup,{" "}
                {accountingOrderingReport?.summary?.reordered_events || 0} reorder,{" "}
                {accountingOrderingReport?.summary?.late_stop_events || 0} stop
              </div>
            </div>
          </div>
          {accountingOrderingReport?.message && (
            <p className="mt-2 text-xs text-gray-500">
              {accountingOrderingReport.message}
            </p>
          )}
        </div>
        <div className="mt-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <h4 className="text-sm font-semibold text-gray-900">
                Accounting Counters
              </h4>
              <p className="mt-1 text-xs text-gray-500">
                Preserve 64-bit octets, gigaword rollover, and counter reset
                evidence.
              </p>
            </div>
            <button
              type="button"
              onClick={loadAccountingCountersReport}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Refresh Counters
            </button>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Counter Engine"
              checked={settings.radius?.accounting_counters?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "accounting_counters", "enabled"], value)
              }
            />
            <ToggleField
              label="Gigawords"
              checked={
                settings.radius?.accounting_counters?.gigawords_enabled !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_counters", "gigawords_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Reset Detection"
              checked={
                settings.radius?.accounting_counters
                  ?.reset_detection_enabled !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "accounting_counters",
                    "reset_detection_enabled",
                  ],
                  value,
                )
              }
            />
            <SelectField
              label="Max Counter Bits"
              value={String(
                settings.radius?.accounting_counters?.max_counter_bits || 64,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_counters", "max_counter_bits"],
                  Number(value),
                )
              }
              options={[
                { value: "64", label: "64-bit" },
                { value: "32", label: "32-bit" },
              ]}
            />
            <SelectField
              label="Overflow Policy"
              value={
                settings.radius?.accounting_counters?.overflow_policy ||
                "saturate"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_counters", "overflow_policy"],
                  value,
                )
              }
              options={[
                { value: "saturate", label: "Saturate" },
                { value: "reject", label: "Reject" },
              ]}
            />
            <TextField
              label="Evidence Retention (d)"
              type="number"
              value={settings.radius?.accounting_counters?.retention_days || 365}
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_counters", "retention_days"],
                  Number(value),
                )
              }
            />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-4">
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Status
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingCountersReport?.status || "unknown"}
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Evidence
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingCountersReport?.summary?.event_rows || 0} events,{" "}
                {accountingCountersReport?.summary?.gigaword_rows || 0} rows
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Recovery
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingCountersReport?.summary?.rollover_events || 0} roll,{" "}
                {accountingCountersReport?.summary?.reset_events || 0} reset
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Maximums
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                in {accountingCountersReport?.summary?.max_input_octets_64 || "0"}{" "}
                / out{" "}
                {accountingCountersReport?.summary?.max_output_octets_64 || "0"}
              </div>
            </div>
          </div>
          {accountingCountersReport?.message && (
            <p className="mt-2 text-xs text-gray-500">
              {accountingCountersReport.message}
            </p>
          )}
          {(accountingCountersReport?.warnings || []).length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-amber-700">
              {(accountingCountersReport?.warnings || []).map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          )}
        </div>
        <div className="mt-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <h4 className="text-sm font-semibold text-gray-900">
                IPv6 And Route Accounting
              </h4>
              <p className="mt-1 text-xs text-gray-500">
                Track IPv6 addresses, delegated prefixes, and framed routes from
                accounting packets.
              </p>
            </div>
            <button
              type="button"
              onClick={loadAccountingIPReport}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Refresh Assignments
            </button>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Assignment Tracking"
              checked={settings.radius?.accounting_ip?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "accounting_ip", "enabled"], value)
              }
            />
            <ToggleField
              label="IPv6 Attributes"
              checked={settings.radius?.accounting_ip?.ipv6_enabled !== false}
              onChange={(value) =>
                updateField(["radius", "accounting_ip", "ipv6_enabled"], value)
              }
            />
            <ToggleField
              label="Delegated Prefix"
              checked={
                settings.radius?.accounting_ip?.delegated_prefix_enabled !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_ip", "delegated_prefix_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Route Attributes"
              checked={
                settings.radius?.accounting_ip?.route_accounting_enabled !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_ip", "route_accounting_enabled"],
                  value,
                )
              }
            />
            <ToggleField
              label="Reject Invalid"
              checked={Boolean(settings.radius?.accounting_ip?.reject_invalid)}
              onChange={(value) =>
                updateField(["radius", "accounting_ip", "reject_invalid"], value)
              }
            />
            <TextField
              label="Evidence Retention (d)"
              type="number"
              value={settings.radius?.accounting_ip?.retention_days || 365}
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_ip", "retention_days"],
                  Number(value),
                )
              }
            />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-5">
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Status
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingIPReport?.status || "unknown"}
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Assignments
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingIPReport?.summary?.assignment_rows || 0} total,{" "}
                {accountingIPReport?.summary?.active_assignments || 0} active
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                IPv6
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingIPReport?.summary?.ipv6_address_rows || 0} address,{" "}
                {accountingIPReport?.summary?.ipv6_prefix_rows || 0} prefix
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Delegated
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingIPReport?.summary?.delegated_prefix_rows || 0} prefix
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Routes
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingIPReport?.summary?.ipv4_route_rows || 0} IPv4,{" "}
                {accountingIPReport?.summary?.ipv6_route_rows || 0} IPv6,{" "}
                {accountingIPReport?.summary?.invalid_rows || 0} invalid
              </div>
            </div>
          </div>
          {accountingIPReport?.message && (
            <p className="mt-2 text-xs text-gray-500">
              {accountingIPReport.message}
            </p>
          )}
          {(accountingIPReport?.warnings || []).length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-amber-700">
              {(accountingIPReport?.warnings || []).map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          )}
        </div>
        <div className="mt-4">
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <h4 className="text-sm font-semibold text-gray-900">
                Multi-Service Accounting
              </h4>
              <p className="mt-1 text-xs text-gray-500">
                Correlate parent sessions, service legs, bearers, calls, VPN
                legs, and subscriber chain accounting evidence.
              </p>
            </div>
            <button
              type="button"
              onClick={loadAccountingServicesReport}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
            >
              Refresh Services
            </button>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Correlation Engine"
              checked={settings.radius?.accounting_services?.enabled !== false}
              onChange={(value) =>
                updateField(["radius", "accounting_services", "enabled"], value)
              }
            />
            <ToggleField
              label="Subscriber Chains"
              checked={
                settings.radius?.accounting_services
                  ?.correlate_subscriber_chains !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "accounting_services",
                    "correlate_subscriber_chains",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Class Metadata"
              checked={
                settings.radius?.accounting_services?.derive_from_class !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_services", "derive_from_class"],
                  value,
                )
              }
            />
            <ToggleField
              label="Multi-Session ID"
              checked={
                settings.radius?.accounting_services
                  ?.derive_from_acct_multi_session_id !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "accounting_services",
                    "derive_from_acct_multi_session_id",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Retain Unmatched"
              checked={
                settings.radius?.accounting_services?.retain_unmatched !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_services", "retain_unmatched"],
                  value,
                )
              }
            />
            <TextField
              label="Evidence Retention (d)"
              type="number"
              value={
                settings.radius?.accounting_services?.retention_days || 365
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_services", "retention_days"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Recent Services"
              type="number"
              value={
                settings.radius?.accounting_services?.max_recent_services || 25
              }
              onChange={(value) =>
                updateField(
                  ["radius", "accounting_services", "max_recent_services"],
                  Number(value),
                )
              }
            />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-5">
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Status
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingServicesReport?.status || "unknown"}
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Correlations
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingServicesReport?.summary?.correlation_rows || 0} total,{" "}
                {accountingServicesReport?.summary?.active_correlations || 0} active
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Services
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingServicesReport?.summary?.data_services || 0} data,{" "}
                {accountingServicesReport?.summary?.voice_services || 0} voice
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Subscriber Links
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingServicesReport?.summary
                  ?.linked_subscriber_services || 0} linked,{" "}
                {accountingServicesReport?.summary
                  ?.unmatched_correlations || 0} unmatched
              </div>
            </div>
            <div className="rounded-md border border-gray-200 px-3 py-2">
              <div className="text-xs font-semibold uppercase text-gray-500">
                Legs
              </div>
              <div className="mt-1 text-sm font-semibold text-gray-900">
                {accountingServicesReport?.summary?.bearer_leg_rows || 0} bearer,{" "}
                {accountingServicesReport?.summary?.call_leg_rows || 0} call,{" "}
                {accountingServicesReport?.summary?.conflict_correlations || 0} conflict
              </div>
            </div>
          </div>
          {accountingServicesReport?.message && (
            <p className="mt-2 text-xs text-gray-500">
              {accountingServicesReport.message}
            </p>
          )}
          {(accountingServicesReport?.warnings || []).length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-amber-700">
              {(accountingServicesReport?.warnings || []).map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          )}
        </div>
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-gray-900">
            Accounting Spool
          </h4>
          <div className="mt-3 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <ToggleField
              label="Durable Spool"
              checked={
                settings.radius?.upstream?.accounting_spool?.enabled !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "accounting_spool", "enabled"],
                  value,
                )
              }
            />
            <TextField
              label="Queue Records"
              type="number"
              value={
                settings.radius?.upstream?.accounting_spool
                  ?.max_queue_records || 10000
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "accounting_spool",
                    "max_queue_records",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Attempts"
              type="number"
              value={
                settings.radius?.upstream?.accounting_spool?.max_attempts || 10
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "accounting_spool", "max_attempts"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Batch Size"
              type="number"
              value={
                settings.radius?.upstream?.accounting_spool?.batch_size || 100
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "accounting_spool", "batch_size"],
                  Number(value),
                )
              }
            />
            <TextField
              label="Initial Retry (s)"
              type="number"
              value={
                settings.radius?.upstream?.accounting_spool
                  ?.initial_retry_seconds || 30
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "accounting_spool",
                    "initial_retry_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Max Retry (s)"
              type="number"
              value={
                settings.radius?.upstream?.accounting_spool
                  ?.max_retry_seconds || 3600
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "accounting_spool",
                    "max_retry_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Record TTL (s)"
              type="number"
              value={
                settings.radius?.upstream?.accounting_spool
                  ?.record_ttl_seconds || 604800
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "accounting_spool",
                    "record_ttl_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Replay Interval (s)"
              type="number"
              value={
                settings.radius?.upstream?.accounting_spool
                  ?.replay_interval_seconds || 60
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "accounting_spool",
                    "replay_interval_seconds",
                  ],
                  Number(value),
                )
              }
            />
          </div>
        </div>
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-gray-900">
            Outage Fallback Policy
          </h4>
          <div className="mt-3 grid gap-3 md:grid-cols-2 lg:grid-cols-5">
            <ToggleField
              label="Policy Enabled"
              checked={
                settings.radius?.upstream?.fallback_policy?.enabled !== false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "enabled"],
                  value,
                )
              }
            />
            <SelectField
              label="Mode"
              value={
                settings.radius?.upstream?.fallback_policy?.mode || "monitor"
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "mode"],
                  value,
                )
              }
              options={transportPolicyModeOptions}
            />
            <ToggleField
              label="Fail Closed"
              checked={
                settings.radius?.upstream?.fallback_policy?.fail_closed !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "fail_closed"],
                  value,
                )
              }
            />
            <ToggleField
              label="Allow Local Users"
              checked={
                settings.radius?.upstream?.fallback_policy
                  ?.allow_portal_local !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "fallback_policy",
                    "allow_portal_local",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Allow LDAP"
              checked={Boolean(
                settings.radius?.upstream?.fallback_policy?.allow_ldap,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "allow_ldap"],
                  value,
                )
              }
            />
            <ToggleField
              label="Require Allowlist"
              checked={
                settings.radius?.upstream?.fallback_policy
                  ?.require_identity_allowlist !== false
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "fallback_policy",
                    "require_identity_allowlist",
                  ],
                  value,
                )
              }
            />
            <ToggleField
              label="Audit Decisions"
              checked={
                settings.radius?.upstream?.fallback_policy?.audit_enabled !==
                false
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "audit_enabled"],
                  value,
                )
              }
            />
            <TextField
              label="Max Outage (s)"
              type="number"
              value={
                settings.radius?.upstream?.fallback_policy
                  ?.max_outage_seconds || 900
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "fallback_policy",
                    "max_outage_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Stale Policy (s)"
              type="number"
              value={
                settings.radius?.upstream?.fallback_policy
                  ?.stale_policy_seconds || 3600
              }
              onChange={(value) =>
                updateField(
                  [
                    "radius",
                    "upstream",
                    "fallback_policy",
                    "stale_policy_seconds",
                  ],
                  Number(value),
                )
              }
            />
            <TextField
              label="Retention Rows"
              type="number"
              value={
                settings.radius?.upstream?.fallback_policy?.retention_limit ||
                6000
              }
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "retention_limit"],
                  Number(value),
                )
              }
            />
          </div>
          <div className="mt-3 grid gap-4 md:grid-cols-3">
            <TextField
              label="Allowed Users"
              value={listToCSV(
                settings.radius?.upstream?.fallback_policy?.allowed_users,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "allowed_users"],
                  csvToList(value),
                )
              }
              placeholder="breakglass@example.com"
            />
            <TextField
              label="Allowed Realms"
              value={listToCSV(
                settings.radius?.upstream?.fallback_policy?.allowed_realms,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "allowed_realms"],
                  csvToList(value),
                )
              }
              placeholder="guest.example.com"
            />
            <TextField
              label="Allowed Roles"
              value={listToCSV(
                settings.radius?.upstream?.fallback_policy?.allowed_roles,
              )}
              onChange={(value) =>
                updateField(
                  ["radius", "upstream", "fallback_policy", "allowed_roles"],
                  csvToList(value),
                )
              }
              placeholder="guest-basic"
            />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Enforce mode denies local or LDAP fallback unless the identity
            source, allowlist, and outage window all match.
          </p>
        </div>
        <div className="mt-4 space-y-4">
          {upstreamServers.length === 0 ? (
            <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
              Primary and secondary AAA servers live here.
            </div>
          ) : (
            upstreamServers.map((server: JsonMap, index: number) => (
              <div
                key={`server-${index}`}
                className="rounded-lg border border-gray-200 p-4"
              >
                <div className="mb-3 flex items-center justify-between">
                  <h4 className="font-semibold text-gray-900">
                    Server {index + 1}
                  </h4>
                  <button
                    onClick={() =>
                      updateField(
                        ["radius", "upstream", "servers"],
                        upstreamServers.filter(
                          (_: unknown, itemIndex: number) =>
                            itemIndex !== index,
                        ),
                      )
                    }
                    className="text-sm font-medium text-red-700"
                  >
                    Remove
                  </button>
                </div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                  <TextField
                    label="Name"
                    value={server.name || ""}
                    onChange={(value) =>
                      updateField(
                        [
                          "radius",
                          "upstream",
                          "servers",
                          String(index),
                          "name",
                        ],
                        value,
                      )
                    }
                  />
                  <TextField
                    label="Address"
                    value={server.address || ""}
                    onChange={(value) =>
                      updateField(
                        [
                          "radius",
                          "upstream",
                          "servers",
                          String(index),
                          "address",
                        ],
                        value,
                      )
                    }
                  />
                  <SelectField
                    label="Transport"
                    value={server.transport || "udp"}
                    onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "transport"], value)}
                    options={[{ value: "udp", label: "RADIUS / UDP" }, { value: "radsec", label: "RadSec / TLS" }]}
                  />
                  {server.transport !== "radsec" ? <>
                  <TextField
                    label="Auth Port"
                    type="number"
                    value={server.auth_port || 1812}
                    onChange={(value) =>
                      updateField(
                        [
                          "radius",
                          "upstream",
                          "servers",
                          String(index),
                          "auth_port",
                        ],
                        Number(value),
                      )
                    }
                  />
                  <TextField
                    label="Acct Port"
                    type="number"
                    value={server.acct_port || 1813}
                    onChange={(value) =>
                      updateField(
                        [
                          "radius",
                          "upstream",
                          "servers",
                          String(index),
                          "acct_port",
                        ],
                        Number(value),
                      )
                    }
                  />
                  <TextField
                    label="Secret"
                    type="password"
                    value={server.secret || ""}
                    onChange={(value) =>
                      updateField(
                        [
                          "radius",
                          "upstream",
                          "servers",
                          String(index),
                          "secret",
                        ],
                        value,
                      )
                    }
                  />
                  </> : <>
                    <TextField label="RadSec Port" type="number" value={server.radsec?.port || 2083} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "port"], Number(value))} />
                    <TextField label="Verified Server Name" value={server.radsec?.server_name || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "server_name"], value)} />
                    <ToggleField label="TLS-PSK" checked={Boolean(server.radsec?.psk?.enabled)} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "enabled"], value)} />
                    {server.radsec?.psk?.enabled ? <>
                      <TextField label="PSK Identity" value={server.radsec?.psk?.identity || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "identity"], value)} />
                      <TextField label="PSK Secret Ref" value={server.radsec?.psk?.secret_ref || ""} placeholder="env:AEGIS_RADSEC_PSK_CURRENT" onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "secret_ref"], value)} />
                      <TextField label="Next PSK Identity" value={server.radsec?.psk?.next_identity || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "next_identity"], value)} />
                      <TextField label="Next PSK Secret Ref" value={server.radsec?.psk?.next_secret_ref || ""} placeholder="env:AEGIS_RADSEC_PSK_NEXT" onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "next_secret_ref"], value)} />
                      <TextField label="Next PSK Not Before" value={server.radsec?.psk?.next_not_before || ""} placeholder="2026-08-01T00:00:00Z" onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "next_not_before"], value)} />
                      <TextField label="Next PSK Not After" value={server.radsec?.psk?.next_not_after || ""} placeholder="2026-08-08T00:00:00Z" onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "next_not_after"], value)} />
                      <TextField label="PSK Overlap (s)" type="number" value={server.radsec?.psk?.overlap_seconds || 86400} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "overlap_seconds"], Number(value))} />
                      <TextField label="PSK Warning (days)" type="number" value={server.radsec?.psk?.warning_days || 30} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "psk", "warning_days"], Number(value))} />
                    </> : null}
                    {!server.radsec?.psk?.enabled ? <>
                      <TextField label="Client Certificate" value={server.radsec?.certificate_file || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "certificate_file"], value)} />
                      <TextField label="Client Private Key" value={server.radsec?.private_key_file || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "private_key_file"], value)} />
                      <TextField label="Key Password Environment" value={server.radsec?.private_key_password_env || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "private_key_password_env"], value)} />
                      <TextField label="Trusted CA File" value={server.radsec?.ca_file || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "ca_file"], value)} />
                      <TextField label="Trusted CA Path" value={server.radsec?.ca_path || ""} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "ca_path"], value)} />
                    </> : null}
                    <SelectField label="RADIUS Version" value={server.radsec?.radius_v11 || "forbid"} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "radius_v11"], value)} options={[{ value: "forbid", label: "RADIUS/1.0" }, { value: "allow", label: "Allow RADIUS/1.1" }, { value: "require", label: "Require RADIUS/1.1" }]} />
                    <SelectField label="TLS Minimum" value={server.radsec?.tls_min_version || "1.2"} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "tls_min_version"], value)} options={[{ value: "1.2", label: "TLS 1.2" }, { value: "1.3", label: "TLS 1.3" }]} />
                    <SelectField label="TLS Maximum" value={server.radsec?.tls_max_version || "1.3"} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "tls_max_version"], value)} options={[{ value: "1.2", label: "TLS 1.2" }, { value: "1.3", label: "TLS 1.3" }]} />
                    {!server.radsec?.psk?.enabled ? <ToggleField label="CRL Validation" checked={Boolean(server.radsec?.check_crl)} onChange={(value) => updateField(["radius", "upstream", "servers", String(index), "radsec", "check_crl"], value)} /> : null}
                  </>}
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              Wireless Radio And SSIDs
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              Use on appliance radios or passthrough Wi-Fi hardware. The preview
              below is ready for hostapd.
            </p>
          </div>
          <button
            onClick={() =>
              updateField(
                ["wireless", "ssids"],
                [
                  ...ssids,
                  {
                    name: "",
                    auth_mode: "captive-portal",
                    passphrase: "",
                    vlan: 0,
                    bridge: "",
                    hidden: false,
                    client_isolation: true,
                    max_clients: 0,
                    dynamic_vlan: false,
                    portal_profile: "",
                    identity_source: "",
                    bandwidth_profile: "",
                  },
                ],
              )
            }
            className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
          >
            Add SSID
          </button>
        </div>
        <div className="mb-4 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <ToggleField
            label="Wireless Enabled"
            checked={Boolean(settings.wireless?.enabled)}
            onChange={(value) => updateField(["wireless", "enabled"], value)}
          />
          <TextField
            label="Country Code"
            value={settings.wireless?.country_code || ""}
            onChange={(value) =>
              updateField(["wireless", "country_code"], value)
            }
          />
          <TextField
            label="Radio Interface"
            value={settings.wireless?.interface || ""}
            onChange={(value) => updateField(["wireless", "interface"], value)}
            placeholder="wlan0"
          />
          <TextField
            label="Driver"
            value={settings.wireless?.driver || ""}
            onChange={(value) => updateField(["wireless", "driver"], value)}
          />
          <SelectField
            label="HW Mode"
            value={settings.wireless?.hw_mode || "g"}
            onChange={(value) => updateField(["wireless", "hw_mode"], value)}
            options={[
              { value: "g", label: "2.4 GHz (802.11g/n)" },
              { value: "a", label: "5 GHz (802.11a/n/ac)" },
              { value: "b", label: "Legacy 802.11b" },
            ]}
          />
          <TextField
            label="Channel"
            type="number"
            value={settings.wireless?.channel || 6}
            onChange={(value) =>
              updateField(["wireless", "channel"], Number(value))
            }
          />
          <TextField
            label="Beacon Interval"
            type="number"
            value={settings.wireless?.beacon_interval || 100}
            onChange={(value) =>
              updateField(["wireless", "beacon_interval"], Number(value))
            }
          />
          <TextField
            label="hostapd Path"
            value={settings.wireless?.hostapd_config_path || ""}
            onChange={(value) =>
              updateField(["wireless", "hostapd_config_path"], value)
            }
          />
        </div>
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <ToggleField
            label="WMM Enabled"
            checked={Boolean(settings.wireless?.wmm_enabled)}
            onChange={(value) =>
              updateField(["wireless", "wmm_enabled"], value)
            }
          />
          <ToggleField
            label="HT Enabled"
            checked={Boolean(settings.wireless?.ht_enabled)}
            onChange={(value) => updateField(["wireless", "ht_enabled"], value)}
          />
          <TextField
            label="Control Socket"
            value={settings.wireless?.ctrl_interface || ""}
            onChange={(value) =>
              updateField(["wireless", "ctrl_interface"], value)
            }
          />
        </div>
        <div className="space-y-4">
          {ssids.length === 0 ? (
            <div className="rounded-md border border-dashed border-gray-300 px-4 py-6 text-sm text-gray-500">
              Open, captive portal, WPA2, and WPA3 SSIDs can all live on this
              radio.
            </div>
          ) : (
            ssids.map((ssid: JsonMap, index: number) => (
              <div
                key={`ssid-${index}`}
                className="rounded-lg border border-gray-200 p-4"
              >
                <div className="mb-3 flex items-center justify-between">
                  <h4 className="font-semibold text-gray-900">
                    {ssid.name || `SSID ${index + 1}`}
                  </h4>
                  <button
                    onClick={() =>
                      updateField(
                        ["wireless", "ssids"],
                        ssids.filter(
                          (_: unknown, itemIndex: number) =>
                            itemIndex !== index,
                        ),
                      )
                    }
                    className="text-sm font-medium text-red-700"
                  >
                    Remove
                  </button>
                </div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                  <TextField
                    label="SSID Name"
                    value={ssid.name || ""}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "name"],
                        value,
                      )
                    }
                  />
                  <SelectField
                    label="Auth Mode"
                    value={ssid.auth_mode || "captive-portal"}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "auth_mode"],
                        value,
                      )
                    }
                    options={[
                      { value: "captive-portal", label: "Captive Portal" },
                      { value: "open", label: "Open" },
                      { value: "wpa2-personal", label: "WPA2 Personal" },
                      { value: "wpa2-enterprise", label: "WPA2 Enterprise" },
                      { value: "wpa3-personal", label: "WPA3 Personal" },
                      { value: "wpa3-enterprise", label: "WPA3 Enterprise" },
                    ]}
                  />
                  <TextField
                    label="Passphrase"
                    type="password"
                    value={ssid.passphrase || ""}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "passphrase"],
                        value,
                      )
                    }
                  />
                  <TextField
                    label="Bridge"
                    value={ssid.bridge || ""}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "bridge"],
                        value,
                      )
                    }
                    placeholder="br-guest"
                  />
                  <TextField
                    label="VLAN"
                    type="number"
                    value={ssid.vlan || 0}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "vlan"],
                        Number(value),
                      )
                    }
                  />
                  <SelectField
                    label="Portal Profile"
                    value={ssid.portal_profile || ""}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "portal_profile"],
                        value,
                      )
                    }
                    options={[
                      { value: "", label: "No portal profile override" },
                      ...portalProfiles,
                    ]}
                  />
                  <SelectField
                    label="Identity Source"
                    value={ssid.identity_source || ""}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "identity_source"],
                        value,
                      )
                    }
                    options={[
                      { value: "", label: "Use portal default" },
                      ...identitySources,
                    ]}
                  />
                  <SelectField
                    label="Bandwidth Profile"
                    value={ssid.bandwidth_profile || ""}
                    onChange={(value) =>
                      updateField(
                        [
                          "wireless",
                          "ssids",
                          String(index),
                          "bandwidth_profile",
                        ],
                        value,
                      )
                    }
                    options={[
                      { value: "", label: "No bandwidth override" },
                      ...bandwidthProfiles,
                    ]}
                  />
                  <TextField
                    label="Max Clients"
                    type="number"
                    value={ssid.max_clients || 0}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "max_clients"],
                        Number(value),
                      )
                    }
                  />
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <ToggleField
                    label="Hidden"
                    checked={Boolean(ssid.hidden)}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "hidden"],
                        value,
                      )
                    }
                  />
                  <ToggleField
                    label="Client Isolation"
                    checked={Boolean(ssid.client_isolation)}
                    onChange={(value) =>
                      updateField(
                        [
                          "wireless",
                          "ssids",
                          String(index),
                          "client_isolation",
                        ],
                        value,
                      )
                    }
                  />
                  <ToggleField
                    label="Dynamic VLAN"
                    checked={Boolean(ssid.dynamic_vlan)}
                    onChange={(value) =>
                      updateField(
                        ["wireless", "ssids", String(index), "dynamic_vlan"],
                        value,
                      )
                    }
                  />
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="rounded-lg bg-white p-6 shadow">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              hostapd Preview
            </h3>
            <p className="mt-1 text-sm text-gray-600">
              {hostapdPath ||
                "Choose a path and write the file when the radio is ready."}
            </p>
          </div>
          <button
            onClick={loadSettings}
            className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700"
          >
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
