import type { Page, Route } from "@playwright/test";

type AuthIdentity = {
  subject: string;
  display_name?: string;
  role: string;
  source: string;
  tenants?: string[];
  permissions: string[];
  break_glass: boolean;
};

type GuestRecord = {
  id: string;
  full_name: string;
  company?: string;
  email?: string;
  phone?: string;
  sponsor_name?: string;
  sponsor_email?: string;
  sponsor_phone?: string;
  status: string;
  rejection_reason?: string;
  approval_delivery_status?: string;
  approval_delivery_error?: string;
  invite_delivery_status?: string;
  invite_delivery_error?: string;
  created_at: string;
  approved_at?: string;
  rejected_at?: string;
  completed_at?: string;
  role?: string;
  approved_by?: string;
};

type MockOptions = {
  authOptions?: Record<string, any>;
  identity?: AuthIdentity;
  guestRegistrations?: GuestRecord[];
};

function createVouchers() {
  return [
    {
      id: 1,
      code: "V-001",
      role: "guest-basic",
      duration_minutes: 1440,
      usage_limit: 1,
      used_count: 0,
      expires_at: "2026-06-04T12:00:00Z",
    },
    {
      id: 2,
      code: "V-002",
      role: "guest-basic",
      duration_minutes: 720,
      usage_limit: 5,
      used_count: 2,
      expires_at: "2026-06-03T12:00:00Z",
    },
    {
      id: 3,
      code: "V-003",
      role: "guest-vip",
      duration_minutes: 60,
      usage_limit: 2,
      used_count: 2,
      expires_at: "2026-06-03T12:00:00Z",
    },
    {
      id: 4,
      code: "V-004",
      role: "guest-basic",
      duration_minutes: 1440,
      usage_limit: 1,
      used_count: 0,
      expires_at: "2026-06-01T08:00:00Z",
    },
    {
      id: 5,
      code: "V-005",
      role: "guest-standard",
      duration_minutes: 30,
      usage_limit: 3,
      used_count: 3,
      expires_at: "2026-06-02T11:00:00Z",
    },
  ];
}

function buildVoucherAnalyticsResponse() {
  return {
    generated_at: "2026-06-02T12:00:00Z",
    window_hours: 720,
    bucket_count: 30,
    summary: {
      window_hours: 720,
      bucket_count: 30,
      bucket_minutes: 1440,
      total_vouchers: 5,
      created_in_window_count: 5,
      active_count: 2,
      exhausted_count: 1,
      expired_count: 2,
      expired_unused_count: 1,
      unused_count: 2,
      partially_used_count: 1,
      fully_used_count: 2,
      expiring_24_hours_count: 2,
      expiring_7_days_count: 2,
      total_issued_uses: 12,
      total_used_uses: 7,
      active_remaining_uses: 4,
      utilization_percent: 58,
      avg_duration_minutes: 738,
      max_duration_minutes: 1440,
      latest_created_at: "2026-06-02T09:00:00Z",
      roles: [
        { name: "guest-basic", count: 3 },
        { name: "guest-standard", count: 1 },
        { name: "guest-vip", count: 1 },
      ],
      states: [
        { name: "active", count: 2 },
        { name: "expired", count: 2 },
        { name: "exhausted", count: 1 },
      ],
      buckets: [
        {
          start: "2026-05-03T12:00:00Z",
          end: "2026-05-04T12:00:00Z",
          created_count: 0,
          active_count: 0,
          exhausted_count: 0,
          expired_count: 0,
          unused_count: 0,
        },
        {
          start: "2026-05-31T12:00:00Z",
          end: "2026-06-01T12:00:00Z",
          created_count: 2,
          active_count: 0,
          exhausted_count: 1,
          expired_count: 1,
          unused_count: 1,
        },
        {
          start: "2026-06-01T12:00:00Z",
          end: "2026-06-02T12:00:00Z",
          created_count: 3,
          active_count: 2,
          exhausted_count: 0,
          expired_count: 1,
          unused_count: 1,
        },
      ],
    },
  };
}

function buildVoucherAgingAnalyticsResponse() {
  return {
    generated_at: "2026-06-02T12:00:00Z",
    window_hours: 720,
    bucket_count: 30,
    summary: {
      window_hours: 720,
      bucket_count: 30,
      bucket_minutes: 1440,
      total_vouchers: 5,
      within_window_count: 4,
      older_than_window_count: 1,
      unused_within_window_count: 1,
      unused_older_than_window_count: 1,
      active_older_than_window_count: 0,
      exhausted_older_than_window_count: 0,
      expired_older_than_window_count: 1,
      remaining_uses_older_than_window: 0,
      unused_older_24_hours_count: 2,
      unused_older_7_days_count: 1,
      unused_older_30_days_count: 1,
      avg_age_minutes: 9960,
      max_age_minutes: 46080,
      avg_unused_age_minutes: 24120,
      max_unused_age_minutes: 46080,
      newest_created_at: "2026-06-02T09:00:00Z",
      oldest_created_at: "2026-05-01T12:00:00Z",
      oldest_unused_created_at: "2026-05-01T12:00:00Z",
      older_roles: [{ name: "guest-standard", count: 1 }],
      unused_older_roles: [{ name: "guest-standard", count: 1 }],
      buckets: [
        {
          min_age_minutes: 0,
          max_age_minutes: 1440,
          voucher_count: 1,
          unused_count: 1,
          active_count: 1,
          exhausted_count: 0,
          expired_count: 0,
          remaining_uses: 1,
        },
        {
          min_age_minutes: 1440,
          max_age_minutes: 4320,
          voucher_count: 1,
          unused_count: 0,
          active_count: 1,
          exhausted_count: 0,
          expired_count: 0,
          remaining_uses: 3,
        },
        {
          min_age_minutes: 4320,
          max_age_minutes: 10080,
          voucher_count: 2,
          unused_count: 0,
          active_count: 0,
          exhausted_count: 1,
          expired_count: 1,
          remaining_uses: 0,
        },
      ],
    },
  };
}

function buildVoucherRedemptionAnalyticsResponse() {
  return {
    generated_at: "2026-06-02T12:00:00Z",
    window_hours: 720,
    bucket_count: 30,
    summary: {
      window_hours: 720,
      bucket_count: 30,
      bucket_minutes: 1440,
      total_vouchers: 5,
      redeemed_voucher_count: 3,
      never_redeemed_count: 2,
      redeemed_in_window_count: 3,
      first_redeemed_in_window_count: 2,
      redeemed_once_count: 2,
      redeemed_repeat_count: 1,
      session_start_count: 4,
      ended_session_count: 3,
      active_session_count: 1,
      active_voucher_count: 1,
      redeemed_within_24_hours_count: 2,
      redeemed_within_7_days_count: 3,
      avg_sessions_per_redeemed_voucher: 1.33,
      avg_first_redemption_delay_minutes: 58,
      max_first_redemption_delay_minutes: 180,
      ended_traffic_total: 1625,
      avg_ended_session_seconds: 1100,
      max_ended_session_seconds: 1800,
      latest_session_start_at: "2026-06-02T10:00:00Z",
      roles: [
        { name: "guest-basic", count: 2 },
        { name: "guest-vip", count: 1 },
      ],
      buckets: [
        {
          start: "2026-05-31T12:00:00Z",
          end: "2026-06-01T12:00:00Z",
          session_start_count: 1,
          unique_voucher_count: 1,
          first_redeemed_count: 1,
          ended_count: 1,
          ended_traffic_total: 125,
        },
        {
          start: "2026-06-01T12:00:00Z",
          end: "2026-06-02T12:00:00Z",
          session_start_count: 3,
          unique_voucher_count: 3,
          first_redeemed_count: 2,
          ended_count: 2,
          ended_traffic_total: 1500,
        },
      ],
    },
  };
}

function buildVoucherExpiryAnalyticsResponse() {
  return {
    generated_at: "2026-06-02T12:00:00Z",
    window_hours: 720,
    bucket_count: 30,
    summary: {
      window_hours: 720,
      bucket_count: 30,
      bucket_minutes: 1440,
      total_vouchers: 5,
      active_with_expiry_count: 3,
      no_expiry_count: 1,
      expired_count: 1,
      expired_unused_count: 1,
      expired_used_count: 0,
      expiring_24_hours_count: 1,
      expiring_7_days_count: 3,
      expiring_in_window_count: 4,
      unused_expiring_in_window_count: 2,
      active_expiring_in_window_count: 3,
      exhausted_expiring_in_window_count: 1,
      total_remaining_uses_expiring_in_window: 4,
      avg_hours_until_expiry: 87,
      max_hours_until_expiry: 168,
      avg_expired_hours_ago: 6,
      max_expired_hours_ago: 6,
      soonest_expiry_at: "2026-06-02T18:00:00Z",
      latest_expiry_in_window_at: "2026-06-09T12:00:00Z",
      roles: [
        { name: "guest-basic", count: 3 },
        { name: "guest-vip", count: 1 },
      ],
      unused_roles: [{ name: "guest-basic", count: 2 }],
      states: [
        { name: "active", count: 3 },
        { name: "exhausted", count: 1 },
      ],
      buckets: [
        {
          start: "2026-06-02T12:00:00Z",
          end: "2026-06-03T12:00:00Z",
          expiring_count: 1,
          unused_expiring_count: 1,
          active_expiring_count: 1,
          exhausted_expiring_count: 0,
          remaining_uses: 1,
        },
        {
          start: "2026-06-03T12:00:00Z",
          end: "2026-06-04T12:00:00Z",
          expiring_count: 1,
          unused_expiring_count: 0,
          active_expiring_count: 1,
          exhausted_expiring_count: 0,
          remaining_uses: 3,
        },
        {
          start: "2026-06-04T12:00:00Z",
          end: "2026-06-05T12:00:00Z",
          expiring_count: 1,
          unused_expiring_count: 0,
          active_expiring_count: 0,
          exhausted_expiring_count: 1,
          remaining_uses: 0,
        },
        {
          start: "2026-06-08T12:00:00Z",
          end: "2026-06-09T12:00:00Z",
          expiring_count: 1,
          unused_expiring_count: 1,
          active_expiring_count: 1,
          exhausted_expiring_count: 0,
          remaining_uses: 0,
        },
      ],
    },
  };
}

const SUPER_ADMIN: AuthIdentity = {
  subject: "admin-1",
  display_name: "Aegis Admin",
  role: "super_admin",
  source: "token",
  tenants: ["default"],
  permissions: ["*"],
  break_glass: true,
};

function createSettings() {
  return {
    mode: "two-nic",
    admin_port: 8083,
    deployment: {
      profile: "branch",
      form: "virtual",
      hardware: {
        memory_mb: 8192,
        cpu_cores: 4,
        prefer_external_ap: true,
        wireless_passthrough: false,
      },
    },
    wan: {
      name: "ens33",
      dhcp: true,
      address: "",
      gateway: "",
      dhcp_range: "",
    },
    lan: {
      name: "ens37",
      dhcp: false,
      address: "192.168.50.1/24",
      gateway: "",
      dhcp_range: "192.168.50.100,192.168.50.200,12h",
    },
    network: {
      interfaces: [],
      gateways: [
        {
          name: "wan-default",
          address: "10.0.0.1",
          interface: "ens33",
          metric: 10,
        },
      ],
      dns: {
        upstream_servers: ["8.8.8.8", "8.8.4.4"],
        search_domains: ["corp.example"],
        local_domain: "aegis.local",
      },
      static_routes: [
        {
          name: "branch-a",
          destination: "172.16.20.0/24",
          gateway: "10.0.0.254",
          interface: "ens33",
          metric: 20,
        },
      ],
      firewall: {
        rules: [
          {
            name: "allow-admin",
            action: "allow",
            source: "192.168.50.0/24",
            destination: "0.0.0.0/0",
            protocol: "tcp",
            ports: "8083",
            enabled: true,
          },
        ],
        free_sites: ["neverssl.com"],
        dos_protection: {
          enabled: true,
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
      static_leases: [
        {
          mac: "aa:bb:cc:dd:ee:ff",
          ip: "192.168.50.10",
          hostname: "lab-client",
          enabled: true,
          description: "Lab device",
        },
      ],
    },
    policy: { default_role: "guest-basic", runtime_shaping_enabled: true },
    telemetry: {
      enabled: true,
      prometheus_port: 9090,
      lease_history_poll_seconds: 300,
      diagnostics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/diagnostics",
        format: "both",
        interval_minutes: 60,
        retention_count: 14,
      },
      audit_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/audit-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      session_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/session-exports",
        format: "both",
        interval_minutes: 60,
        retention_count: 21,
      },
      session_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/session-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      voucher_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      voucher_aging_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-aging-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      voucher_redemption_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-redemption-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      voucher_expiry_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-expiry-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      guest_lifecycle_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-lifecycle-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      guest_invite_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-invite-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      guest_conversion_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-conversion-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      guest_rejection_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-rejection-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      guest_delivery_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-delivery-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      guest_delivery_failures_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-delivery-failures-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      guest_sponsor_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-sponsor-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      integration_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/integration-exports",
        format: "both",
        interval_minutes: 60,
        retention_count: 21,
      },
      ha_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/ha-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      network_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/network-exports",
        format: "both",
        interval_minutes: 60,
        retention_count: 21,
      },
      upstream_aaa_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/upstream-aaa-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
      },
      upgrade_readiness_exports: {
        enabled: true,
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
        enabled: true,
        provider: "oidc",
        issuer_url: "https://sso.example.test",
        client_id: "aegisnas-ui",
        client_secret_env: "AEGIS_SSO_SECRET",
        redirect_url: "http://127.0.0.1:4173/login",
        groups_claim: "groups",
        tenant_claim: "",
      },
      siem: {
        enabled: true,
        provider: "webhook",
        endpoint: "https://siem.example.test/events",
        api_key_env: "AEGIS_SIEM_API_KEY",
        batch_size: 100,
      },
      controller: {
        enabled: true,
        platform: "vendor-neutral",
        endpoint: "https://controller.example.test/api",
        api_token_env: "AEGIS_CONTROLLER_API_TOKEN",
        sync_mode: "monitor",
        site: "lab",
      },
    },
    governance: {
      delegated_admin_enabled: true,
      rbac_mode: "local",
      external_groups_enabled: false,
      multi_tenant_enabled: false,
      tenant_claim: "",
    },
    high_availability: {
      enabled: true,
      role: "standby",
      peer_api_url: "https://peer.example.test:8083",
      virtual_ip: "192.168.50.2",
      heartbeat_interval_seconds: 5,
      failover_timeout_seconds: 20,
      replication_interval_seconds: 300,
      replication_stale_after_seconds: 900,
      split_brain_protection_enabled: true,
      auto_stage_shared_package: true,
      auto_activate_on_failover: false,
      witness_api_url: "",
      witness_urls: [
        "https://witness-a.example.test/ha",
        "https://witness-b.example.test/ha",
      ],
      witness_quorum: 2,
      witness_weights: {
        "https://witness-a.example.test/ha": 2,
        "https://witness-b.example.test/ha": 1,
      },
      witness_weight_threshold: 2,
      witness_groups: {
        "https://witness-a.example.test/ha": "dc-a",
        "https://witness-b.example.test/ha": "dc-b",
      },
      witness_min_distinct_groups: 2,
      witness_required_groups: ["dc-a"],
      witness_sources: {
        "https://witness-a.example.test/ha": "local",
        "https://witness-b.example.test/ha": "external",
      },
      witness_source_confidence: {
        local: "critical",
        external: "advisory",
      },
      witness_required_sources: ["local", "external"],
      witness_required_urls: ["https://witness-a.example.test/ha"],
      witness_required_sources_by_tier: {
        critical: ["local"],
      },
      witness_required_urls_by_tier: {
        critical: ["https://witness-a.example.test/ha"],
      },
      witness_required_groups_by_tier: {
        critical: ["dc-a"],
      },
      witness_policy_mode: "all",
      witness_policy_mode_by_tier: {
        advisory: "any",
      },
      witness_failure_tolerance: 1,
      witness_failure_weight_tolerance: 1,
      witness_min_approvals_by_tier: {
        critical: 1,
      },
      witness_min_weight_by_tier: {
        critical: 2,
      },
      witness_min_distinct_groups_by_tier: {
        critical: 1,
      },
      witness_min_distinct_sources_by_tier: {
        critical: 1,
      },
      witness_max_age_by_tier: {
        critical: 10,
        advisory: 30,
      },
      witness_required_node_by_tier: {
        critical: "witness-a",
      },
      witness_signature_required_tiers: ["critical"],
      witness_replay_required_tiers: ["critical"],
      witness_failure_tolerance_by_tier: {
        advisory: 1,
      },
      witness_failure_weight_tolerance_by_tier: {
        advisory: 1,
      },
      witness_blocking_tiers: ["critical"],
      witness_token_env: "AEGIS_HA_WITNESS_TOKEN",
      witness_signing_key_env: "AEGIS_HA_WITNESS_SIGNING_KEY",
      witness_max_age_seconds: 30,
      witness_required_node: "witness-1",
      witness_replay_protection_enabled: true,
      preempt: false,
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
        self_registration_enabled: true,
        sponsor_approval_enabled: true,
        invite_delivery: "email",
        approval_delivery: "email",
        email_from: "guest@example.test",
        smtp_server: "smtp.example.test",
        smtp_port: 587,
        sms_provider: "",
        sms_endpoint: "",
      },
    },
    radius: {
      secret: "secret",
      auth_port: 1812,
      acct_port: 1813,
      max_sessions: 1024,
      cert_dir: "/etc/freeradius/3.0/certs",
      nas_identifier: "aegisnas",
      request_timeout_seconds: 5,
      interim_update_seconds: 300,
      dynamic_auth: { enabled: true, port: 3799 },
      vendor: {
        enabled: true,
        name: "AegisNAS",
        id: 55555,
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
      },
      upstream: {
        enabled: true,
        realm: "aegis-upstream",
        pool_strategy: "fail-over",
        status_check: "status-server",
        response_window: 20,
        zombie_period: 40,
        revive_interval: 120,
        check_interval: 30,
        num_answers_to_alive: 3,
        strip_realm: false,
        servers: [
          {
            name: "upstream-1",
            address: "10.0.0.20",
            auth_port: 1812,
            acct_port: 1813,
          },
        ],
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
}

function createDeploymentPreview() {
  return {
    profile: "branch",
    form: "virtual",
    label: "Branch Virtual Appliance",
    summary: "Balanced branch profile for a virtual appliance.",
    recommended_min_memory: 4096,
    recommended_min_cores: 2,
    hardware: {
      memory_mb: 8192,
      cpu_cores: 4,
      prefer_external_ap: true,
      wireless_passthrough: false,
    },
    warnings: [],
    capabilities: [
      {
        key: "runtime_shaping",
        label: "Runtime Shaping",
        state: "enabled",
        active: true,
        summary: "Runtime bandwidth shaping is ready.",
        recommendation: "",
        dependencies: [],
      },
    ],
  };
}

function createProductionReadiness() {
  return {
    generated_at: "2026-05-05T12:00:00Z",
    status: "blocked",
    ready: false,
    score: 75,
    message: "Production readiness is blocked by 1 required check(s).",
    deployment_profile: "branch",
    deployment_form: "virtual",
    blocking_count: 1,
    warning_count: 1,
    degraded_count: 0,
    passing_count: 6,
    checks: [
      {
        key: "vendor_identity",
        category: "vendor",
        label: "AegisNAS Vendor Identity",
        status: "blocked",
        summary:
          "AegisNAS product VSAs are enabled with the lab placeholder vendor ID 55555.",
        recommendation:
          "Request an IANA Private Enterprise Number before production VSA use.",
      },
      {
        key: "product_dictionary",
        category: "vendor",
        label: "Product Dictionary Install",
        status: "warned",
        summary:
          "AegisNAS product dictionary was not detected in the FreeRADIUS dictionary imports.",
        recommendation:
          "Install dictionary.aegisnas before hardware smoke tests.",
      },
    ],
  };
}

function createSystemStatus() {
  const productionReadiness = createProductionReadiness();
  return {
    generated_at: "2026-05-05T12:00:00Z",
    summary: {
      users: 12,
      active_sessions: 3,
      quarantined_sessions: 0,
      shaped_sessions: 2,
      pending_changes: 0,
      unacknowledged_alerts: 1,
      healthy_services: 9,
      total_services: 9,
      session_methods: { portal: 2, radius: 1 },
    },
    services: [
      {
        key: "admin_api",
        label: "Admin API",
        kind: "go",
        status: "ok",
        message: "Admin API is healthy.",
        port: 8083,
      },
      {
        key: "gateway",
        label: "Gateway",
        kind: "go",
        status: "ok",
        message: "Gateway is healthy.",
        port: 8080,
      },
    ],
    production_readiness: {
      status: productionReadiness.status,
      ready: productionReadiness.ready,
      score: productionReadiness.score,
      message: productionReadiness.message,
      blocking_count: productionReadiness.blocking_count,
      warning_count: productionReadiness.warning_count,
      degraded_count: productionReadiness.degraded_count,
      passing_count: productionReadiness.passing_count,
    },
    deployment: createDeploymentPreview(),
    radius: {
      upstream_enabled: true,
      realm: "aegis-upstream",
      pool_strategy: "fail-over",
      configured_servers: [
        {
          name: "upstream-1",
          address: "10.0.0.20",
          auth_port: 1812,
          acct_port: 1813,
        },
      ],
      server_statuses: [
        {
          name: "upstream-1",
          address: "10.0.0.20",
          auth_port: 1812,
          acct_port: 1813,
          status: "ok",
          message: "Healthy",
          supports_status_server: true,
        },
      ],
      enabled_radius_clients: 2,
      broker_auth: { status: "ok", message: "Auth path healthy." },
      broker_accounting: { status: "ok", message: "Accounting path healthy." },
    },
    wireless: {
      enabled: false,
      interface: "",
      country_code: "US",
      channel: 6,
      hostapd_config_path: "/etc/hostapd/hostapd.conf",
      ssid_count: 0,
      auth_modes: [],
    },
    enforcement: {
      shaping_enabled: true,
      shaping_interface: "ens37",
      shaped_sessions: 2,
      shaper: { status: "ok", message: "Runtime shaper healthy." },
    },
    high_availability: {
      enabled: true,
      role: "standby",
      peer_api_url: "https://peer.example.test:8083",
      virtual_ip: "192.168.50.2",
      heartbeat_interval_seconds: 5,
      failover_timeout_seconds: 20,
      replication_interval_seconds: 300,
      replication_stale_after_seconds: 900,
      split_brain_protection_enabled: true,
      auto_stage_shared_package: true,
      auto_activate_on_failover: false,
      witness_api_url: "",
      witness_urls: [
        "https://witness-a.example.test/ha",
        "https://witness-b.example.test/ha",
      ],
      witness_quorum: 2,
      witness_weights: {
        "https://witness-a.example.test/ha": 2,
        "https://witness-b.example.test/ha": 1,
      },
      witness_weight_threshold: 2,
      witness_groups: {
        "https://witness-a.example.test/ha": "dc-a",
        "https://witness-b.example.test/ha": "dc-b",
      },
      witness_min_distinct_groups: 2,
      witness_required_groups: ["dc-a"],
      witness_sources: {
        "https://witness-a.example.test/ha": "local",
        "https://witness-b.example.test/ha": "external",
      },
      witness_source_confidence: {
        local: "critical",
        external: "advisory",
      },
      witness_required_sources: ["local", "external"],
      witness_required_urls: ["https://witness-a.example.test/ha"],
      witness_required_sources_by_tier: {
        critical: ["local"],
      },
      witness_required_urls_by_tier: {
        critical: ["https://witness-a.example.test/ha"],
      },
      witness_required_groups_by_tier: {
        critical: ["dc-a"],
      },
      witness_policy_mode: "all",
      witness_policy_mode_by_tier: {
        advisory: "any",
      },
      witness_failure_tolerance: 1,
      witness_failure_weight_tolerance: 1,
      witness_min_approvals_by_tier: {
        critical: 1,
      },
      witness_min_weight_by_tier: {
        critical: 2,
      },
      witness_min_distinct_groups_by_tier: {
        critical: 1,
      },
      witness_min_distinct_sources_by_tier: {
        critical: 1,
      },
      witness_max_age_by_tier: {
        critical: 10,
        advisory: 30,
      },
      witness_required_node_by_tier: {
        critical: "witness-a",
      },
      witness_signature_required_tiers: ["critical"],
      witness_replay_required_tiers: ["critical"],
      witness_failure_tolerance_by_tier: {
        advisory: 1,
      },
      witness_failure_weight_tolerance_by_tier: {
        advisory: 1,
      },
      witness_blocking_tiers: ["critical"],
      witness_token_env: "AEGIS_HA_WITNESS_TOKEN",
      witness_signing_key_env: "AEGIS_HA_WITNESS_SIGNING_KEY",
      witness_max_age_seconds: 30,
      witness_required_node: "witness-1",
      witness_replay_protection_enabled: true,
      preempt: false,
      shared_state_dir: "/var/lib/aegisnas/ha",
      runtime: {
        status: "ok",
        message: "Peer health probe is healthy.",
        updated_at: "2026-05-05T12:00:00Z",
        details: {
          peer_health_url: "https://peer.example.test:8083/health",
          peer_reachable: true,
          peer_status_code: 200,
          fencing_status: "peer_fresh",
          split_brain_protection_enabled: true,
          witness_status: "idle",
          witness_allow_count: 0,
          witness_total_count: 2,
          witness_allow_weight: 0,
          witness_total_weight: 3,
          witness_allow_group_count: 0,
          witness_total_group_count: 2,
          witness_allow_source_count: 0,
          witness_total_source_count: 2,
          witness_allow_sources: [],
          witness_policy_mode: "all",
          witness_failure_tolerance: 1,
          witness_failure_weight_tolerance: 1,
          witness_min_approvals_by_tier: {
            critical: 1,
          },
          witness_min_weight_by_tier: {
            critical: 2,
          },
          witness_max_age_by_tier: {
            critical: 10,
            advisory: 30,
          },
          witness_confidence: {
            "https://witness-a.example.test/ha": "critical",
            "https://witness-b.example.test/ha": "advisory",
          },
          witness_total_tier_count: 2,
          witness_blocking_tiers: ["critical"],
          witness_failure_tolerance_by_tier: {
            advisory: 1,
          },
          witness_failure_weight_tolerance_by_tier: {
            advisory: 1,
          },
          peer_shared_heartbeat_present: true,
          peer_shared_heartbeat_age_seconds: 4,
          peer_shared_heartbeat_stale: false,
          vip_announcement_status: "sent",
          vip_announcement_at: "2026-05-05T11:59:58Z",
        },
      },
      replication_runtime: {
        status: "ok",
        message:
          "Observed fresh shared HA replication package. Standby auto-stage is ready with package shared-stage-001.",
        updated_at: "2026-05-05T12:00:00Z",
        details: {
          latest_source_node: "active-node",
          latest_age_seconds: 42,
          stale: false,
          auto_stage_enabled: true,
          auto_stage_status: "ready",
          auto_stage_stage_id: "shared-stage-001",
        },
      },
      history_stats: {
        total_records: 12,
        failover_promotions: 1,
        failover_returns: 1,
        peer_failures: 2,
        peer_recoveries: 2,
        vip_acquisitions: 2,
        vip_preemptions: 0,
        vip_releases: 2,
        vip_announcements: 2,
        vip_announcement_failures: 0,
        replication_publishes: 4,
        replication_failures: 0,
        replication_stale_count: 1,
        shared_stages: 2,
        activations: 1,
        last_event_at: "2026-05-05T12:00:00Z",
      },
    },
    integrations: {
      admin_sso: {
        enabled: true,
        provider: "oidc",
        issuer_url: "https://sso.example.test",
        redirect_url: "http://127.0.0.1:4173/login",
        groups_claim: "groups",
        session: { status: "ok", message: "OIDC admin SSO ready." },
      },
      siem: {
        enabled: true,
        provider: "webhook",
        endpoint: "https://siem.example.test/events",
        batch_size: 100,
        export: { status: "ok", message: "SIEM export healthy." },
      },
      controller: {
        enabled: true,
        platform: "vendor-neutral",
        endpoint: "https://controller.example.test/api",
        sync_mode: "monitor",
        site: "lab",
        sync: {
          status: "ok",
          message: "Controller sync healthy.",
          details: {
            sync_count: 4,
            success_count: 4,
            failure_count: 0,
            last_duration_ms: 182,
          },
        },
      },
    },
    profiling: {
      mac_inventory_enabled: true,
      passive_enabled: true,
      posture_enabled: true,
      mdm_sync_enabled: true,
      mdm_provider: "workspace-one",
      mdm_endpoint: "https://mdm.example.test/api",
      compliance_webhook: "https://policy.example.test/compliance",
      device_inventory: {
        status: "ok",
        message: "Device inventory runtime is active.",
        details: { passive_enabled: true, posture_enabled: true },
      },
      mdm_sync: {
        status: "ok",
        message: "MDM sync completed successfully.",
        details: {
          provider: "workspace-one",
          total_records: 12,
          managed_records: 11,
          compliant_records: 10,
          non_compliant_records: 2,
          remediation_records: 1,
        },
      },
      posture_checks: {
        status: "ok",
        message: "Compliance webhook evaluation completed.",
        details: {
          provider: "compliance-webhook",
          total_records: 4,
          managed_records: 4,
          compliant_records: 3,
          non_compliant_records: 1,
          remediation_records: 1,
        },
      },
    },
    telemetry: {
      enabled: true,
      prometheus_port: 9090,
      lease_history_poll_seconds: 300,
      diagnostics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/diagnostics",
        format: "both",
        interval_minutes: 60,
        retention_count: 14,
        runtime: {
          status: "ok",
          message: "Scheduled diagnostics exports are healthy.",
          details: {
            format: "both",
            interval_minutes: 60,
            retention_count: 14,
            directory: "/var/lib/aegisnas/diagnostics",
            last_export_at: "2026-05-05T11:55:00Z",
            next_due_at: "2026-05-05T12:55:00Z",
          },
        },
      },
      audit_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/audit-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled audit exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/audit-exports",
            last_export_at: "2026-05-05T11:58:00Z",
            next_due_at: "2026-05-05T12:58:00Z",
          },
        },
      },
      session_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/session-exports",
        format: "both",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled session exports are healthy.",
          details: {
            format: "both",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/session-exports",
            last_export_at: "2026-05-05T11:53:00Z",
            next_due_at: "2026-05-05T12:53:00Z",
          },
        },
      },
      session_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/session-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled session analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/session-analytics-exports",
            window_hours: 24,
            bucket_count: 24,
            last_export_at: "2026-05-05T11:54:00Z",
            next_due_at: "2026-05-05T12:54:00Z",
          },
        },
      },
      voucher_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled voucher analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/voucher-analytics-exports",
            window_hours: 720,
            bucket_count: 30,
            last_export_at: "2026-05-05T11:54:30Z",
            next_due_at: "2026-05-05T12:54:30Z",
          },
        },
      },
      voucher_aging_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-aging-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled voucher aging analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/voucher-aging-analytics-exports",
            window_hours: 720,
            bucket_count: 30,
            last_export_at: "2026-05-05T11:54:40Z",
            next_due_at: "2026-05-05T12:54:40Z",
          },
        },
      },
      voucher_redemption_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-redemption-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled voucher redemption analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/voucher-redemption-analytics-exports",
            window_hours: 720,
            bucket_count: 30,
            last_export_at: "2026-05-05T11:54:45Z",
            next_due_at: "2026-05-05T12:54:45Z",
          },
        },
      },
      voucher_expiry_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/voucher-expiry-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled voucher expiry analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/voucher-expiry-analytics-exports",
            window_hours: 720,
            bucket_count: 30,
            last_export_at: "2026-05-05T11:55:00Z",
            next_due_at: "2026-05-05T12:55:00Z",
          },
        },
      },
      guest_lifecycle_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-lifecycle-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled guest lifecycle exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/guest-lifecycle-exports",
            window_hours: 24,
            bucket_count: 24,
            limit: 5000,
            last_export_at: "2026-05-05T11:55:00Z",
            next_due_at: "2026-05-05T12:55:00Z",
          },
        },
      },
      guest_invite_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-invite-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled guest invite analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/guest-invite-analytics-exports",
            window_hours: 24,
            bucket_count: 24,
            limit: 5000,
            last_export_at: "2026-05-05T11:55:30Z",
            next_due_at: "2026-05-05T12:55:30Z",
          },
        },
      },
      guest_conversion_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-conversion-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled guest conversion analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/guest-conversion-analytics-exports",
            window_hours: 24,
            bucket_count: 24,
            limit: 5000,
            last_export_at: "2026-05-05T11:55:45Z",
            next_due_at: "2026-05-05T12:55:45Z",
          },
        },
      },
      guest_rejection_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-rejection-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled guest rejection analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/guest-rejection-analytics-exports",
            window_hours: 24,
            bucket_count: 24,
            limit: 5000,
            last_export_at: "2026-05-05T11:55:50Z",
            next_due_at: "2026-05-05T12:55:50Z",
          },
        },
      },
      guest_delivery_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-delivery-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled guest delivery analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/guest-delivery-analytics-exports",
            window_hours: 24,
            bucket_count: 24,
            limit: 5000,
            last_export_at: "2026-05-05T11:56:00Z",
            next_due_at: "2026-05-05T12:56:00Z",
          },
        },
      },
      guest_delivery_failures_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-delivery-failures-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled guest delivery failure exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/guest-delivery-failures-exports",
            window_hours: 24,
            bucket_count: 24,
            limit: 5000,
            last_export_at: "2026-05-05T11:56:30Z",
            next_due_at: "2026-05-05T12:56:30Z",
          },
        },
      },
      guest_sponsor_analytics_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/guest-sponsor-analytics-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled guest sponsor analytics exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/guest-sponsor-analytics-exports",
            window_hours: 24,
            bucket_count: 24,
            limit: 5000,
            last_export_at: "2026-05-05T11:57:00Z",
            next_due_at: "2026-05-05T12:57:00Z",
          },
        },
      },
      integration_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/integration-exports",
        format: "both",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled integration exports are healthy.",
          details: {
            format: "both",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/integration-exports",
            last_export_at: "2026-05-05T11:57:00Z",
            next_due_at: "2026-05-05T12:57:00Z",
          },
        },
      },
      ha_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/ha-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled HA exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/ha-exports",
            last_export_at: "2026-05-05T11:56:00Z",
            next_due_at: "2026-05-05T12:56:00Z",
          },
        },
      },
      network_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/network-exports",
        format: "both",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled network exports are healthy.",
          details: {
            format: "both",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/network-exports",
            last_export_at: "2026-05-05T11:54:00Z",
            next_due_at: "2026-05-05T12:54:00Z",
          },
        },
      },
      upstream_aaa_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/upstream-aaa-exports",
        format: "json",
        interval_minutes: 60,
        retention_count: 21,
        runtime: {
          status: "ok",
          message: "Scheduled upstream AAA exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 60,
            retention_count: 21,
            directory: "/var/lib/aegisnas/upstream-aaa-exports",
            last_export_at: "2026-05-05T11:59:30Z",
            next_due_at: "2026-05-05T12:59:30Z",
          },
        },
      },
      upgrade_readiness_exports: {
        enabled: true,
        directory: "/var/lib/aegisnas/upgrade-readiness-exports",
        format: "json",
        interval_minutes: 240,
        retention_count: 14,
        runtime: {
          status: "ok",
          message: "Scheduled upgrade readiness exports are healthy.",
          details: {
            format: "json",
            interval_minutes: 240,
            retention_count: 14,
            directory: "/var/lib/aegisnas/upgrade-readiness-exports",
            last_export_at: "2026-05-05T08:00:00Z",
            next_due_at: "2026-05-05T12:00:00Z",
          },
        },
      },
    },
    network_observability: {
      apply_stats: {
        total_records: 3,
        apply_success_count: 1,
        apply_failure_count: 0,
        pending_confirmation_count: 0,
        confirmed_count: 1,
        rollback_count: 1,
        auto_rollback_count: 0,
        auto_rollback_failure_count: 0,
        last_applied_at: "2026-05-05T12:10:00Z",
        last_failure_at: "",
      },
      lease_trends: {
        window_hours: 24,
        total_records: 2,
        unique_macs_window: 1,
        unique_ips_window: 1,
        active_observations_window: 2,
        expired_observations_window: 0,
        reservation_observations_window: 2,
        peak_concurrent_leases_window: 1,
        latest_observed_at: "2026-05-05T12:00:00Z",
      },
      recovery: null,
      controller_sync: {
        status: "ok",
        message: "Controller sync healthy.",
        details: {
          sync_count: 4,
          success_count: 4,
          failure_count: 0,
          last_duration_ms: 182,
        },
      },
    },
  };
}

function createRiskyPreview() {
  return {
    desired_state: {},
    current_state: {},
    diff: {
      interfaces_added: [],
      interfaces_removed: [],
      gateways_added: ["wan-default via 10.0.1.1"],
      gateways_removed: ["wan-default via 10.0.0.1"],
      routes_added: ["172.16.30.0/24 via 10.0.1.254"],
      routes_removed: ["172.16.20.0/24 via 10.0.0.254"],
    },
    risk: {
      requires_confirmation: true,
      confirmation_phrase: "APPLY EDGE NETWORK",
      summary:
        "This edge-network apply changes primary connectivity. Review the warnings and enter the confirmation phrase before applying.",
      items: [
        {
          level: "danger",
          code: "default_gateway_change",
          message:
            "Default gateway selection will change. Upstream reachability and remote management may be interrupted until the new gateway is healthy.",
        },
      ],
    },
    dnsmasq_enabled: true,
    dnsmasq_config: "dhcp-range=192.168.50.100,192.168.50.200,12h",
    firewall_rules:
      "table inet aegis { chain input { type filter hook input priority 0; } }",
    free_site_count: 1,
    custom_firewall_rules: 1,
    static_reservations: 1,
    available_rollback_ids: [],
  };
}

function createAppliedPreview() {
  return {
    desired_state: {},
    current_state: {},
    diff: {
      interfaces_added: [],
      interfaces_removed: [],
      gateways_added: [],
      gateways_removed: [],
      routes_added: [],
      routes_removed: [],
    },
    risk: {
      requires_confirmation: false,
      summary: "No risky edge-network changes detected.",
      items: [],
    },
    dnsmasq_enabled: true,
    dnsmasq_config: "dhcp-range=192.168.50.100,192.168.50.200,12h",
    firewall_rules:
      "table inet aegis { chain input { type filter hook input priority 0; } }",
    free_site_count: 1,
    custom_firewall_rules: 1,
    static_reservations: 1,
    available_rollback_ids: [],
    recovery: null,
  };
}

function parseBody(route: Route): any {
  try {
    return route.request().postDataJSON();
  } catch {
    return {};
  }
}

function buildGuestLifecycleResponse(
  records: GuestRecord[],
  statusFilter = "",
) {
  const history = statusFilter
    ? records.filter((item) => item.status === statusFilter)
    : records;
  const roles = new Map<string, number>();
  const summary = {
    window_hours: 24,
    bucket_count: 24,
    bucket_minutes: 60,
    total_records: history.length,
    pending_count: 0,
    approved_count: 0,
    rejected_count: 0,
    completed_count: 0,
    sponsor_approval_required_count: 0,
    approval_delivery_pending_count: 0,
    approval_delivery_sent_count: 0,
    approval_delivery_failed_count: 0,
    invite_queued_count: 0,
    invite_sent_count: 0,
    invite_failed_count: 0,
    unique_guests_window: 0,
    unique_sponsors_window: 0,
    unique_companies_window: 0,
    avg_approval_minutes: 15,
    avg_completion_minutes: 40,
    latest_submitted_at: "",
    latest_approved_at: "",
    latest_rejected_at: "",
    latest_completed_at: "",
    roles: [] as { name: string; count: number }[],
    buckets: [
      {
        start: "2026-05-05T08:00:00Z",
        end: "2026-05-05T09:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T09:00:00Z",
        end: "2026-05-05T10:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T10:00:00Z",
        end: "2026-05-05T11:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T11:00:00Z",
        end: "2026-05-05T12:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T12:00:00Z",
        end: "2026-05-05T13:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T13:00:00Z",
        end: "2026-05-05T14:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
    ],
  };
  const guestSet = new Set<string>();
  const sponsorSet = new Set<string>();
  const companySet = new Set<string>();

  history.forEach((item, index) => {
    if (item.status === "pending") summary.pending_count += 1;
    if (item.status === "approved") summary.approved_count += 1;
    if (item.status === "rejected") summary.rejected_count += 1;
    if (item.status === "completed") summary.completed_count += 1;

    if (
      item.approval_delivery_status &&
      item.approval_delivery_status !== "not_required"
    ) {
      summary.sponsor_approval_required_count += 1;
    }
    if (item.approval_delivery_status === "pending")
      summary.approval_delivery_pending_count += 1;
    if (item.approval_delivery_status === "sent")
      summary.approval_delivery_sent_count += 1;
    if (item.approval_delivery_status === "failed")
      summary.approval_delivery_failed_count += 1;
    if (item.invite_delivery_status === "queued")
      summary.invite_queued_count += 1;
    if (item.invite_delivery_status === "sent") summary.invite_sent_count += 1;
    if (item.invite_delivery_status === "failed")
      summary.invite_failed_count += 1;

    guestSet.add(item.email || item.full_name || item.id);
    if (item.sponsor_email || item.sponsor_name) {
      sponsorSet.add(item.sponsor_email || item.sponsor_name || item.id);
    }
    if (item.company) {
      companySet.add(item.company);
    }
    if (item.role) {
      roles.set(item.role, (roles.get(item.role) || 0) + 1);
    }

    if (
      !summary.latest_submitted_at ||
      item.created_at > summary.latest_submitted_at
    )
      summary.latest_submitted_at = item.created_at;
    if (
      item.approved_at &&
      (!summary.latest_approved_at ||
        item.approved_at > summary.latest_approved_at)
    )
      summary.latest_approved_at = item.approved_at;
    if (
      item.rejected_at &&
      (!summary.latest_rejected_at ||
        item.rejected_at > summary.latest_rejected_at)
    )
      summary.latest_rejected_at = item.rejected_at;
    if (
      item.completed_at &&
      (!summary.latest_completed_at ||
        item.completed_at > summary.latest_completed_at)
    )
      summary.latest_completed_at = item.completed_at;

    const bucket = summary.buckets[Math.min(index, summary.buckets.length - 1)];
    bucket.submitted_count += 1;
    if (item.status === "approved") bucket.approved_count += 1;
    if (item.status === "rejected") bucket.rejected_count += 1;
    if (item.status === "completed") bucket.completed_count += 1;
  });

  summary.unique_guests_window = guestSet.size;
  summary.unique_sponsors_window = sponsorSet.size;
  summary.unique_companies_window = companySet.size;
  summary.roles = Array.from(roles.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  return {
    generated_at: "2026-05-05T12:15:00Z",
    status: statusFilter,
    window_hours: summary.window_hours,
    bucket_count: summary.bucket_count,
    count: history.length,
    history,
    summary,
  };
}

function buildGuestDeliveryAnalyticsResponse(
  records: GuestRecord[],
  statusFilter = "",
) {
  const history = statusFilter
    ? records.filter((item) => item.status === statusFilter)
    : records;
  const sponsors = new Map<string, number>();
  const companies = new Map<string, number>();
  const roles = new Map<string, number>();
  const approvalStatuses = new Map<string, number>();
  const inviteStatuses = new Map<string, number>();
  const summary = {
    window_hours: 24,
    bucket_count: 24,
    bucket_minutes: 60,
    total_records: history.length,
    sponsor_approval_required_count: 0,
    pending_sponsor_approval_count: 0,
    pending_invite_queue_count: 0,
    approval_delivery_pending_count: 0,
    approval_delivery_sent_count: 0,
    approval_delivery_failed_count: 0,
    invite_queued_count: 0,
    invite_sent_count: 0,
    invite_failed_count: 0,
    approved_count: 0,
    rejected_count: 0,
    completed_count: 0,
    unique_guests_window: 0,
    unique_sponsors_window: 0,
    unique_companies_window: 0,
    avg_approval_minutes: 15,
    max_approval_minutes: 20,
    avg_approval_to_completion_minutes: 30,
    max_approval_to_completion_minutes: 30,
    latest_submitted_at: "",
    latest_approved_at: "",
    latest_rejected_at: "",
    latest_completed_at: "",
    sponsors: [] as { name: string; count: number }[],
    companies: [] as { name: string; count: number }[],
    roles: [] as { name: string; count: number }[],
    approval_delivery_statuses: [] as { name: string; count: number }[],
    invite_delivery_statuses: [] as { name: string; count: number }[],
    buckets: [
      {
        start: "2026-05-05T08:00:00Z",
        end: "2026-05-05T09:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        approval_delivery_failed_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T09:00:00Z",
        end: "2026-05-05T10:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        approval_delivery_failed_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T10:00:00Z",
        end: "2026-05-05T11:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        approval_delivery_failed_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T11:00:00Z",
        end: "2026-05-05T12:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        approval_delivery_failed_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T12:00:00Z",
        end: "2026-05-05T13:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        approval_delivery_failed_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T13:00:00Z",
        end: "2026-05-05T14:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        approval_delivery_failed_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_count: 0,
      },
    ],
  };
  const guestSet = new Set<string>();
  const sponsorSet = new Set<string>();
  const companySet = new Set<string>();

  history.forEach((item, index) => {
    if (item.status === "approved") summary.approved_count += 1;
    if (item.status === "rejected") summary.rejected_count += 1;
    if (item.status === "completed") summary.completed_count += 1;

    if (
      item.approval_delivery_status &&
      item.approval_delivery_status !== "not_required"
    ) {
      summary.sponsor_approval_required_count += 1;
      if (item.status === "pending") {
        summary.pending_sponsor_approval_count += 1;
      }
    }
    if (item.approval_delivery_status === "pending")
      summary.approval_delivery_pending_count += 1;
    if (item.approval_delivery_status === "sent")
      summary.approval_delivery_sent_count += 1;
    if (item.approval_delivery_status === "failed")
      summary.approval_delivery_failed_count += 1;

    if (item.invite_delivery_status === "queued") {
      summary.invite_queued_count += 1;
      summary.pending_invite_queue_count += 1;
    }
    if (item.invite_delivery_status === "sent") summary.invite_sent_count += 1;
    if (item.invite_delivery_status === "failed")
      summary.invite_failed_count += 1;

    guestSet.add(item.email || item.full_name || item.id);
    if (item.sponsor_email || item.sponsor_name) {
      const label = item.sponsor_email || item.sponsor_name || item.id;
      sponsorSet.add(label);
      sponsors.set(label, (sponsors.get(label) || 0) + 1);
    }
    if (item.company) {
      companySet.add(item.company);
      companies.set(item.company, (companies.get(item.company) || 0) + 1);
    }
    if (item.role) {
      roles.set(item.role, (roles.get(item.role) || 0) + 1);
    }

    const approvalStatus = item.approval_delivery_status || "unknown";
    approvalStatuses.set(
      approvalStatus,
      (approvalStatuses.get(approvalStatus) || 0) + 1,
    );
    const inviteStatus = item.invite_delivery_status || "unknown";
    inviteStatuses.set(
      inviteStatus,
      (inviteStatuses.get(inviteStatus) || 0) + 1,
    );

    if (
      !summary.latest_submitted_at ||
      item.created_at > summary.latest_submitted_at
    )
      summary.latest_submitted_at = item.created_at;
    if (
      item.approved_at &&
      (!summary.latest_approved_at ||
        item.approved_at > summary.latest_approved_at)
    )
      summary.latest_approved_at = item.approved_at;
    if (
      item.rejected_at &&
      (!summary.latest_rejected_at ||
        item.rejected_at > summary.latest_rejected_at)
    )
      summary.latest_rejected_at = item.rejected_at;
    if (
      item.completed_at &&
      (!summary.latest_completed_at ||
        item.completed_at > summary.latest_completed_at)
    )
      summary.latest_completed_at = item.completed_at;

    const bucket = summary.buckets[Math.min(index, summary.buckets.length - 1)];
    bucket.submitted_count += 1;
    if (
      item.status === "pending" &&
      item.approval_delivery_status &&
      item.approval_delivery_status !== "not_required"
    ) {
      bucket.pending_sponsor_approval_count += 1;
    }
    if (item.approval_delivery_status === "failed") {
      bucket.approval_delivery_failed_count += 1;
    }
    if (item.status === "approved") bucket.approved_count += 1;
    if (item.status === "rejected") bucket.rejected_count += 1;
    if (item.invite_delivery_status === "queued")
      bucket.invite_queued_count += 1;
    if (item.invite_delivery_status === "sent") bucket.invite_sent_count += 1;
    if (item.invite_delivery_status === "failed")
      bucket.invite_failed_count += 1;
    if (item.status === "completed") bucket.completed_count += 1;
  });

  summary.unique_guests_window = guestSet.size;
  summary.unique_sponsors_window = sponsorSet.size;
  summary.unique_companies_window = companySet.size;
  summary.sponsors = Array.from(sponsors.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.companies = Array.from(companies.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.roles = Array.from(roles.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.approval_delivery_statuses = Array.from(approvalStatuses.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.invite_delivery_statuses = Array.from(inviteStatuses.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  return {
    generated_at: "2026-05-05T12:15:00Z",
    status: statusFilter,
    window_hours: summary.window_hours,
    bucket_count: summary.bucket_count,
    summary,
  };
}

function buildGuestInviteAnalyticsResponse(
  records: GuestRecord[],
  statusFilter = "",
) {
  const history = statusFilter
    ? records.filter((item) => item.status === statusFilter)
    : records;
  const sponsors = new Map<string, number>();
  const companies = new Map<string, number>();
  const roles = new Map<string, number>();
  const inviteStatuses = new Map<string, number>();
  const inviteFailureReasons = new Map<string, number>();
  const guestSet = new Set<string>();
  const sponsorSet = new Set<string>();
  const companySet = new Set<string>();
  const summary = {
    window_hours: 24,
    bucket_count: 24,
    bucket_minutes: 60,
    total_records: history.length,
    tracked_invite_records_count: 0,
    invite_queued_count: 0,
    invite_sent_count: 0,
    invite_failed_count: 0,
    invite_not_requested_count: 0,
    completed_after_invite_count: 0,
    unique_guests_window: 0,
    unique_sponsors_window: 0,
    unique_companies_window: 0,
    avg_approval_to_invite_minutes: 12,
    max_approval_to_invite_minutes: 20,
    avg_invite_to_completion_minutes: 18,
    max_invite_to_completion_minutes: 30,
    latest_invite_queued_at: "",
    latest_invite_sent_at: "",
    latest_invite_failed_at: "",
    latest_invite_completed_at: "",
    sponsors: [] as { name: string; count: number }[],
    companies: [] as { name: string; count: number }[],
    roles: [] as { name: string; count: number }[],
    invite_delivery_statuses: [] as { name: string; count: number }[],
    invite_failure_reasons: [] as { name: string; count: number }[],
    buckets: [
      {
        start: "2026-05-05T08:00:00Z",
        end: "2026-05-05T09:00:00Z",
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_after_invite_count: 0,
      },
      {
        start: "2026-05-05T09:00:00Z",
        end: "2026-05-05T10:00:00Z",
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_after_invite_count: 0,
      },
      {
        start: "2026-05-05T10:00:00Z",
        end: "2026-05-05T11:00:00Z",
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_after_invite_count: 0,
      },
      {
        start: "2026-05-05T11:00:00Z",
        end: "2026-05-05T12:00:00Z",
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_after_invite_count: 0,
      },
      {
        start: "2026-05-05T12:00:00Z",
        end: "2026-05-05T13:00:00Z",
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_after_invite_count: 0,
      },
      {
        start: "2026-05-05T13:00:00Z",
        end: "2026-05-05T14:00:00Z",
        invite_queued_count: 0,
        invite_sent_count: 0,
        invite_failed_count: 0,
        completed_after_invite_count: 0,
      },
    ],
  };

  history.forEach((item, index) => {
    const inviteStatus = item.invite_delivery_status || "unknown";
    inviteStatuses.set(
      inviteStatus,
      (inviteStatuses.get(inviteStatus) || 0) + 1,
    );

    if (inviteStatus === "queued") {
      summary.tracked_invite_records_count += 1;
      summary.invite_queued_count += 1;
      summary.latest_invite_queued_at = item.approved_at || item.created_at;
    } else if (inviteStatus === "sent") {
      summary.tracked_invite_records_count += 1;
      summary.invite_sent_count += 1;
      summary.latest_invite_sent_at =
        item.approved_at || item.completed_at || item.created_at;
    } else if (inviteStatus === "failed") {
      summary.tracked_invite_records_count += 1;
      summary.invite_failed_count += 1;
      summary.latest_invite_failed_at =
        item.rejected_at || item.approved_at || item.created_at;
      const reason = item.invite_delivery_error || "unknown";
      inviteFailureReasons.set(
        reason,
        (inviteFailureReasons.get(reason) || 0) + 1,
      );
    } else if (inviteStatus === "not_requested") {
      summary.invite_not_requested_count += 1;
    }

    if (item.completed_at && inviteStatus === "sent") {
      summary.completed_after_invite_count += 1;
      summary.latest_invite_completed_at = item.completed_at;
    }

    if (
      inviteStatus === "queued" ||
      inviteStatus === "sent" ||
      inviteStatus === "failed"
    ) {
      guestSet.add(item.email || item.full_name || item.id);
      if (item.sponsor_email || item.sponsor_name) {
        const label = item.sponsor_email || item.sponsor_name || item.id;
        sponsorSet.add(label);
        sponsors.set(label, (sponsors.get(label) || 0) + 1);
      }
      if (item.company) {
        companySet.add(item.company);
        companies.set(item.company, (companies.get(item.company) || 0) + 1);
      }
      if (item.role) {
        roles.set(item.role, (roles.get(item.role) || 0) + 1);
      }
    }

    const bucket = summary.buckets[Math.min(index, summary.buckets.length - 1)];
    if (inviteStatus === "queued") bucket.invite_queued_count += 1;
    if (inviteStatus === "sent") bucket.invite_sent_count += 1;
    if (inviteStatus === "failed") bucket.invite_failed_count += 1;
    if (item.completed_at && inviteStatus === "sent") {
      bucket.completed_after_invite_count += 1;
    }
  });

  summary.unique_guests_window = guestSet.size;
  summary.unique_sponsors_window = sponsorSet.size;
  summary.unique_companies_window = companySet.size;
  summary.sponsors = Array.from(sponsors.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.companies = Array.from(companies.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.roles = Array.from(roles.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.invite_delivery_statuses = Array.from(inviteStatuses.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.invite_failure_reasons = Array.from(inviteFailureReasons.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  return {
    generated_at: "2026-05-05T12:15:00Z",
    status: statusFilter,
    window_hours: summary.window_hours,
    bucket_count: summary.bucket_count,
    summary,
  };
}

function buildGuestConversionAnalyticsResponse(
  records: GuestRecord[],
  statusFilter = "",
) {
  const history = statusFilter
    ? records.filter((item) => item.status === statusFilter)
    : records;
  const roles = new Map<string, number>();
  const sponsors = new Map<string, number>();
  const companies = new Map<string, number>();
  const guestSet = new Set<string>();
  const sponsorSet = new Set<string>();
  const companySet = new Set<string>();
  const summary = {
    window_hours: 24,
    bucket_count: 24,
    bucket_minutes: 60,
    total_records: history.length,
    open_pending_count: 0,
    sponsor_approval_required_count: 0,
    approved_stage_count: 0,
    rejected_stage_count: 0,
    invite_queued_count: 0,
    invite_sent_count: 0,
    invite_failed_count: 0,
    completed_stage_count: 0,
    approved_without_successful_invite_count: 0,
    invited_not_completed_count: 0,
    completed_after_invite_count: 0,
    unique_guests_window: 0,
    unique_sponsors_window: 0,
    unique_companies_window: 0,
    approval_rate_percent: 0,
    invite_send_rate_percent: 0,
    invite_completion_rate_percent: 0,
    end_to_end_completion_rate_percent: 0,
    avg_submit_to_approval_minutes: 18,
    max_submit_to_approval_minutes: 35,
    avg_submit_to_invite_minutes: 26,
    max_submit_to_invite_minutes: 45,
    avg_submit_to_completion_minutes: 40,
    max_submit_to_completion_minutes: 75,
    latest_submitted_at: "",
    latest_approved_at: "",
    latest_invite_sent_at: "",
    latest_completed_at: "",
    roles: [] as { name: string; count: number }[],
    sponsors: [] as { name: string; count: number }[],
    companies: [] as { name: string; count: number }[],
    buckets: [
      {
        start: "2026-05-05T08:00:00Z",
        end: "2026-05-05T09:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_sent_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T09:00:00Z",
        end: "2026-05-05T10:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_sent_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T10:00:00Z",
        end: "2026-05-05T11:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_sent_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T11:00:00Z",
        end: "2026-05-05T12:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_sent_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T12:00:00Z",
        end: "2026-05-05T13:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_sent_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T13:00:00Z",
        end: "2026-05-05T14:00:00Z",
        submitted_count: 0,
        approved_count: 0,
        rejected_count: 0,
        invite_sent_count: 0,
        completed_count: 0,
      },
    ],
  };

  history.forEach((item, index) => {
    const bucket = summary.buckets[Math.min(index, summary.buckets.length - 1)];
    const inviteStatus = item.invite_delivery_status || "unknown";
    const role = item.role || "unassigned";
    roles.set(role, (roles.get(role) || 0) + 1);
    guestSet.add(item.email || item.full_name || item.id);
    if (item.sponsor_email || item.sponsor_name) {
      const sponsor = item.sponsor_email || item.sponsor_name || item.id;
      sponsors.set(sponsor, (sponsors.get(sponsor) || 0) + 1);
      sponsorSet.add(sponsor);
    }
    if (item.company) {
      companies.set(item.company, (companies.get(item.company) || 0) + 1);
      companySet.add(item.company);
    }

    summary.latest_submitted_at =
      item.created_at || summary.latest_submitted_at;
    bucket.submitted_count += 1;

    if (
      item.approval_delivery_status === "pending" ||
      item.approval_delivery_status === "sent" ||
      item.approval_delivery_status === "failed"
    ) {
      summary.sponsor_approval_required_count += 1;
    }
    if (item.status === "pending") {
      summary.open_pending_count += 1;
    }
    if (
      item.approved_at ||
      item.status === "approved" ||
      item.status === "completed"
    ) {
      summary.approved_stage_count += 1;
      summary.latest_approved_at =
        item.approved_at || summary.latest_approved_at;
      bucket.approved_count += 1;
    }
    if (item.rejected_at || item.status === "rejected") {
      summary.rejected_stage_count += 1;
      bucket.rejected_count += 1;
    }
    if (item.completed_at || item.status === "completed") {
      summary.completed_stage_count += 1;
      summary.latest_completed_at =
        item.completed_at || summary.latest_completed_at;
      bucket.completed_count += 1;
    }
    if (inviteStatus === "queued") {
      summary.invite_queued_count += 1;
    }
    if (inviteStatus === "sent") {
      summary.invite_sent_count += 1;
      summary.latest_invite_sent_at =
        item.completed_at || item.approved_at || item.created_at || "";
      bucket.invite_sent_count += 1;
    }
    if (inviteStatus === "failed") {
      summary.invite_failed_count += 1;
    }
    if (
      (item.approved_at ||
        item.status === "approved" ||
        item.status === "completed") &&
      inviteStatus !== "sent" &&
      item.status !== "rejected" &&
      item.status !== "completed"
    ) {
      summary.approved_without_successful_invite_count += 1;
    }
    if (inviteStatus === "sent" && item.status !== "completed") {
      summary.invited_not_completed_count += 1;
    }
    if (inviteStatus === "sent" && item.status === "completed") {
      summary.completed_after_invite_count += 1;
    }
  });

  summary.unique_guests_window = guestSet.size;
  summary.unique_sponsors_window = sponsorSet.size;
  summary.unique_companies_window = companySet.size;
  summary.approval_rate_percent = summary.total_records
    ? Math.round((summary.approved_stage_count * 100) / summary.total_records)
    : 0;
  summary.invite_send_rate_percent = summary.approved_stage_count
    ? Math.round(
        (summary.invite_sent_count * 100) / summary.approved_stage_count,
      )
    : 0;
  summary.invite_completion_rate_percent = summary.invite_sent_count
    ? Math.round(
        (summary.completed_after_invite_count * 100) /
          summary.invite_sent_count,
      )
    : 0;
  summary.end_to_end_completion_rate_percent = summary.total_records
    ? Math.round((summary.completed_stage_count * 100) / summary.total_records)
    : 0;
  summary.roles = Array.from(roles.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.sponsors = Array.from(sponsors.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.companies = Array.from(companies.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  return {
    generated_at: "2026-05-05T12:15:00Z",
    status: statusFilter,
    window_hours: summary.window_hours,
    bucket_count: summary.bucket_count,
    summary,
  };
}

function buildGuestRejectionAnalyticsResponse(
  records: GuestRecord[],
  statusFilter = "",
) {
  const history = statusFilter
    ? records.filter((item) => item.status === statusFilter)
    : records;
  const reasons = new Map<string, number>();
  const sponsors = new Map<string, number>();
  const companies = new Map<string, number>();
  const roles = new Map<string, number>();
  const sponsorSet = new Set<string>();
  const companySet = new Set<string>();
  const reasonSet = new Set<string>();
  const summary = {
    window_hours: 24,
    bucket_count: 6,
    bucket_minutes: 60,
    total_records: history.length,
    rejected_count: 0,
    rejected_with_sponsor_count: 0,
    rejected_without_sponsor_count: 0,
    rejected_after_approval_count: 0,
    rejected_before_approval_count: 0,
    unique_rejection_reasons_window: 0,
    unique_sponsors_window: 0,
    unique_companies_window: 0,
    avg_submit_to_rejection_minutes: 0,
    max_submit_to_rejection_minutes: 0,
    latest_rejected_at: "",
    rejection_reasons: [] as { name: string; count: number }[],
    sponsors: [] as { name: string; count: number }[],
    companies: [] as { name: string; count: number }[],
    roles: [] as { name: string; count: number }[],
    buckets: [
      {
        start: "2026-05-05T08:00:00Z",
        end: "2026-05-05T09:00:00Z",
        rejected_count: 0,
        rejected_with_sponsor_count: 0,
        rejected_without_sponsor_count: 0,
        rejected_after_approval_count: 0,
      },
      {
        start: "2026-05-05T09:00:00Z",
        end: "2026-05-05T10:00:00Z",
        rejected_count: 0,
        rejected_with_sponsor_count: 0,
        rejected_without_sponsor_count: 0,
        rejected_after_approval_count: 0,
      },
      {
        start: "2026-05-05T10:00:00Z",
        end: "2026-05-05T11:00:00Z",
        rejected_count: 0,
        rejected_with_sponsor_count: 0,
        rejected_without_sponsor_count: 0,
        rejected_after_approval_count: 0,
      },
      {
        start: "2026-05-05T11:00:00Z",
        end: "2026-05-05T12:00:00Z",
        rejected_count: 0,
        rejected_with_sponsor_count: 0,
        rejected_without_sponsor_count: 0,
        rejected_after_approval_count: 0,
      },
      {
        start: "2026-05-05T12:00:00Z",
        end: "2026-05-05T13:00:00Z",
        rejected_count: 0,
        rejected_with_sponsor_count: 0,
        rejected_without_sponsor_count: 0,
        rejected_after_approval_count: 0,
      },
      {
        start: "2026-05-05T13:00:00Z",
        end: "2026-05-05T14:00:00Z",
        rejected_count: 0,
        rejected_with_sponsor_count: 0,
        rejected_without_sponsor_count: 0,
        rejected_after_approval_count: 0,
      },
    ],
  };
  let rejectionTotalMinutes = 0;
  let rejectionSamples = 0;

  history.forEach((item, index) => {
    if (item.status !== "rejected" && !item.rejected_at) {
      return;
    }

    summary.rejected_count += 1;
    const bucket = summary.buckets[Math.min(index, summary.buckets.length - 1)];
    bucket.rejected_count += 1;

    const reason = item.rejection_reason || "unspecified";
    reasons.set(reason, (reasons.get(reason) || 0) + 1);
    reasonSet.add(reason);

    const role = item.role || "unassigned";
    roles.set(role, (roles.get(role) || 0) + 1);

    const sponsor = item.sponsor_email || item.sponsor_name || "";
    if (sponsor !== "") {
      summary.rejected_with_sponsor_count += 1;
      bucket.rejected_with_sponsor_count += 1;
      sponsors.set(sponsor, (sponsors.get(sponsor) || 0) + 1);
      sponsorSet.add(sponsor);
    } else {
      summary.rejected_without_sponsor_count += 1;
      bucket.rejected_without_sponsor_count += 1;
    }

    if (item.company) {
      companies.set(item.company, (companies.get(item.company) || 0) + 1);
      companySet.add(item.company);
    }

    const createdAt = item.created_at
      ? Date.parse(item.created_at)
      : Number.NaN;
    const approvedAt = item.approved_at
      ? Date.parse(item.approved_at)
      : Number.NaN;
    const rejectedAt = item.rejected_at
      ? Date.parse(item.rejected_at)
      : item.created_at
        ? Date.parse(item.created_at)
        : Number.NaN;

    if (
      !Number.isNaN(approvedAt) &&
      !Number.isNaN(rejectedAt) &&
      rejectedAt > approvedAt
    ) {
      summary.rejected_after_approval_count += 1;
      bucket.rejected_after_approval_count += 1;
    } else {
      summary.rejected_before_approval_count += 1;
    }

    if (
      !Number.isNaN(createdAt) &&
      !Number.isNaN(rejectedAt) &&
      rejectedAt >= createdAt
    ) {
      const minutes = Math.floor((rejectedAt - createdAt) / 60000);
      rejectionTotalMinutes += minutes;
      rejectionSamples += 1;
      summary.max_submit_to_rejection_minutes = Math.max(
        summary.max_submit_to_rejection_minutes,
        minutes,
      );
    }

    const rejectedAtText =
      item.rejected_at || item.updated_at || item.created_at || "";
    if (
      rejectedAtText &&
      (!summary.latest_rejected_at ||
        rejectedAtText > summary.latest_rejected_at)
    ) {
      summary.latest_rejected_at = rejectedAtText;
    }
  });

  summary.unique_rejection_reasons_window = reasonSet.size;
  summary.unique_sponsors_window = sponsorSet.size;
  summary.unique_companies_window = companySet.size;
  summary.avg_submit_to_rejection_minutes =
    rejectionSamples > 0
      ? Math.floor(rejectionTotalMinutes / rejectionSamples)
      : 0;
  summary.rejection_reasons = Array.from(reasons.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.sponsors = Array.from(sponsors.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.companies = Array.from(companies.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.roles = Array.from(roles.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  return {
    generated_at: "2026-05-05T12:15:00Z",
    status: statusFilter,
    window_hours: summary.window_hours,
    bucket_count: summary.bucket_count,
    summary,
  };
}

function buildGuestDeliveryFailuresResponse(
  records: GuestRecord[],
  statusFilter = "",
) {
  const history = statusFilter
    ? records.filter((item) => item.status === statusFilter)
    : records;
  const now = new Date("2026-05-05T12:15:00Z").getTime();
  const approvalErrors = new Map<string, number>();
  const inviteErrors = new Map<string, number>();
  const sponsors = new Map<
    string,
    {
      name: string;
      delivery_issue_records_count: number;
      approval_delivery_failed_count: number;
      invite_failed_count: number;
      pending_invite_queue_count: number;
      total_failure_count: number;
      avg_pending_invite_queue_minutes: number;
      max_pending_invite_queue_minutes: number;
      latest_issue_at?: string;
      queue_total_minutes: number;
      queue_samples: number;
    }
  >();
  const companies = new Map<
    string,
    {
      name: string;
      delivery_issue_records_count: number;
      approval_delivery_failed_count: number;
      invite_failed_count: number;
      pending_invite_queue_count: number;
      total_failure_count: number;
      avg_pending_invite_queue_minutes: number;
      max_pending_invite_queue_minutes: number;
      latest_issue_at?: string;
      queue_total_minutes: number;
      queue_samples: number;
    }
  >();
  const sponsorSet = new Set<string>();
  const companySet = new Set<string>();
  const summary = {
    window_hours: 24,
    bucket_count: 6,
    bucket_minutes: 60,
    total_records: history.length,
    delivery_issue_records_count: 0,
    approval_delivery_failed_count: 0,
    invite_failed_count: 0,
    pending_invite_queue_count: 0,
    total_failure_count: 0,
    unique_sponsors_window: 0,
    unique_companies_window: 0,
    avg_pending_invite_queue_minutes: 0,
    max_pending_invite_queue_minutes: 0,
    latest_approval_failure_at: "",
    latest_invite_failure_at: "",
    latest_queued_invite_at: "",
    approval_errors: [] as { name: string; count: number }[],
    invite_errors: [] as { name: string; count: number }[],
    sponsors: [] as any[],
    companies: [] as any[],
    buckets: [
      {
        start: "2026-05-05T08:00:00Z",
        end: "2026-05-05T09:00:00Z",
        approval_delivery_failed_count: 0,
        invite_failed_count: 0,
        pending_invite_queue_count: 0,
        total_failure_count: 0,
      },
      {
        start: "2026-05-05T09:00:00Z",
        end: "2026-05-05T10:00:00Z",
        approval_delivery_failed_count: 0,
        invite_failed_count: 0,
        pending_invite_queue_count: 0,
        total_failure_count: 0,
      },
      {
        start: "2026-05-05T10:00:00Z",
        end: "2026-05-05T11:00:00Z",
        approval_delivery_failed_count: 0,
        invite_failed_count: 0,
        pending_invite_queue_count: 0,
        total_failure_count: 0,
      },
      {
        start: "2026-05-05T11:00:00Z",
        end: "2026-05-05T12:00:00Z",
        approval_delivery_failed_count: 0,
        invite_failed_count: 0,
        pending_invite_queue_count: 0,
        total_failure_count: 0,
      },
      {
        start: "2026-05-05T12:00:00Z",
        end: "2026-05-05T13:00:00Z",
        approval_delivery_failed_count: 0,
        invite_failed_count: 0,
        pending_invite_queue_count: 0,
        total_failure_count: 0,
      },
      {
        start: "2026-05-05T13:00:00Z",
        end: "2026-05-05T14:00:00Z",
        approval_delivery_failed_count: 0,
        invite_failed_count: 0,
        pending_invite_queue_count: 0,
        total_failure_count: 0,
      },
    ],
  };
  let queueTotalMinutes = 0;
  let queueSamples = 0;

  history.forEach((item, index) => {
    const sponsorName =
      item.sponsor_email || item.sponsor_name || item.sponsor_phone || "";
    const companyName = item.company || "";
    const sponsor =
      sponsorName === ""
        ? null
        : sponsors.get(sponsorName) || {
            name: sponsorName,
            delivery_issue_records_count: 0,
            approval_delivery_failed_count: 0,
            invite_failed_count: 0,
            pending_invite_queue_count: 0,
            total_failure_count: 0,
            avg_pending_invite_queue_minutes: 0,
            max_pending_invite_queue_minutes: 0,
            latest_issue_at: "",
            queue_total_minutes: 0,
            queue_samples: 0,
          };
    if (sponsorName !== "") {
      sponsors.set(sponsorName, sponsor!);
    }
    const company =
      companyName === ""
        ? null
        : companies.get(companyName) || {
            name: companyName,
            delivery_issue_records_count: 0,
            approval_delivery_failed_count: 0,
            invite_failed_count: 0,
            pending_invite_queue_count: 0,
            total_failure_count: 0,
            avg_pending_invite_queue_minutes: 0,
            max_pending_invite_queue_minutes: 0,
            latest_issue_at: "",
            queue_total_minutes: 0,
            queue_samples: 0,
          };
    if (companyName !== "") {
      companies.set(companyName, company!);
    }

    let issueRecord = false;
    const bucket = summary.buckets[Math.min(index, summary.buckets.length - 1)];
    const createdAt = item.created_at
      ? Date.parse(item.created_at)
      : Number.NaN;
    const approvedAt = item.approved_at
      ? Date.parse(item.approved_at)
      : Number.NaN;
    const updatedAt = item.updated_at
      ? Date.parse(item.updated_at)
      : Number.NaN;
    const inviteAnchor = !Number.isNaN(approvedAt) ? approvedAt : createdAt;

    const latestStamp = (current: string, next?: string) =>
      !next ? current : !current || next > current ? next : current;

    const issueAtText = !Number.isNaN(updatedAt)
      ? new Date(updatedAt).toISOString()
      : item.created_at || "";

    if (item.approval_delivery_status === "failed") {
      issueRecord = true;
      summary.approval_delivery_failed_count += 1;
      summary.total_failure_count += 1;
      bucket.approval_delivery_failed_count += 1;
      bucket.total_failure_count += 1;
      const errorName = item.approval_delivery_error || "unspecified";
      approvalErrors.set(errorName, (approvalErrors.get(errorName) || 0) + 1);
      summary.latest_approval_failure_at = latestStamp(
        summary.latest_approval_failure_at,
        issueAtText,
      );
      if (sponsor) {
        sponsor.approval_delivery_failed_count += 1;
        sponsor.total_failure_count += 1;
        sponsor.latest_issue_at = latestStamp(
          sponsor.latest_issue_at || "",
          issueAtText,
        );
        sponsorSet.add(sponsor.name);
      }
      if (company) {
        company.approval_delivery_failed_count += 1;
        company.total_failure_count += 1;
        company.latest_issue_at = latestStamp(
          company.latest_issue_at || "",
          issueAtText,
        );
        companySet.add(company.name);
      }
    }

    if (item.invite_delivery_status === "failed") {
      issueRecord = true;
      summary.invite_failed_count += 1;
      summary.total_failure_count += 1;
      bucket.invite_failed_count += 1;
      bucket.total_failure_count += 1;
      const errorName = item.invite_delivery_error || "unspecified";
      inviteErrors.set(errorName, (inviteErrors.get(errorName) || 0) + 1);
      summary.latest_invite_failure_at = latestStamp(
        summary.latest_invite_failure_at,
        issueAtText,
      );
      if (sponsor) {
        sponsor.invite_failed_count += 1;
        sponsor.total_failure_count += 1;
        sponsor.latest_issue_at = latestStamp(
          sponsor.latest_issue_at || "",
          issueAtText,
        );
        sponsorSet.add(sponsor.name);
      }
      if (company) {
        company.invite_failed_count += 1;
        company.total_failure_count += 1;
        company.latest_issue_at = latestStamp(
          company.latest_issue_at || "",
          issueAtText,
        );
        companySet.add(company.name);
      }
    }

    if (item.invite_delivery_status === "queued") {
      issueRecord = true;
      summary.pending_invite_queue_count += 1;
      bucket.pending_invite_queue_count += 1;
      const queuedAtText =
        !Number.isNaN(inviteAnchor) && inviteAnchor > 0
          ? new Date(inviteAnchor).toISOString()
          : item.created_at || "";
      summary.latest_queued_invite_at = latestStamp(
        summary.latest_queued_invite_at,
        queuedAtText,
      );
      if (!Number.isNaN(inviteAnchor) && inviteAnchor > 0) {
        const queueMinutes = Math.max(
          0,
          Math.floor((now - inviteAnchor) / 60000),
        );
        queueTotalMinutes += queueMinutes;
        queueSamples += 1;
        summary.max_pending_invite_queue_minutes = Math.max(
          summary.max_pending_invite_queue_minutes,
          queueMinutes,
        );
        if (sponsor) {
          sponsor.pending_invite_queue_count += 1;
          sponsor.queue_total_minutes += queueMinutes;
          sponsor.queue_samples += 1;
          sponsor.max_pending_invite_queue_minutes = Math.max(
            sponsor.max_pending_invite_queue_minutes,
            queueMinutes,
          );
          sponsor.latest_issue_at = latestStamp(
            sponsor.latest_issue_at || "",
            queuedAtText,
          );
          sponsorSet.add(sponsor.name);
        }
        if (company) {
          company.pending_invite_queue_count += 1;
          company.queue_total_minutes += queueMinutes;
          company.queue_samples += 1;
          company.max_pending_invite_queue_minutes = Math.max(
            company.max_pending_invite_queue_minutes,
            queueMinutes,
          );
          company.latest_issue_at = latestStamp(
            company.latest_issue_at || "",
            queuedAtText,
          );
          companySet.add(company.name);
        }
      }
    }

    if (issueRecord) {
      summary.delivery_issue_records_count += 1;
      if (sponsor) sponsor.delivery_issue_records_count += 1;
      if (company) company.delivery_issue_records_count += 1;
    }
  });

  summary.unique_sponsors_window = sponsorSet.size;
  summary.unique_companies_window = companySet.size;
  if (queueSamples > 0) {
    summary.avg_pending_invite_queue_minutes = Math.floor(
      queueTotalMinutes / queueSamples,
    );
  }
  summary.approval_errors = Array.from(approvalErrors.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.invite_errors = Array.from(inviteErrors.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  summary.sponsors = Array.from(sponsors.values())
    .map((item) => ({
      ...item,
      avg_pending_invite_queue_minutes:
        item.queue_samples > 0
          ? Math.floor(item.queue_total_minutes / item.queue_samples)
          : 0,
    }))
    .sort(
      (a, b) =>
        b.total_failure_count - a.total_failure_count ||
        b.pending_invite_queue_count - a.pending_invite_queue_count ||
        a.name.localeCompare(b.name),
    );
  summary.companies = Array.from(companies.values())
    .map((item) => ({
      ...item,
      avg_pending_invite_queue_minutes:
        item.queue_samples > 0
          ? Math.floor(item.queue_total_minutes / item.queue_samples)
          : 0,
    }))
    .sort(
      (a, b) =>
        b.total_failure_count - a.total_failure_count ||
        b.pending_invite_queue_count - a.pending_invite_queue_count ||
        a.name.localeCompare(b.name),
    );

  return {
    generated_at: "2026-05-05T12:15:00Z",
    status: statusFilter,
    window_hours: summary.window_hours,
    bucket_count: summary.bucket_count,
    summary,
  };
}

function buildGuestSponsorAnalyticsResponse(
  records: GuestRecord[],
  statusFilter = "",
) {
  const history = statusFilter
    ? records.filter((item) => item.status === statusFilter)
    : records;
  const now = new Date("2026-05-05T12:15:00Z").getTime();
  const sponsors = new Map<
    string,
    {
      name: string;
      pending_count: number;
      approved_count: number;
      rejected_count: number;
      completed_count: number;
      older_than_30_minutes_count: number;
      older_than_4_hours_count: number;
      older_than_24_hours_count: number;
      avg_approval_minutes: number;
      max_approval_minutes: number;
      latest_submitted_at?: string;
      latest_approved_at?: string;
      approval_total_minutes: number;
      approval_samples: number;
    }
  >();
  const companies = new Map<string, number>();
  const sponsorSet = new Set<string>();
  const companySet = new Set<string>();
  const summary = {
    window_hours: 24,
    bucket_count: 24,
    bucket_minutes: 60,
    total_records: history.length,
    sponsor_approval_required_count: 0,
    pending_sponsor_approval_count: 0,
    pending_older_than_30_minutes_count: 0,
    pending_older_than_4_hours_count: 0,
    pending_older_than_24_hours_count: 0,
    approved_with_sponsor_count: 0,
    rejected_with_sponsor_count: 0,
    completed_with_sponsor_count: 0,
    unique_sponsors_window: 0,
    unique_companies_window: 0,
    avg_approval_minutes: 0,
    max_approval_minutes: 0,
    avg_pending_approval_minutes: 0,
    max_pending_approval_minutes: 0,
    latest_submitted_at: "",
    latest_approved_at: "",
    latest_rejected_at: "",
    sponsors: [] as any[],
    companies: [] as { name: string; count: number }[],
    buckets: [
      {
        start: "2026-05-05T08:00:00Z",
        end: "2026-05-05T09:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        pending_older_than_30_minutes_count: 0,
        pending_older_than_4_hours_count: 0,
        pending_older_than_24_hours_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T09:00:00Z",
        end: "2026-05-05T10:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        pending_older_than_30_minutes_count: 0,
        pending_older_than_4_hours_count: 0,
        pending_older_than_24_hours_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T10:00:00Z",
        end: "2026-05-05T11:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        pending_older_than_30_minutes_count: 0,
        pending_older_than_4_hours_count: 0,
        pending_older_than_24_hours_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T11:00:00Z",
        end: "2026-05-05T12:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        pending_older_than_30_minutes_count: 0,
        pending_older_than_4_hours_count: 0,
        pending_older_than_24_hours_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T12:00:00Z",
        end: "2026-05-05T13:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        pending_older_than_30_minutes_count: 0,
        pending_older_than_4_hours_count: 0,
        pending_older_than_24_hours_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
      {
        start: "2026-05-05T13:00:00Z",
        end: "2026-05-05T14:00:00Z",
        submitted_count: 0,
        pending_sponsor_approval_count: 0,
        pending_older_than_30_minutes_count: 0,
        pending_older_than_4_hours_count: 0,
        pending_older_than_24_hours_count: 0,
        approved_count: 0,
        rejected_count: 0,
        completed_count: 0,
      },
    ],
  };
  let pendingTotalMinutes = 0;
  let pendingSamples = 0;
  let approvalTotalMinutes = 0;
  let approvalSamples = 0;

  history.forEach((item, index) => {
    const requiresSponsor =
      !!item.approval_delivery_status &&
      item.approval_delivery_status !== "not_required";
    if (!requiresSponsor) {
      return;
    }
    summary.sponsor_approval_required_count += 1;

    const sponsorName =
      item.sponsor_email ||
      item.sponsor_name ||
      item.sponsor_phone ||
      "missing sponsor";
    const sponsor = sponsors.get(sponsorName) || {
      name: sponsorName,
      pending_count: 0,
      approved_count: 0,
      rejected_count: 0,
      completed_count: 0,
      older_than_30_minutes_count: 0,
      older_than_4_hours_count: 0,
      older_than_24_hours_count: 0,
      avg_approval_minutes: 0,
      max_approval_minutes: 0,
      latest_submitted_at: "",
      latest_approved_at: "",
      approval_total_minutes: 0,
      approval_samples: 0,
    };
    sponsors.set(sponsorName, sponsor);
    sponsorSet.add(sponsorName);
    if (item.company) {
      companies.set(item.company, (companies.get(item.company) || 0) + 1);
      companySet.add(item.company);
    }

    if (
      !summary.latest_submitted_at ||
      item.created_at > summary.latest_submitted_at
    )
      summary.latest_submitted_at = item.created_at;
    if (
      item.created_at &&
      (!sponsor.latest_submitted_at ||
        item.created_at > sponsor.latest_submitted_at)
    )
      sponsor.latest_submitted_at = item.created_at;
    if (
      item.approved_at &&
      (!summary.latest_approved_at ||
        item.approved_at > summary.latest_approved_at)
    )
      summary.latest_approved_at = item.approved_at;
    if (
      item.approved_at &&
      (!sponsor.latest_approved_at ||
        item.approved_at > sponsor.latest_approved_at)
    )
      sponsor.latest_approved_at = item.approved_at;
    if (
      item.rejected_at &&
      (!summary.latest_rejected_at ||
        item.rejected_at > summary.latest_rejected_at)
    )
      summary.latest_rejected_at = item.rejected_at;

    const bucket = summary.buckets[Math.min(index, summary.buckets.length - 1)];
    bucket.submitted_count += 1;

    if (item.status === "pending") {
      summary.pending_sponsor_approval_count += 1;
      sponsor.pending_count += 1;
      bucket.pending_sponsor_approval_count += 1;
      const createdAt = Date.parse(item.created_at);
      if (!Number.isNaN(createdAt)) {
        const pendingMinutes = Math.max(
          0,
          Math.floor((now - createdAt) / 60000),
        );
        pendingTotalMinutes += pendingMinutes;
        pendingSamples += 1;
        summary.max_pending_approval_minutes = Math.max(
          summary.max_pending_approval_minutes,
          pendingMinutes,
        );
        if (pendingMinutes >= 30) {
          summary.pending_older_than_30_minutes_count += 1;
          sponsor.older_than_30_minutes_count += 1;
          bucket.pending_older_than_30_minutes_count += 1;
        }
        if (pendingMinutes >= 240) {
          summary.pending_older_than_4_hours_count += 1;
          sponsor.older_than_4_hours_count += 1;
          bucket.pending_older_than_4_hours_count += 1;
        }
        if (pendingMinutes >= 1440) {
          summary.pending_older_than_24_hours_count += 1;
          sponsor.older_than_24_hours_count += 1;
          bucket.pending_older_than_24_hours_count += 1;
        }
      }
    }

    if (item.status === "approved") {
      summary.approved_with_sponsor_count += 1;
      sponsor.approved_count += 1;
      bucket.approved_count += 1;
    }
    if (item.status === "rejected") {
      summary.rejected_with_sponsor_count += 1;
      sponsor.rejected_count += 1;
      bucket.rejected_count += 1;
    }
    if (item.status === "completed") {
      summary.completed_with_sponsor_count += 1;
      sponsor.completed_count += 1;
      bucket.completed_count += 1;
    }

    if (item.created_at && item.approved_at) {
      const createdAt = Date.parse(item.created_at);
      const approvedAt = Date.parse(item.approved_at);
      if (
        !Number.isNaN(createdAt) &&
        !Number.isNaN(approvedAt) &&
        approvedAt > createdAt
      ) {
        const approvalMinutes = Math.floor((approvedAt - createdAt) / 60000);
        approvalTotalMinutes += approvalMinutes;
        approvalSamples += 1;
        summary.max_approval_minutes = Math.max(
          summary.max_approval_minutes,
          approvalMinutes,
        );
        sponsor.approval_total_minutes += approvalMinutes;
        sponsor.approval_samples += 1;
        sponsor.max_approval_minutes = Math.max(
          sponsor.max_approval_minutes,
          approvalMinutes,
        );
      }
    }
  });

  summary.unique_sponsors_window = sponsorSet.size;
  summary.unique_companies_window = companySet.size;
  if (approvalSamples > 0) {
    summary.avg_approval_minutes = Math.floor(
      approvalTotalMinutes / approvalSamples,
    );
  }
  if (pendingSamples > 0) {
    summary.avg_pending_approval_minutes = Math.floor(
      pendingTotalMinutes / pendingSamples,
    );
  }
  summary.sponsors = Array.from(sponsors.values())
    .map((item) => ({
      ...item,
      avg_approval_minutes:
        item.approval_samples > 0
          ? Math.floor(item.approval_total_minutes / item.approval_samples)
          : 0,
    }))
    .sort((a, b) => {
      if (b.pending_count !== a.pending_count)
        return b.pending_count - a.pending_count;
      if (b.older_than_24_hours_count !== a.older_than_24_hours_count)
        return b.older_than_24_hours_count - a.older_than_24_hours_count;
      return a.name.localeCompare(b.name);
    });
  summary.companies = Array.from(companies.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  return {
    generated_at: "2026-05-05T12:15:00Z",
    status: statusFilter,
    window_hours: summary.window_hours,
    bucket_count: summary.bucket_count,
    summary,
  };
}

export async function seedAuthenticatedSession(
  page: Page,
  token = "token-super",
) {
  await page.addInitScript((seedToken) => {
    localStorage.setItem("token", seedToken);
    localStorage.setItem("auth_mode", "token");
  }, token);
}

export async function installMockApi(page: Page, options: MockOptions = {}) {
  const state = {
    settings: createSettings(),
    deploymentPreview: createDeploymentPreview(),
    systemStatus: createSystemStatus(),
    productionReadiness: createProductionReadiness(),
    identity: options.identity || SUPER_ADMIN,
    authOptions: options.authOptions || {
      token_login: true,
      sso: {
        enabled: true,
        provider: "oidc",
        supported: true,
        redirect_url: "http://127.0.0.1:4173/login",
        issuer_url: "https://sso.example.test",
      },
    },
    networkApplied: false,
    networkBackups: [
      {
        id: "snap-001",
        created_at: "2026-05-05T12:00:00Z",
        interfaces: 2,
        gateways: 1,
        routes: 1,
        dnsmasq_enabled: true,
        has_firewall: true,
        created_by: "seed",
        reason: "pre-apply",
      },
    ],
    networkApplyHistory: [
      {
        id: 1,
        action: "apply",
        status: "success",
        summary: "Previous edge-network apply completed successfully.",
        backup_id: "snap-001",
        actor: "seed",
        created_at: "2026-05-05T12:00:00Z",
      },
    ],
    haHistory: [
      {
        id: 1,
        event_type: "replication_publish",
        status: "success",
        summary: "Published shared HA replication package.",
        node_role: "active",
        actor: "",
        created_at: "2026-05-05T12:00:00Z",
      },
      {
        id: 2,
        event_type: "failover",
        status: "promoted",
        summary: "Standby node promoted after peer failure.",
        node_role: "standby",
        actor: "",
        created_at: "2026-05-05T11:50:00Z",
      },
    ],
    auditHistory: [
      {
        id: 1,
        timestamp: "2026-05-05T12:00:00Z",
        user: "Aegis Admin",
        action: "download_support_bundle",
        details: "aegisnas-support-bundle.zip",
        result: "downloaded",
        ip_address: "192.168.50.10",
      },
      {
        id: 2,
        timestamp: "2026-05-05T12:10:30Z",
        user: "Aegis Admin",
        action: "apply_edge_network",
        details: "snap-002",
        result: "confirmed",
        ip_address: "192.168.50.10",
      },
    ],
	vouchers: createVouchers(),
	aclPolicies: [
		{
			id: 1,
			name: "guest-internet",
			description: "Permit guest web access.",
			enabled: true,
			inbound_acl: "guest-in",
			outbound_acl: "guest-out",
			rules: [
				{
					action: "permit",
					direction: "in",
					protocol: "tcp",
					source: "any",
					destination: "any",
					destination_port: "443",
				},
			],
		},
	],
    sessionHistory: [
      {
        id: "sess-001",
        username: "alice",
        mac: "aa:bb:cc:dd:ee:ff",
        ip: "192.168.50.10",
        auth_method: "dot1x",
        identity_source: "local-users",
        vlan: 20,
        role: "employee",
        bandwidth_profile: "10m-down-5m-up",
        filter_id: "corp-access",
        radius_class: "radius-class-1",
        session_timeout: 3600,
        idle_timeout: 900,
        acct_session_time: 1800,
        called_station_id: "ap-lab-1",
        nas_identifier: "switch-lab-1",
        radius_session_id: "radius-001",
        start_time: "2026-05-05T11:30:00Z",
        last_activity: "2026-05-05T11:59:00Z",
        end_time: "",
        stop_reason: "",
        bytes_in: 1024,
        bytes_out: 2048,
        total_bytes: 3072,
      },
      {
        id: "sess-000",
        username: "bob",
        mac: "11:22:33:44:55:66",
        ip: "192.168.50.22",
        auth_method: "mab",
        identity_source: "device-inventory",
        vlan: 30,
        role: "iot",
        bandwidth_profile: "2m-down-1m-up",
        filter_id: "iot-access",
        radius_class: "radius-class-2",
        session_timeout: 7200,
        idle_timeout: 600,
        acct_session_time: 2400,
        called_station_id: "ap-lab-2",
        nas_identifier: "switch-lab-2",
        radius_session_id: "radius-000",
        start_time: "2026-05-05T10:00:00Z",
        last_activity: "2026-05-05T10:40:00Z",
        end_time: "2026-05-05T10:40:00Z",
        stop_reason: "user-request",
        bytes_in: 4096,
        bytes_out: 8192,
        total_bytes: 12288,
      },
    ],
    dhcpLeases: [
      {
        expires_at: "2026-05-05T13:00:00Z",
        remaining_seconds: 3600,
        mac: "aa:bb:cc:dd:ee:ff",
        ip: "192.168.50.10",
        hostname: "lab-client",
        client_id: "",
        reservation: true,
        expired: false,
      },
    ],
    dhcpLeaseHistory: [
      {
        id: 1,
        observed_at: "2026-05-05T11:55:00Z",
        mac: "aa:bb:cc:dd:ee:ff",
        ip: "192.168.50.10",
        hostname: "lab-client",
        client_id: "",
        reservation: true,
        expired: false,
        expires_at: "2026-05-05T13:00:00Z",
        remaining_seconds: 3600,
      },
    ],
    guestRegistrations: options.guestRegistrations || [
      {
        id: "guest-1",
        full_name: "Alice Guest",
        company: "LabCo",
        email: "alice@example.test",
        sponsor_name: "Sam Sponsor",
        sponsor_email: "sam@example.test",
        status: "pending",
        role: "guest-basic",
        approval_delivery_status: "sent",
        invite_delivery_status: "queued",
        created_at: "2026-05-05T12:00:00Z",
      },
      {
        id: "guest-2",
        full_name: "Bob Visitor",
        company: "Visitors Inc",
        email: "bob@example.test",
        sponsor_name: "Taylor Sponsor",
        sponsor_email: "taylor@example.test",
        status: "pending",
        role: "guest-standard",
        approval_delivery_status: "sent",
        invite_delivery_status: "queued",
        created_at: "2026-05-05T12:05:00Z",
      },
      {
        id: "guest-3",
        full_name: "Carla Declined",
        company: "Visitors Inc",
        email: "carla@example.test",
        sponsor_name: "Jordan Sponsor",
        sponsor_email: "jordan@example.test",
        status: "rejected",
        role: "guest-standard",
        approval_delivery_status: "failed",
        approval_delivery_error: "smtp bounce",
        invite_delivery_status: "failed",
        invite_delivery_error: "smtp timeout",
        rejection_reason: "Missing sponsor clearance",
        created_at: "2026-05-05T10:45:00Z",
        updated_at: "2026-05-05T11:15:00Z",
        rejected_at: "2026-05-05T11:15:00Z",
      },
    ],
    integrationHistory: [
      {
        id: 1,
        component: "controller_automation",
        status: "ok",
        summary: "Controller sync completed.",
        details: { adapter: "cisco", sync_count: 2 },
        created_at: "2026-05-05T11:58:00Z",
      },
      {
        id: 2,
        component: "mdm_sync",
        status: "degraded",
        summary: "MDM sync needs attention.",
        details: { provider: "intune" },
        created_at: "2026-05-05T11:59:00Z",
      },
    ],
    vendorIdentity: {
      status: "lab",
      ready: false,
      current: { name: "AegisNAS", pen: 55555, identity_mode: "lab" },
      config_evidence_valid: false,
      legacy_window_active: false,
      migrations: [] as Record<string, any>[],
      metrics: { previewed: 0, applying: 0, applied: 0, failed: 0, rolled_back: 0 },
      warnings: ["The lab PEN must not be used for production vendor-specific attributes."],
    } as any,
    networkRecovery: null as null | Record<string, any>,
  };

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const method = request.method().toUpperCase();

    if (path === "/auth/sso/start" && method === "GET") {
      await route.fulfill({
        status: 302,
        headers: { location: "/login#sso_token=sso-demo&auth_mode=sso" },
        body: "",
      });
      return;
    }

    if (path === "/auth/options" && method === "GET") {
      await route.fulfill({ json: state.authOptions });
      return;
    }

    if (path === "/auth/validate" && method === "GET") {
      const authHeader = request.headers()["authorization"] || "";
      if (
        authHeader === "Bearer token-super" ||
        authHeader === "Bearer sso-demo"
      ) {
        await route.fulfill({
          json: {
            identity: {
              ...state.identity,
              source: authHeader.includes("sso-demo")
                ? "sso"
                : state.identity.source,
            },
          },
        });
      } else {
        await route.fulfill({ status: 401, json: { error: "invalid token" } });
      }
      return;
    }

    if (path === "/auth/logout" && method === "POST") {
      await route.fulfill({ json: { status: "ok" } });
      return;
    }

    if (path === "/system/status" && method === "GET") {
      await route.fulfill({ json: state.systemStatus });
      return;
    }

	if (path === "/system/production-readiness" && method === "GET") {
		await route.fulfill({ json: state.productionReadiness });
		return;
	}

	if (path === "/system/controller-sync/preview" && method === "GET") {
		const operation = url.searchParams.get("operation") === "push" ? "push" : "pull";
		await route.fulfill({
			json: {
				preview: {
					operation,
					adapter: "generic-rest",
					method: operation === "push" ? "POST" : "GET",
					target_url:
						operation === "push"
							? "https://controller.example.test/api/sync"
							: "https://controller.example.test/api/state",
					desired_state_hash: "desired-controller-state",
				},
				push_confirmation: "PUSH CONTROLLER POLICY",
			},
		});
		return;
	}

	if (path === "/system/controller-sync" && method === "POST") {
		const body = parseBody(route);
		const operation = body.operation === "push" ? "push" : "pull";
		await route.fulfill({
			json: {
				status: operation === "pull" ? "degraded" : "ok",
				message:
					operation === "pull"
						? "Controller pull completed with detected policy drift."
						: "Controller push completed successfully.",
				result: {
					operation,
					drift_detected: operation === "pull",
					drift_count: operation === "pull" ? 2 : 0,
					applied_count: operation === "push" ? 3 : 0,
					failed_count: 0,
					desired_state_hash: "desired-controller-state",
					observed_state_hash:
						operation === "pull" ? "observed-controller-state" : "desired-controller-state",
				},
			},
		});
		return;
	}

    if (path === "/system/vendor-compatibility" && method === "GET") {
      await route.fulfill({
        json: {
          summary: {
            product_vendor_id: state.vendorIdentity.current.pen,
            product_vendor_name: "AegisNAS",
            dictionary_release_profile_id: "freeradius-3.2.8",
            dictionary_release: "3.2.8",
            dictionary_release_source_sha256: "6".repeat(64),
            product_vendor_id_source: "config:radius.vendor.id",
            product_vendor_id_placeholder: state.vendorIdentity.current.pen === 55555,
            product_vendor_dictionary_filename: "dictionary.aegisnas",
            product_vendor_dictionary_install_path: "/etc/freeradius/3.0/dictionary.aegisnas",
            product_vendor_dictionary_include: "$INCLUDE dictionary.aegisnas",
            product_attribute_count: 13,
            semantic_count: 29,
            pack_count: 1,
            implemented_count: 10,
            planned_count: 19,
            hardware_profiles: ["lite", "branch", "enterprise"],
            product_vendor_assigned_organization: state.vendorIdentity.current.assigned_organization,
          },
          active_packs: ["aegisnas"],
          packs: [],
          dictionary_release_profile: {
            id: "freeradius-3.2.8",
            release: "3.2.8",
            status: "active",
            default: true,
            registry_source_sha256: "6".repeat(64),
            source_file_count: 246,
            source_attribute_count: 7654,
            effective_attribute_count: 7661,
            vendor_count: 196,
            mapped_attribute_count: 148,
            runtime_decoder_count: 134,
            vendor_alias_count: 43,
            attribute_alias_count: 10,
            firmware_profile_count: 9,
            vendor_aliases: [
              { alias: "unifi", canonical_vendor: "Ubiquiti", canonical_pack_key: "ubnt", pen: 41112, scope: "controller family" },
              { alias: "routeros", canonical_vendor: "Mikrotik", canonical_pack_key: "mikrotik", pen: 14988, scope: "product firmware" },
            ],
            firmware_profiles: [
              { key: "ubiquiti-unifi-network", vendor: "Ubiquiti", pack_key: "ubnt", pen: 41112, product_family: "UniFi Network", firmware_scope: "UniFi Network controllers and AP firmware that accept UBNT rate VSAs", hardware_profiles: ["branch", "enterprise"], support_state: "software-ready", evidence_state: "external-certification-required", attribute_scope: ["UBNT-Data-Rate-DL", "UBNT-Data-Rate-UL"] },
              { key: "mikrotik-routeros", vendor: "Mikrotik", pack_key: "mikrotik", pen: 14988, product_family: "RouterOS", firmware_scope: "RouterOS 6.x and 7.x dictionary-compatible RADIUS attributes", hardware_profiles: ["lite", "branch", "enterprise"], support_state: "software-ready", evidence_state: "external-certification-required", attribute_scope: ["Mikrotik-Rate-Limit"] },
            ],
          },
          client_profiles: [],
          profile_summary: { total_clients: 0, enabled_clients: 0, profile_counts: {}, global_fallback_client_count: 0, known_vendor_profile_clients: 0 },
          dictionary_coverage: { catalog_vendor_count: 1, catalog_attribute_count: 13, pack_count: 1, active_pack_count: 1, dictionary_backed_pack_count: 1, partial_dictionary_pack_count: 0, missing_dictionary_vendor_count: 0, dictionary_matched_attribute_count: 13, missing_dictionary_attribute_count: 0, rows: [] },
          semantics: [],
          notes: [],
        },
      });
      return;
    }

    if (path === "/system/attribute-registry" && method === "GET") {
      const vendor = (url.searchParams.get("vendor") || "Aruba").trim();
      const entries = [
        { key: "freeradius:3.2.8:14823:aruba-user-role", source: "freeradius-3.2.8", release_profile_id: "freeradius-3.2.8", vendor: "Aruba", pen: 14823, attribute: "Aruba-User-Role", number: 1, wire_type: "string", capability_family: "Authorization", dictionary_status: "partial", pack_key: "aruba", semantic: "access.role", semantic_provenance: "freeradius-audit:3.2.8", directions: ["inbound", "outbound_reply"], decode_kind: "string" },
        { key: "freeradius:3.2.8:14823:aruba-user-vlan", source: "freeradius-3.2.8", release_profile_id: "freeradius-3.2.8", vendor: "Aruba", pen: 14823, attribute: "Aruba-User-Vlan", number: 2, wire_type: "integer", capability_family: "Dynamic VLAN", dictionary_status: "partial", pack_key: "aruba", semantic: "access.vlan", semantic_provenance: "freeradius-audit:3.2.8", directions: ["inbound", "outbound_reply"], decode_kind: "vlan" },
      ].filter((entry) => !vendor || entry.vendor.toLowerCase() === vendor.toLowerCase());
      await route.fulfill({ json: { schema_version: 1, release_profile_id: "freeradius-3.2.8", source_release: "3.2.8", source_file_count: 246, source_attribute_count: 7654, source_sha256: "6".repeat(64), vendor_count: 196, attribute_count: 7661, mapped_count: 148, filtered_count: entries.length, entries } });
      return;
    }

    if (path === "/system/vendor-identity" && method === "GET") {
      await route.fulfill({ json: state.vendorIdentity });
      return;
    }

    if (path === "/system/vendor-identity/migrations/preview" && method === "POST") {
      const body = parseBody(route);
      const migrationID = "identity-migration-1";
      state.vendorIdentity.metrics.previewed = 1;
      state.vendorIdentity.migrations = [{ id: migrationID, status: "previewed", from_pen: 55555, to_pen: body.pen, organization: body.expected_organization, expires_at: "2026-07-08T10:15:00Z", created_at: "2026-07-08T10:00:00Z" }];
      await route.fulfill({
        json: {
          migration_id: migrationID,
          confirmation_token: "one-time-confirmation",
          expires_at: "2026-07-08T10:15:00Z",
          current: state.vendorIdentity.current,
          target: { name: "AegisNAS", pen: body.pen, identity_mode: "production", assigned_organization: body.expected_organization, legacy_pens: [55555], legacy_accept_until: "2026-07-15T10:00:00Z" },
          evidence: { pen: body.pen, organization: body.expected_organization, registry_url: "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers.txt", registry_last_updated: "2026-07-06", fetched_at: "2026-07-08T10:00:00Z", registry_sha256: "a".repeat(64), record_sha256: "b".repeat(64) },
          active_sessions: 3,
          affected_systems: ["configuration", "dictionary", "packet codec"],
          warnings: ["Update every peer and integration to the assigned PEN."],
        },
      });
      return;
    }

    if (path === "/system/vendor-identity/migrations/apply" && method === "POST") {
      state.vendorIdentity.status = "production_verified";
      state.vendorIdentity.ready = true;
      state.vendorIdentity.config_evidence_valid = true;
      state.vendorIdentity.legacy_window_active = true;
      state.vendorIdentity.current = { name: "AegisNAS", pen: 424242, identity_mode: "production", assigned_organization: "AegisNAS Systems Ltd.", legacy_pens: [55555], legacy_accept_until: "2026-07-15T10:00:00Z" };
      state.vendorIdentity.metrics.applied = 1;
      state.vendorIdentity.warnings = [];
      state.vendorIdentity.migrations[0] = { ...state.vendorIdentity.migrations[0], status: "applied", applied_at: "2026-07-08T10:01:00Z" };
      await route.fulfill({ json: { status: "applied", migration_id: "identity-migration-1", radius_restarted: true } });
      return;
    }

    if (path === "/staged-changes" && method === "GET") {
      await route.fulfill({ json: [] });
      return;
    }

    if (path === "/validate" && method === "POST") {
      await route.fulfill({ json: { changes: 0 } });
      return;
    }

    if (path === "/apply" && method === "POST") {
      await route.fulfill({ json: { changes: 0 } });
      return;
    }

	if (path === "/roles" && method === "GET") {
      await route.fulfill({ json: [{ id: 1, name: "guest-basic" }] });
		return;
	}
	if (path === "/acl-policies" && method === "GET") {
		await route.fulfill({ json: state.aclPolicies });
		return;
	}
	if (path === "/acl-policies" && method === "POST") {
		await route.fulfill({ status: 202, json: { status: "staged" } });
		return;
	}
    if (path === "/portal-profiles" && method === "GET") {
      await route.fulfill({ json: [{ id: 1, name: "default-guest" }] });
      return;
    }
    if (path === "/identity-sources" && method === "GET") {
      await route.fulfill({ json: [{ id: 1, name: "local-users" }] });
      return;
    }
	if (path === "/bandwidth-profiles" && method === "GET") {
      await route.fulfill({ json: [{ id: 1, name: "10m-down-5m-up" }] });
      return;
    }
    if (path === "/radius-clients" && method === "GET") {
      await route.fulfill({ json: [{ id: 1, shortname: "secure-nas", ip: "192.0.2.10", secret_set: true, nas_type: "cisco", transport: "radsec", radsec_certificate_cn: "secure-nas.example.test", radsec_radius_v11: "forbid", description: "Branch NAS", enabled: true }] });
      return;
    }
    if (path === "/radius-clients" && method === "POST") {
      await route.fulfill({ status: 202, json: { status: "staged" } });
      return;
    }

    if (path === "/system/settings" && method === "GET") {
      await route.fulfill({ json: state.settings });
      return;
    }
    if (path === "/system/settings" && method === "PUT") {
      state.settings = parseBody(route);
      await route.fulfill({ json: { settings: state.settings } });
      return;
    }
    if (path === "/system/settings/evaluate" && method === "POST") {
      await route.fulfill({
        json: { valid: true, deployment: state.deploymentPreview },
      });
      return;
    }
    if (path === "/system/hostapd-preview" && method === "GET") {
      await route.fulfill({
        json: {
          path: "/etc/hostapd/hostapd.conf",
          config: "# hostapd preview",
        },
      });
      return;
    }
    if (path === "/system/dhcp-leases" && method === "GET") {
      await route.fulfill({
        json: {
          leases: state.dhcpLeases,
          count: state.dhcpLeases.length,
          dhcp_enabled: true,
          lease_file: "/var/lib/misc/dnsmasq.leases",
          generated_at: "2026-05-05T12:00:00Z",
          static_leases: 1,
          authoritative: true,
          lease_duration: "12h",
        },
      });
      return;
    }
    if (path === "/system/dhcp-lease-history" && method === "GET") {
      await route.fulfill({
        json: {
          history: state.dhcpLeaseHistory,
          count: state.dhcpLeaseHistory.length,
          generated_at: "2026-05-05T12:00:00Z",
        },
      });
      return;
    }
    if (path === "/system/dhcp-lease-history/export" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: "id,observed_at,mac,ip,hostname,client_id,reservation,expired,expires_at,remaining_seconds\n1,2026-05-05T11:55:00Z,aa:bb:cc:dd:ee:ff,192.168.50.10,lab-client,,true,false,2026-05-05T13:00:00Z,3600\n",
      });
      return;
    }
    if (path === "/sessions" && method === "GET") {
      await route.fulfill({
        json: state.sessionHistory.map((item) => ({
          id: item.id,
          username: item.username,
          mac: item.mac,
          ip: item.ip,
          auth_method: item.auth_method,
          vlan: item.vlan,
          start_time: item.start_time,
          last_activity: item.last_activity,
          end_time: item.end_time,
          bytes_in: item.bytes_in,
          bytes_out: item.bytes_out,
        })),
      });
      return;
    }
    if (path.startsWith("/sessions/") && method === "DELETE") {
      const id = path.split("/")[2];
      state.sessionHistory = state.sessionHistory.map((item) =>
        item.id === id && !item.end_time
          ? {
              ...item,
              end_time: "2026-05-05T12:00:00Z",
              stop_reason: "admin",
            }
          : item,
      );
      await route.fulfill({ status: 204, body: "" });
      return;
    }
    if (path === "/system/session-history" && method === "GET") {
      const username = url.searchParams.get("username") || "";
      const authMethod = url.searchParams.get("auth_method") || "";
      const active = url.searchParams.get("active") || "";
      let history = [...state.sessionHistory];
      if (username) {
        history = history.filter((item) => item.username === username);
      }
      if (authMethod) {
        history = history.filter((item) => item.auth_method === authMethod);
      }
      if (active === "true") {
        history = history.filter((item) => !item.end_time);
      } else if (active === "false") {
        history = history.filter((item) => Boolean(item.end_time));
      }
      const stats = history.reduce(
        (acc, item) => {
          acc.total_records += 1;
          if (item.end_time) {
            acc.ended_count += 1;
          } else {
            acc.active_count += 1;
          }
          if (
            item.acct_session_time > 0 ||
            item.bytes_in > 0 ||
            item.bytes_out > 0
          ) {
            acc.accounted_record_count += 1;
          }
          acc.bytes_in_total += item.bytes_in;
          acc.bytes_out_total += item.bytes_out;
          acc.traffic_total += item.total_bytes;
          acc.acct_session_seconds_total += item.acct_session_time;
          acc.max_acct_session_seconds = Math.max(
            acc.max_acct_session_seconds,
            item.acct_session_time,
          );
          if (!acc.last_started_at || item.start_time > acc.last_started_at) {
            acc.last_started_at = item.start_time;
          }
          if (
            item.end_time &&
            (!acc.last_ended_at || item.end_time > acc.last_ended_at)
          ) {
            acc.last_ended_at = item.end_time;
          }
          return acc;
        },
        {
          total_records: 0,
          active_count: 0,
          ended_count: 0,
          accounted_record_count: 0,
          bytes_in_total: 0,
          bytes_out_total: 0,
          traffic_total: 0,
          acct_session_seconds_total: 0,
          avg_acct_session_seconds: 0,
          max_acct_session_seconds: 0,
          last_started_at: "",
          last_ended_at: "",
        },
      );
      if (stats.total_records > 0) {
        stats.avg_acct_session_seconds = Math.trunc(
          stats.acct_session_seconds_total / stats.total_records,
        );
      }
      await route.fulfill({
        json: {
          generated_at: "2026-05-05T12:00:00Z",
          username,
          auth_method: authMethod,
          active: active === "true" ? true : active === "false" ? false : null,
          history,
          count: history.length,
          stats,
        },
      });
      return;
    }
    if (path === "/system/session-history/export" && method === "GET") {
      const format = (url.searchParams.get("format") || "csv").toLowerCase();
      if (format === "json") {
        await route.fulfill({
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            generated_at: "2026-05-05T12:00:00Z",
            username: "",
            auth_method: "",
            active: null,
            history: state.sessionHistory,
            count: state.sessionHistory.length,
            stats: {
              total_records: 2,
              active_count: 1,
              ended_count: 1,
              accounted_record_count: 2,
              bytes_in_total: 5120,
              bytes_out_total: 10240,
              traffic_total: 15360,
              acct_session_seconds_total: 4200,
              avg_acct_session_seconds: 2100,
              max_acct_session_seconds: 2400,
              last_started_at: "2026-05-05T11:30:00Z",
              last_ended_at: "2026-05-05T10:40:00Z",
            },
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: "id,username,mac,ip,auth_method,identity_source,vlan,role,bandwidth_profile,filter_id,radius_class,session_timeout,idle_timeout,acct_session_time,called_station_id,nas_identifier,radius_session_id,start_time,last_activity,end_time,stop_reason,bytes_in,bytes_out,total_bytes\nsess-001,alice,aa:bb:cc:dd:ee:ff,192.168.50.10,dot1x,local-users,20,employee,10m-down-5m-up,corp-access,radius-class-1,3600,900,1800,ap-lab-1,switch-lab-1,radius-001,2026-05-05T11:30:00Z,2026-05-05T11:59:00Z,,,1024,2048,3072\n",
      });
      return;
    }
    if (path === "/system/session-analytics" && method === "GET") {
      const windowHours = Number(url.searchParams.get("window_hours") || "24");
      const bucketCount = Number(url.searchParams.get("bucket_count") || "24");
      await route.fulfill({
        json: {
          generated_at: "2026-05-05T12:00:00Z",
          username: "",
          auth_method: "",
          window_hours: windowHours,
          bucket_count: bucketCount,
          summary: {
            window_hours: windowHours,
            bucket_count: bucketCount,
            bucket_minutes:
              windowHours >= 24
                ? Math.round((windowHours * 60) / bucketCount)
                : 60,
            total_records: state.sessionHistory.length,
            started_count: 2,
            ended_count: state.sessionHistory.filter((item) =>
              Boolean(item.end_time),
            ).length,
            active_now: state.sessionHistory.filter((item) => !item.end_time)
              .length,
            unique_users_window: 2,
            unique_macs_window: 2,
            unique_ips_window: 2,
            ended_traffic_total: 12288,
            ended_session_seconds_total: 2400,
            avg_ended_session_seconds: 2400,
            max_ended_session_seconds: 2400,
            longest_active_session_seconds: 1800,
            peak_concurrent_sessions: 2,
            latest_start_at: "2026-05-05T11:30:00Z",
            latest_end_at: "2026-05-05T10:40:00Z",
            auth_methods: [
              { name: "dot1x", count: 1 },
              { name: "mab", count: 1 },
            ],
            roles: [
              { name: "employee", count: 1 },
              { name: "iot", count: 1 },
            ],
            vlans: [
              { name: "20", count: 1 },
              { name: "30", count: 1 },
            ],
            buckets: [
              {
                start: "2026-05-05T10:00:00Z",
                end: "2026-05-05T11:00:00Z",
                started_count: 1,
                ended_count: 1,
                ended_traffic_total: 12288,
                ended_session_seconds_total: 2400,
              },
              {
                start: "2026-05-05T11:00:00Z",
                end: "2026-05-05T12:00:00Z",
                started_count: 1,
                ended_count: 0,
                ended_traffic_total: 0,
                ended_session_seconds_total: 0,
              },
            ],
          },
        },
      });
      return;
    }
    if (path === "/system/session-analytics/export" && method === "GET") {
      const format = (url.searchParams.get("format") || "csv").toLowerCase();
      if (format === "json") {
        await route.fulfill({
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            generated_at: "2026-05-05T12:00:00Z",
            username: "",
            auth_method: "",
            window_hours: 24,
            bucket_count: 24,
            summary: {
              window_hours: 24,
              bucket_count: 24,
              bucket_minutes: 60,
              total_records: 2,
              started_count: 2,
              ended_count: 1,
              active_now: 1,
              unique_users_window: 2,
              unique_macs_window: 2,
              unique_ips_window: 2,
              ended_traffic_total: 12288,
              ended_session_seconds_total: 2400,
              avg_ended_session_seconds: 2400,
              max_ended_session_seconds: 2400,
              longest_active_session_seconds: 1800,
              peak_concurrent_sessions: 2,
              latest_start_at: "2026-05-05T11:30:00Z",
              latest_end_at: "2026-05-05T10:40:00Z",
              auth_methods: [
                { name: "dot1x", count: 1 },
                { name: "mab", count: 1 },
              ],
              roles: [
                { name: "employee", count: 1 },
                { name: "iot", count: 1 },
              ],
              vlans: [
                { name: "20", count: 1 },
                { name: "30", count: 1 },
              ],
              buckets: [],
            },
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: "section,name,bucket_start,bucket_end,count,bytes_total,seconds_total\nsummary,total_records,,,2,,\nauth_method,dot1x,,,1,,\nbucket,ended_traffic_total,2026-05-05T10:00:00Z,2026-05-05T11:00:00Z,,12288,\n",
      });
      return;
    }
    if (path === "/system/session-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime: state.systemStatus.telemetry.session_exports.runtime,
          exports: [
            {
              name: "aegisnas-session-history-20260505-115300Z.json",
              path: "/var/lib/aegisnas/session-exports/aegisnas-session-history-20260505-115300Z.json",
              format: "json",
              size_bytes: 1320,
              created_at: "2026-05-05T11:53:00Z",
            },
            {
              name: "aegisnas-session-history-20260505-115300Z.csv",
              path: "/var/lib/aegisnas/session-exports/aegisnas-session-history-20260505-115300Z.csv",
              format: "csv",
              size_bytes: 640,
              created_at: "2026-05-05T11:53:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/session-exports/download" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T11:53:00Z",
          username: "",
          auth_method: "",
          active: null,
          history: state.sessionHistory,
          count: state.sessionHistory.length,
          stats: {
            total_records: 2,
            active_count: 1,
            ended_count: 1,
            accounted_record_count: 2,
            bytes_in_total: 5120,
            bytes_out_total: 10240,
            traffic_total: 15360,
            acct_session_seconds_total: 4200,
            avg_acct_session_seconds: 2100,
            max_acct_session_seconds: 2400,
            last_started_at: "2026-05-05T11:30:00Z",
            last_ended_at: "2026-05-05T10:40:00Z",
          },
        }),
      });
      return;
    }
    if (path === "/system/session-analytics-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.session_analytics_exports.runtime,
          exports: [
            {
              name: "aegisnas-session-analytics-20260505-115400Z.json",
              path: "/var/lib/aegisnas/session-analytics-exports/aegisnas-session-analytics-20260505-115400Z.json",
              format: "json",
              size_bytes: 1480,
              created_at: "2026-05-05T11:54:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/guest-lifecycle-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime: state.systemStatus.telemetry.guest_lifecycle_exports.runtime,
          exports: [
            {
              name: "aegisnas-guest-lifecycle-20260505-115500Z.json",
              path: "/var/lib/aegisnas/guest-lifecycle-exports/aegisnas-guest-lifecycle-20260505-115500Z.json",
              format: "json",
              size_bytes: 1720,
              created_at: "2026-05-05T11:55:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/vouchers" && method === "GET") {
      await route.fulfill({ json: state.vouchers });
      return;
    }
    if (path === "/system/voucher-analytics" && method === "GET") {
      await route.fulfill({ json: buildVoucherAnalyticsResponse() });
      return;
    }
    if (path === "/system/voucher-aging-analytics" && method === "GET") {
      await route.fulfill({ json: buildVoucherAgingAnalyticsResponse() });
      return;
    }
    if (path === "/system/voucher-analytics/export" && method === "GET") {
      const url = new URL(route.request().url());
      const format = url.searchParams.get("format") || "json";
      await route.fulfill({
        status: 200,
        headers: {
          "content-type":
            format === "csv" ? "text/csv; charset=utf-8" : "application/json",
        },
        body:
          format === "csv"
            ? "section,name,bucket_start,bucket_end,count,value\nsummary,total_vouchers,,,,5\nsummary,utilization_percent,,,,58\nrole,guest-basic,,,3,\nstate,active,,,2,\n"
            : JSON.stringify(buildVoucherAnalyticsResponse()),
      });
      return;
    }
    if (
      path === "/system/voucher-aging-analytics/export" &&
      method === "GET"
    ) {
      const url = new URL(route.request().url());
      const format = url.searchParams.get("format") || "json";
      await route.fulfill({
        status: 200,
        headers: {
          "content-type":
            format === "csv" ? "text/csv; charset=utf-8" : "application/json",
        },
        body:
          format === "csv"
            ? "section,name,bucket_min_age_minutes,bucket_max_age_minutes,count,value\nsummary,older_than_window_count,,,,1\nsummary,unused_older_than_window_count,,,,1\nolder_role,guest-standard,,,1,\nbucket,voucher_count,0,1440,1,\n"
            : JSON.stringify(buildVoucherAgingAnalyticsResponse()),
      });
      return;
    }
    if (path === "/system/voucher-redemption-analytics" && method === "GET") {
      await route.fulfill({ json: buildVoucherRedemptionAnalyticsResponse() });
      return;
    }
    if (path === "/system/voucher-expiry-analytics" && method === "GET") {
      await route.fulfill({ json: buildVoucherExpiryAnalyticsResponse() });
      return;
    }
    if (
      path === "/system/voucher-redemption-analytics/export" &&
      method === "GET"
    ) {
      const url = new URL(route.request().url());
      const format = url.searchParams.get("format") || "json";
      await route.fulfill({
        status: 200,
        headers: {
          "content-type":
            format === "csv" ? "text/csv; charset=utf-8" : "application/json",
        },
        body:
          format === "csv"
            ? "section,name,bucket_start,bucket_end,count,value\nsummary,redeemed_voucher_count,,,,3\nsummary,avg_sessions_per_redeemed_voucher,,,,,1.33\nrole,guest-basic,,,2,\nbucket,first_redeemed_count,2026-05-31T12:00:00Z,2026-06-01T12:00:00Z,1,\n"
            : JSON.stringify(buildVoucherRedemptionAnalyticsResponse()),
      });
      return;
    }
    if (
      path === "/system/voucher-expiry-analytics/export" &&
      method === "GET"
    ) {
      const url = new URL(route.request().url());
      const format = url.searchParams.get("format") || "json";
      await route.fulfill({
        status: 200,
        headers: {
          "content-type":
            format === "csv" ? "text/csv; charset=utf-8" : "application/json",
        },
        body:
          format === "csv"
            ? "section,name,bucket_start,bucket_end,count,value\nsummary,expiring_in_window_count,,,,4\nsummary,unused_expiring_in_window_count,,,,2\nrole,guest-basic,,,3,\nunused_role,guest-basic,,,2,\nbucket,expiring_count,2026-06-02T12:00:00Z,2026-06-03T12:00:00Z,1,\n"
            : JSON.stringify(buildVoucherExpiryAnalyticsResponse()),
      });
      return;
    }
    if (
      path === "/system/voucher-expiry-analytics-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.voucher_expiry_analytics_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-voucher-expiry-analytics-20260505-115500Z.json",
              path: "/var/lib/aegisnas/voucher-expiry-analytics-exports/aegisnas-voucher-expiry-analytics-20260505-115500Z.json",
              format: "json",
              size_bytes: 1140,
              created_at: "2026-05-05T11:55:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/voucher-analytics-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.voucher_analytics_exports.runtime,
          exports: [
            {
              name: "aegisnas-voucher-analytics-20260505-115430Z.json",
              path: "/var/lib/aegisnas/voucher-analytics-exports/aegisnas-voucher-analytics-20260505-115430Z.json",
              format: "json",
              size_bytes: 1080,
              created_at: "2026-05-05T11:54:30Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/voucher-aging-analytics-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.voucher_aging_analytics_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-voucher-aging-analytics-20260505-115440Z.json",
              path: "/var/lib/aegisnas/voucher-aging-analytics-exports/aegisnas-voucher-aging-analytics-20260505-115440Z.json",
              format: "json",
              size_bytes: 1120,
              created_at: "2026-05-05T11:54:40Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/voucher-redemption-analytics-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.voucher_redemption_analytics_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-voucher-redemption-analytics-20260505-115445Z.json",
              path: "/var/lib/aegisnas/voucher-redemption-analytics-exports/aegisnas-voucher-redemption-analytics-20260505-115445Z.json",
              format: "json",
              size_bytes: 1160,
              created_at: "2026-05-05T11:54:45Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/voucher-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-disposition":
            'attachment; filename="aegisnas-voucher-analytics-20260505-115430Z.json"',
        },
        body: JSON.stringify(buildVoucherAnalyticsResponse()),
      });
      return;
    }
    if (
      path === "/system/voucher-aging-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-disposition":
            'attachment; filename="aegisnas-voucher-aging-analytics-20260505-115440Z.json"',
        },
        body: JSON.stringify(buildVoucherAgingAnalyticsResponse()),
      });
      return;
    }
    if (
      path === "/system/voucher-expiry-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-disposition":
            'attachment; filename="aegisnas-voucher-expiry-analytics-20260505-115500Z.json"',
        },
        body: JSON.stringify(buildVoucherExpiryAnalyticsResponse()),
      });
      return;
    }
    if (
      path === "/system/voucher-redemption-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-disposition":
            'attachment; filename="aegisnas-voucher-redemption-analytics-20260505-115445Z.json"',
        },
        body: JSON.stringify(buildVoucherRedemptionAnalyticsResponse()),
      });
      return;
    }
    if (path === "/system/guest-invite-analytics-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.guest_invite_analytics_exports.runtime,
          exports: [
            {
              name: "aegisnas-guest-invite-analytics-20260505-115530Z.json",
              path: "/var/lib/aegisnas/guest-invite-analytics-exports/aegisnas-guest-invite-analytics-20260505-115530Z.json",
              format: "json",
              size_bytes: 1130,
              created_at: "2026-05-05T11:55:30Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/guest-conversion-analytics-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.guest_conversion_analytics_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-guest-conversion-analytics-20260505-115545Z.json",
              path: "/var/lib/aegisnas/guest-conversion-analytics-exports/aegisnas-guest-conversion-analytics-20260505-115545Z.json",
              format: "json",
              size_bytes: 1290,
              created_at: "2026-05-05T11:55:45Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/guest-rejection-analytics-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.guest_rejection_analytics_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-guest-rejection-analytics-20260505-115550Z.json",
              path: "/var/lib/aegisnas/guest-rejection-analytics-exports/aegisnas-guest-rejection-analytics-20260505-115550Z.json",
              format: "json",
              size_bytes: 1360,
              created_at: "2026-05-05T11:55:50Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/guest-invite-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestInviteAnalyticsResponse(state.guestRegistrations, ""),
        ),
      });
      return;
    }
    if (
      path === "/system/guest-conversion-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestConversionAnalyticsResponse(state.guestRegistrations, ""),
        ),
      });
      return;
    }
    if (
      path === "/system/guest-rejection-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestRejectionAnalyticsResponse(state.guestRegistrations, ""),
        ),
      });
      return;
    }
    if (
      path === "/system/guest-lifecycle-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestLifecycleResponse(state.guestRegistrations, ""),
        ),
      });
      return;
    }
    if (
      path === "/system/guest-delivery-analytics-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.guest_delivery_analytics_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-guest-delivery-analytics-20260505-115600Z.json",
              path: "/var/lib/aegisnas/guest-delivery-analytics-exports/aegisnas-guest-delivery-analytics-20260505-115600Z.json",
              format: "json",
              size_bytes: 1460,
              created_at: "2026-05-05T11:56:00Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/guest-delivery-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestDeliveryAnalyticsResponse(state.guestRegistrations, ""),
        ),
      });
      return;
    }
    if (
      path === "/system/guest-delivery-failures-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.guest_delivery_failures_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-guest-delivery-failures-20260505-115630Z.json",
              path: "/var/lib/aegisnas/guest-delivery-failures-exports/aegisnas-guest-delivery-failures-20260505-115630Z.json",
              format: "json",
              size_bytes: 1510,
              created_at: "2026-05-05T11:56:30Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/guest-delivery-failures-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestDeliveryFailuresResponse(state.guestRegistrations, ""),
        ),
      });
      return;
    }
    if (
      path === "/system/guest-sponsor-analytics-exports" &&
      method === "GET"
    ) {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.guest_sponsor_analytics_exports
              .runtime,
          exports: [
            {
              name: "aegisnas-guest-sponsor-analytics-20260505-115700Z.json",
              path: "/var/lib/aegisnas/guest-sponsor-analytics-exports/aegisnas-guest-sponsor-analytics-20260505-115700Z.json",
              format: "json",
              size_bytes: 1420,
              created_at: "2026-05-05T11:57:00Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/guest-sponsor-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestSponsorAnalyticsResponse(state.guestRegistrations, ""),
        ),
      });
      return;
    }
    if (
      path === "/system/session-analytics-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T11:54:00Z",
          username: "",
          auth_method: "",
          window_hours: 24,
          bucket_count: 24,
          summary: {
            window_hours: 24,
            bucket_count: 24,
            bucket_minutes: 60,
            total_records: 2,
            started_count: 2,
            ended_count: 1,
            active_now: 1,
            unique_users_window: 2,
            unique_macs_window: 2,
            unique_ips_window: 2,
            ended_traffic_total: 12288,
            ended_session_seconds_total: 2400,
            avg_ended_session_seconds: 2400,
            max_ended_session_seconds: 2400,
            longest_active_session_seconds: 1800,
            peak_concurrent_sessions: 2,
            latest_start_at: "2026-05-05T11:30:00Z",
            latest_end_at: "2026-05-05T10:40:00Z",
            auth_methods: [
              { name: "dot1x", count: 1 },
              { name: "mab", count: 1 },
            ],
            roles: [
              { name: "employee", count: 1 },
              { name: "iot", count: 1 },
            ],
            vlans: [
              { name: "20", count: 1 },
              { name: "30", count: 1 },
            ],
            buckets: [],
          },
        }),
      });
      return;
    }
    if (path === "/system/upstream-aaa-history" && method === "GET") {
      await route.fulfill({
        json: {
          history: [
            {
              id: 1,
              server_name: "upstream-1",
              address: "10.0.0.20",
              auth_port: 1812,
              acct_port: 1813,
              status: "ok",
              message: "Healthy",
              response_code: "Access-Accept",
              latency_ms: 12,
              supports_status_server: true,
              checked_at: "2026-05-05T11:59:30Z",
              created_at: "2026-05-05T11:59:30Z",
            },
            {
              id: 2,
              server_name: "upstream-2",
              address: "10.0.0.21",
              auth_port: 1812,
              acct_port: 1813,
              status: "degraded",
              message: "Unexpected reject response",
              response_code: "Access-Reject",
              latency_ms: 21,
              supports_status_server: true,
              checked_at: "2026-05-05T11:57:30Z",
              created_at: "2026-05-05T11:57:30Z",
            },
          ],
          count: 2,
          server: url.searchParams.get("server") || "",
          status: url.searchParams.get("status") || "",
          generated_at: "2026-05-05T12:00:00Z",
          stats: {
            total_records: 2,
            ok_count: 1,
            degraded_count: 1,
            down_count: 0,
            disabled_count: 0,
            avg_latency_ms: 17,
            last_checked_at: "2026-05-05T11:59:30Z",
          },
        },
      });
      return;
    }
    if (path === "/system/upstream-aaa-history/export" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: "id,checked_at,created_at,server_name,address,auth_port,acct_port,status,message,response_code,latency_ms,supports_status_server\n1,2026-05-05T11:59:30Z,2026-05-05T11:59:30Z,upstream-1,10.0.0.20,1812,1813,ok,Healthy,Access-Accept,12,true\n",
      });
      return;
    }
    if (path === "/system/upstream-aaa-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime: state.systemStatus.telemetry.upstream_aaa_exports.runtime,
          exports: [
            {
              name: "aegisnas-upstream-aaa-history-20260505-115930Z.json",
              path: "/var/lib/aegisnas/upstream-aaa-exports/aegisnas-upstream-aaa-history-20260505-115930Z.json",
              format: "json",
              size_bytes: 880,
              created_at: "2026-05-05T11:59:30Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/upstream-aaa-exports/download" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T11:59:30Z",
          server: "",
          status: "",
          history: [
            {
              id: 1,
              server_name: "upstream-1",
              address: "10.0.0.20",
              auth_port: 1812,
              acct_port: 1813,
              status: "ok",
              message: "Healthy",
              response_code: "Access-Accept",
              latency_ms: 12,
              supports_status_server: true,
              checked_at: "2026-05-05T11:59:30Z",
              created_at: "2026-05-05T11:59:30Z",
            },
          ],
          count: 1,
        }),
      });
      return;
    }
    if (path === "/system/upgrade-readiness-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime:
            state.systemStatus.telemetry.upgrade_readiness_exports.runtime,
          exports: [
            {
              name: "aegisnas-upgrade-readiness-20260505-080000Z.json",
              path: "/var/lib/aegisnas/upgrade-readiness-exports/aegisnas-upgrade-readiness-20260505-080000Z.json",
              format: "json",
              size_bytes: 940,
              created_at: "2026-05-05T08:00:00Z",
            },
          ],
        },
      });
      return;
    }
    if (
      path === "/system/upgrade-readiness-exports/download" &&
      method === "GET"
    ) {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T08:00:00Z",
          config_path: "/etc/aegisnas/config.yaml",
          database_path: "/var/lib/aegisnas/data.db",
          database_exists: true,
          database_size_bytes: 4096,
          current_schema_version: 10,
          target_schema_version: 10,
          config_valid: true,
          deployment_profile: "branch",
          deployment_form: "virtual",
          rehearsal: {
            ran: true,
            succeeded: true,
            started_schema_version: 10,
            result_schema_version: 10,
            duration_milliseconds: 42,
          },
          recommendations: ["Upgrade rehearsal passed."],
        }),
      });
      return;
    }
    if (path === "/system/audit-history" && method === "GET") {
      await route.fulfill({
        json: {
          history: state.auditHistory,
          count: state.auditHistory.length,
          generated_at: "2026-05-05T12:00:00Z",
          stats: {
            total_records: state.auditHistory.length,
            unique_users: 1,
            export_action_count: 1,
            staged_change_count: 0,
            network_action_count: 1,
            ha_action_count: 0,
            upgrade_action_count: 0,
            guest_action_count: 0,
            last_recorded_at: "2026-05-05T12:10:30Z",
          },
        },
      });
      return;
    }
    if (path === "/system/audit-history/export" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: "id,timestamp,user,action,details,result,ip_address\n1,2026-05-05T12:00:00Z,Aegis Admin,download_support_bundle,aegisnas-support-bundle.zip,downloaded,192.168.50.10\n",
      });
      return;
    }
    if (path === "/system/audit-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime: state.systemStatus.telemetry.audit_exports.runtime,
          exports: [
            {
              name: "aegisnas-audit-history-20260505-115800Z.json",
              path: "/var/lib/aegisnas/audit-exports/aegisnas-audit-history-20260505-115800Z.json",
              format: "json",
              size_bytes: 1024,
              created_at: "2026-05-05T11:58:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/audit-exports/download" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T11:58:00Z",
          user: "",
          action_prefix: "",
          history: state.auditHistory,
          count: state.auditHistory.length,
        }),
      });
      return;
    }
    if (path === "/system/integration-history" && method === "GET") {
      await route.fulfill({
        json: {
          history: state.integrationHistory,
          count: state.integrationHistory.length,
          component: url.searchParams.get("component") || "",
          generated_at: "2026-05-05T12:00:00Z",
          stats: {
            total_records: state.integrationHistory.length,
            controller_event_count: 1,
            controller_success_count: 1,
            controller_failure_count: 0,
            mdm_sync_event_count: 1,
            mdm_sync_success_count: 0,
            mdm_sync_failure_count: 1,
            posture_event_count: 0,
            posture_success_count: 0,
            posture_failure_count: 0,
            last_event_at: "2026-05-05T11:59:00Z",
          },
        },
      });
      return;
    }
    if (path === "/system/integration-history/export" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: 'id,created_at,component,status,summary,details_json\n1,2026-05-05T11:58:00Z,controller_automation,ok,Controller sync completed.,"{""adapter"":""cisco""}"\n',
      });
      return;
    }
    if (path === "/system/integration-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime: state.systemStatus.telemetry.integration_exports.runtime,
          exports: [
            {
              name: "aegisnas-integration-history-20260505-115700Z.json",
              path: "/var/lib/aegisnas/integration-exports/aegisnas-integration-history-20260505-115700Z.json",
              format: "json",
              size_bytes: 1536,
              created_at: "2026-05-05T11:57:00Z",
            },
            {
              name: "aegisnas-integration-history-20260505-115700Z.csv",
              path: "/var/lib/aegisnas/integration-exports/aegisnas-integration-history-20260505-115700Z.csv",
              format: "csv",
              size_bytes: 512,
              created_at: "2026-05-05T11:57:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/integration-exports/download" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T11:57:00Z",
          component: "",
          history: state.integrationHistory,
          count: state.integrationHistory.length,
        }),
      });
      return;
    }
    if (path === "/system/network-preview" && method === "GET") {
      const preview = state.networkApplied
        ? createAppliedPreview()
        : createRiskyPreview();
      preview.available_rollback_ids = state.networkBackups;
      preview.recovery = state.networkRecovery;
      await route.fulfill({ json: preview });
      return;
    }
    if (path === "/system/network-backups" && method === "GET") {
      await route.fulfill({
        json: {
          snapshots: state.networkBackups,
          count: state.networkBackups.length,
        },
      });
      return;
    }
    if (path === "/system/network-apply-history" && method === "GET") {
      await route.fulfill({
        json: {
          history: state.networkApplyHistory,
          count: state.networkApplyHistory.length,
          generated_at: "2026-05-05T12:00:00Z",
        },
      });
      return;
    }
    if (path === "/system/network-apply-history/export" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: "id,created_at,action,status,summary,backup_id,rollback_id,actor,details_json\n1,2026-05-05T12:00:00Z,apply,success,Previous edge-network apply completed successfully.,snap-001,,seed,\n",
      });
      return;
    }
    if (path === "/system/network-observability" && method === "GET") {
      await route.fulfill({
        json: {
          generated_at: "2026-05-05T12:00:00Z",
          apply_stats: state.systemStatus.network_observability.apply_stats,
          lease_trends: state.systemStatus.network_observability.lease_trends,
          controller_sync:
            state.systemStatus.network_observability.controller_sync,
          recovery: state.networkRecovery,
        },
      });
      return;
    }
    if (path === "/system/network-exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime: state.systemStatus.telemetry.network_exports.runtime,
          exports: [
            {
              name: "aegisnas-network-apply-history-20260505-115400Z.json",
              path: "/var/lib/aegisnas/network-exports/aegisnas-network-apply-history-20260505-115400Z.json",
              kind: "network_apply_history",
              format: "json",
              size_bytes: 1540,
              created_at: "2026-05-05T11:54:00Z",
            },
            {
              name: "aegisnas-dhcp-lease-history-20260505-115400Z.json",
              path: "/var/lib/aegisnas/network-exports/aegisnas-dhcp-lease-history-20260505-115400Z.json",
              kind: "dhcp_lease_history",
              format: "json",
              size_bytes: 1180,
              created_at: "2026-05-05T11:54:00Z",
            },
            {
              name: "aegisnas-network-apply-history-20260505-115400Z.csv",
              path: "/var/lib/aegisnas/network-exports/aegisnas-network-apply-history-20260505-115400Z.csv",
              kind: "network_apply_history",
              format: "csv",
              size_bytes: 620,
              created_at: "2026-05-05T11:54:00Z",
            },
            {
              name: "aegisnas-dhcp-lease-history-20260505-115400Z.csv",
              path: "/var/lib/aegisnas/network-exports/aegisnas-dhcp-lease-history-20260505-115400Z.csv",
              kind: "dhcp_lease_history",
              format: "csv",
              size_bytes: 540,
              created_at: "2026-05-05T11:54:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/network-exports/download" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T11:54:00Z",
          history: state.networkApplyHistory,
          count: state.networkApplyHistory.length,
        }),
      });
      return;
    }
    if (path === "/system/ha/history" && method === "GET") {
      await route.fulfill({
        json: {
          history: state.haHistory,
          count: state.haHistory.length,
          generated_at: "2026-05-05T12:00:00Z",
          stats: state.systemStatus.high_availability.history_stats,
        },
      });
      return;
    }
    if (path === "/system/ha/history/export" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "text/csv; charset=utf-8" },
        body: "id,created_at,event_type,status,summary,node_role,actor,details_json\n1,2026-05-05T12:00:00Z,replication_publish,success,Published shared HA replication package.,active,,\n",
      });
      return;
    }
    if (path === "/system/ha/exports" && method === "GET") {
      await route.fulfill({
        json: {
          runtime: state.systemStatus.telemetry.ha_exports.runtime,
          exports: [
            {
              name: "aegisnas-ha-history-20260505-115600Z.json",
              path: "/var/lib/aegisnas/ha-exports/aegisnas-ha-history-20260505-115600Z.json",
              format: "json",
              size_bytes: 1280,
              created_at: "2026-05-05T11:56:00Z",
            },
          ],
        },
      });
      return;
    }
    if (path === "/system/ha/exports/download" && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          generated_at: "2026-05-05T11:56:00Z",
          history: state.haHistory,
          count: state.haHistory.length,
        }),
      });
      return;
    }
    if (path === "/system/ha/replication-shared" && method === "GET") {
      await route.fulfill({
        json: {
          shared: {
            present: true,
            package_path: "/var/lib/aegisnas/ha/replication/live/latest.tar.gz",
            metadata_path: "/var/lib/aegisnas/ha/replication/live/latest.json",
            published_at: "2026-05-05T12:00:00Z",
            source_node: "active-node",
            source_role: "active",
            schema_version: 8,
          },
        },
      });
      return;
    }
    if (path === "/system/ha/replication-stage-shared" && method === "POST") {
      await route.fulfill({
        json: {
          message:
            "Latest shared HA replication package is staged on this node.",
          package: {
            id: "shared-stage-001",
          },
        },
      });
      return;
    }
    if (path === "/system/network-apply" && method === "POST") {
      const body = parseBody(route);
      if (body?.confirmation_text !== "APPLY EDGE NETWORK") {
        await route.fulfill({
          status: 400,
          body: "risky edge-network change requires confirmation phrase: APPLY EDGE NETWORK",
        });
        return;
      }
      state.networkApplied = true;
      state.networkBackups = [
        {
          id: "snap-002",
          created_at: "2026-05-05T12:10:00Z",
          interfaces: 2,
          gateways: 1,
          routes: 1,
          dnsmasq_enabled: true,
          has_firewall: true,
          created_by: "Aegis Admin",
          reason: "pre-apply",
        },
        ...state.networkBackups,
      ];
      state.networkApplyHistory = [
        {
          id: state.networkApplyHistory.length + 1,
          action: "apply",
          status: "pending_confirmation",
          summary:
            "Applied edge-network changes successfully and opened the management confirmation window.",
          backup_id: "snap-002",
          actor: "Aegis Admin",
          created_at: "2026-05-05T12:10:00Z",
        },
        ...state.networkApplyHistory,
      ];
      state.networkRecovery = {
        pending: true,
        backup_id: "snap-002",
        deadline: "2026-05-05T12:11:30Z",
        remaining_seconds: 90,
        grace_period_seconds: 90,
        risk_summary: "This edge-network apply changes primary connectivity.",
        validation_summary: "all validation checks passed",
        status: "pending",
        message:
          "Risky edge-network changes are live. Confirm management reachability before the rollback deadline or the appliance will restore the previous snapshot automatically.",
      };
      state.systemStatus.network_observability.apply_stats.pending_confirmation_count = 1;
      state.systemStatus.network_observability.apply_stats.last_applied_at =
        "2026-05-05T12:10:00Z";
      state.systemStatus.network_observability.recovery = state.networkRecovery;
      await route.fulfill({
        json: {
          status: "applied",
          restart_required: false,
          leases_path: "/var/lib/misc/dnsmasq.leases",
          backup_id: "snap-002",
          recovery: state.networkRecovery,
          validation: {
            healthy: true,
            checks: [
              {
                name: "service:dnsmasq",
                status: "ok",
                detail: "dnsmasq is active after apply.",
              },
              {
                name: "health:admin_api",
                status: "ok",
                detail: "admin_api health endpoint responded.",
              },
            ],
          },
        },
      });
      return;
    }
    if (path === "/system/network-recovery/confirm" && method === "POST") {
      state.networkRecovery = {
        ...(state.networkRecovery || {}),
        pending: false,
        remaining_seconds: 0,
        status: "ok",
        message:
          "Admin reachability was confirmed before the rollback deadline.",
        confirmed_by: "Aegis Admin",
        confirmed_at: "2026-05-05T12:10:30Z",
      };
      state.networkApplyHistory = [
        {
          id: state.networkApplyHistory.length + 1,
          action: "apply",
          status: "confirmed",
          summary:
            "Management reachability confirmed before the rollback deadline.",
          backup_id: "snap-002",
          actor: "Aegis Admin",
          created_at: "2026-05-05T12:10:30Z",
        },
        ...state.networkApplyHistory,
      ];
      state.systemStatus.network_observability.apply_stats.pending_confirmation_count = 0;
      state.systemStatus.network_observability.apply_stats.confirmed_count = 2;
      state.systemStatus.network_observability.recovery = state.networkRecovery;
      await route.fulfill({
        json: { status: "confirmed", recovery: state.networkRecovery },
      });
      return;
    }
    if (path === "/system/network-rollback" && method === "POST") {
      state.networkApplied = false;
      state.networkRecovery = null;
      state.networkApplyHistory = [
        {
          id: state.networkApplyHistory.length + 1,
          action: "rollback",
          status: "success",
          summary: "Restored rollback snapshot snap-002.",
          rollback_id: "snap-002",
          actor: "Aegis Admin",
          created_at: "2026-05-05T12:11:00Z",
        },
        ...state.networkApplyHistory,
      ];
      state.systemStatus.network_observability.apply_stats.rollback_count += 1;
      state.systemStatus.network_observability.recovery = null;
      await route.fulfill({
        json: {
          status: "restored",
          rollback_id: "snap-002",
          restart_required: false,
        },
      });
      return;
    }

    if (path === "/guest-registrations" && method === "GET") {
      await route.fulfill({ json: state.guestRegistrations });
      return;
    }
    if (path === "/system/guest-lifecycle" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        json: buildGuestLifecycleResponse(state.guestRegistrations, status),
      });
      return;
    }
    if (path === "/system/guest-lifecycle/export" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestLifecycleResponse(state.guestRegistrations, status),
        ),
      });
      return;
    }
    if (path === "/system/guest-delivery-analytics" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        json: buildGuestDeliveryAnalyticsResponse(
          state.guestRegistrations,
          status,
        ),
      });
      return;
    }
    if (
      path === "/system/guest-delivery-analytics/export" &&
      method === "GET"
    ) {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestDeliveryAnalyticsResponse(state.guestRegistrations, status),
        ),
      });
      return;
    }
    if (path === "/system/guest-rejection-analytics" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        json: buildGuestRejectionAnalyticsResponse(
          state.guestRegistrations,
          status,
        ),
      });
      return;
    }
    if (
      path === "/system/guest-rejection-analytics/export" &&
      method === "GET"
    ) {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestRejectionAnalyticsResponse(
            state.guestRegistrations,
            status,
          ),
        ),
      });
      return;
    }
    if (path === "/system/guest-invite-analytics" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        json: buildGuestInviteAnalyticsResponse(
          state.guestRegistrations,
          status,
        ),
      });
      return;
    }
    if (path === "/system/guest-invite-analytics/export" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestInviteAnalyticsResponse(state.guestRegistrations, status),
        ),
      });
      return;
    }
    if (path === "/system/guest-conversion-analytics" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        json: buildGuestConversionAnalyticsResponse(
          state.guestRegistrations,
          status,
        ),
      });
      return;
    }
    if (
      path === "/system/guest-conversion-analytics/export" &&
      method === "GET"
    ) {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestConversionAnalyticsResponse(
            state.guestRegistrations,
            status,
          ),
        ),
      });
      return;
    }
    if (path === "/system/guest-sponsor-analytics" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        json: buildGuestSponsorAnalyticsResponse(
          state.guestRegistrations,
          status,
        ),
      });
      return;
    }
    if (path === "/system/guest-sponsor-analytics/export" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestSponsorAnalyticsResponse(state.guestRegistrations, status),
        ),
      });
      return;
    }
    if (path === "/system/guest-delivery-failures" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        json: buildGuestDeliveryFailuresResponse(
          state.guestRegistrations,
          status,
        ),
      });
      return;
    }
    if (path === "/system/guest-delivery-failures/export" && method === "GET") {
      const url = new URL(route.request().url());
      const status = url.searchParams.get("status") || "";
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildGuestDeliveryFailuresResponse(state.guestRegistrations, status),
        ),
      });
      return;
    }
    if (
      path.startsWith("/guest-registrations/") &&
      path.endsWith("/approve") &&
      method === "POST"
    ) {
      const id = path.split("/")[2];
      state.guestRegistrations = state.guestRegistrations.map((record) =>
        record.id === id
          ? {
              ...record,
              status: "approved",
              approved_by: "Aegis Admin",
              approved_at: "2026-05-05T12:10:00Z",
              invite_delivery_status: "sent",
            }
          : record,
      );
      await route.fulfill({ json: { status: "approved" } });
      return;
    }
    if (
      path.startsWith("/guest-registrations/") &&
      path.endsWith("/reject") &&
      method === "POST"
    ) {
      const id = path.split("/")[2];
      const body = parseBody(route);
      state.guestRegistrations = state.guestRegistrations.map((record) =>
        record.id === id
          ? {
              ...record,
              status: "rejected",
              rejected_at: "2026-05-05T12:11:00Z",
              rejection_reason: body?.reason || "",
            }
          : record,
      );
      await route.fulfill({ json: { status: "rejected" } });
      return;
    }

    await route.fulfill({
      status: 404,
      body: `Unhandled mock API route: ${method} ${path}`,
    });
  });

  return state;
}
