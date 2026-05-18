import type { Page, Route } from '@playwright/test';

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
};

type MockOptions = {
  authOptions?: Record<string, any>;
  identity?: AuthIdentity;
  guestRegistrations?: GuestRecord[];
};

const SUPER_ADMIN: AuthIdentity = {
  subject: 'admin-1',
  display_name: 'Aegis Admin',
  role: 'super_admin',
  source: 'token',
  tenants: ['default'],
  permissions: ['*'],
  break_glass: true,
};

function createSettings() {
  return {
    mode: 'two-nic',
    admin_port: 8083,
    deployment: {
      profile: 'branch',
      form: 'virtual',
      hardware: {
        memory_mb: 8192,
        cpu_cores: 4,
        prefer_external_ap: true,
        wireless_passthrough: false,
      },
    },
    wan: { name: 'ens33', dhcp: true, address: '', gateway: '', dhcp_range: '' },
    lan: { name: 'ens37', dhcp: false, address: '192.168.50.1/24', gateway: '', dhcp_range: '192.168.50.100,192.168.50.200,12h' },
    network: {
      interfaces: [],
      gateways: [{ name: 'wan-default', address: '10.0.0.1', interface: 'ens33', metric: 10 }],
      dns: {
        upstream_servers: ['8.8.8.8', '8.8.4.4'],
        search_domains: ['corp.example'],
        local_domain: 'aegis.local',
      },
      static_routes: [{ name: 'branch-a', destination: '172.16.20.0/24', gateway: '10.0.0.254', interface: 'ens33', metric: 20 }],
      firewall: {
        rules: [{ name: 'allow-admin', action: 'allow', source: '192.168.50.0/24', destination: '0.0.0.0/0', protocol: 'tcp', ports: '8083', enabled: true }],
        free_sites: ['neverssl.com'],
        dos_protection: {
          enabled: true,
          syn_rate: '50/second',
          icmp_rate: '25/second',
          conn_rate: '200/second',
          burst: 100,
          log_drops: true,
        },
      },
    },
    dhcp: {
      enabled: true,
      lease_time: '12h',
      authoritative: true,
      static_leases: [{ mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.50.10', hostname: 'lab-client', enabled: true, description: 'Lab device' }],
    },
    policy: { default_role: 'guest-basic', runtime_shaping_enabled: true },
    telemetry: { enabled: true, prometheus_port: 9090, lease_history_poll_seconds: 300 },
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
        enabled: true,
        provider: 'oidc',
        issuer_url: 'https://sso.example.test',
        client_id: 'aegisnas-ui',
        client_secret_env: 'AEGIS_SSO_SECRET',
        redirect_url: 'http://127.0.0.1:4173/login',
        groups_claim: 'groups',
        tenant_claim: '',
      },
      siem: {
        enabled: true,
        provider: 'webhook',
        endpoint: 'https://siem.example.test/events',
        api_key_env: 'AEGIS_SIEM_API_KEY',
        batch_size: 100,
      },
      controller: {
        enabled: true,
        platform: 'vendor-neutral',
        endpoint: 'https://controller.example.test/api',
        api_token_env: 'AEGIS_CONTROLLER_API_TOKEN',
        sync_mode: 'monitor',
        site: 'lab',
      },
    },
    governance: {
      delegated_admin_enabled: true,
      rbac_mode: 'local',
      external_groups_enabled: false,
      multi_tenant_enabled: false,
      tenant_claim: '',
    },
    high_availability: {
      enabled: true,
      role: 'standby',
      peer_api_url: 'https://peer.example.test:8083',
      virtual_ip: '192.168.50.2',
      heartbeat_interval_seconds: 5,
      failover_timeout_seconds: 20,
      replication_interval_seconds: 300,
      replication_stale_after_seconds: 900,
      split_brain_protection_enabled: true,
      auto_stage_shared_package: true,
      auto_activate_on_failover: false,
      witness_api_url: '',
      witness_urls: ['https://witness-a.example.test/ha', 'https://witness-b.example.test/ha'],
      witness_quorum: 2,
      witness_weights: {
        'https://witness-a.example.test/ha': 2,
        'https://witness-b.example.test/ha': 1,
      },
      witness_weight_threshold: 2,
      witness_groups: {
        'https://witness-a.example.test/ha': 'dc-a',
        'https://witness-b.example.test/ha': 'dc-b',
      },
      witness_min_distinct_groups: 2,
      witness_sources: {
        'https://witness-a.example.test/ha': 'local',
        'https://witness-b.example.test/ha': 'external',
      },
      witness_source_confidence: {
        local: 'critical',
        external: 'advisory',
      },
      witness_required_sources: ['local', 'external'],
      witness_required_sources_by_tier: {
        critical: ['local'],
      },
      witness_required_urls_by_tier: {
        critical: ['https://witness-a.example.test/ha'],
      },
      witness_required_groups_by_tier: {
        critical: ['dc-a'],
      },
      witness_policy_mode: 'all',
      witness_policy_mode_by_tier: {
        advisory: 'any',
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
        critical: 'witness-a',
      },
      witness_signature_required_tiers: ['critical'],
      witness_replay_required_tiers: ['critical'],
      witness_failure_tolerance_by_tier: {
        advisory: 1,
      },
      witness_failure_weight_tolerance_by_tier: {
        advisory: 1,
      },
      witness_blocking_tiers: ['critical'],
      witness_token_env: 'AEGIS_HA_WITNESS_TOKEN',
      witness_signing_key_env: 'AEGIS_HA_WITNESS_SIGNING_KEY',
      witness_max_age_seconds: 30,
      witness_required_node: 'witness-1',
      witness_replay_protection_enabled: true,
      preempt: false,
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
        self_registration_enabled: true,
        sponsor_approval_enabled: true,
        invite_delivery: 'email',
        approval_delivery: 'email',
        email_from: 'guest@example.test',
        smtp_server: 'smtp.example.test',
        smtp_port: 587,
        sms_provider: '',
        sms_endpoint: '',
      },
    },
    radius: {
      secret: 'secret',
      auth_port: 1812,
      acct_port: 1813,
      max_sessions: 1024,
      cert_dir: '/etc/freeradius/3.0/certs',
      nas_identifier: 'aegisnas',
      request_timeout_seconds: 5,
      interim_update_seconds: 300,
      dynamic_auth: { enabled: true, port: 3799 },
      vendor: {
        enabled: true,
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
        enabled: true,
        realm: 'aegis-upstream',
        pool_strategy: 'fail-over',
        status_check: 'status-server',
        response_window: 20,
        zombie_period: 40,
        revive_interval: 120,
        check_interval: 30,
        num_answers_to_alive: 3,
        strip_realm: false,
        servers: [{ name: 'upstream-1', address: '10.0.0.20', auth_port: 1812, acct_port: 1813 }],
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
}

function createDeploymentPreview() {
  return {
    profile: 'branch',
    form: 'virtual',
    label: 'Branch Virtual Appliance',
    summary: 'Balanced branch profile for a virtual appliance.',
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
        key: 'runtime_shaping',
        label: 'Runtime Shaping',
        state: 'enabled',
        active: true,
        summary: 'Runtime bandwidth shaping is ready.',
        recommendation: '',
        dependencies: [],
      },
    ],
  };
}

function createSystemStatus() {
  return {
    generated_at: '2026-05-05T12:00:00Z',
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
      { key: 'admin_api', label: 'Admin API', kind: 'go', status: 'ok', message: 'Admin API is healthy.', port: 8083 },
      { key: 'gateway', label: 'Gateway', kind: 'go', status: 'ok', message: 'Gateway is healthy.', port: 8080 },
    ],
    deployment: createDeploymentPreview(),
    radius: {
      upstream_enabled: true,
      realm: 'aegis-upstream',
      pool_strategy: 'fail-over',
      configured_servers: [{ name: 'upstream-1', address: '10.0.0.20', auth_port: 1812, acct_port: 1813 }],
      server_statuses: [{ name: 'upstream-1', address: '10.0.0.20', auth_port: 1812, acct_port: 1813, status: 'ok', message: 'Healthy', supports_status_server: true }],
      enabled_radius_clients: 2,
      broker_auth: { status: 'ok', message: 'Auth path healthy.' },
      broker_accounting: { status: 'ok', message: 'Accounting path healthy.' },
    },
    wireless: {
      enabled: false,
      interface: '',
      country_code: 'US',
      channel: 6,
      hostapd_config_path: '/etc/hostapd/hostapd.conf',
      ssid_count: 0,
      auth_modes: [],
    },
    enforcement: {
      shaping_enabled: true,
      shaping_interface: 'ens37',
      shaped_sessions: 2,
      shaper: { status: 'ok', message: 'Runtime shaper healthy.' },
    },
    high_availability: {
      enabled: true,
      role: 'standby',
      peer_api_url: 'https://peer.example.test:8083',
      virtual_ip: '192.168.50.2',
      heartbeat_interval_seconds: 5,
      failover_timeout_seconds: 20,
      replication_interval_seconds: 300,
      replication_stale_after_seconds: 900,
      split_brain_protection_enabled: true,
      auto_stage_shared_package: true,
      auto_activate_on_failover: false,
      witness_api_url: '',
      witness_urls: ['https://witness-a.example.test/ha', 'https://witness-b.example.test/ha'],
      witness_quorum: 2,
      witness_weights: {
        'https://witness-a.example.test/ha': 2,
        'https://witness-b.example.test/ha': 1,
      },
      witness_weight_threshold: 2,
      witness_groups: {
        'https://witness-a.example.test/ha': 'dc-a',
        'https://witness-b.example.test/ha': 'dc-b',
      },
      witness_min_distinct_groups: 2,
      witness_sources: {
        'https://witness-a.example.test/ha': 'local',
        'https://witness-b.example.test/ha': 'external',
      },
      witness_source_confidence: {
        local: 'critical',
        external: 'advisory',
      },
      witness_required_sources: ['local', 'external'],
      witness_required_sources_by_tier: {
        critical: ['local'],
      },
      witness_required_urls_by_tier: {
        critical: ['https://witness-a.example.test/ha'],
      },
      witness_required_groups_by_tier: {
        critical: ['dc-a'],
      },
      witness_policy_mode: 'all',
      witness_policy_mode_by_tier: {
        advisory: 'any',
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
        critical: 'witness-a',
      },
      witness_signature_required_tiers: ['critical'],
      witness_replay_required_tiers: ['critical'],
      witness_failure_tolerance_by_tier: {
        advisory: 1,
      },
      witness_failure_weight_tolerance_by_tier: {
        advisory: 1,
      },
      witness_blocking_tiers: ['critical'],
      witness_token_env: 'AEGIS_HA_WITNESS_TOKEN',
      witness_signing_key_env: 'AEGIS_HA_WITNESS_SIGNING_KEY',
      witness_max_age_seconds: 30,
      witness_required_node: 'witness-1',
      witness_replay_protection_enabled: true,
      preempt: false,
      shared_state_dir: '/var/lib/aegisnas/ha',
      runtime: {
        status: 'ok',
        message: 'Peer health probe is healthy.',
        updated_at: '2026-05-05T12:00:00Z',
        details: {
          peer_health_url: 'https://peer.example.test:8083/health',
          peer_reachable: true,
          peer_status_code: 200,
          fencing_status: 'peer_fresh',
          split_brain_protection_enabled: true,
          witness_status: 'idle',
          witness_allow_count: 0,
          witness_total_count: 2,
          witness_allow_weight: 0,
          witness_total_weight: 3,
          witness_allow_group_count: 0,
          witness_total_group_count: 2,
          witness_allow_source_count: 0,
          witness_total_source_count: 2,
          witness_allow_sources: [],
          witness_policy_mode: 'all',
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
            'https://witness-a.example.test/ha': 'critical',
            'https://witness-b.example.test/ha': 'advisory',
          },
          witness_total_tier_count: 2,
          witness_blocking_tiers: ['critical'],
          witness_failure_tolerance_by_tier: {
            advisory: 1,
          },
          witness_failure_weight_tolerance_by_tier: {
            advisory: 1,
          },
          peer_shared_heartbeat_present: true,
          peer_shared_heartbeat_age_seconds: 4,
          peer_shared_heartbeat_stale: false,
          vip_announcement_status: 'sent',
          vip_announcement_at: '2026-05-05T11:59:58Z',
        },
      },
      replication_runtime: {
        status: 'ok',
        message: 'Observed fresh shared HA replication package. Standby auto-stage is ready with package shared-stage-001.',
        updated_at: '2026-05-05T12:00:00Z',
        details: {
          latest_source_node: 'active-node',
          latest_age_seconds: 42,
          stale: false,
          auto_stage_enabled: true,
          auto_stage_status: 'ready',
          auto_stage_stage_id: 'shared-stage-001',
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
        last_event_at: '2026-05-05T12:00:00Z',
      },
    },
    integrations: {
      admin_sso: {
        enabled: true,
        provider: 'oidc',
        issuer_url: 'https://sso.example.test',
        redirect_url: 'http://127.0.0.1:4173/login',
        groups_claim: 'groups',
        session: { status: 'ok', message: 'OIDC admin SSO ready.' },
      },
      siem: {
        enabled: true,
        provider: 'webhook',
        endpoint: 'https://siem.example.test/events',
        batch_size: 100,
        export: { status: 'ok', message: 'SIEM export healthy.' },
      },
      controller: {
        enabled: true,
        platform: 'vendor-neutral',
        endpoint: 'https://controller.example.test/api',
        sync_mode: 'monitor',
        site: 'lab',
        sync: { status: 'ok', message: 'Controller sync healthy.', details: { sync_count: 4, success_count: 4, failure_count: 0, last_duration_ms: 182 } },
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
        last_applied_at: '2026-05-05T12:10:00Z',
        last_failure_at: '',
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
        latest_observed_at: '2026-05-05T12:00:00Z',
      },
      recovery: null,
      controller_sync: { status: 'ok', message: 'Controller sync healthy.', details: { sync_count: 4, success_count: 4, failure_count: 0, last_duration_ms: 182 } },
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
      gateways_added: ['wan-default via 10.0.1.1'],
      gateways_removed: ['wan-default via 10.0.0.1'],
      routes_added: ['172.16.30.0/24 via 10.0.1.254'],
      routes_removed: ['172.16.20.0/24 via 10.0.0.254'],
    },
    risk: {
      requires_confirmation: true,
      confirmation_phrase: 'APPLY EDGE NETWORK',
      summary: 'This edge-network apply changes primary connectivity. Review the warnings and enter the confirmation phrase before applying.',
      items: [
        {
          level: 'danger',
          code: 'default_gateway_change',
          message: 'Default gateway selection will change. Upstream reachability and remote management may be interrupted until the new gateway is healthy.',
        },
      ],
    },
    dnsmasq_enabled: true,
    dnsmasq_config: 'dhcp-range=192.168.50.100,192.168.50.200,12h',
    firewall_rules: 'table inet aegis { chain input { type filter hook input priority 0; } }',
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
      summary: 'No risky edge-network changes detected.',
      items: [],
    },
    dnsmasq_enabled: true,
    dnsmasq_config: 'dhcp-range=192.168.50.100,192.168.50.200,12h',
    firewall_rules: 'table inet aegis { chain input { type filter hook input priority 0; } }',
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

export async function seedAuthenticatedSession(page: Page, token = 'token-super') {
  await page.addInitScript((seedToken) => {
    localStorage.setItem('token', seedToken);
    localStorage.setItem('auth_mode', 'token');
  }, token);
}

export async function installMockApi(page: Page, options: MockOptions = {}) {
  const state = {
    settings: createSettings(),
    deploymentPreview: createDeploymentPreview(),
    systemStatus: createSystemStatus(),
    identity: options.identity || SUPER_ADMIN,
    authOptions: options.authOptions || {
      token_login: true,
      sso: {
        enabled: true,
        provider: 'oidc',
        supported: true,
        redirect_url: 'http://127.0.0.1:4173/login',
        issuer_url: 'https://sso.example.test',
      },
    },
    networkApplied: false,
    networkBackups: [
      {
        id: 'snap-001',
        created_at: '2026-05-05T12:00:00Z',
        interfaces: 2,
        gateways: 1,
        routes: 1,
        dnsmasq_enabled: true,
        has_firewall: true,
        created_by: 'seed',
        reason: 'pre-apply',
      },
    ],
    networkApplyHistory: [
      {
        id: 1,
        action: 'apply',
        status: 'success',
        summary: 'Previous edge-network apply completed successfully.',
        backup_id: 'snap-001',
        actor: 'seed',
        created_at: '2026-05-05T12:00:00Z',
      },
    ],
    haHistory: [
      {
        id: 1,
        event_type: 'replication_publish',
        status: 'success',
        summary: 'Published shared HA replication package.',
        node_role: 'active',
        actor: '',
        created_at: '2026-05-05T12:00:00Z',
      },
      {
        id: 2,
        event_type: 'failover',
        status: 'promoted',
        summary: 'Standby node promoted after peer failure.',
        node_role: 'standby',
        actor: '',
        created_at: '2026-05-05T11:50:00Z',
      },
    ],
    dhcpLeases: [
      {
        expires_at: '2026-05-05T13:00:00Z',
        remaining_seconds: 3600,
        mac: 'aa:bb:cc:dd:ee:ff',
        ip: '192.168.50.10',
        hostname: 'lab-client',
        client_id: '',
        reservation: true,
        expired: false,
      },
    ],
    dhcpLeaseHistory: [
      {
        id: 1,
        observed_at: '2026-05-05T11:55:00Z',
        mac: 'aa:bb:cc:dd:ee:ff',
        ip: '192.168.50.10',
        hostname: 'lab-client',
        client_id: '',
        reservation: true,
        expired: false,
        expires_at: '2026-05-05T13:00:00Z',
        remaining_seconds: 3600,
      },
    ],
    guestRegistrations: options.guestRegistrations || [
      {
        id: 'guest-1',
        full_name: 'Alice Guest',
        company: 'LabCo',
        email: 'alice@example.test',
        sponsor_name: 'Sam Sponsor',
        sponsor_email: 'sam@example.test',
        status: 'pending',
        approval_delivery_status: 'sent',
        invite_delivery_status: 'queued',
        created_at: '2026-05-05T12:00:00Z',
      },
      {
        id: 'guest-2',
        full_name: 'Bob Visitor',
        company: 'Visitors Inc',
        email: 'bob@example.test',
        sponsor_name: 'Taylor Sponsor',
        sponsor_email: 'taylor@example.test',
        status: 'pending',
        approval_delivery_status: 'sent',
        invite_delivery_status: 'queued',
        created_at: '2026-05-05T12:05:00Z',
      },
    ],
    networkRecovery: null as null | Record<string, any>,
  };

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const method = request.method().toUpperCase();

    if (path === '/auth/sso/start' && method === 'GET') {
      await route.fulfill({
        status: 302,
        headers: { location: '/login#sso_token=sso-demo&auth_mode=sso' },
        body: '',
      });
      return;
    }

    if (path === '/auth/options' && method === 'GET') {
      await route.fulfill({ json: state.authOptions });
      return;
    }

    if (path === '/auth/validate' && method === 'GET') {
      const authHeader = request.headers()['authorization'] || '';
      if (authHeader === 'Bearer token-super' || authHeader === 'Bearer sso-demo') {
        await route.fulfill({ json: { identity: { ...state.identity, source: authHeader.includes('sso-demo') ? 'sso' : state.identity.source } } });
      } else {
        await route.fulfill({ status: 401, json: { error: 'invalid token' } });
      }
      return;
    }

    if (path === '/auth/logout' && method === 'POST') {
      await route.fulfill({ json: { status: 'ok' } });
      return;
    }

    if (path === '/system/status' && method === 'GET') {
      await route.fulfill({ json: state.systemStatus });
      return;
    }

    if (path === '/staged-changes' && method === 'GET') {
      await route.fulfill({ json: [] });
      return;
    }

    if (path === '/validate' && method === 'POST') {
      await route.fulfill({ json: { changes: 0 } });
      return;
    }

    if (path === '/apply' && method === 'POST') {
      await route.fulfill({ json: { changes: 0 } });
      return;
    }

    if (path === '/roles' && method === 'GET') {
      await route.fulfill({ json: [{ id: 1, name: 'guest-basic' }] });
      return;
    }
    if (path === '/portal-profiles' && method === 'GET') {
      await route.fulfill({ json: [{ id: 1, name: 'default-guest' }] });
      return;
    }
    if (path === '/identity-sources' && method === 'GET') {
      await route.fulfill({ json: [{ id: 1, name: 'local-users' }] });
      return;
    }
    if (path === '/bandwidth-profiles' && method === 'GET') {
      await route.fulfill({ json: [{ id: 1, name: '10m-down-5m-up' }] });
      return;
    }

    if (path === '/system/settings' && method === 'GET') {
      await route.fulfill({ json: state.settings });
      return;
    }
    if (path === '/system/settings' && method === 'PUT') {
      state.settings = parseBody(route);
      await route.fulfill({ json: { settings: state.settings } });
      return;
    }
    if (path === '/system/settings/evaluate' && method === 'POST') {
      await route.fulfill({ json: { valid: true, deployment: state.deploymentPreview } });
      return;
    }
    if (path === '/system/hostapd-preview' && method === 'GET') {
      await route.fulfill({ json: { path: '/etc/hostapd/hostapd.conf', config: '# hostapd preview' } });
      return;
    }
    if (path === '/system/dhcp-leases' && method === 'GET') {
      await route.fulfill({
        json: {
          leases: state.dhcpLeases,
          count: state.dhcpLeases.length,
          dhcp_enabled: true,
          lease_file: '/var/lib/misc/dnsmasq.leases',
          generated_at: '2026-05-05T12:00:00Z',
          static_leases: 1,
          authoritative: true,
          lease_duration: '12h',
        },
      });
      return;
    }
    if (path === '/system/dhcp-lease-history' && method === 'GET') {
      await route.fulfill({ json: { history: state.dhcpLeaseHistory, count: state.dhcpLeaseHistory.length, generated_at: '2026-05-05T12:00:00Z' } });
      return;
    }
    if (path === '/system/dhcp-lease-history/export' && method === 'GET') {
      await route.fulfill({
        status: 200,
        headers: { 'content-type': 'text/csv; charset=utf-8' },
        body: 'id,observed_at,mac,ip,hostname,client_id,reservation,expired,expires_at,remaining_seconds\n1,2026-05-05T11:55:00Z,aa:bb:cc:dd:ee:ff,192.168.50.10,lab-client,,true,false,2026-05-05T13:00:00Z,3600\n',
      });
      return;
    }
    if (path === '/system/network-preview' && method === 'GET') {
      const preview = state.networkApplied ? createAppliedPreview() : createRiskyPreview();
      preview.available_rollback_ids = state.networkBackups;
      preview.recovery = state.networkRecovery;
      await route.fulfill({ json: preview });
      return;
    }
    if (path === '/system/network-backups' && method === 'GET') {
      await route.fulfill({ json: { snapshots: state.networkBackups, count: state.networkBackups.length } });
      return;
    }
    if (path === '/system/network-apply-history' && method === 'GET') {
      await route.fulfill({ json: { history: state.networkApplyHistory, count: state.networkApplyHistory.length, generated_at: '2026-05-05T12:00:00Z' } });
      return;
    }
    if (path === '/system/network-apply-history/export' && method === 'GET') {
      await route.fulfill({
        status: 200,
        headers: { 'content-type': 'text/csv; charset=utf-8' },
        body: 'id,created_at,action,status,summary,backup_id,rollback_id,actor,details_json\n1,2026-05-05T12:00:00Z,apply,success,Previous edge-network apply completed successfully.,snap-001,,seed,\n',
      });
      return;
    }
    if (path === '/system/network-observability' && method === 'GET') {
      await route.fulfill({
        json: {
          generated_at: '2026-05-05T12:00:00Z',
          apply_stats: state.systemStatus.network_observability.apply_stats,
          lease_trends: state.systemStatus.network_observability.lease_trends,
          controller_sync: state.systemStatus.network_observability.controller_sync,
          recovery: state.networkRecovery,
        },
      });
      return;
    }
    if (path === '/system/ha/history' && method === 'GET') {
      await route.fulfill({
        json: {
          history: state.haHistory,
          count: state.haHistory.length,
          generated_at: '2026-05-05T12:00:00Z',
          stats: state.systemStatus.high_availability.history_stats,
        },
      });
      return;
    }
    if (path === '/system/ha/history/export' && method === 'GET') {
      await route.fulfill({
        status: 200,
        headers: { 'content-type': 'text/csv; charset=utf-8' },
        body: 'id,created_at,event_type,status,summary,node_role,actor,details_json\n1,2026-05-05T12:00:00Z,replication_publish,success,Published shared HA replication package.,active,,\n',
      });
      return;
    }
    if (path === '/system/ha/replication-shared' && method === 'GET') {
      await route.fulfill({
        json: {
          shared: {
            present: true,
            package_path: '/var/lib/aegisnas/ha/replication/live/latest.tar.gz',
            metadata_path: '/var/lib/aegisnas/ha/replication/live/latest.json',
            published_at: '2026-05-05T12:00:00Z',
            source_node: 'active-node',
            source_role: 'active',
            schema_version: 8,
          },
        },
      });
      return;
    }
    if (path === '/system/ha/replication-stage-shared' && method === 'POST') {
      await route.fulfill({
        json: {
          message: 'Latest shared HA replication package is staged on this node.',
          package: {
            id: 'shared-stage-001',
          },
        },
      });
      return;
    }
    if (path === '/system/network-apply' && method === 'POST') {
      const body = parseBody(route);
      if (body?.confirmation_text !== 'APPLY EDGE NETWORK') {
        await route.fulfill({ status: 400, body: 'risky edge-network change requires confirmation phrase: APPLY EDGE NETWORK' });
        return;
      }
      state.networkApplied = true;
      state.networkBackups = [
        {
          id: 'snap-002',
          created_at: '2026-05-05T12:10:00Z',
          interfaces: 2,
          gateways: 1,
          routes: 1,
          dnsmasq_enabled: true,
          has_firewall: true,
          created_by: 'Aegis Admin',
          reason: 'pre-apply',
        },
        ...state.networkBackups,
      ];
      state.networkApplyHistory = [
        {
          id: state.networkApplyHistory.length + 1,
          action: 'apply',
          status: 'pending_confirmation',
          summary: 'Applied edge-network changes successfully and opened the management confirmation window.',
          backup_id: 'snap-002',
          actor: 'Aegis Admin',
          created_at: '2026-05-05T12:10:00Z',
        },
        ...state.networkApplyHistory,
      ];
      state.networkRecovery = {
        pending: true,
        backup_id: 'snap-002',
        deadline: '2026-05-05T12:11:30Z',
        remaining_seconds: 90,
        grace_period_seconds: 90,
        risk_summary: 'This edge-network apply changes primary connectivity.',
        validation_summary: 'all validation checks passed',
        status: 'pending',
        message: 'Risky edge-network changes are live. Confirm management reachability before the rollback deadline or the appliance will restore the previous snapshot automatically.',
      };
      state.systemStatus.network_observability.apply_stats.pending_confirmation_count = 1;
      state.systemStatus.network_observability.apply_stats.last_applied_at = '2026-05-05T12:10:00Z';
      state.systemStatus.network_observability.recovery = state.networkRecovery;
      await route.fulfill({
        json: {
          status: 'applied',
          restart_required: false,
          leases_path: '/var/lib/misc/dnsmasq.leases',
          backup_id: 'snap-002',
          recovery: state.networkRecovery,
          validation: {
            healthy: true,
            checks: [
              { name: 'service:dnsmasq', status: 'ok', detail: 'dnsmasq is active after apply.' },
              { name: 'health:admin_api', status: 'ok', detail: 'admin_api health endpoint responded.' },
            ],
          },
        },
      });
      return;
    }
    if (path === '/system/network-recovery/confirm' && method === 'POST') {
      state.networkRecovery = {
        ...(state.networkRecovery || {}),
        pending: false,
        remaining_seconds: 0,
        status: 'ok',
        message: 'Admin reachability was confirmed before the rollback deadline.',
        confirmed_by: 'Aegis Admin',
        confirmed_at: '2026-05-05T12:10:30Z',
      };
      state.networkApplyHistory = [
        {
          id: state.networkApplyHistory.length + 1,
          action: 'apply',
          status: 'confirmed',
          summary: 'Management reachability confirmed before the rollback deadline.',
          backup_id: 'snap-002',
          actor: 'Aegis Admin',
          created_at: '2026-05-05T12:10:30Z',
        },
        ...state.networkApplyHistory,
      ];
      state.systemStatus.network_observability.apply_stats.pending_confirmation_count = 0;
      state.systemStatus.network_observability.apply_stats.confirmed_count = 2;
      state.systemStatus.network_observability.recovery = state.networkRecovery;
      await route.fulfill({ json: { status: 'confirmed', recovery: state.networkRecovery } });
      return;
    }
    if (path === '/system/network-rollback' && method === 'POST') {
      state.networkApplied = false;
      state.networkRecovery = null;
      state.networkApplyHistory = [
        {
          id: state.networkApplyHistory.length + 1,
          action: 'rollback',
          status: 'success',
          summary: 'Restored rollback snapshot snap-002.',
          rollback_id: 'snap-002',
          actor: 'Aegis Admin',
          created_at: '2026-05-05T12:11:00Z',
        },
        ...state.networkApplyHistory,
      ];
      state.systemStatus.network_observability.apply_stats.rollback_count += 1;
      state.systemStatus.network_observability.recovery = null;
      await route.fulfill({ json: { status: 'restored', rollback_id: 'snap-002', restart_required: false } });
      return;
    }

    if (path === '/guest-registrations' && method === 'GET') {
      await route.fulfill({ json: state.guestRegistrations });
      return;
    }
    if (path.startsWith('/guest-registrations/') && path.endsWith('/approve') && method === 'POST') {
      const id = path.split('/')[2];
      state.guestRegistrations = state.guestRegistrations.map((record) =>
        record.id === id ? { ...record, status: 'approved', invite_delivery_status: 'sent' } : record,
      );
      await route.fulfill({ json: { status: 'approved' } });
      return;
    }
    if (path.startsWith('/guest-registrations/') && path.endsWith('/reject') && method === 'POST') {
      const id = path.split('/')[2];
      const body = parseBody(route);
      state.guestRegistrations = state.guestRegistrations.map((record) =>
        record.id === id ? { ...record, status: 'rejected', rejection_reason: body?.reason || '' } : record,
      );
      await route.fulfill({ json: { status: 'rejected' } });
      return;
    }

    await route.fulfill({ status: 404, body: `Unhandled mock API route: ${method} ${path}` });
  });

  return state;
}
