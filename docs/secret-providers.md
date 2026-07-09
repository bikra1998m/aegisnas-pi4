# Enterprise Secret Providers

NAS-0007 adds a central secret-provider interface for RADIUS, LDAP, RadSec,
controller, SIEM, onboarding, profiling, and HA credentials.

Software implementation is complete when secrets can be referenced, resolved,
validated, reported, and tested without exposing secret material. External
secret-manager certification is tracked separately in the NAS-0007 release
certification checklist.

## Reference Formats

Supported references:

```text
env:AEGIS_SECRET_RADIUS_SHARED
file:branch-ap.secret
file:/etc/aegisnas/secrets/branch-ap.secret
```

`env:` reads an environment variable from the running service environment.
`file:` reads a root-owned file under `security.secrets.file_base_dir`. Relative
file refs are resolved under that base directory. Absolute file refs must remain
inside the same directory after symlink resolution.

Use environment variable names that do not collide with config keys. For
example, use `AEGIS_SECRET_RADIUS_SHARED`, not `AEGIS_RADIUS_SECRET`, because
Viper would treat `AEGIS_RADIUS_SECRET` as an override for `radius.secret`.

Unsupported providers such as Vault, HSM, TPM, and envelope encryption are
reserved for NAS-0112 and are rejected by config validation today.

## Configuration

```yaml
security:
  secrets:
    enabled: true
    providers: ["env", "file"]
    file_base_dir: /etc/aegisnas/secrets
    max_secret_bytes: 8192
    allow_inline: true
    production_require_references: true

radius:
  secret: ""
  secret_ref: "env:AEGIS_SECRET_RADIUS_SHARED"
  clients:
    - ip: 192.0.2.10
      shortname: branch-ap
      transport: udp
      secret: ""
      secret_ref: "file:branch-ap.secret"
  upstream:
    servers:
      - name: primary
        address: 198.51.100.10
        transport: udp
        secret: ""
        secret_ref: "env:AEGIS_SECRET_UPSTREAM_PRIMARY"

ldap:
  bind_password: ""
  bind_password_ref: "env:AEGIS_SECRET_LDAP_BIND"
```

`allow_inline: true` preserves backward-compatible upgrade behavior. Production
readiness still blocks inline material when `production_require_references` is
true. After all refs resolve, set `allow_inline: false` to make generation fail
closed if inline material returns.

## Database-Backed RADIUS Clients

The `radius_clients` table now includes:

```text
secret_ref TEXT
```

For UDP clients, either `secret` or `secret_ref` is required. When `secret_ref`
is set through the admin API, the inline `secret` field is cleared. RadSec
clients continue to use the fixed RFC 6614 application secret `radsec` and
certificate identity checks.

## Admin API

```text
GET /api/v1/system/secret-providers
```

The response is fully redacted. It reports:

- provider policy
- config and database source inventory
- reference readiness
- inline source count
- missing reference count
- unsupported provider count
- SHA-256 fingerprints of references, not values

RADIUS-client list responses include:

- `secret_set`
- `inline_secret_set`
- `secret_ref`
- `secret_ref_set`
- `secret_ref_fingerprint`

No endpoint returns secret values.

## FreeRADIUS Generation

The generator resolves refs only while rendering runtime configuration:

- `clients.conf` UDP client secrets
- local broker client secrets from `radius.secret_ref`
- upstream `proxy.conf` UDP home-server secrets
- LDAP module bind password

Generated files contain the resolved values because FreeRADIUS needs them at
runtime. Support bundles and readiness reports do not include those values.

## Operations

Create file-backed secrets with root-only permissions:

```bash
sudo install -d -m 0750 -o root -g aegisnas /etc/aegisnas/secrets
printf '%s' 'replace-with-random-secret' | sudo tee /etc/aegisnas/secrets/branch-ap.secret >/dev/null
sudo chmod 0640 /etc/aegisnas/secrets/branch-ap.secret
```

Set environment-backed secrets through the service manager, not shell history:

```ini
[Service]
Environment=AEGIS_RADIUS_SECRET=replace-with-random-secret
```

Then reload and restart the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart aegis-admin-api
```

Run:

```bash
curl -fsS -H "Authorization: Bearer $AEGIS_TOKEN" \
  http://127.0.0.1:8083/api/v1/system/secret-providers | jq
```

The report must be `ready` before release sign-off. Any hardware, customer,
third-party secret manager, or security-audit activity belongs in the release
certification checklist.
