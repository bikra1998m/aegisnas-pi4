# Security Hardening

## Admin Tokens

Admin API access uses bearer tokens stored as `sha256:<hex>` digests in SQLite. Set a long bootstrap token before seeding:

```bash
export AEGIS_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
aegis-admin seed --config /etc/aegisnas/config.yaml
```

Rotate tokens by inserting a new digest into `api_tokens`, confirming login, and disabling the old token. Legacy plaintext tokens are accepted only for compatibility with old databases and should be rotated out.

## CORS

The admin API no longer allows wildcard credentials. By default it allows:

- `https://aegis.local`
- `http://localhost:5173`
- `http://127.0.0.1:5173`

For production, set the exact UI origins:

```bash
export AEGIS_ADMIN_ALLOWED_ORIGINS="https://admin.example.net"
```

## Signed Configuration Revisions

Configuration revision signing is supported through HMAC-SHA256. Set one of:

```bash
export AEGIS_REVISION_SIGNING_KEY="replace-with-random-key"
```

or place the key at `/etc/aegisnas/revision.key`.

Every staged apply and rollback creates a config revision snapshot. Rollback verifies the stored checksum before restoring.

## Management VLAN Isolation

Administrative access must stay on VLAN 40 by default. Guest and corporate VLANs should not reach SSH, admin API, health endpoints, or snap control surfaces unless an explicit site policy allows it.

## LDAP

Prefer `ldaps://` for production. The LDAP client uses TLS verification by default; install the directory CA into the OS trust store on the appliance.

## Firewall

- Guest traffic must not reach management or corporate networks by default.
- Corporate traffic should be allowed only by explicit policy.
- Captive portal pre-auth traffic should allow DNS, portal, and defined wall-garden destinations only.

## Backups

Backups are not encrypted by the application. Store archives in encrypted storage or wrap them with site-standard encryption before moving them off-device.

## AI Plane

The AI engine is advisory only. If AI Lite, full AI, the provider endpoint, or a remote webhook fails, authentication, session enforcement, and traffic admission continue.

Full AI mode sends a bounded operational snapshot to the configured provider. Keep provider keys in `/etc/default/aegisnas` through `AEGIS_AI_API_KEY`, restrict that file to root-readable permissions, and use a private endpoint when customer policy forbids cloud analysis.
