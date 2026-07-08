# RadSec (RADIUS over TLS)

## Feature definition

RadSec protects RADIUS authentication, authorization, accounting, Status-Server,
CoA, and Disconnect traffic with TLS over TCP. It replaces source-IP plus shared
secret transport trust with certificate-based peer authentication, encrypted
transport, integrity protection, server-name verification, and revocation
policy. The RFC 6614 application-layer secret is always `radsec`; it is not an
operator credential and is never used as a UDP fallback secret.

This implementation covers the mandatory X.509 mutual-TLS profile. TLS-PSK is
an optional, separately negotiated profile defined by RFC 9813 and is not
represented as X.509 support. DTLS is not enabled because the current
RADIUS/DTLS revision is not an RFC.

## Standards and vendor interoperability

| Item | Implementation |
|---|---|
| RFC 6614 | TCP port 2083 default, one stream for RADIUS packet classes, fixed `radsec` application secret, X.509 mTLS, no automatic UDP downgrade |
| RFC 8996 | TLS 1.2 minimum; TLS 1.0 and 1.1 are rejected by configuration validation |
| RFC 9765 | `radius/1.0` and `radius/1.1` ALPN policy with `forbid`, `allow`, and `require`; RADIUS/1.1 requires TLS 1.3 |
| RFC 2865/2866 | Authentication and accounting packets retain ordinary RADIUS packet semantics inside TLS |
| RFC 5176 | CoA and Disconnect are accepted on the inbound RadSec listener |
| RFC 5997 | Status-Server is used for active RADIUS/1.0 health checks |

RadSec is a transport feature and has no vendor dictionary or VSA. Every
standard and vendor-specific attribute already handled by AegisNAS travels
unchanged inside the TLS stream. Interoperability therefore depends on the
peer's RadSec implementation, certificate policy, and the existing attribute
pack, not on a RadSec-specific dictionary.

Verified implementation references include FreeRADIUS 3.2.8's TLS listener and
home-server model, Cisco IOS XE RadSec, and Junos RadSec destinations. Vendor
support remains platform and software-release specific; certify each target
model before rollout.

## Implemented architecture

### Configuration and policy

- `radius.radsec` owns the inbound listener identity, trust anchors, CRL policy,
  TLS bounds, connection limits, RADIUS version policy, collection interval,
  and certificate warning window.
- Managed RADIUS clients select `udp` or `radsec`. A RadSec client must have a
  source IP/CIDR and exact certificate common name. An optional issuer DN adds a
  second connection-authorization condition.
- Each upstream home server independently selects `udp` or `radsec`. RadSec
  peers require a verified server name, client certificate/key, CA material,
  TLS bounds, and connection limits.
- Password fields hold environment variable names only. Raw private-key
  passwords are not stored in YAML, SQLite, API responses, generated history,
  or support metadata.
- A RadSec transport never falls back to UDP. Operators must define a separate
  UDP home server explicitly if degraded transport is an accepted policy.

Implementation: `internal/config/config.go`, `internal/config/radsec.go`, and
`configs/config.example.yaml`.

### FreeRADIUS packet path

`internal/radius/generator.go` produces:

- `clients.conf` with UDP clients only;
- `sites-enabled/aegis-radsec` with a nonblocking `auth+acct+coa` TCP listener,
  mandatory client certificates, exact CN matching, optional issuer matching,
  CRL checks, TLS limits, and a dedicated TLS client namespace;
- `proxy.conf` home servers with `proto = tcp`, `secret = radsec`, SNI/hostname,
  client credentials, CA/CRL policy, and bounded connection pools; and
- no `radiusv1_1` directive in compatibility mode, allowing stock distribution
  builds without `WITH_RADIUSV11` to validate the generated configuration.

`internal/radius/apply.go` writes the dedicated site before running
`freeradius -XC`. A validation failure prevents service restart and participates
in the existing staged apply/rollback workflow.

### Persistence and APIs

Schema v14 adds managed-client transport/certificate identity and durable
upstream TLS observations. Each observation can contain transport and RadSec
port, TLS version and cipher suite, negotiated ALPN, peer subject/issuer/serial
and expiry, response code, latency, status, and message.

Existing endpoints expose the feature without a parallel control plane:

| Endpoint | Use |
|---|---|
| `GET/POST/PUT/DELETE /api/v1/radius-clients` | Manage UDP or RadSec NAS peers; list responses expose `secret_set`, never the secret |
| settings preview/apply/rollback endpoints | Configure inbound and outbound RadSec safely |
| `GET /api/v1/system/status` | Active upstream TLS and RADIUS health |
| `GET /api/v1/system/upstream-aaa-history` | Durable TLS negotiation and certificate history |
| `GET /api/v1/system/upstream-aaa-history/export?format=csv` | CSV operational evidence |
| `GET /api/v1/system/upstream-aaa-history/export?format=json` | JSON operational evidence |
| `GET /api/v1/system/production-readiness` | Credential-file and environment readiness blockers |

### Runtime health and monitoring

`internal/radius/radsec_health.go` performs a real mTLS connection with CA and
server-name verification. It validates CRL signature, freshness, and peer
serial when CRL enforcement is enabled. For RADIUS/1.0 it sends Status-Server,
validates the response authenticator, and records the response. For required
RADIUS/1.1 it validates TLS 1.3 and ALPN without sending an incompatible
RADIUS/1.0 probe.

`internal/telemetry/upstream_aaa.go` collects history in the background, so an
outage is recorded even when no administrator has the dashboard open. Runtime
status and structured warning logs expose down/degraded peers. The admin UI
shows TLS version, ALPN, cipher, peer identity, and expiry in upstream history.

### High availability

RadSec configuration follows the existing signed/encrypted HA configuration
replication. Schema v14 follows the database replication path. Each active node
must have the same certificate paths and service environment, or node-specific
certificates signed by the same trusted CA. Private key material is deliberately
not copied through the application database.

## Production procedure

1. Issue separate server and client certificates for RADIUS transport. Do not
   reuse EAP server certificates.
2. Include `serverAuth` on listener certificates and `clientAuth` on outbound
   client certificates. Put the expected DNS name in SAN.
3. Install private keys with root ownership and least-privilege read access for
   the FreeRADIUS and telemetry services.
4. Install CA certificates and current CRLs, then run `c_rehash` on the trust
   directory when CRL validation is enabled.
5. Enable `radius.radsec`, add RadSec managed clients, preview the change, apply
   it, and confirm management reachability.
6. Add outbound RadSec home servers. Do not retain a UDP peer unless explicit
   downgrade is part of the approved threat model.
7. Run `scripts/radsec-smoke-test.sh` and inspect upstream history.

RADIUS/1.1 `allow` or `require` needs a FreeRADIUS build with
`WITH_RADIUSV11`. Keep `forbid` for ordinary FreeRADIUS 3.2.x distribution
packages. Apply validation detects an unsupported directive before restart.

## Validation and failure behavior

Automated coverage includes invalid TLS and identity policy, generated inbound
and outbound syntax, fixed application secret, environment expansion, schema
migration, successful mTLS plus Status-Server, wrong server identity,
incompatible ALPN, API secret redaction, blank-edit secret preservation, and a
production TypeScript build.

Operational failure is fail-closed. Invalid chains, names, CRLs, ALPN, response
authenticators, or configuration prevent a peer from becoming healthy. No
automatic UDP retry occurs.

## Completion record

| Phase | Result |
|---|---|
| Configuration and validation | Complete |
| Inbound listener and client identity | Complete |
| Outbound proxy pools | Complete |
| Packet health and revocation | Complete |
| Background history and exports | Complete |
| REST API and secret handling | Complete |
| Admin UI | Complete |
| Unit and local integration tests | Complete |
| Ubuntu FreeRADIUS and physical vendor certification | Run on the deployment lab before release sign-off |

The X.509 RadSec software implementation is complete. Release sign-off still
requires the environment-owned Ubuntu and target-device matrix because those
systems and certificates are not available in the source workspace.
