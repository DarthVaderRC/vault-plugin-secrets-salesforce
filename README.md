# vault-plugin-secrets-salesforce

A HashiCorp Vault secrets engine that brokers **Salesforce OAuth 2.0 access
tokens** via the **JWT Bearer** and **Client Credentials** grant flows. Vault
holds the Connected App secrets, mints short-lived access tokens on demand,
caches one token per role, and manages their lifecycle as Vault leases.

> Status: **Stage 2 (production hardening) in progress.** Both flows are
> validated end-to-end through Vault against a real Salesforce org. See
> [Roadmap](#roadmap).

## Why

Salesforce has no first-party Vault secrets engine for OAuth token management.
Applications typically embed a Consumer Secret or a JWT signing key and mint
tokens themselves. This engine centralizes that: secrets live only in Vault,
consumers get short-lived tokens via a single `read`, and rotation/revocation
are centrally controlled.

## Features

- **Two server-to-server flows:** JWT Bearer (RS256 assertion) and Client
  Credentials.
- **Per-role token cache** in the Vault barrier — one token per role, re-minted
  near expiry (`renew_skew`), so a burst of reads doesn't churn tokens.
- **Anti-stampede mint lock** — concurrent reads on a cold cache trigger exactly
  one token request.
- **Lease lifecycle** — issued tokens are Vault leases (renew / revoke).
- **`rotate`** — force a fresh token on demand.
- **Resilience** — transient failures (network / 429 / 5xx) retried with
  exponential backoff + jitter; a still-valid cached token is served if a
  re-mint briefly fails.
- **Security** — secrets are write-only and redacted on read; a token-endpoint
  host allowlist (`*.salesforce.com` / `*.force.com`) prevents leaking secrets
  to the wrong host; TLS verification on by default with optional `ca_cert`.

## Architecture

```
config/<name>     roles/<name>            creds/<name>  (read)
 (secrets)   <--   (flow + identity   -->  issue/cache/lease a token
 login_url         + TTLs, bound to        |
 client_id         a config)               +-- cache/<role> in barrier
 client_secret                             +-- lease (renew/revoke)
 private_key
```

- **config/** holds connection + secret material for one Salesforce org/app.
- **roles/** binds a config to a grant flow, identity, scopes, and TTLs.
- **creds/** (and alias **token/**) issues a leased access token for a role.
- **roles/\<name\>/rotate** discards the cached token and mints a fresh one.

## Build

```bash
make build           # host platform -> dist/vault-plugin-secrets-salesforce
make build-linux     # linux/arm64 (the lab container) -> dist/...
make test            # unit tests (-race)
make testacc         # acceptance tests (VAULT_ACC=1)
make cover           # coverage report
```

A Vault plugin is a native binary for one GOOS/GOARCH; build for the platform of
the Vault server that will run it.

## Install (self-hosted Vault)

```bash
# 1. Place the binary in Vault's plugin_directory and register it.
SHA=$(sha256sum vault-plugin-secrets-salesforce | cut -d' ' -f1)
vault plugin register -sha256="$SHA" \
  -command="vault-plugin-secrets-salesforce" \
  secret vault-plugin-secrets-salesforce

# 2. Enable it at a mount path.
vault secrets enable -path=salesforce vault-plugin-secrets-salesforce
```

For the lab sandbox, `scripts/deploy-sandbox.sh` builds, registers, and
enables/reloads the plugin in one step (see `docs/E2E-RUNBOOK.md`).

## Configure

First, set up a Salesforce Connected App (see **[docs/SALESFORCE-SETUP.md](docs/SALESFORCE-SETUP.md)**).

### Client Credentials

```bash
vault write salesforce/config/prod-cc \
  login_url="https://<MyDomain>.my.salesforce.com" \
  client_id="<ConsumerKey>" \
  client_secret="<ConsumerSecret>"

vault write salesforce/roles/cc \
  config=prod-cc grant_type=client_credentials \
  token_ttl=15m ttl=10m max_ttl=1h

vault read salesforce/creds/cc
```

### JWT Bearer

```bash
vault write salesforce/config/prod-jwt \
  login_url="https://<MyDomain>.my.salesforce.com" \
  client_id="<ConsumerKey>" \
  private_key=@sf_jwt.key

vault write salesforce/roles/jwt \
  config=prod-jwt grant_type=jwt_bearer \
  username="integration@example.com" \
  audience="https://login.salesforce.com" \
  token_ttl=15m ttl=10m

vault read salesforce/creds/jwt
```

Use the returned `access_token` against `instance_url`:

```bash
TOKEN=$(vault read -field=access_token salesforce/creds/jwt)
INSTANCE=$(vault read -field=instance_url salesforce/creds/jwt)
curl -s -H "Authorization: Bearer $TOKEN" \
  "$INSTANCE/services/data/v60.0/limits"
```

## Configuration reference

### `config/<name>`

| Field | Required | Description |
|---|---|---|
| `login_url` | yes | My Domain / login host, e.g. `https://acme.my.salesforce.com`. |
| `client_id` | yes | Connected App Consumer Key. |
| `client_secret` | for CC | Consumer Secret. **Write-only, redacted on read.** |
| `private_key` | for JWT | PEM RSA private key for assertion signing. **Write-only.** |
| `token_url` | no | Override the full token endpoint (default `<login_url>/services/oauth2/token`). |
| `ca_cert` | no | PEM CA bundle to validate the TLS endpoint. |
| `tls_skip_verify` | no | Disable TLS verification (testing only). Default `false`. |
| `allow_non_salesforce_host` | no | Permit a non-Salesforce token host (private gateway). Default `false`. |

### `roles/<name>`

| Field | Required | Description |
|---|---|---|
| `config` | yes | The `config/<name>` this role uses. |
| `grant_type` | yes | `jwt_bearer` or `client_credentials`. |
| `username` | for JWT | Salesforce username for the JWT `sub` (run-as identity). |
| `scopes` | no | OAuth scopes (Client Credentials ignores request scopes — set on the app). |
| `token_ttl` | no | Assumed token lifetime; drives cache expiry. Default `15m`. |
| `ttl` / `max_ttl` | no | Vault lease TTL / max. |
| `renew_skew` | no | Re-mint this long before expiry. Default `60s`. |
| `jwt_expiry` | no | JWT `exp` window. Default `3m`, max `5m`. |
| `audience` | no | Override JWT `aud` (default `login_url`; for many orgs use `https://login.salesforce.com`). |

## Operations

```bash
# Force a fresh token (e.g. during an incident or scheduled rotation).
vault write -f salesforce/roles/cc/rotate

# Inspect / revoke a lease.
LEASE=$(vault read -field=lease_id salesforce/creds/cc)
vault lease lookup "$LEASE"
vault lease revoke "$LEASE"   # clears the cached token; next read re-mints
```

## Security

- **Secrets are write-only** and never returned (`read` shows `<redacted>`).
  Treat `config/*` write access as equivalent to holding those secrets.
- **Host allowlist** restricts the token endpoint to Salesforce domains by
  default; only relax with `allow_non_salesforce_host=true` for a vetted host.
- **Least-privilege ACLs:** see **[docs/ACL-EXAMPLES.md](docs/ACL-EXAMPLES.md)**.
- The same access token is shared by all leases of a role; revoking a lease
  clears the cache but does **not** call Salesforce `/revoke` (which would
  break other holders). Use `rotate` to roll the cached token forward.

## Documentation

| Doc | Purpose |
|---|---|
| [docs/SALESFORCE-SETUP.md](docs/SALESFORCE-SETUP.md) | Connected App setup (screenshots, gotchas). |
| [docs/E2E-RUNBOOK.md](docs/E2E-RUNBOOK.md) | Deploy + run both flows against a real org. |
| [docs/ACL-EXAMPLES.md](docs/ACL-EXAMPLES.md) | Example Vault policies. |
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Full RFC-style design spec. |
| [docs/analysis-of-salesforce-api-limits.md](docs/analysis-of-salesforce-api-limits.md) | Salesforce limits analysis (no blockers). |

## Roadmap

- [x] Stage 1 — PoC: both flows, caching, leasing; validated end-to-end against a real org.
- [x] Lifecycle hardening — mint lock, rotate, retry/backoff, graceful degradation.
- [x] Comprehensive tests + acceptance suite.
- [x] Security hardening — host allowlist, secret-leak tests, ACL examples.
- [ ] CI + multi-arch release.

## License

See repository license.
