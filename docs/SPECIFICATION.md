# Specification: `vault-plugin-secrets-salesforce`

A custom HashiCorp Vault secrets engine for managing Salesforce OAuth 2.0 access tokens.

| | |
|---|---|
| **Status** | Draft (v1) — pending implementation |
| **Plugin name** | `vault-plugin-secrets-salesforce` |
| **Plugin type** | Secrets engine (external plugin) |
| **Language** | Go (`github.com/hashicorp/vault/sdk`) |
| **Supported grant flows (v1)** | JWT Bearer, Client Credentials |
| **Token lifecycle** | Cache + lease, transparent re-mint near expiry |
| **Target test environment** | `vault-lab-sandbox` (Vault Enterprise, Docker, Raft) |

---

## 1. Overview & goals

### 1.1 Problem

Most enterprise Salesforce integrations are server-to-server: a backend service calls the
Salesforce REST/Bulk/SOAP APIs and must present a short-lived OAuth 2.0 **access token**.
Today each integrating application typically holds the long-lived secret material itself —
the RSA private key (JWT Bearer flow) or the consumer secret (Client Credentials flow) —
and implements its own token-minting and caching logic. This spreads high-value secrets
across many services, produces inconsistent token handling, and provides no central
audit, rotation, or revocation point.

Vault is the natural broker for this, but **no first-party or community Vault secrets
engine manages Salesforce OAuth tokens**. This engine fills that gap.

### 1.2 Goals

- Centralize Salesforce signing keys / client secrets inside Vault's encrypted barrier.
- Vend short-lived Salesforce **access tokens** on demand through a Vault read path.
- Cache and lease tokens so callers reuse a valid token until it nears expiry, at which
  point Vault transparently re-mints a new one.
- Provide full Vault audit, ACL policy control, and a single revocation surface.
- Support the two flows that cover the vast majority of enterprise use cases:
  **JWT Bearer** and **Client Credentials**.

### 1.3 Non-goals (v1)

- Web-server (authorization code) / refresh-token flow.
- Username-Password (Resource Owner Password) flow.
- Device, SAML Bearer, or Asset Token flows.
- Managing Connected App / External Client App definitions inside Salesforce (the engine
  consumes an already-configured app; it does not create one).
- Acting as an OAuth **authorization server** — the engine is strictly a client/broker.

### 1.4 Target users

- Platform / security teams that own Vault and want to broker Salesforce credentials.
- Application teams that consume a Vault path instead of holding Salesforce secrets.

---

## 2. Background: Salesforce OAuth 2.0

### 2.1 Connected App vs External Client App

Salesforce OAuth clients are defined as either a **Connected App** (classic) or an
**External Client App** (newer packaging model). Both expose:

- A **Consumer Key** (OAuth `client_id`).
- A **Consumer Secret** (OAuth `client_secret`) — used by Client Credentials flow.
- OAuth scopes, and per-flow enablement toggles.

For **JWT Bearer flow**, the app is configured with a digital certificate whose public key
Salesforce holds; Vault holds the corresponding RSA **private key** and signs assertions.

For **Client Credentials flow**, the app must have a **run-as user** assigned (the token is
issued in that user's context) and the "Client Credentials Flow" enabled.

### 2.2 OAuth endpoints

All endpoints are served from the org's login host:

| Host | Use |
|---|---|
| `https://login.salesforce.com` | Production / Developer Edition |
| `https://test.salesforce.com` | Sandboxes |
| `https://<MyDomain>.my.salesforce.com` | Org My Domain (recommended, required for some flows) |

| Endpoint | Method | Path | Purpose |
|---|---|---|---|
| Token | POST | `/services/oauth2/token` | Exchange assertion/credentials for an access token |
| Revoke | POST | `/services/oauth2/revoke` | Revoke an access token |
| Introspect | POST | `/services/oauth2/introspect` | Inspect token validity/expiry (RFC 7662) |
| UserInfo | GET | `/services/oauth2/userinfo` | Identity of the token subject |

> The token response returns an `instance_url` (the org's API base URL, e.g.
> `https://<MyDomain>.my.salesforce.com`). Callers must use `instance_url` for subsequent
> API calls, not the login host. The engine returns `instance_url` alongside the token.

### 2.3 JWT Bearer flow

`POST /services/oauth2/token` with:

```
grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
assertion  = <signed JWT>
```

The JWT is RS256-signed by Vault using the app's private key. Claims:

| Claim | Value |
|---|---|
| `iss` | Consumer Key (client_id) of the Connected App |
| `sub` | Salesforce username to impersonate (the run-as identity) |
| `aud` | Login host, e.g. `https://login.salesforce.com` (or `test`/My Domain) |
| `exp` | Now + short window (≤ 3 min; Salesforce rejects > 5 min in the future) |

No `client_secret` is sent and **no refresh token is issued** — the access token is the
only credential returned. Re-minting means signing a fresh JWT and calling the token
endpoint again. This is the cleanest fit for a Vault dynamic secret.

### 2.4 Client Credentials flow

`POST /services/oauth2/token` with:

```
grant_type    = client_credentials
client_id     = <Consumer Key>
client_secret = <Consumer Secret>
```

(Credentials may be sent in the body or via HTTP Basic auth.) Requires an External Client
App / Connected App with the Client Credentials flow enabled and a run-as user assigned.
Also returns no refresh token; Vault re-mints by repeating the request.

### 2.5 Token TTL behavior

Salesforce access-token lifetime is governed by the org session settings and the
Connected App policy ("Timeout Value"), not by an `expires_in` field — the token response
generally does **not** include `expires_in`. The engine therefore treats token TTL as a
**configurable role parameter** (default conservative, e.g. 15m) bounded by Vault
`max_ttl`, optionally validated via the introspection endpoint.

### 2.6 Scopes

Common scopes: `api`, `web`, `refresh_token`, `openid`, `full`, `id`. For v1 the relevant
scope is typically `api` (and `openid` when identity claims are needed). Scopes are a
role parameter; the engine forwards them where the flow accepts a `scope` parameter
(Client Credentials) and otherwise relies on the app's configured scopes (JWT Bearer).

---

## 3. Architecture

### 3.1 Process model

A standard external Vault secrets plugin: a separate Go binary that Vault launches over
its plugin RPC. It implements `logical.Backend` via `framework.Backend`, registered with a
`Factory` function. Vault mounts it at a path (default `salesforce/`).

```
+-----------------------------+        plugin RPC        +------------------------------+
|        Vault server         | <----------------------> |  vault-plugin-secrets-       |
|  (Enterprise, Raft)         |                          |  salesforce (Go binary)      |
|                             |                          |                              |
|  mount: salesforce/         |                          |  framework.Backend           |
|  barrier-encrypted storage  |  read/write storage      |   - path_config              |
|  audit / ACL / leases       | <----------------------> |   - path_roles               |
+-----------------------------+                          |   - path_creds (issue)       |
            ^                                             |   - client (HTTP to SF)      |
            | API (token)                                 +---------------+--------------+
            |                                                             | HTTPS
     +------+------+                                              +-------v--------+
     |  Caller app |                                              |  Salesforce    |
     +-------------+                                              |  /oauth2/token |
                                                                  +----------------+
```

### 3.2 Request flow — JWT Bearer

```
caller --> GET salesforce/creds/<role>
  backend:
    1. load role + config from storage
    2. check token cache for <role>; if cached and (now < expiry - skew) -> return cached
    3. build JWT claims (iss=client_id, sub=username, aud=login_host, exp=now+window)
    4. sign JWT with role private key (RS256)
    5. POST /services/oauth2/token (grant_type=jwt-bearer, assertion=JWT)
    6. parse access_token + instance_url
    7. cache token with computed expiry; create Vault lease (ttl=role.ttl)
    8. return {access_token, instance_url, token_type, expires_at}
```

### 3.3 Request flow — Client Credentials

```
caller --> GET salesforce/creds/<role>
  backend:
    1..2 same cache check
    3. POST /services/oauth2/token (grant_type=client_credentials,
         client_id, client_secret, scope?)
    4. parse access_token + instance_url
    5. cache + lease + return (same as 6-8 above)
```

### 3.4 Caching & lease design

- One cache entry per role, keyed `cache/<role>`, stored in the Vault barrier (survives
  plugin reload; encrypted at rest).
- A cached entry holds `{access_token, instance_url, issued_at, expires_at}`.
- On read: if `now < expires_at - renew_skew`, return cached; else re-mint.
- Each successful read returns a **lease** with TTL = `role.ttl` (bounded by
  `role.max_ttl` and mount/system max). The lease's revoke function removes/ignores the
  cache entry; optionally calls Salesforce `/revoke`.
- `expires_at` is `issued_at + role.token_ttl` (since Salesforce omits `expires_in`),
  unless introspection is enabled and returns an authoritative `exp`.
- `renew_skew` (default 60s) protects callers from receiving a token about to expire.

### 3.5 Concurrency

Token minting per role is guarded by a per-role lock to avoid a thundering herd of
simultaneous re-mints. A read that finds a stale cache acquires the lock, re-checks, mints
once, and populates the cache for waiters.

---

## 4. API path tree

Mounted at `salesforce/` (configurable at `vault secrets enable`).

```
salesforce/
├── config/<name>                 # connection config (per Salesforce org/app)
│     GET    read config (secrets redacted)
│     POST   create/update config
│     DELETE delete config
├── config?list                   # LIST config names
├── roles/<name>                  # a token-issuing role bound to a config + grant flow
│     GET    read role (secrets redacted)
│     POST   create/update role
│     DELETE delete role
├── roles?list                    # LIST role names
├── creds/<name>                  # READ to obtain an access token (lease-backed)
│     GET    issue/return token for role <name>
├── token/<name>                  # alias of creds/<name> (read)
└── roles/<name>/rotate           # POST force re-mint (invalidate cache) [optional v1]
```

Design note: `config` holds **org/app connection** material that can be shared by multiple
roles; `roles` holds the **flow + identity + TTL** policy. A role references a config by
name. This mirrors the database / LDAP engine config-vs-role split.

---

## 5. Endpoint reference

### 5.1 `POST salesforce/config/<name>`

Create or update an org/app connection.

| Field | Type | Required | Description |
|---|---|---|---|
| `login_url` | string | yes | Base login host: `https://login.salesforce.com`, `https://test.salesforce.com`, or `https://<MyDomain>.my.salesforce.com`. |
| `token_url` | string | no | Override full token endpoint. Defaults to `<login_url>/services/oauth2/token`. |
| `client_id` | string | yes | Connected App / External Client App Consumer Key. |
| `client_secret` | string | no | Consumer Secret. Required when any bound role uses `client_credentials`. Write-only (never returned). |
| `private_key` | string | no | PEM RSA private key for JWT Bearer signing. Required when any bound role uses `jwt_bearer`. Write-only. |
| `ca_cert` | string | no | Optional PEM CA bundle to validate the Salesforce TLS endpoint. |
| `tls_skip_verify` | bool | no | Disable TLS verification (sandbox/testing only; default `false`). |

**Example request**

```bash
vault write salesforce/config/acme-prod \
  login_url="https://acme.my.salesforce.com" \
  client_id="3MVG9..." \
  private_key=@server.key
```

**Response:** `204 No Content`.

### 5.2 `GET salesforce/config/<name>`

Returns config with `client_secret` and `private_key` redacted.

```json
{
  "data": {
    "login_url": "https://acme.my.salesforce.com",
    "token_url": "https://acme.my.salesforce.com/services/oauth2/token",
    "client_id": "3MVG9...",
    "client_secret": "<redacted>",
    "private_key": "<redacted>",
    "tls_skip_verify": false
  }
}
```

### 5.3 `LIST salesforce/config` — returns `{ "keys": ["acme-prod", ...] }`.
### 5.4 `DELETE salesforce/config/<name>` — `204`. Fails if roles still reference it (or cascades per config flag).

### 5.5 `POST salesforce/roles/<name>`

| Field | Type | Required | Description |
|---|---|---|---|
| `config` | string | yes | Name of the `config/<name>` this role uses. |
| `grant_type` | string | yes | `jwt_bearer` or `client_credentials`. |
| `username` | string | cond. | Salesforce username for `sub` (JWT Bearer). Required when `grant_type=jwt_bearer`. |
| `scopes` | list | no | OAuth scopes (forwarded for client_credentials). |
| `token_ttl` | duration | no | Assumed access-token lifetime (default `15m`). Drives cache expiry. |
| `ttl` | duration | no | Default Vault lease TTL for issued tokens. |
| `max_ttl` | duration | no | Max Vault lease TTL. |
| `renew_skew` | duration | no | Re-mint this long before `expires_at` (default `60s`). |
| `jwt_expiry` | duration | no | JWT assertion `exp` window (default `3m`, max `5m`). |
| `audience` | string | no | Override JWT `aud` (default = `login_url`). |
| `use_introspection` | bool | no | Validate token expiry via `/introspect` (default `false`). |

**Example (JWT Bearer)**

```bash
vault write salesforce/roles/integration-svc \
  config="acme-prod" grant_type="jwt_bearer" \
  username="integration@acme.com" scopes="api" token_ttl="15m"
```

**Example (Client Credentials)**

```bash
vault write salesforce/roles/eca-svc \
  config="acme-prod" grant_type="client_credentials" scopes="api"
```

Validation: `jwt_bearer` requires `username` + the config's `private_key`;
`client_credentials` requires the config's `client_secret`.

### 5.6 `GET salesforce/roles/<name>` — role config, secrets redacted.
### 5.7 `LIST salesforce/roles` / `DELETE salesforce/roles/<name>`.

### 5.8 `GET salesforce/creds/<name>` (and alias `GET salesforce/token/<name>`)

Issue or return a cached access token. **This is the primary read path.**

**Response**

```json
{
  "lease_id": "salesforce/creds/integration-svc/9f2c...",
  "lease_duration": 900,
  "renewable": true,
  "data": {
    "access_token": "00D...!AQ...",
    "instance_url": "https://acme.my.salesforce.com",
    "token_type": "Bearer",
    "expires_at": "2026-06-15T03:34:00Z",
    "grant_type": "jwt_bearer",
    "cached": false
  }
}
```

`cached: true` indicates a reused token. `expires_at` is the engine's computed expiry.

**Error responses** (mapped from Salesforce token endpoint):

| HTTP | Body `error` | Cause |
|---|---|---|
| 400 | `invalid_grant` | Bad assertion, user not pre-authorized, clock skew, wrong `aud`/`sub`. |
| 400 | `invalid_client` | Wrong consumer key/secret or app not enabled for the flow. |
| 400 | `inactive_user` / `inactive_org` | Run-as user/org disabled. |
| 5xx | — | Salesforce unavailable. |

Vault returns these as a `400`/`502` logical error with the Salesforce `error` and
`error_description` surfaced in the message (no secret material logged).

### 5.9 `POST salesforce/roles/<name>/rotate` (optional v1)

Invalidate the cache entry and re-mint on next read. `204`.

---

## 6. Storage schema

All entries live under the mount's barrier-encrypted storage (`framework.Backend` Storage).

**Config entry** — `config/<name>`:

```json
{
  "login_url": "https://acme.my.salesforce.com",
  "token_url": "https://acme.my.salesforce.com/services/oauth2/token",
  "client_id": "3MVG9...",
  "client_secret": "shhh...",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "ca_cert": "",
  "tls_skip_verify": false
}
```

**Role entry** — `role/<name>`:

```json
{
  "config": "acme-prod",
  "grant_type": "jwt_bearer",
  "username": "integration@acme.com",
  "scopes": ["api"],
  "token_ttl": 900,
  "ttl": 900,
  "max_ttl": 3600,
  "renew_skew": 60,
  "jwt_expiry": 180,
  "audience": "",
  "use_introspection": false
}
```

**Cache entry** — `cache/<role>`:

```json
{
  "access_token": "00D...!AQ...",
  "instance_url": "https://acme.my.salesforce.com",
  "token_type": "Bearer",
  "issued_at": "2026-06-15T03:19:00Z",
  "expires_at": "2026-06-15T03:34:00Z"
}
```

Secret-handling rules:

- `client_secret`, `private_key`, and cached `access_token` are stored only inside the
  Vault barrier and **never** returned by read paths (redacted) or written to logs.
- Read responses for `config`/`roles` replace secret fields with `<redacted>`.
- The plugin must scrub secret values from any error wrapping before returning to Vault.

---

## 7. Token lifecycle & leasing

### 7.1 Cache key & freshness

- Key: `cache/<role>`. One token per role (the run-as identity is fixed by the role).
- Fresh if `now < expires_at - renew_skew`.

### 7.2 Expiry derivation

1. If `use_introspection=true`: after minting, call `/introspect`; use returned `exp`.
2. Else if the token response includes `expires_in`: use it.
3. Else: `expires_at = issued_at + token_ttl` (role parameter, default 15m).

### 7.3 Vault lease mapping

- Each `creds/<role>` read returns a Secret with `TTL = role.ttl`, `MaxTTL = role.max_ttl`.
- The Secret is a **custom secret type** (e.g. `salesforce_access_token`) with:
  - **Revoke** func: delete the cache entry; if `use_introspection`/revoke configured,
    POST `/revoke` to Salesforce. Because Salesforce access tokens are short-lived and
    shared per role, revoke primarily clears Vault's cache.
  - **Renew** func: extend the lease up to `max_ttl` only while the underlying token is
    still fresh; otherwise the next read re-mints.

> Note: because the same Salesforce token is shared across multiple leases of one role,
> Salesforce-side `/revoke` is opt-in (it would invalidate the token for all holders). The
> default revoke behavior is cache-clear only. This is documented for operators.

### 7.4 Failure handling

- On token-endpoint 5xx / network error: return the cached token if still fresh; otherwise
  surface a `502`.
- On `invalid_grant`/`invalid_client`: do not retry; surface `400` with SF error detail.

---

## 8. Security model

### 8.1 Secret handling

- Private keys and client secrets enter only via write paths, are stored in the barrier,
  and are never returned or logged. PEM parsing happens in-memory; keys are not written to
  the plugin's temp files.
- TLS to Salesforce is verified by default; `tls_skip_verify` is gated for sandbox use and
  surfaced in config reads.

### 8.2 Least privilege & ACL

Example policy granting an app read-only token issuance for one role:

```hcl
path "salesforce/creds/integration-svc" {
  capabilities = ["read"]
}
```

Admin policy for managing config/roles:

```hcl
path "salesforce/config/*" { capabilities = ["create","read","update","delete","list"] }
path "salesforce/roles/*"  { capabilities = ["create","read","update","delete","list"] }
```

Callers never receive the signing key — only minted access tokens.

### 8.3 Audit

All requests flow through Vault's audit devices. Responses are HMAC'd by Vault; the plugin
additionally ensures secret fields are redacted so even un-HMAC'd debug paths are safe.

### 8.4 Host validation

`login_url`/`token_url` should be restricted to `*.salesforce.com` /
`*.my.salesforce.com` (and `test.salesforce.com`) unless an operator override is set, to
prevent assertion/credential exfiltration to an attacker-controlled token endpoint.

### 8.5 Threat model summary

| Threat | Mitigation |
|---|---|
| Signing key theft | Key never leaves Vault barrier; not returned/logged. |
| Token endpoint spoofing | TLS verify on by default; host allowlist for `token_url`. |
| Over-broad token sharing | Per-role identity; ACL per `creds/<role>`; optional revoke. |
| Clock-skew JWT rejection | `jwt_expiry` ≤ 5m; rely on accurate Vault host clock. |
| Replay of cached token | Short `token_ttl` + `renew_skew`; optional introspection. |

---

## 9. Configuration & deployment to the sandbox

Target: `vault-lab-sandbox` primary container (`vault-ent-primary`, `hashicorp/vault-enterprise:latest`, Raft).

### 9.1 Enable plugin directory (one-time HCL change)

Add to `perf-replication/vault-ent-primary.hcl`:

```hcl
plugin_directory = "/vault/plugins"
```

Mount a host plugin dir into the container in
`shared-vault-environment.sh:shared_env_recreate_primary_container()`:

```bash
  -v "${PLUGIN_DIR}:/vault/plugins" \
```

(where `PLUGIN_DIR` is e.g. `output/shared-vault-replication/plugins`). Note: the binary
must be built for the **container's** OS/arch (`linux/amd64` or `linux/arm64`), not macOS.

### 9.2 Build the plugin

```bash
cd /Users/dineshgawande/Documents/code/sfdc
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -o dist/vault-plugin-secrets-salesforce ./cmd/vault-plugin-secrets-salesforce
cp dist/vault-plugin-secrets-salesforce \
  /path/to/vault-lab-sandbox/output/shared-vault-replication/plugins/
```

### 9.3 Register & enable

```bash
SHA=$(shasum -a 256 dist/vault-plugin-secrets-salesforce | cut -d' ' -f1)

vault plugin register -sha256="$SHA" \
  secret vault-plugin-secrets-salesforce

vault secrets enable -path=salesforce vault-plugin-secrets-salesforce
```

### 9.4 Smoke test

```bash
vault write salesforce/config/sbx \
  login_url="https://test.salesforce.com" \
  client_id="$SF_CLIENT_ID" private_key=@server.key

vault write salesforce/roles/sbx-jwt \
  config="sbx" grant_type="jwt_bearer" \
  username="$SF_USERNAME" scopes="api" token_ttl="15m"

vault read salesforce/creds/sbx-jwt   # returns access_token + instance_url
# verify against Salesforce:
curl -s -H "Authorization: Bearer <access_token>" \
  "<instance_url>/services/data/" | head
```

### 9.5 Local/dev iteration

For fast iteration without the sandbox, run `vault server -dev
-dev-plugin-dir=./dist` and register/enable against the dev server.

---

## 10. Testing strategy

### 10.1 Unit tests

- JWT claim construction & RS256 signing (golden assertion, verify with public key).
- Client-credentials request body construction.
- Cache freshness logic across skew boundaries (table-driven, fake clock).
- Storage round-trip for config/role/cache entries.
- Redaction of secret fields on read.

### 10.2 Mock Salesforce token server

An `httptest.Server` that emulates `/services/oauth2/token`, `/revoke`, `/introspect`:

- Validates `grant_type`, returns `access_token` + `instance_url`.
- For JWT Bearer, optionally verifies the assertion signature with a test public key.
- Error-injection modes: `invalid_grant`, `invalid_client`, 5xx.

### 10.3 Acceptance tests (`VAULT_ACC=1`)

Drive a real in-memory backend (`logical.TestBackendConfig` / `vault.TestCoreUnsealed`)
through config → role → creds → renew → revoke, pointed at the mock server via
`token_url`/`login_url` overrides.

### 10.4 Manual end-to-end runbook (sandbox)

1. Provision a Salesforce Developer Edition / sandbox org.
2. Create a Connected App: enable JWT Bearer (upload cert) and/or Client Credentials
   (assign run-as user); pre-authorize the user via a Permission Set.
3. Deploy the plugin to `vault-lab-sandbox` (§9).
4. Run the §9.4 smoke test for both `jwt_bearer` and `client_credentials` roles.
5. Confirm caching (`cached:true` on 2nd read), re-mint after `token_ttl`, lease revoke.

---

## 11. Project layout & build

```
sfdc/
├── go.mod
├── go.sum
├── Makefile
├── main.go                              # alias of cmd main (optional)
├── cmd/
│   └── vault-plugin-secrets-salesforce/
│       └── main.go                      # plugin serve entrypoint
├── backend.go                           # Factory + Backend struct + path registration
├── path_config.go                       # config/<name> CRUD
├── path_roles.go                        # roles/<name> CRUD
├── path_creds.go                        # creds|token/<name> issue + secret type
├── path_rotate.go                       # roles/<name>/rotate (optional)
├── client.go                            # Salesforce HTTP client (token/revoke/introspect)
├── jwt.go                               # assertion building + RS256 signing
├── cache.go                             # cache read/write + freshness + per-role lock
├── secret_access_token.go               # lease revoke/renew funcs
├── docs/
│   └── SPECIFICATION.md                 # this document
└── *_test.go                            # unit + acceptance tests + mock server
```

`cmd/.../main.go` skeleton:

```go
func main() {
    apiClientMeta := &pluginutil.APIClientMeta{}
    flags := apiClientMeta.FlagSet()
    flags.Parse(os.Args[1:])
    tlsConfig := apiClientMeta.GetTLSConfig()
    tlsProviderFunc := apiClientMeta.GetTLSProvider(tlsConfig)
    if err := plugin.ServeMultiplex(&plugin.ServeOpts{
        BackendFactoryFunc: salesforce.Factory,
        TLSProviderFunc:    tlsProviderFunc,
    }); err != nil {
        log.Fatal(err)
    }
}
```

Makefile targets: `build` (host), `build-linux`, `test`, `testacc`, `fmt`, `vet`,
`dev` (dev-server + register), `deploy-sandbox`.

Dependencies: `github.com/hashicorp/vault/sdk`, `github.com/hashicorp/vault/api` (tests),
a JWT library (`github.com/golang-jwt/jwt/v5`), stdlib `net/http`.

---

## 12. Build roadmap

| Milestone | Contents |
|---|---|
| M1 — Scaffold | `go.mod`, `cmd/main.go`, `backend.go`, plugin serves & mounts; empty paths. |
| M2 — Config & roles | `path_config.go`, `path_roles.go`, storage schema, redaction, validation. |
| M3 — Client Credentials | `client.go` token call, `path_creds.go`, cache, lease secret type. |
| M4 — JWT Bearer | `jwt.go` assertion signing, JWT flow in client + creds path. |
| M5 — Lifecycle polish | renew/revoke funcs, `renew_skew`, optional introspection, rotate path. |
| M6 — Tests | unit + mock SF server + acceptance tests; CI build for linux. |
| M7 — Sandbox deploy | HCL/plugin-dir change, build linux binary, register/enable, e2e runbook. |

(Ordering puts Client Credentials before JWT because it is simpler to validate end-to-end;
both ship in v1.)

---

## 13. Open questions & future work

- **Refresh-token / web-server flow** — store a refresh token as a static secret and vend
  short-lived access tokens; needs a callback/bootstrap path.
- **Username-Password flow** — deprecated by Salesforce; likely never.
- **Revocation semantics** — should Salesforce-side `/revoke` ever be the default given
  tokens are shared per role? Currently opt-in.
- **Per-request `sub` override** — allow JWT Bearer to impersonate different users at read
  time (subject to ACL) rather than fixing `username` on the role.
- **Multiple instances / org failover** — config-level support for multiple `login_url`s.
- **Signing-key rotation** — coordinate Connected App cert rotation with config updates.
- **WIF / external key storage** — sign JWT via Vault Transit or an HSM instead of an
  in-barrier private key.
- **Open-sourcing** — align repo layout/CI with HashiCorp `vault-plugin-secrets-*`
  conventions for potential community release.
