# End-to-end runbook (real Salesforce org, via the sandbox)

Validates `vault-plugin-secrets-salesforce` against a **real Salesforce org**
using the `vault-lab-sandbox` Vault Enterprise container. Complete
`docs/SALESFORCE-SETUP.md` first.

## Prerequisites

- Salesforce Connected App configured (see `SALESFORCE-SETUP.md`); you have:
  `LOGIN_URL`, `CONSUMER_KEY`, and either `CONSUMER_SECRET` (Client Credentials)
  or the `sf_jwt.key` PEM + integration `USERNAME` (JWT Bearer).
- `vault-lab-sandbox` primary container `vault-ent` running and unsealed.
- `vault` CLI on PATH.

## 0. Environment

```bash
export PATH="/Users/dineshgawande/Documents/code/binaries:$PATH"
export VAULT_ADDR=http://127.0.0.1:8200
INIT=/Users/dineshgawande/Documents/code/vault-lab-sandbox/output/shared-vault-replication/secrets/vault-ent.init
export VAULT_TOKEN=$(grep 'Initial Root Token:' "$INIT" | awk '{print $4}')
```

## 1. Deploy the latest plugin build

```bash
cd /path/to/sfdc
./scripts/deploy-sandbox.sh
vault read salesforce/info   # sanity check
```

## 2. Client Credentials flow

```bash
vault write salesforce/config/prod-cc \
  login_url="$LOGIN_URL" \
  client_id="$CONSUMER_KEY" \
  client_secret="$CONSUMER_SECRET"

vault write salesforce/roles/cc \
  config="prod-cc" grant_type="client_credentials" \
  scopes="api" token_ttl="15m" ttl="10m" max_ttl="1h"

vault read salesforce/creds/cc
```

Expect a real `access_token` and your org's `instance_url`. Verify the token
works against the Salesforce API:

```bash
TOKEN=$(vault read -field=access_token salesforce/creds/cc)
INSTANCE=$(vault read -field=instance_url salesforce/creds/cc)
curl -s -H "Authorization: Bearer $TOKEN" "$INSTANCE/services/data/" | jq .
```

## 3. JWT Bearer flow

```bash
vault write salesforce/config/prod-jwt \
  login_url="$LOGIN_URL" \
  client_id="$CONSUMER_KEY" \
  private_key=@sf_jwt.key

vault write salesforce/roles/jwt \
  config="prod-jwt" grant_type="jwt_bearer" \
  username="$USERNAME" scopes="api" token_ttl="15m" ttl="10m"

vault read salesforce/creds/jwt

TOKEN=$(vault read -field=access_token salesforce/creds/jwt)
INSTANCE=$(vault read -field=instance_url salesforce/creds/jwt)
curl -s -H "Authorization: Bearer $TOKEN" "$INSTANCE/services/data/" | jq .
```

## 4. Verify caching and leasing

```bash
# Second read should be served from cache (cached=true) — confirm with Salesforce
# login history showing a single auth event for the role's token_ttl window.
vault read -field=cached salesforce/creds/cc   # expect: true

# Inspect/revoke the lease
LEASE=$(vault read -field=lease_id salesforce/creds/cc)
vault lease lookup "$LEASE"
vault lease revoke "$LEASE"   # clears the cached token
```

## 5. Verify the token-cap behavior (Claim 2)

To check how many concurrent access tokens the org allows per user/app:

1. Set a short `token_ttl` and disable caching effect by revoking between reads,
   or use `roles/<name>/rotate` (Stage 2) to force fresh mints.
2. Mint several tokens for the same role/user; in Salesforce, open the
   integration user → **OAuth Connected Apps** / Setup → **Connected Apps OAuth
   Usage** to observe active tokens and whether older ones are revoked.
3. Record the observed cap in `docs/analysis-of-salesforce-api-limits.md`
   (replaces the unverified "5" with the measured value).

## 6. Expected results checklist

- [ ] Client Credentials: `creds/cc` returns a real token; Salesforce API call succeeds.
- [ ] JWT Bearer: `creds/jwt` returns a real token; Salesforce API call succeeds.
- [ ] Second read returns `cached=true`; Salesforce login history shows one auth event.
- [ ] `vault lease revoke` clears the cache (next read re-mints).
- [ ] Token-cap behavior observed and recorded.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `invalid_grant: user hasn't approved this consumer` | Run-as/subject user not pre-authorized (Permission Set step). |
| `invalid_client` | Wrong consumer key/secret, or Client Credentials flow not enabled / no run-as user. |
| `invalid_grant` (JWT) with correct user | Clock skew, wrong `aud` (use My Domain), or cert/key mismatch. |
| Connection refused from container | Use a host reachable from the container; `host.docker.internal` for host-run endpoints. |
