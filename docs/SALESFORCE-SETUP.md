# Salesforce setup guide

This guide configures a Salesforce org so `vault-plugin-secrets-salesforce` can
mint access tokens via the **JWT Bearer** and **Client Credentials** flows.

You only need the flow(s) you intend to use. Both can share one Connected App.

> Use a **Developer Edition** org (free) or a sandbox. JWT Bearer and Client
> Credentials both require **My Domain** to be enabled (Developer Edition has it
> on by default).

---

## 0. Prerequisites

- A Salesforce org where you are a System Administrator.
- **My Domain** enabled: Setup → **My Domain**. Note your domain host, e.g.
  `https://your-domain.my.salesforce.com`. This is your `login_url`.
- The Vault sandbox running with the plugin deployed (see `docs/E2E-RUNBOOK.md`).

---

## 1. (JWT Bearer) Create an X.509 signing certificate

Vault holds the **private key**; Salesforce holds the **public certificate**.

```bash
# 2048-bit key + self-signed cert (valid 1 year)
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout sf_jwt.key -out sf_jwt.crt \
  -subj "/CN=vault-salesforce-engine" -days 365
```

- `sf_jwt.key` → goes into Vault config `private_key` (keep secret).
- `sf_jwt.crt` → uploaded to the Connected App below.

---

## 2. Create the Connected App

Setup → **App Manager** → **New Connected App** (or **New External Client App**).

Basic info:
- **Connected App Name**: `Vault Salesforce Engine`
- **Contact Email**: your email.

Enable **OAuth Settings** → "Enable OAuth Settings":
- **Callback URL**: `https://login.salesforce.com/services/oauth2/callback`
  (required by the form even though these flows don't use it).
- **Selected OAuth Scopes**: add **Manage user data via APIs (api)**; add
  **Perform requests at any time (refresh_token, offline_access)** only if needed.

### For JWT Bearer
- Check **Use digital signatures** and upload `sf_jwt.crt`.

### For Client Credentials
- Check **Enable Client Credentials Flow** (you'll set the run-as user after save).

Save. It can take 2–10 minutes for the app to propagate.

After save, from **Manage Consumer Details** copy:
- **Consumer Key** → Vault config `client_id`.
- **Consumer Secret** → Vault config `client_secret` (Client Credentials only).

---

## 3. Connected App policies

App Manager → your app → **Manage** → **Edit Policies**:

- **Permitted Users**: `Admin approved users are pre-authorized` (recommended for
  server-to-server). This makes pre-authorization explicit via a Permission Set/Profile.
- **IP Relaxation**: `Relax IP restrictions` (or allowlist Vault's egress IP).
- **(Client Credentials) Run As**: select the integration user the tokens act as.

---

## 4. Pre-authorize the run-as / subject user (JWT Bearer)

Because Permitted Users is "Admin approved", the user in the JWT `sub` (and the
Client Credentials run-as user) must be granted the app via a **Permission Set**:

1. Setup → **Permission Sets** → New: `Vault Salesforce Access`.
2. Open it → **Assigned Connected Apps** → add `Vault Salesforce Engine`.
3. **Manage Assignments** → assign the integration user.

> Symptom if skipped: token request fails with
> `invalid_grant: user hasn't approved this consumer`.

---

## 5. Note the values for Vault

| Vault field | Source |
|---|---|
| `login_url` | Your My Domain host, e.g. `https://your-domain.my.salesforce.com` |
| `client_id` | Connected App Consumer Key |
| `client_secret` | Connected App Consumer Secret (Client Credentials) |
| `private_key` | Contents of `sf_jwt.key` (JWT Bearer) |
| `username` (role) | The integration user's username (JWT Bearer `sub`) |

For a **sandbox**, the token host is your sandbox My Domain or
`https://test.salesforce.com`.

---

## 6. Quick manual verification (optional, outside Vault)

JWT Bearer (after creating a signed assertion) and Client Credentials can be
tested directly with curl to confirm the org side before involving Vault:

```bash
# Client Credentials
curl -s https://your-domain.my.salesforce.com/services/oauth2/token \
  -d grant_type=client_credentials \
  -d client_id="$CONSUMER_KEY" \
  -d client_secret="$CONSUMER_SECRET" | jq .
```

A successful response contains `access_token` and `instance_url`. Then proceed to
`docs/E2E-RUNBOOK.md` to drive the same through Vault.
