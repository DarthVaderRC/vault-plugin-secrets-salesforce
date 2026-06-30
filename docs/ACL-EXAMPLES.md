# Vault ACL policy examples

Example Vault policies for the Salesforce secrets engine mounted at `salesforce/`.
Adjust the mount path to match your environment.

## 1. Application / workload: read tokens only

Most consumers only need to read tokens for the role(s) they own. They must not
see or change configs (which hold secrets) or roles.

```hcl
# salesforce-app-read.hcl
# Read access tokens for a specific role only.
path "salesforce/creds/sales-sync" {
  capabilities = ["read"]
}

# Optional alias path.
path "salesforce/token/sales-sync" {
  capabilities = ["read"]
}
```

Grant per role; avoid wildcarding `salesforce/creds/*` unless a workload legitimately
needs every role.

## 2. Operator: manage roles, rotate, but not connection secrets

Lets a platform/operator define roles and force rotation without granting the
ability to read back secret material (configs are write-only/redacted anyway).

```hcl
# salesforce-operator.hcl
path "salesforce/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Force a fresh token (e.g. during an incident).
path "salesforce/roles/+/rotate" {
  capabilities = ["update"]
}

# Read tokens for verification.
path "salesforce/creds/*" {
  capabilities = ["read"]
}
```

## 3. Admin: manage connection configs (secret material)

Only trusted admins should write `config/*`, which accepts the Consumer Secret
and JWT private key. These are write-only and redacted on read.

```hcl
# salesforce-admin.hcl
path "salesforce/config/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "salesforce/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

## 4. Rotation automation: rotate only

A narrowly-scoped policy for a scheduled job that periodically forces fresh
tokens, with no other access.

```hcl
# salesforce-rotator.hcl
path "salesforce/roles/+/rotate" {
  capabilities = ["update"]
}
```

## Notes

- **Mutation capability ≈ secret access.** The Consumer Secret and JWT private
  key are write-only and never returned (`read` shows `<redacted>`), but treat
  `config/*` **and** `roles/*` write access as equivalent to holding the brokered
  secrets. An update-only principal can otherwise repoint the token endpoint or
  change the run-as identity to exfiltrate or misuse them. The engine adds
  guardrails (re-supply-on-sensitive-change; immutable `username`/`config`), but
  scope mutation capabilities to a trusted tier regardless.
- **Mirror `creds/*` policies on `token/*`.** The path `salesforce/token/<name>`
  is a functional alias of `salesforce/creds/<name>`. A `deny` or omission on
  `creds/*` is bypassable via `token/*` unless you apply the **same** rule to
  both paths (see the examples above, which grant both).
- **Lease management.** Token reads issue leases. Consumers that need to revoke
  early require `update` on `sys/leases/revoke` (or use the lease's own revoke).
- **Least privilege.** Prefer per-role `creds/<name>` grants over `creds/*`.
- **Host allowlist.** By default the engine refuses token endpoints outside
  `*.salesforce.com` / `*.force.com` / `*.salesforce.mil`, including loopback.
  Only set `allow_non_salesforce_host=true` for a vetted private gateway.
