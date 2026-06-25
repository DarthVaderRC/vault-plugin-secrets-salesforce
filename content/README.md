# Vault docs-site content (Salesforce secrets engine)

This tree mirrors the layout of the public Vault documentation repository
(`hashicorp/web-unified-docs`, formerly `vault-docs-common`) so the pages can be
lifted into the published site with minimal change.

```
content/vault/v1.20.x/
├── docs/secrets/salesforce/        # Conceptual + how-to + tutorial pages
├── api-docs/secret/salesforce/     # HTTP API reference
└── data/
    ├── docs-nav-data.json          # Salesforce subtree for the docs sidebar
    └── api-nav-data.json           # Salesforce subtree for the API sidebar
```

## Merging into the Vault docs repo

The two files in `data/` contain **only the Salesforce subtree**. To publish,
merge each object into the corresponding `Secrets Engines` section of the real
`docs-nav-data.json` / `api-nav-data.json` for the target Vault version.

The version directory (`v1.20.x`) is a placeholder. Rename it to match the Vault
release you are documenting.
