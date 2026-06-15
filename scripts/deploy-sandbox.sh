#!/usr/bin/env bash
# Build the plugin for the sandbox container (linux/arm64), copy it into the
# mounted plugin directory, (re)register it with its SHA256, and enable the
# mount if it is not already enabled.
#
# Prerequisites:
#   - The vault-lab-sandbox primary container (vault-ent) is running and unsealed.
#   - vault CLI on PATH; VAULT_ADDR + VAULT_TOKEN exported (root or sufficient policy).
#
# Usage: VAULT_ADDR=... VAULT_TOKEN=... ./scripts/deploy-sandbox.sh
set -euo pipefail

PLUGIN_NAME="vault-plugin-secrets-salesforce"
MOUNT_PATH="${MOUNT_PATH:-salesforce}"
SANDBOX_PLUGIN_DIR="${SANDBOX_PLUGIN_DIR:-/Users/dineshgawande/Documents/code/vault-lab-sandbox/output/shared-vault-replication/runtime/vault-ent-plugins}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building ${PLUGIN_NAME} for linux/arm64"
( cd "$REPO_DIR" && make build-linux >/dev/null )

echo "==> Copying binary into sandbox plugin dir"
mkdir -p "$SANDBOX_PLUGIN_DIR"
cp "${REPO_DIR}/dist/${PLUGIN_NAME}_linux_arm64" "${SANDBOX_PLUGIN_DIR}/${PLUGIN_NAME}"
chmod +x "${SANDBOX_PLUGIN_DIR}/${PLUGIN_NAME}"

SHA="$(shasum -a 256 "${SANDBOX_PLUGIN_DIR}/${PLUGIN_NAME}" | cut -d' ' -f1)"
echo "==> SHA256=${SHA}"

echo "==> Registering plugin"
vault plugin register -sha256="${SHA}" secret "${PLUGIN_NAME}"

if vault secrets list -format=json | grep -q "\"${MOUNT_PATH}/\""; then
  echo "==> Mount ${MOUNT_PATH}/ exists; reloading plugin"
  vault plugin reload -plugin "${PLUGIN_NAME}" >/dev/null || true
else
  echo "==> Enabling mount at ${MOUNT_PATH}/"
  vault secrets enable -path="${MOUNT_PATH}" "${PLUGIN_NAME}"
fi

echo "==> Done. Try: vault read ${MOUNT_PATH}/info"
