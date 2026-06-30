#!/usr/bin/env bash
# Build the plugin for a local Vault test environment (linux/arm64), copy it into
# the configured plugin directory, (re)register it with its SHA256, and enable the
# mount if it is not already enabled.
#
# Prerequisites:
#   - A local Vault server is running and unsealed, with a plugin directory configured.
#   - vault CLI on PATH; VAULT_ADDR + VAULT_TOKEN exported (root or sufficient policy).
#   - PLUGIN_DIR points at the server's configured plugin directory.
#
# Usage: VAULT_ADDR=... VAULT_TOKEN=... PLUGIN_DIR=... ./scripts/deploy-sandbox.sh
set -euo pipefail

PLUGIN_NAME="vault-plugin-secrets-salesforce"
MOUNT_PATH="${MOUNT_PATH:-salesforce}"
SANDBOX_PLUGIN_DIR="${PLUGIN_DIR:-${SANDBOX_PLUGIN_DIR:-/path/to/vault/plugins}}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building ${PLUGIN_NAME} for linux/arm64"
( cd "$REPO_DIR" && make build-linux >/dev/null )

echo "==> Copying binary into plugin dir (atomic replace)"
mkdir -p "$SANDBOX_PLUGIN_DIR"
# Atomic replace: write a temp file then rename. Overwriting the binary in
# place would truncate the inode that a running plugin process still has
# mmap'd, corrupting it and crashing the plugin. rename(2) is atomic and
# leaves the old inode intact until the old process exits.
cp "${REPO_DIR}/dist/${PLUGIN_NAME}_linux_arm64" "${SANDBOX_PLUGIN_DIR}/.${PLUGIN_NAME}.tmp"
chmod +x "${SANDBOX_PLUGIN_DIR}/.${PLUGIN_NAME}.tmp"
mv -f "${SANDBOX_PLUGIN_DIR}/.${PLUGIN_NAME}.tmp" "${SANDBOX_PLUGIN_DIR}/${PLUGIN_NAME}"

SHA="$(shasum -a 256 "${SANDBOX_PLUGIN_DIR}/${PLUGIN_NAME}" | cut -d' ' -f1)"
echo "==> SHA256=${SHA}"

echo "==> Registering plugin"
vault plugin register -sha256="${SHA}" secret "${PLUGIN_NAME}"

if vault secrets list -format=json | grep -q "\"${MOUNT_PATH}/\""; then
  echo "==> Mount ${MOUNT_PATH}/ exists; reloading plugin"
  if ! vault plugin reload -plugin "${PLUGIN_NAME}"; then
    echo "!! reload failed/timed out. If the mount is wedged, recover by" >&2
    echo "   restarting the Vault server and unsealing it." >&2
    exit 1
  fi
else
  echo "==> Enabling mount at ${MOUNT_PATH}/"
  vault secrets enable -path="${MOUNT_PATH}" "${PLUGIN_NAME}"
fi

echo "==> Done. Try: vault read ${MOUNT_PATH}/info"
