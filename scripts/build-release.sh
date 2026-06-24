#!/usr/bin/env bash
# Cross-compile vault-plugin-secrets-salesforce for the supported platforms and
# emit per-arch binaries plus a SHA256SUMS file under dist/.
#
# Usage: scripts/build-release.sh [version]
#   version: optional tag embedded in artifact names (default: dev)
set -euo pipefail

PLUGIN_NAME="vault-plugin-secrets-salesforce"
PKG="./cmd/${PLUGIN_NAME}"
VERSION="${1:-dev}"
OUT="dist"

# GOOS/GOARCH targets. Vault plugins are native binaries; build one per platform
# of the Vault servers that will run the plugin.
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

rm -rf "${OUT}"
mkdir -p "${OUT}"

echo "==> Building ${PLUGIN_NAME} ${VERSION}"
for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%/*}"
  GOARCH="${platform#*/}"
  bin="${PLUGIN_NAME}_${VERSION}_${GOOS}_${GOARCH}"
  echo "    - ${GOOS}/${GOARCH}"
  GOOS="${GOOS}" GOARCH="${GOARCH}" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "${OUT}/${bin}" "${PKG}"
done

echo "==> Generating SHA256SUMS"
( cd "${OUT}" && shasum -a 256 ${PLUGIN_NAME}_* > SHA256SUMS )
cat "${OUT}/SHA256SUMS"
echo "==> Done. Artifacts in ${OUT}/"
