#!/usr/bin/env bash
# Build the Chrome Web Store package: a clean zip of the extension files.
#
# Refuses to run on a dirty tree (committed CSS / WIP would be packaged).
# Excludes dev artifacts (.codegraph, .claude, .superpowers, tests, docs/superpowers,
# CLAUDE.md, docs/PRIVACY.md, docs/STORE_LISTING.md, scripts, tools, etc).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$REPO_ROOT"

# 1. Refuse dirty tree.
if ! git diff --quiet HEAD 2>/dev/null; then
  echo "ERROR: working tree is dirty. Commit or stash changes before packaging." >&2
  exit 1
fi

# 2. Read version from manifest.json (no jq dependency).
if [ ! -f manifest.json ]; then
  echo "ERROR: manifest.json not found in $REPO_ROOT" >&2
  exit 1
fi
VERSION="$(grep -E '"version"' manifest.json | head -1 | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
if [ -z "$VERSION" ]; then
  echo "ERROR: could not parse version from manifest.json" >&2
  exit 1
fi

ZIP_NAME="soc-analyst-toolkit-${VERSION}.zip"
STAGING_DIR="dist/staging"

# 3. Clean and recreate staging.
rm -rf dist
mkdir -p "$STAGING_DIR"

# 4. Copy required files.
REQUIRED_FILES=(
  manifest.json
  background.js
  content.js
  popup.js
  popup.html
  triage_prompt.js
  tlds.js
  vis-network.min.js
)
REQUIRED_DIRS=(
  icons
  css
  webfonts
)
# Only ship what the extension needs at runtime plus the license. README /
# CHANGELOG are repo docs, not loaded by the extension, so they stay out of the
# store package.
REQUIRED_DOCS=(
  LICENSE
)

for f in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: required file missing: $f" >&2
    exit 1
  fi
  cp -p "$f" "$STAGING_DIR/"
done

for d in "${REQUIRED_DIRS[@]}"; do
  if [ ! -d "$d" ]; then
    echo "ERROR: required directory missing: $d" >&2
    exit 1
  fi
  cp -Rp "$d" "$STAGING_DIR/"
done

# Drop source-only assets the manifest never references (icon.svg is the master
# artwork; the manifest ships the rendered PNGs).
rm -f "$STAGING_DIR/icons/icon.svg"

for f in "${REQUIRED_DOCS[@]}"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: required doc missing: $f" >&2
    exit 1
  fi
  cp -p "$f" "$STAGING_DIR/"
done

# 5. Print staging manifest for review.
echo ""
echo "Staging manifest:"
( cd "$STAGING_DIR" && find . -type f | sort )

# 6. Zip.
if ! command -v zip >/dev/null 2>&1; then
  echo "ERROR: 'zip' not on PATH. Install with 'brew install zip' or equivalent." >&2
  exit 1
fi

( cd "$STAGING_DIR" && zip -qr "../$ZIP_NAME" . -x "*.DS_Store" )

# 7. SHA256 for record-keeping.
SHA="$(shasum -a 256 "dist/$ZIP_NAME" | awk '{print $1}')"

echo ""
echo "Built: dist/$ZIP_NAME"
echo "SHA256: $SHA"
