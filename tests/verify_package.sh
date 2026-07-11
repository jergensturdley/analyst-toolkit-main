#!/usr/bin/env bash
# Verify a built Chrome Web Store zip exists and contains exactly the
# expected files. Runs against an already-built zip in dist/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$REPO_ROOT"

# 1. Build script must exist and be executable.
if [ ! -x scripts/build-store-package.sh ]; then
  echo "FAIL: scripts/build-store-package.sh is missing or not executable" >&2
  exit 1
fi

# 2. A built zip must exist.
shopt -s nullglob
ZIPS=( dist/soc-analyst-toolkit-*.zip )
shopt -u nullglob
if [ "${#ZIPS[@]}" -eq 0 ]; then
  echo "FAIL: no dist/soc-analyst-toolkit-*.zip found. Run scripts/build-store-package.sh first." >&2
  exit 1
fi
ZIP="${ZIPS[0]}"
echo "Checking: $ZIP"

# 3. Extract the zip into a temp dir and inspect.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
unzip -q "$ZIP" -d "$TMP"

# 4. Required files must be present.
REQUIRED=(
  manifest.json
  background.js
  content.js
  popup.js
  popup.html
  triage_prompt.js
  tlds.js
  vis-network.min.js
  icons/icon16.png
  icons/icon32.png
  icons/icon48.png
  icons/icon128.png
  README.md
  LICENSE
  CHANGELOG.md
)
for f in "${REQUIRED[@]}"; do
  if [ ! -e "$TMP/$f" ]; then
    echo "FAIL: zip missing required entry: $f" >&2
    exit 1
  fi
done

# 5. Excluded paths must NOT be present.
EXCLUDED=(
  ".codegraph"
  ".claude"
  ".superpowers"
  "CLAUDE.md"
  "docs/superpowers"
  "docs/PRIVACY.md"
  "docs/STORE_LISTING.md"
  "tests"
  "scripts"
  "tools"
  ".git"
  ".gitignore"
  ".DS_Store"
)
for e in "${EXCLUDED[@]}"; do
  if [ -e "$TMP/$e" ]; then
    echo "FAIL: zip contains excluded entry: $e" >&2
    exit 1
  fi
done

# 6. manifest.json version must match semver.
VERSION="$(grep -E '"version"' "$TMP/manifest.json" | head -1 | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "FAIL: manifest.json version '$VERSION' is not semver" >&2
  exit 1
fi

echo "PASS: zip $ZIP contents OK (version $VERSION, ${#REQUIRED[@]} required files present, ${#EXCLUDED[@]} excluded paths absent)"
