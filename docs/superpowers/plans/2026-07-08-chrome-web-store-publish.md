# Chrome Web Store Publish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a reproducible Chrome Web Store package (`dist/soc-analyst-toolkit-0.5.0.zip`) with manifest version bumped, store listing copy, privacy policy, and SVG marquee/promo tile assets. Keep all current permissions; document each in the listing justification. Final manual step (dashboard upload + screenshot capture) is the user's.

**Architecture:** Bash-only packaging pipeline. A `scripts/build-store-package.sh` reads `manifest.json`, copies a fixed set of files into `dist/staging/`, and zips. No npm, no bundler. SVG assets hand-authored; PNG screenshots captured manually by the user (no headless Chrome in env). A `tests/verify_package.sh` asserts the zip contents.

**Tech Stack:** Bash, GNU coreutils (`cp`, `mkdir`, `zip`), `git`. SVG (hand-authored). Markdown for docs.

**Spec:** `docs/superpowers/specs/2026-07-08-chrome-web-store-publish.md`

## Global Constraints

- Edit main in place. No branch. Commit per task with conventional-commit messages.
- No new npm dependencies. No bundler. No `package.json`.
- Manifest version bumps from `0.4` to `0.5.0` exactly. Description stays ≤ 132 chars.
- All existing permissions retained: `storage`, `clipboardWrite`, `contextMenus`, `notifications`, `activeTab`, `host_permissions: <all_urls>`.
- `node tests/verify_features.js` must end with `Failed: 0` after every task.
- `bash scripts/build-store-package.sh && bash tests/verify_package.sh` must both exit 0 at the end.
- Conventional-commit format: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`. End commit bodies with `Co-Authored-By: Claude <noreply@anthropic.com>`.
- Working tree must be clean before running `build-store-package.sh` (the script refuses a dirty tree).
- `docs/PRIVACY.md` and `docs/STORE_LISTING.md` are EXCLUDED from the published zip (user-facing copy, not part of the runtime extension).
- SVG assets ship as SVG only (no PNG render tool dependency).

## File Structure

**Modified:**
- `manifest.json` — version bump `0.4` → `0.5.0`.
- `CHANGELOG.md` — move `[Unreleased]` into a new `[0.5.0] - 2026-07-08` section.

**Created:**
- `scripts/build-store-package.sh` — packaging script.
- `tests/verify_package.sh` — zip contents test.
- `docs/PRIVACY.md` — privacy policy page.
- `docs/STORE_LISTING.md` — store listing copy.
- `tools/store-assets/marquee.svg` — 1400×560 marquee asset.
- `tools/store-assets/small-promo.svg` — 440×280 small promo tile.
- `tools/store-assets/README.md` — manual screenshot capture recipe + asset usage notes.
- `tools/store-assets/sample-iocs.txt` — sample IOC text used in the screenshot recipe.

**Not touched:**
- `popup.js`, `background.js`, `content.js`, `popup.html` — code untouched.
- `icons/` — icons already exist.
- `README.md`, `LICENSE`, `AGENTS.md`, `FEATURES.md`, `UPGRADE_GUIDE.md` — content unchanged.
- The pre-existing `M popup.html` defang CSS — Task 1 commits it before any packaging happens.

---

### Task 1: Pre-flight — commit the working-tree defang CSS

**Files:**
- Modify: `popup.html` (no code change; the existing uncommitted `.defang-item-btn` / `.refang-item-btn` CSS additions become a `chore:` commit)

The packaging script (Task 4) refuses a dirty tree. The only working-tree modification at session start is the defang CSS. Commit it first.

- [ ] **Step 1: Inspect the uncommitted change**

Run: `git diff --stat HEAD -- popup.html`
Expected: a small block of CSS additions for `.defang-item-btn` and `.refang-item-btn`. Confirm the diff matches what was visible at session start.

- [ ] **Step 2: Verify the diff is non-functional (style only)**

Run: `git diff HEAD -- popup.html | head -30`
Expected: only CSS rules in a `<style>` block. No HTML, no JS. If anything beyond CSS appears, STOP and surface it to the user before proceeding.

- [ ] **Step 3: Commit the CSS**

```bash
git add popup.html
git commit -m "chore: defang/refang item button styles

Pre-existing working-tree additions for .defang-item-btn and
.refang-item-btn. Required as a separate commit so the package script
(sees a clean tree) does not refuse to run.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

- [ ] **Step 4: Confirm clean tree**

Run: `git status --short`
Expected: empty output (no tracked modifications). Untracked files (`.codegraph/`, `CLAUDE.md`) are fine — they are git-ignored or pre-existing review artifacts.

---

### Task 2: Manifest version bump + CHANGELOG move

**Files:**
- Modify: `manifest.json:4` (version field)
- Modify: `CHANGELOG.md` (move `[Unreleased]` content into a new `[0.5.0] - 2026-07-08` section; add Ask AI to the Added block; remove the `[Unreleased]` header)

- [ ] **Step 1: Read the current `[Unreleased]` block**

Run: `awk '/^## \[Unreleased\]/,/^## \[0\.4\.0\]/' CHANGELOG.md | head -40`
Capture the three sub-headings (Fixed / Changed / Verified) and their bullets. These move into the new 0.5.0 section.

- [ ] **Step 2: Bump manifest version**

Edit `manifest.json` line 4:

```json
  "version": "0.4",
```

→

```json
  "version": "0.5.0",
```

- [ ] **Step 3: Restructure CHANGELOG.md**

Replace the existing `## [Unreleased]` block with a `## [0.5.0] - 2026-07-08` block. The new block keeps the three existing sub-headings (Fixed / Changed / Verified) and adds a new `### Added` block with the Ask AI work:

```markdown
## [0.5.0] - 2026-07-08

### Added
- **Ask AI**: Replaces "Ask Claude" with a configurable clipboard-copy triage helper. Choose target AI chat from a preset dropdown (Claude / ChatGPT / Gemini / Copilot / Perplexity / Mistral / Custom…) and customize the prompt template via Settings. All processing local; no API keys; no streaming.

### Fixed
- **CyberChef Integration**: Fixed URL encoding issue where highlighted text showed unexpected characters (e.g., %20, %21). CyberChef now correctly receives Base64 encoded input instead of URL encoded text.

### Changed
- **OSINT Sources**: Removed ANY.RUN from hash analysis integrations. Hash IOCs now link to VirusTotal, threat.rip, MalwareBazaar, and Hybrid Analysis.

### Verified
- **Pulsedive Integration**: Confirmed correct Base64 encoding for IOC parameters.
```

The existing `## [0.4.0] - 2024-01-15` section follows the new 0.5.0 section, unchanged.

- [ ] **Step 4: Verify the manifest is valid JSON**

Run: `node -e "console.log(JSON.parse(require('fs').readFileSync('manifest.json','utf8')).version)"`
Expected: `0.5.0`

- [ ] **Step 5: Run the existing test suite**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 6: Commit**

```bash
git add manifest.json CHANGELOG.md
git commit -m "chore(release): 0.4 → 0.5.0

Ask AI feature + CyberChef base64 fix + OSINT source cleanup.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: Privacy policy + store listing copy

**Files:**
- Create: `docs/PRIVACY.md`
- Create: `docs/STORE_LISTING.md`

- [ ] **Step 1: Create `docs/PRIVACY.md`**

Write the file with the following content (verbatim):

```markdown
# SOC Analyst Toolkit — Privacy Policy

SOC Analyst Toolkit is free, with no in-app purchases, subscriptions, ads, upsells, or premium tiers. It does not collect, transmit, or sell user data.

## Pricing

The extension is 100% free. There are no in-app purchases, no subscriptions, no ads, no premium features, and no paid tier. The source is open (MIT license) on GitHub.

## Data storage

Settings, snippets, IOC history, and enrichment-agent results are stored locally in your browser via `chrome.storage.local`. They never leave your machine except when you explicitly initiate an OSINT lookup.

## Network usage

Outbound HTTP requests only occur when you click an OSINT lookup link, run an enrichment agent, or invoke the Ask AI flow. Requests go to the providers configured in Settings (default: VirusTotal, ipinfo.io, AbuseIPDB, GreyNoise, plus the user-configured Ask AI target URL). The extension never makes network requests without a user action.

## Third-party access

The extension author has no access to user data. No analytics SDK, telemetry, fingerprinting, or remote code loading is included.

## Updates

This policy may change with new versions; the change log is in `CHANGELOG.md` in the project repository.

## Contact

Open an issue on the project GitHub repository.
```

- [ ] **Step 2: Create `docs/STORE_LISTING.md`**

Write the file with the following content (verbatim). Sections are labeled so the user can copy each into the corresponding Chrome Web Store dashboard field.

```markdown
# SOC Analyst Toolkit — Chrome Web Store Listing

Copy each section below into the matching field in the Chrome Web Store developer dashboard.

## Title

SOC Analyst Toolkit

## Short description (≤ 132 chars)

Extract IOCs from selected text, run OSINT lookups across 20+ threat-intel platforms, manage snippets, and triage with AI. 100% local.

## Detailed description

SOC Analyst Toolkit is a free, open-source browser extension for SOC analysts and cybersecurity professionals. It extracts indicators of compromise (IOCs) from selected text, generates deep links to 20+ threat-intel platforms for one-click lookup, manages a personal snippet library, and offers an optional Ask AI panel that builds a triage prompt for the user's chosen AI chat.

100% free, no in-app purchases, no subscriptions, no ads, no premium tier. MIT-licensed open source.

### IOC Detection & Analysis
- IPv4 / IPv6, domains, URLs, email addresses, file hashes (MD5 / SHA1 / SHA256 / SHA512), CVEs, MITRE ATT&CK technique IDs, cryptocurrency addresses (Bitcoin / Ethereum), MAC addresses
- Defang / refang, batch dedupe, per-type statistics

### OSINT Integration
Quick lookup against 20+ providers including VirusTotal, AlienVault OTX, AbuseIPDB, ipinfo.io, GreyNoise, Shodan, URLhaus, urlscan.io, MalwareBazaar, Hybrid Analysis, MITRE ATT&CK, D3FEND, blockchain explorers, MAC vendor databases. Configurable IP enrichment with caching and rate limits. Custom OSINT sources supported.

### Productivity
- Personal searchable snippet library with prefix triggers
- Timestamped investigation notes
- Text processing: Base64, hex, ROT13, URL decode, entropy, hash generation
- CyberChef integration (including custom / self-hosted instances)
- Export IOCs as CSV / JSON / Markdown / Obsidian-compatible
- 7 themes (Arc / Coffee / Monokai / Oceanic / Solarized / Earth / Midnight)

### Ask AI
Replaces the older "Ask Claude" clipboard shortcut with a configurable helper. Pick a target AI chat from a preset dropdown (Claude / ChatGPT / Gemini / Copilot / Perplexity / Mistral / Custom…) and customize the prompt template via Settings. All processing is local; the extension never makes network calls without a user action.

### Privacy
- All data stored locally in your browser
- No analytics, no telemetry, no fingerprinting
- Network requests only when you initiate an OSINT lookup or invoke Ask AI
- Open source: review the code on GitHub

## Category

Productivity

## Language

English

## Single-purpose justification

Triage security indicators of compromise. The extension extracts IOCs from selected text, generates deep links to 20+ OSINT providers for one-click lookup, manages analyst snippets, and offers an optional Ask AI panel that builds a triage prompt for the user's chosen AI chat. All processing is local; the only outbound network calls are user-initiated.

## Permission justifications

- **`storage`** — Stores user settings (theme, snippets, custom OSINT sources, Ask AI config, enrichment cache) in `chrome.storage.local`. No sync, no remote.
- **`clipboardWrite`** — Copies IOCs and AI triage prompts to the clipboard at user request.
- **`contextMenus`** — Adds the right-click "Analyze with SOC Toolkit" item and the OSINT-lookup submenu.
- **`notifications`** — Surfaces background-task results (e.g. enrichment agent completion).
- **`activeTab`** — Lets the context-menu actions read the current tab's selected text.
- **`host_permissions: <all_urls>`** — Required because the OSINT links and enrichment agents target user-configurable third-party services (VirusTotal, ipinfo.io, AbuseIPDB, GreyNoise, etc.). Only the user-configured domains are contacted, only when the user clicks.

## Privacy policy URL

`https://raw.githubusercontent.com/<your-org>/<your-repo>/main/docs/PRIVACY.md`

(Replace `<your-org>` and `<your-repo>` with the actual GitHub repo path.)

## Single-purpose disclosure

The extension contains no analytics SDK, no remote code load, no auto-update mechanism, no fingerprinting. All code is the files in this repository.
```

- [ ] **Step 3: Verify files were created with the expected content**

Run: `wc -l docs/PRIVACY.md docs/STORE_LISTING.md && head -1 docs/PRIVACY.md && head -1 docs/STORE_LISTING.md`
Expected: both files > 0 lines; `docs/PRIVACY.md` starts with `# SOC Analyst Toolkit`; `docs/STORE_LISTING.md` starts with `# SOC Analyst Toolkit`.

- [ ] **Step 4: Run the existing test suite**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 5: Commit**

```bash
git add docs/PRIVACY.md docs/STORE_LISTING.md
git commit -m "docs: Chrome Web Store privacy policy + listing copy

docs/PRIVACY.md is the user-facing privacy disclosure (hosted via the
GitHub raw URL in the dashboard). docs/STORE_LISTING.md holds the
copy-paste-ready field values for the Chrome Web Store dashboard.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: Store assets (SVG marquee + small promo + screenshot recipe)

**Files:**
- Create: `tools/store-assets/marquee.svg`
- Create: `tools/store-assets/small-promo.svg`
- Create: `tools/store-assets/README.md`
- Create: `tools/store-assets/sample-iocs.txt`

- [ ] **Step 1: Create `tools/store-assets/marquee.svg`**

Write the file with this content (verbatim):

```svg
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1400" height="560" viewBox="0 0 1400 560">
  <rect width="1400" height="560" fill="#0d1117"/>
  <g transform="translate(80, 100)">
    <!-- icon glyph (use the 128px icon) -->
    <image href="../../icons/icon128.png" x="0" y="0" width="360" height="360"/>
  </g>
  <g transform="translate(500, 200)" fill="#f0f6fc" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">
    <text x="0" y="0" font-size="72" font-weight="700">SOC Analyst Toolkit</text>
    <text x="0" y="80" font-size="32" font-weight="400" fill="#8b949e">IOC extraction · OSINT lookups · AI triage</text>
    <text x="0" y="160" font-size="22" font-weight="400" fill="#8b949e">100% local · Free · Open source</text>
  </g>
</svg>
```

The SVG references `../../icons/icon128.png`. When rendering to PNG, the renderer resolves the relative path. SVG can be opened directly in a browser; Chrome Web Store accepts SVG in marquee/promo slots, and the user can also File → Save As → PNG if a raster is needed.

- [ ] **Step 2: Create `tools/store-assets/small-promo.svg`**

```svg
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="440" height="280" viewBox="0 0 440 280">
  <rect width="440" height="280" fill="#0d1117"/>
  <g transform="translate(20, 50)">
    <image href="../../icons/icon128.png" x="0" y="0" width="180" height="180"/>
  </g>
  <g transform="translate(220, 110)" fill="#f0f6fc" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">
    <text x="0" y="0" font-size="32" font-weight="700">SOC Analyst</text>
    <text x="0" y="36" font-size="32" font-weight="700">Toolkit</text>
    <text x="0" y="80" font-size="14" font-weight="400" fill="#8b949e">IOC · OSINT · AI triage</text>
  </g>
</svg>
```

- [ ] **Step 3: Create `tools/store-assets/sample-iocs.txt`**

```text
ALERT: Suspicious outbound connection from workstation WS-042 (10.20.30.40) to 198.51.100.42 (malicious.example.org). Hash of dropped file: 5d41402abc4b2a76b9719d911017c592a3ae0e2f4e6f9c1d2b3c4d5e6f7a8b9c. CVE-2024-3094 referenced. User clicked phishing email from attacker@evil.example.com. Technique T1566.001 suspected. Bitcoin address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa observed. MAC address 00:1B:44:11:3A:B7 noted on local segment.
```

This is the sample text the screenshot recipe uses to populate the IOC input.

- [ ] **Step 4: Create `tools/store-assets/README.md`**

```markdown
# Store assets

SVG-only assets for the Chrome Web Store listing.

## Files

- `marquee.svg` — 1400×560 marquee tile.
- `small-promo.svg` — 440×280 small promo tile.
- `sample-iocs.txt` — sample alert text used in the screenshot recipe.

## Rendering to PNG (optional)

SVG works in some Chrome Web Store slots. If you need PNG:

1. Open the SVG in Chrome.
2. File → Save As → choose PNG.
3. Resize / crop to the target dimensions if needed.

No `rsvg-convert` or other tool dependency — the SVGs are the canonical artifact.

## Screenshot recipe

Five screenshots, 1280×800 PNG, captured manually in the default Arc theme.

1. Load the extension unpacked (`chrome://extensions` → Load unpacked → select this repo).
2. Open the toolbar popup.
3. Paste the contents of `sample-iocs.txt` into the IOC input.
4. Click "Analyze".
5. Use Chrome DevTools → toggle device toolbar → 1280×800.
6. Capture each of the five views below; save into `screenshots/`:

   - `01-ioc-extraction.png` — IOC list with type badges and counts.
   - `02-osint-links.png` — per-IOC OSINT link list expanded.
   - `03-graph-view.png` — vis-network graph view.
   - `04-snippets.png` — snippets tab with a few sample snippets.
   - `05-ask-ai.png` — settings tab showing the Ask AI section (preset dropdown + URL + template textarea + Reset button).

The screenshots are committed to `screenshots/` separately (Task 8 / manual step) and are NOT included in the package zip — they're uploaded directly to the Chrome Web Store dashboard.
```

- [ ] **Step 5: Verify the files exist**

Run: `ls -la tools/store-assets/`
Expected: four files listed (marquee.svg, small-promo.svg, README.md, sample-iocs.txt).

- [ ] **Step 6: Run the existing test suite**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 7: Commit**

```bash
git add tools/store-assets/
git commit -m "docs(assets): store-listing SVG assets + screenshot recipe

SVG marquee (1400x560) and small promo tile (440x280) hand-authored,
referencing the existing 128px icon. README documents the manual PNG
render (browser File > Save As) and the screenshot capture recipe.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Package builder script

**Files:**
- Create: `scripts/build-store-package.sh`

- [ ] **Step 1: Create the script**

Write `scripts/build-store-package.sh` with the following content (verbatim):

```bash
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
  tlds.js
  vis-network.min.js
)
REQUIRED_DIRS=(
  icons
  css
  webfonts
)
REQUIRED_DOCS=(
  README.md
  LICENSE
  CHANGELOG.md
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
SHA="$(shasum -a 256 "$ZIP_NAME" | awk '{print $1}')"

echo ""
echo "Built: dist/$ZIP_NAME"
echo "SHA256: $SHA"
```

- [ ] **Step 2: Make the script executable**

Run: `chmod +x scripts/build-store-package.sh`
Verify: `ls -la scripts/build-store-package.sh` shows `-rwxr-xr-x`.

- [ ] **Step 3: Run the script and verify the staging manifest**

Run: `bash scripts/build-store-package.sh`
Expected output:
- A `Staging manifest:` section listing all the required files.
- A `Built: dist/soc-analyst-toolkit-0.5.0.zip` line.
- A `SHA256:` line with the hash.

- [ ] **Step 4: Verify the zip is valid**

Run: `unzip -l dist/soc-analyst-toolkit-0.5.0.zip | head -30`
Expected: lists all staged files; no excluded paths (`.codegraph/`, `tests/`, `docs/superpowers/`, `CLAUDE.md`, `scripts/`, `tools/`, `docs/PRIVACY.md`, `docs/STORE_LISTING.md`).

- [ ] **Step 5: Run the existing test suite**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 6: Commit**

```bash
git add scripts/build-store-package.sh
git commit -m "feat: Chrome Web Store packaging script

Bash script that copies a fixed set of extension files into
dist/staging/, prints a manifest for review, and zips into
dist/soc-analyst-toolkit-<version>.zip. Refuses dirty trees, missing
manifest, missing files, and missing 'zip' on PATH. No npm dep.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: Package contents test

**Files:**
- Create: `tests/verify_package.sh`

- [ ] **Step 1: Create `tests/verify_package.sh`**

Write the file with the following content (verbatim):

```bash
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
```

- [ ] **Step 2: Make the script executable**

Run: `chmod +x tests/verify_package.sh`

- [ ] **Step 3: Run the test**

Run: `bash tests/verify_package.sh`
Expected: `PASS: zip dist/soc-analyst-toolkit-0.5.0.zip contents OK (version 0.5.0, 15 required files present, 13 excluded paths absent)` (or similar counts).

- [ ] **Step 4: Run the existing test suite**

Run: `node tests/verify_features.js`
Expected: `Failed: 0`.

- [ ] **Step 5: Commit**

```bash
git add tests/verify_package.sh
git commit -m "test: package contents assertion

Asserts that dist/soc-analyst-toolkit-*.zip exists, contains every
required entry (manifest + scripts + icons + docs), and excludes dev
artifacts (.codegraph, tests, docs/superpowers, CLAUDE.md, etc).
Validates manifest.version is semver.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 7: End-to-end build + manual smoke

**Files:** none (verification step).

- [ ] **Step 1: Clean and rebuild**

Run: `rm -rf dist && bash scripts/build-store-package.sh`
Expected: clean build. Staging manifest printed. Zip built. SHA256 printed.

- [ ] **Step 2: Run both test suites**

Run: `node tests/verify_features.js && bash tests/verify_package.sh`
Expected: both exit 0.

- [ ] **Step 3: Manual smoke — extract and inspect the zip**

Run: `mkdir -p /tmp/soc-toolkit-smoke && unzip -q dist/soc-analyst-toolkit-0.5.0.zip -d /tmp/soc-toolkit-smoke && ls /tmp/soc-toolkit-smoke`
Expected: manifest.json, background.js, content.js, popup.js, popup.html, tlds.js, vis-network.min.js, icons/, css/, webfonts/, README.md, LICENSE, CHANGELOG.md.

- [ ] **Step 4: Manual smoke — confirm manifest.json in the zip is correct**

Run: `grep '"version"' /tmp/soc-toolkit-smoke/manifest.json`
Expected: `"version": "0.5.0"`.

- [ ] **Step 5: Manual smoke — load unpacked and check the popup renders**

(This step requires Chrome.) Load `/tmp/soc-toolkit-smoke` as an unpacked extension in Chrome. Open the toolbar popup. Confirm:
- The popup renders.
- "Ask AI" button is visible (rename from "Ask Claude" landed).
- Settings tab shows the Ask AI section.

If Chrome is not available in your environment, document this in your report and rely on the zip contents check + the test suite.

- [ ] **Step 6: Clean up smoke dir**

Run: `rm -rf /tmp/soc-toolkit-smoke`

- [ ] **Step 7: No commit**

This task is verification only. If everything passes, the build is publish-ready. If anything fails, fix and re-run.

---

### Task 8: Manual screenshot capture (user-driven)

**Files:**
- Create: `tools/store-assets/screenshots/01-ioc-extraction.png`
- Create: `tools/store-assets/screenshots/02-osint-links.png`
- Create: `tools/store-assets/screenshots/03-graph-view.png`
- Create: `tools/store-assets/screenshots/04-snippets.png`
- Create: `tools/store-assets/screenshots/05-ask-ai.png`

These are captured by the user (no headless Chrome in the implementer env). Each is a 1280×800 PNG.

- [ ] **Step 1: Prepare Chrome**

Load the unpacked extension (use `/tmp/soc-toolkit-smoke` from Task 7, or load from the repo root).

- [ ] **Step 2: Capture `01-ioc-extraction.png`**

Open the popup. Paste `tools/store-assets/sample-iocs.txt` into the IOC input. Click "Analyze". Open DevTools → toggle device toolbar → 1280×800. Capture.

- [ ] **Step 3: Capture `02-osint-links.png`**

In the same analyzed view, expand the OSINT links section. Capture.

- [ ] **Step 4: Capture `03-graph-view.png`**

Click into the graph view tab. Capture.

- [ ] **Step 5: Capture `04-snippets.png`**

Switch to the Snippets tab. Create 2–3 sample snippets first. Capture.

- [ ] **Step 6: Capture `05-ask-ai.png`**

Open Settings. Capture the Ask AI section showing the preset dropdown, URL input, prompt template textarea, Reset button.

- [ ] **Step 7: Commit the screenshots**

```bash
git add tools/store-assets/screenshots/
git commit -m "docs(assets): 5 store-listing screenshots

Captured manually per tools/store-assets/README.md recipe.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

If headless capture is unavailable, the user can defer this task and capture later; the build and listing copy are publish-ready without it.

---

### Task 9: Manual dashboard upload (user-driven, not committed)

This is outside the repo. The user does it.

- [ ] **Step 1: Open the Chrome Web Store Developer Dashboard**

Visit `https://chrome.google.com/webstore/devconsole/`.

- [ ] **Step 2: Create a new item**

Click "New Item". Upload `dist/soc-analyst-toolkit-0.5.0.zip`.

- [ ] **Step 3: Fill in the listing**

Copy each section from `docs/STORE_LISTING.md` into the matching dashboard field. Replace `<your-org>` / `<your-repo>` in the Privacy Policy URL with the actual GitHub path.

- [ ] **Step 4: Upload store assets**

- Small promo tile: `tools/store-assets/small-promo.svg` (or PNG render).
- Marquee: `tools/store-assets/marquee.svg` (or PNG render).
- Screenshots: the five PNGs from Task 8.

- [ ] **Step 5: Submit for review**

Click "Submit for Review". Wait for the store team's response. No commit.

---

## Self-Review Notes

- **Spec coverage**: §1 → Task 2; §2 → Task 3; §3 → Task 3; §4 → Task 4 (SVG) + Task 8 (screenshots); §5 → Task 5; §6 → Task 6; §7 → Tasks 1–8; §8 → Task 7; §9 risks noted.
- **No placeholders**: every script and SVG file has the literal content above.
- **Type/signature consistency**: `manifest.json` version field is read identically in `build-store-package.sh` (Task 5) and `verify_package.sh` (Task 6) — same `grep -E '"version"' | sed -E 's/...'` pattern.
- **No task contradicts another**: Task 1 commits the working-tree CSS so Task 5's "refuse dirty tree" guard passes; Task 5 builds the zip that Task 6 asserts against.
- **Ambiguity cleared**: Task 5's `REQUIRED_DOCS` list (README / LICENSE / CHANGELOG) is explicit; the spec's "store-listing copy" is NOT shipped in the zip (it lives in `docs/STORE_LISTING.md` and the user pastes it into the dashboard).