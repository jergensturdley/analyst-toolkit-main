# Chrome Web Store Publish — Design

**Date:** 2026-07-08
**Scope:** SOC Analyst Toolkit browser extension (MV3). Edit main in place. No branch.
**Out of scope:** refactoring `popup.js` / `background.js`; module split; CI release workflow; non-English listing translations.

---

## Goals

1. Produce a reproducible Chrome Web Store package (`dist/soc-analyst-toolkit-0.5.0.zip`) from a clean checkout.
2. Produce all required store-listing assets: small promo tile (440×280), marquee (1400×560), and 5 screenshots.
3. Bump `manifest.version` to `0.5.0` to reflect the Ask AI + security work.
4. Add a privacy policy page (`docs/PRIVACY.md`) and store-listing copy (`docs/STORE_LISTING.md`).
5. Document the manual Chrome Web Store dashboard steps the user runs (since the dashboard itself is outside the repo).

## Non-goals

- Module refactor of `popup.js` (3,794 lines) / `background.js` (2,517 lines) into ES modules.
- Removing the pre-existing `M popup.html` defang CSS — that is pre-session user work, out of scope.
- Adding CI / GitHub Actions release workflow. The user uploads manually.
- Translating the store listing to other languages.
- Submitting for review. The user submits; we don't have access to the dashboard.

---

## Architecture context (established)

- MV3 extension, vanilla JS, no bundler, no `package.json`.
- Current manifest declares: `storage`, `clipboardWrite`, `contextMenus`, `notifications`, `activeTab`, `host_permissions: <all_urls>`. All retained per user decision.
- Icons: `icons/icon{16,32,48,128}.png` already exist (verified PNG, correct dimensions).
- License: MIT (`LICENSE`).
- Documentation: `README.md` (5.4K), `CHANGELOG.md` (3.3K, has `[Unreleased]` section with current work), `FEATURES.md` (6.0K), `AGENTS.md` (62.3K, internal enrichment-agent spec), `UPGRADE_GUIDE.md` (6.5K).

---

## 1. Manifest version bump

### 1.1 Change

`manifest.json` line 4:

```json
"version": "0.4",
```

→

```json
"version": "0.5.0",
```

### 1.2 CHANGELOG entry

Move the existing `[Unreleased]` section into a new `## [0.5.0] - 2026-07-08` heading in `CHANGELOG.md`. Add Ask AI to the new section's `### Added` block. Keep the `[Unreleased]` section absent (no new unreleased work after this release).

---

## 2. Privacy policy (`docs/PRIVACY.md`)

Single Markdown file, ≤ 50 lines, written in user-facing language. Hosted via the GitHub raw URL of the file in the repository (no GitHub Pages needed; Chrome Web Store accepts raw GitHub URLs).

Required content:

- One-line summary: "SOC Analyst Toolkit is free, with no in-app purchases, subscriptions, ads, upsells, or premium tiers. It does not collect, transmit, or sell user data."
- Pricing: "The extension is 100% free. There are no in-app purchases, no subscriptions, no ads, no premium features, and no paid tier. The source is open (MIT license) on GitHub."
- Data storage: "Settings, snippets, IOC history, and enrichment-agent results are stored locally in your browser via `chrome.storage.local`. They never leave your machine except when you explicitly initiate an OSINT lookup."
- Network usage: "Outbound HTTP requests only occur when you click an OSINT lookup link, run an enrichment agent, or invoke the Ask AI flow. Requests go to the providers configured in Settings (default: VirusTotal, ipinfo.io, AbuseIPDB, GreyNoise, plus the user-configured Ask AI target URL)."
- Third-party access: "The extension author has no access to user data."
- Updates: "This policy may change with new versions; the change log is in `CHANGELOG.md`."
- Contact: GitHub repo URL.

---

## 3. Store listing copy (`docs/STORE_LISTING.md`)

Markdown file with sections that map 1:1 to the Chrome Web Store dashboard fields. User copy-pastes each section.

Sections:

### 3.1 Title

```
SOC Analyst Toolkit
```

### 3.2 Short description (≤ 132 chars)

```
Extract IOCs from selected text, run OSINT lookups across 20+ threat-intel platforms, manage snippets, and triage with AI. 100% local.
```

(120 chars; leaves margin.)

### 3.3 Detailed description

Markdown body, ~250 words. Pulls from `README.md` and `FEATURES.md`. Sections:

- One-paragraph pitch.
- Free + open: "100% free, no in-app purchases, no subscriptions, no ads, no premium tier. MIT-licensed open source."
- Feature bullets grouped: IOC Detection & Analysis / OSINT Integration / Productivity / Ask AI.
- Privacy line ("All processing local; only user-initiated lookups hit the network").
- Link to the GitHub repo for source.

### 3.4 Category

Productivity.

### 3.5 Language

English.

### 3.6 Single-purpose justification

```
Triage security indicators of compromise. The extension extracts IOCs from selected
text, generates deep links to 20+ OSINT providers for one-click lookup, manages
analyst snippets, and offers an optional Ask AI panel that builds a triage prompt
for the user's chosen AI chat. All processing is local; the only outbound network
calls are user-initiated.
```

### 3.7 Permission justifications

One paragraph per permission, in the order Chrome Web Store lists them:

- **`storage`** — Stores user settings (theme, snippets, custom OSINT sources, Ask AI config, enrichment cache) in `chrome.storage.local`. No sync, no remote.
- **`clipboardWrite`** — Copies IOCs and AI triage prompts to the clipboard at user request.
- **`contextMenus`** — Adds the right-click "Analyze with SOC Toolkit" item and the OSINT-lookup submenu.
- **`notifications`** — Surfaces background-task results (e.g. enrichment agent completion).
- **`activeTab`** — Lets the context-menu actions read the current tab's selected text.
- **`host_permissions: <all_urls>`** — Required because the OSINT links and enrichment agents target user-configurable third-party services (VirusTotal, ipinfo.io, AbuseIPDB, GreyNoise, etc.). Only the user-configured domains are contacted, only when the user clicks.

### 3.8 Privacy policy URL

The GitHub raw URL of `docs/PRIVACY.md` in the repo. Placeholder until the repo URL is known — user fills in.

### 3.9 Single-purpose disclosure (justification for "no remote code / no data sale")

Explicit attestation: the extension contains no analytics SDK, no remote code load, no auto-update mechanism, no fingerprinting. All code is the files in this repository.

---

## 4. Store listing assets

### 4.1 Marquee (1400 × 560)

`tools/store-assets/marquee.svg` — ship SVG only. Chrome Web Store accepts SVG in some slots and the user can render PNG in any browser via File → Save As (1280×800 PNG export). No `rsvg-convert` dependency.

- Background: solid dark navy matching the popup's default theme (`#0d1117` from existing CSS).
- Foreground: the existing `icons/icon128.png` rendered as a large glyph on the left, the extension name + tagline on the right.
- Tagline (≤ 60 chars): "IOC extraction · OSINT lookups · AI triage".
- Font: system-ui sans-serif (no embedded fonts; renders consistently).

### 4.2 Small promo tile (440 × 280)

`tools/store-assets/small-promo.svg` — same SVG-only approach as the marquee. Visual style consistent with the marquee, scaled for the 440×280 slot.

### 4.3 Screenshots (1280 × 800, 5 total)

PNG, captured manually. `tools/store-assets/README.md` provides the recipe:

1. Load the extension unpacked in Chrome.
2. Open the popup, paste the sample text provided in the README.
3. Click "Analyze".
4. Use Chrome DevTools → device toolbar → 1280×800, capture each tab/section.

Files (numbered for dashboard order):

- `01-ioc-extraction.png` — popup showing extracted IOCs (counts, types, defang toggle).
- `02-osint-links.png` — per-IOC OSINT link list expanded.
- `03-graph-view.png` — vis-network graph of IOCs and their relationships.
- `04-snippets.png` — snippet library with a few sample snippets.
- `05-ask-ai.png` — Ask AI settings section showing preset dropdown + custom prompt template.

The recipe includes the sample text and theme recommendation (use the default Arc theme for consistency).

---

## 5. Package builder (`scripts/build-store-package.sh`)

Bash script, ~60 lines, no dependencies beyond standard Unix tools (`bash`, `cp`, `mkdir`, `zip`, `git`).

### 5.1 Behavior

```
1. Set repo_root = $(git rev-parse --show-toplevel).
2. Refuse to run if working tree is dirty (git diff --quiet HEAD || exit 1).
3. Read manifest.json; extract version with grep+sed (no jq required).
4. Create dist/ (rm -rf, mkdir).
5. Create dist/staging/.
6. Copy required files into dist/staging/:
     manifest.json, background.js, content.js, popup.js, popup.html,
     tlds.js, vis-network.min.js,
     icons/, css/, webfonts/,
     README.md, LICENSE, CHANGELOG.md
7. Print a manifest of staged files for human review.
8. (dist/soc-analyst-toolkit-${version}.zip, no DS_Store)
9. Print SHA256 of the zip.
```

### 5.2 Excluded paths (must NOT appear in the zip)

```
.git/ .gitignore
.codegraph/ .claude/ .superpowers/
CLAUDE.md
docs/superpowers/
docs/PRIVACY.md docs/STORE_LISTING.md
tests/ scripts/ tools/
node_modules/ dist/
*.log *.tmp *.bak .DS_Store
```

Exclusion is explicit (rsync `--exclude` flags), not implicit. The manifest printout lets the user eyeball what's included.

### 5.3 Failure modes

- Working tree dirty → exit 1 with "commit or stash changes first".
- `manifest.json` missing or unparseable → exit 1.
- `zip` not on PATH → exit 1 with install hint.
- A required file missing → exit 1 listing the missing file.

### 5.4 Verification

After packaging, list the staged files. No automated Chrome load (no headless Chrome in CI). User manually loads `dist/soc-analyst-toolkit-0.5.0.zip` via `chrome://extensions` after extraction (or uses the dashboard's "Load unpacked" on the staging dir).

---

## 6. Tests

### 6.1 Existing

`node tests/verify_features.js` — 57 passed / 0 failed. Gates code correctness.

### 6.2 New — package contents test

`tests/verify_package.sh` (bash, framework-free, ~25 lines).

Asserts against the **already-built** `dist/soc-analyst-toolkit-*.zip`:
- `scripts/build-store-package.sh` exists and is executable.
- A `dist/soc-analyst-toolkit-*.zip` exists (assume previously built; this test does NOT re-run the build, so a dirty tree does not break the test).
- The zip, when unzipped, contains every required file and none of the excluded paths.
- `manifest.json` inside the zip has `version` matching `^[0-9]+\.[0-9]+\.[0-9]+$`.

Run via:

```bash
bash scripts/build-store-package.sh && bash tests/verify_package.sh
```

Or to verify an existing build:

```bash
bash tests/verify_package.sh
```

If both pass, the package is publish-ready modulo the user-driven Chrome Web Store dashboard steps.

---

## 7. Implementation order

1. **Pre-flight commit**: commit the pre-existing `M popup.html` defang CSS as a `chore:` commit. Refuses-to-package guard depends on a clean tree.
2. **Manifest version bump** + **CHANGELOG entry** — small, single commit.
3. **`docs/PRIVACY.md`** + **`docs/STORE_LISTING.md`** — text-only, one commit.
4. **`tools/store-assets/`** — SVG sources + README recipe. One commit.
5. **`scripts/build-store-package.sh`** — the packaging script. One commit.
6. **`tests/verify_package.sh`** — the contents test. One commit.
7. **First end-to-end build** — run the script, eyeball the staging manifest, verify the zip unzips cleanly. Manual.
8. **Manual screenshot capture** — five PNGs in `tools/store-assets/screenshots/`. Manual.
9. **Manual dashboard upload** — outside the repo, not committed.

Each step leaves the extension loadable from the working tree AND the test suite green.

---

## 8. Verification

- `node tests/verify_features.js` — must report `Failed: 0`.
- `bash scripts/build-store-package.sh && bash tests/verify_package.sh` — both exit 0.
- `unzip -l dist/soc-analyst-toolkit-0.5.0.zip` — manifest matches §5.2.
- Manual: extract the zip, load unpacked in Chrome, smoke-test the popup as in the Ask AI plan §6.

---

## 9. Risks

- **Store review delays.** Chrome Web Store review averages a few days but can take longer. Acceptable.
- **Permission scrutiny.** `<all_urls>` triggers a manual review flag. The justification in §3.7 is detailed; if rejected, fall back to narrowing host_permissions to a curated list (out of scope for this spec).
- **Screenshot consistency.** Manually captured screenshots may drift visually across themes. The recipe recommends the default Arc theme for store assets; user picks a coherent set.
- **Render tool availability.** `rsvg-convert` is not always installed; the SVG-only fallback requires the user to render manually. The README documents this.
- **Pre-existing working-tree changes.** The `M popup.html` defang CSS is pre-session user work. The packaging script refuses a dirty tree, so this commit (§7.1) is mandatory before packaging.

---

## Self-Review

- **Spec coverage**: each §1–§6 maps to a task in §7. Self-contained.
- **No placeholders**: §3.8 has one "URL filled in by user" line — intentional, not a TODO.
- **Type/signature consistency**: `version` field in `manifest.json` is read by the build script via the same grep pattern; both refer to `0.5.0`.
- **Scope check**: focused on packaging + listing; no module refactor creep.
- **Ambiguity check**: the "manual screenshot capture" step is explicit that it's a user action, not an automated task.