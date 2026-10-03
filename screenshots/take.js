// SOC Analyst Toolkit — Playwright screenshot capture
// Loads the unpacked extension in Chrome-for-Testing and captures
// IOC parsing, enrichment, graph, and settings screenshots.
// Prerequisites: npm install && npx playwright install chromium,
// plus a built package (scripts/build-store-package.sh → dist/staging).

let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (e) {
  console.error('Playwright is not installed. Run: npm install && npx playwright install chromium');
  process.exit(1);
}
const path = require('path');
const fs = require('fs');

const EXT_PATH = path.resolve(__dirname, '..', 'dist', 'staging');
const OUT_DIR = path.resolve(__dirname);

// Chrome binary: explicit override, else the newest cached Playwright
// chromium build (the exact build number drifts with each Playwright
// release, so nothing is hardcoded), else whatever this Playwright
// expects.
function resolveChromePath() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const cache = path.join(process.env.HOME, 'Library/Caches/ms-playwright');
  if (fs.existsSync(cache)) {
    const builds = fs.readdirSync(cache)
      .filter((d) => /^chromium-\d+$/.test(d))
      .sort()
      .reverse();
    for (const b of builds) {
      const p = path.join(cache, b, 'chrome-mac-arm64',
        'Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
      if (fs.existsSync(p)) return p;
      const pX64 = p.replace('chrome-mac-arm64', 'chrome-mac');
      if (fs.existsSync(pX64)) return pX64;
    }
  }
  return chromium.executablePath();
}

const SAMPLE_IOCS = `Suspicious activity observed from 198.51.100.42 contacting evil[.]example[.]com
and hxxps://malware[.]example[.]net/payload.exe at 2026-07-09 03:14 UTC.
Additional indicators:
  - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  - CVE-2024-3400
  - contact: attacker@badactor[.]test
  - 203.0.113.7
Defanged URLs:
  hxxp://phish[.]login-portal[.]example/auth
  hxxps://cdn[.]badactor[.]test/track.js
`;

const crypto = require('crypto');

function unpackedExtensionId(extPath) {
  // Chrome derives the unpacked extension ID from the sha256 of the absolute
  // load path: first 32 hex chars, mapped 0-9a-f -> a-p.
  const hex = crypto.createHash('sha256').update(extPath, 'utf8').digest('hex').slice(0, 32);
  return hex.split('').map((c) => String.fromCharCode(97 + parseInt(c, 16))).join('');
}

async function getExtensionId(context, extPath) {
  // Service workers are the most reliable live signal that the MV3
  // extension loaded; the path hash is the deterministic fallback.
  let sw = context.serviceWorkers().find(w => w.url().includes('chrome-extension://'));
  if (!sw) {
    sw = await context.waitForEvent('serviceworker', { timeout: 8000 }).catch(() => null);
  }
  if (sw) {
    const m = sw.url().match(/^chrome-extension:\/\/([a-z]+)\//);
    if (m) return m[1];
  }
  console.log('[info] no service worker seen; using unpacked path-hash id');
  return unpackedExtensionId(extPath);
}

async function shot(page, file, opts = {}) {
  const out = path.join(OUT_DIR, file);
  await page.screenshot({ path: out, fullPage: false, ...opts });
  console.log(`[ok] ${file}`);
}

(async () => {
  const userDataDir = path.resolve(__dirname, '.pw-profile');
  if (fs.existsSync(userDataDir)) {
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }

  // The cached "chrome-headless-shell" binary fails on this Mac (Mach port
  // permission denied). Branded Google Chrome ignores --load-extension since
  // ~v137, so default to the Playwright-cached Chrome-for-Testing binary.
  const chromePath = resolveChromePath();

  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false, // Extensions only load with a window server on macOS.
    // The popup renders at its fixed ~800px design width; capture there and
    // pad to the store's 1280x800 afterwards (scripts/make-store-jpegs.sh).
    viewport: { width: 820, height: 620 },
    deviceScaleFactor: 2,
    executablePath: chromePath,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      '--no-sandbox',
      '--disable-dev-shm-usage',
    ],
  });

  try {
    const extId = await getExtensionId(context, EXT_PATH);
    const popupUrl = `chrome-extension://${extId}/popup.html`;
    console.log(`[info] extension id: ${extId}`);

    const page = await context.newPage();
    page.on('console', msg => {
      if (msg.type() === 'error') console.log(`[console.error] ${msg.text()}`);
    });
    page.on('pageerror', err => console.log(`[pageerror] ${err.message}`));

    await page.goto(popupUrl, { waitUntil: 'load' });
    // Give popup.js time to bind event listeners and load vis-network.
    await page.waitForSelector('#iocInput', { timeout: 10000 });
    await page.waitForFunction(() => typeof window.vis !== 'undefined' || typeof window.analyzeIOCs === 'function', { timeout: 10000 }).catch(() => {});
    await page.waitForTimeout(400);

    // ── 1. IOC parsing (initial state, empty input) ────────────────────────
    await shot(page, '01-initial-empty.png');

    // Fill with sample IOCs and trigger analysis.
    await page.fill('#iocInput', SAMPLE_IOCS);
    await page.click('#analyzeBtn');
    // Wait for results to render (ioc-results list contains non-empty-state items).
    await page.waitForFunction(() => {
      const items = document.querySelectorAll('#iocResults .ioc-item');
      return items.length > 1; // >1 because empty-state may still exist briefly
    }, { timeout: 10000 }).catch(() => {});
    await page.waitForTimeout(600);
    await shot(page, '02-ioc-parsing.png');

    // ── 2. Enrichment view ─────────────────────────────────────────────────
    // Click the first row's Enrich pill (per-row enrichment via the live
    // providers), pass the one-time consent gate, then capture the verdict
    // chip with its inline summary and the full detail panel.
    let enriched = false;
    const rowEnrich = await page.$('.ioc-item[data-type="ip"] .row-enrich-btn')
      || await page.$('.row-enrich-btn');
    if (rowEnrich) {
      await rowEnrich.click();
      enriched = true;
    }
    if (enriched) {
      // First enrichment shows the consent modal; allow it so the flow runs.
      await page.waitForSelector('#consentModal', { state: 'visible', timeout: 4000 }).catch(() => {});
      const allow = await page.$('#consentAllowBtn');
      if (allow && await allow.isVisible()) {
        await allow.click();
      }
      await page.waitForSelector('.row-status-chip', { timeout: 20000 }).catch(() => {});
      await page.waitForTimeout(500);
      const chip = await page.$('.row-status-chip');
      if (chip) await chip.click();            // expand the inline summary
      await page.waitForTimeout(300);
      const details = await page.$('.row-details-btn');
      if (details) {
        await details.click();                 // open the full enrichment panel
        await page.waitForSelector('#enrichmentDetailPanel', { state: 'visible', timeout: 5000 }).catch(() => {});
        await page.waitForFunction(() => document.querySelectorAll('.enrichment-source-card').length > 0, { timeout: 10000 }).catch(() => {});
      }
      await page.evaluate(() => document.getElementById('enrichmentDetailPanel')?.scrollIntoView({ block: 'center' }));
      await page.waitForTimeout(800);
    }
    await shot(page, '03-enrichment.png');

    // ── 3. Graph visualization ─────────────────────────────────────────────
    // The graph generates together with the results (enableGraph defaults on).
    await page.waitForSelector('#iocGraph.active', { timeout: 8000 }).catch(() => {});
    // vis-network runs a physics layout; let it settle before the shot.
    await page.waitForTimeout(1500);
    await page.evaluate(() => document.getElementById('iocGraph')?.scrollIntoView({ block: 'center' }));
    await page.waitForTimeout(300);
    await shot(page, '04-graph.png');

    // ── 4. Settings tab ────────────────────────────────────────────────────
    await page.click('.tab-btn[data-tab="settings"]');
    await page.waitForSelector('#settings-tab.active', { timeout: 5000 }).catch(() => {});
    // Scroll the settings tab to the top so the screenshot shows the header.
    await page.evaluate(() => {
      const tab = document.querySelector('#settings-tab');
      if (tab) tab.scrollTop = 0;
    });
    await page.waitForTimeout(400);
    await shot(page, '05-settings-top.png');

    // And a second shot of the lower portion (enrichment providers + storage).
    await page.evaluate(() => {
      const tab = document.querySelector('#settings-tab');
      if (tab) tab.scrollTop = tab.scrollHeight / 2;
    });
    await page.waitForTimeout(400);
    await shot(page, '06-settings-mid.png');

    await page.close();
  } finally {
    await context.close();
    // Clean the persistent profile so re-runs are deterministic.
    if (fs.existsSync(userDataDir)) {
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  }

  console.log('[done]');
})().catch(err => {
  console.error('[fatal]', err);
  process.exit(1);
});