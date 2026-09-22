// SOC Analyst Toolkit — Playwright screenshot capture
// Loads the unpacked extension in Chrome-for-Testing and captures
// IOC parsing, enrichment, graph, and settings screenshots.

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const EXT_PATH = path.resolve(__dirname, '..', 'dist', 'staging');
const OUT_DIR = path.resolve(__dirname);

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

async function getExtensionId(context) {
  // Service workers are the most reliable signal that the MV3 extension is loaded.
  let sw = context.serviceWorkers().find(w => w.url().includes('chrome-extension://'));
  if (!sw) {
    sw = await context.waitForEvent('serviceworker', { timeout: 15000 }).catch(() => null);
  }
  if (sw) {
    const m = sw.url().match(/^chrome-extension:\/\/([a-z]+)\//);
    if (m) return m[1];
  }
  // Fallback: scrape about:extensions via a real page.
  const page = await context.newPage();
  await page.goto('chrome://extensions/');
  await page.waitForTimeout(800);
  const id = await page.evaluate(() => {
    const m = location.href.match(/id=([a-z]+)/);
    if (m) return m[1];
    return null;
  });
  await page.close();
  if (id) return id;
  throw new Error('Could not determine extension ID');
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
  // permission denied). Use the full Chrome-for-Testing binary instead.
  const chromePath = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false, // Extensions only load with a window server on macOS.
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
    const extId = await getExtensionId(context);
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