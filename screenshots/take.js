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
  const chromePath = '/Users/jhonniey/Library/Caches/ms-playwright/chromium-1228/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing';

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
    // Try to enrich the first IP via its per-item button if present, otherwise
    // fall back to the bulk "Enrich IPs" button.
    let enriched = false;
    const enrichBtns = await page.$$('.enrich-btn, [data-action="enrich"]');
    if (enrichBtns.length > 0) {
      await enrichBtns[0].click();
      enriched = true;
    } else {
      const enrichIps = await page.$('#enrichAllIPsBtn');
      if (enrichIps) {
        await enrichIps.click();
        enriched = true;
      }
    }
    if (enriched) {
      await page.waitForSelector('#enrichmentDetailPanel', { state: 'visible', timeout: 8000 }).catch(() => {});
      // Wait for either the panel body to open or for source cards to render.
      await page.waitForFunction(() => {
        const panel = document.querySelector('#enrichmentDetailPanel');
        if (!panel || panel.style.display === 'none') return false;
        const cards = document.querySelectorAll('.enrichment-source-card');
        return cards.length > 0;
      }, { timeout: 12000 }).catch(() => {});
      // Open the panel body so the source cards are visible in the shot.
      await page.evaluate(() => {
        const body = document.querySelector('#enrichmentPanelBody');
        if (body) body.classList.add('open');
      });
      await page.waitForTimeout(800);
    }
    await shot(page, '03-enrichment.png');

    // ── 3. Graph visualization ─────────────────────────────────────────────
    // Trigger the graph (the popup exposes a graph element with id iocGraph).
    await page.evaluate(() => {
      // Try common entry points used by popup.js.
      const fns = ['renderGraph', 'showGraph', 'updateGraph', 'displayGraph'];
      for (const f of fns) {
        if (typeof window[f] === 'function') { window[f](); return; }
      }
      // Fallback: simulate clicking an IOC to surface any graph wiring.
      const firstIoc = document.querySelector('#iocResults .ioc-item');
      if (firstIoc) firstIoc.click();
    });
    await page.waitForSelector('#iocGraph.active', { timeout: 5000 }).catch(() => {});
    // Some implementations use a vis-network canvas; give it a moment to lay out.
    await page.waitForTimeout(1200);
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