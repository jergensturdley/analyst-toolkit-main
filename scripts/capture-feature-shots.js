#!/usr/bin/env node
'use strict';
// Capture store screenshots for the layout features (sidebar navigation,
// floating window, side panel) from the real extension in Chromium over CDP,
// then convert them to Chrome Web Store 1280x800 JPEGs. Dependency-free
// (Node >= 22 for the global WebSocket); macOS not required — no synthetic
// input is used. Regenerates screenshots/07..09.png and
// screenshots/store/screenshot-7..9.jpg. (screenshots 01-06 come from
// take.js + make-store-jpegs.sh.)
//
// Usage: node scripts/capture-feature-shots.js [chromium-binary]

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CHROME = process.argv[2] || process.env.CHROME_BIN || '/Applications/Chromium.app/Contents/MacOS/Chromium';
const ROOT = path.resolve(__dirname, '..');
const PORT = Number(process.env.SHOTS_PORT || 9351);
const PROFILE = '/tmp/soc-feature-shots';
const SAMPLE = fs.readFileSync(path.join(ROOT, 'tools/store-assets/sample-iocs.txt'), 'utf8').trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function openPage(url, metrics) {
  const t = await (await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' })).json();
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let seq = 0; const pending = new Map(); const logs = [];
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); }
    else if (m.method === 'Runtime.consoleAPICalled') logs.push(m.params.args.map((a) => a.value ?? a.description ?? '').join(' ').slice(0, 160));
    else if (m.method === 'Runtime.exceptionThrown') logs.push('EXC ' + (m.params.exceptionDetails.exception?.description || '').slice(0, 200));
  };
  const send = (method, params = {}) => new Promise((res, rej) => { const i = ++seq; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { ...metrics, mobile: false });
  const page = {
    send, logs,
    eval: async (expression) => {
      const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error('eval threw: ' + (r.exceptionDetails.exception?.description || '').slice(0, 200));
      return r.result.value;
    },
    shot: async (file) => {
      const r = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(file, Buffer.from(r.data, 'base64'));
    },
    analyze: async () => {
      await page.eval(`document.getElementById('iocInput').value = ${JSON.stringify(SAMPLE)}; document.getElementById('analyzeBtn').click(); 'ok'`);
      await sleep(900);
    },
  };
  await sleep(1000);
  return page;
}

const pad = (input, output) => execSync(
  `ffmpeg -y -v error -i "${input}" -vf "scale=w='min(1280,iw*800/ih)':h='min(800,ih*1280/iw)':flags=lanczos,pad=1280:800:(ow-iw)/2:(oh-ih)/2:color=#0d1117" -q:v 2 "${output}"`);

async function main() {
  execSync(`rm -rf ${PROFILE}`);
  const chrome = spawn(CHROME, [
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${PROFILE}`,
    `--disable-extensions-except=${ROOT}`, `--load-extension=${ROOT}`,
    '--no-first-run', '--window-size=1400,1000', 'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    for (let i = 0; i < 40; i++) { try { await fetch(`http://127.0.0.1:${PORT}/json/version`); break; } catch { await sleep(250); } }
    await sleep(1500);
    const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
    const id = list.find((t) => t.type === 'service_worker' && t.url.startsWith('chrome-extension://')).url.split('/')[2];

    // Seed preferences (sidebar rail + expanded OSINT rows) from an extension page.
    const seed = await openPage(`chrome-extension://${id}/popup.html`, { width: 800, height: 600, deviceScaleFactor: 1 });
    await seed.eval(`chrome.storage.local.set({ socSettings: { navLayout: 'sidebar', linksExpanded: true } }); 'ok'`);

    // 07 — sidebar navigation in the toolbar popup.
    const sidebar = await openPage(`chrome-extension://${id}/popup.html`, { width: 800, height: 600, deviceScaleFactor: 2 });
    await sidebar.analyze();
    await sidebar.shot(path.join(ROOT, 'screenshots/07-sidebar-navigation.png'));

    // 08 — floating window: wide, sidebar rail, resize grip in the corner.
    const floating = await openPage(`chrome-extension://${id}/popup.html?float=1`, { width: 1040, height: 780, deviceScaleFactor: 2 });
    await floating.analyze();
    if (!(await floating.eval('getComputedStyle(document.getElementById("floatResizeGrip")).display')) === 'block') throw new Error('resize grip not visible');
    await floating.shot(path.join(ROOT, 'screenshots/08-floating-window.png'));

    // 09 — side panel: real ?panel=1 layout at panel dimensions.
    const panel = await openPage(`chrome-extension://${id}/popup.html?panel=1`, { width: 400, height: 800, deviceScaleFactor: 2 });
    await panel.analyze();
    if (await panel.eval('document.documentElement.scrollWidth - window.innerWidth') > 0) throw new Error('panel overflows horizontally');
    await panel.shot('/tmp/panel-raw.png');

    // The composite: the sample alert page beside the panel that triages it.
    const mail = await openPage(`file://${path.join(ROOT, 'tools/store-assets/sample-alert.html')}`, { width: 868, height: 800, deviceScaleFactor: 2 });
    await mail.shot('/tmp/mail-raw.png');
    execSync(`ffmpeg -y -v error -i /tmp/panel-raw.png -i /tmp/mail-raw.png -filter_complex "[0]scale=400:800:flags=lanczos[p];[1]scale=868:800:flags=lanczos[m];[p][m]hstack=inputs=2,pad=1280:800:(ow-iw)/2:(oh-ih)/2:color=#0d1117" -q:v 2 "${path.join(ROOT, 'screenshots/09-side-panel.png')}"`);

    pad(path.join(ROOT, 'screenshots/07-sidebar-navigation.png'), path.join(ROOT, 'screenshots/store/screenshot-7.jpg'));
    pad(path.join(ROOT, 'screenshots/08-floating-window.png'), path.join(ROOT, 'screenshots/store/screenshot-8.jpg'));
    pad(path.join(ROOT, 'screenshots/09-side-panel.png'), path.join(ROOT, 'screenshots/store/screenshot-9.jpg'));

    for (const p of [sidebar, floating, panel, mail]) {
      if (p.logs.length) throw new Error('console noise during capture: ' + p.logs.join(' | '));
    }
    console.log('wrote screenshots/07..09.png and screenshots/store/screenshot-7..9.jpg');
  } finally {
    chrome.kill('SIGKILL');
    execSync(`rm -rf ${PROFILE}`);
  }
}

main().catch((e) => { console.error('capture failed:', e.message); process.exit(1); });
