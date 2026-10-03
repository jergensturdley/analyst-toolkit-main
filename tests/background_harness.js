'use strict';
// Loads the REAL background.js into a Node vm sandbox so tests exercise
// production code. Mirrors tests/popup_harness.js: chrome.runtime listeners
// are captured via stubs, and top-level declarations are reached through a
// second vm.runInContext call (same-context lexical scope).
const fs = require('fs');
const vm = require('vm');
const path = require('path');

function makeStorageArea() {
  const data = {};
  return {
    get(keys, cb) {
      let result;
      if (keys === null || keys === undefined) {
        result = { ...data };
      } else {
        result = {};
        for (const k of Array.isArray(keys) ? keys : [keys]) {
          if (k in data) result[k] = data[k];
        }
      }
      if (typeof cb === 'function') { cb(result); return; }
      return Promise.resolve(result);
    },
    set(obj, cb) { Object.assign(data, obj); if (typeof cb === 'function') { cb(); return; } return Promise.resolve(); },
    remove(keys, cb) { for (const k of Array.isArray(keys) ? keys : [keys]) delete data[k]; if (typeof cb === 'function') { cb(); return; } return Promise.resolve(); },
    clear() { for (const k of Object.keys(data)) delete data[k]; },
    _data: data,
  };
}

// Browser-faithful btoa: throws on code points outside Latin-1, exactly like
// the Window.btoa that production code runs against.
function btoa(s) {
  let binary = '';
  for (const ch of String(s)) {
    if (ch.codePointAt(0) > 0xff) {
      throw new Error("Failed to execute 'btoa' on 'Window': The string to be encoded contains characters outside of the Latin1 range.");
    }
    binary += ch;
  }
  return Buffer.from(binary, 'latin1').toString('base64');
}

async function loadBackgroundToolkit(root) {
  const src = fs.readFileSync(path.join(root, 'background.js'), 'utf8');
  const storageArea = makeStorageArea();
  const tabsCreated = [];
  const menuCreated = [];
  const listeners = { installed: [], message: [], command: [], windowRemoved: [] };
  const sidePanelCalls = { setOptions: [], setPanelBehavior: [] };

  let fetchImpl = async () => { throw new Error('harness: no fetch impl set'); };
  const fetchCalls = [];

  const sandbox = {
    console: { log: console.log, warn: () => {}, error: () => {} },
    TextEncoder,
    URL,
    URLSearchParams,
    structuredClone: typeof structuredClone === 'function' ? structuredClone : undefined,
    btoa,
    atob: (s) => Buffer.from(s, 'base64').toString('latin1'),
    crypto: require('crypto').webcrypto,
    // Fast timers: production delays (urlscan polling, backoff) run in milliseconds.
    setTimeout: (fn, ms) => setTimeout(fn, Math.min(Number(ms) || 0, 5)),
    clearTimeout,
    fetch: (...args) => {
      fetchCalls.push(String(args[0]));
      return Promise.resolve().then(() => fetchImpl(...args));
    },
    chrome: {
      runtime: {
        onInstalled: { addListener: (fn) => listeners.installed.push(fn) },
        onMessage: { addListener: (fn) => listeners.message.push(fn) },
        getURL: (p) => 'chrome-extension://harness/' + p,
        lastError: null,
      },
      storage: { local: storageArea },
      contextMenus: {
        removeAll: (cb) => cb && cb(),
        create: (opts) => { menuCreated.push(opts && opts.id); },
        onClicked: { addListener: () => {} },
      },
      action: {
        setBadgeBackgroundColor: () => {},
        setBadgeText: () => {},
        openPopup: async () => {},
      },
      tabs: {
        create: (opts) => { tabsCreated.push(opts); },
        query: (q, cb) => cb && cb([]),
        sendMessage: () => {},
      },
      windows: {
        create: async () => ({ id: 1 }),
        remove: async () => {},
        onRemoved: { addListener: (fn) => listeners.windowRemoved.push(fn) },
        onBoundsChanged: { addListener: () => {}, removeListener: () => {} },
      },
      sidePanel: {
        setOptions: (options) => { sidePanelCalls.setOptions.push(options); return Promise.resolve(); },
        setPanelBehavior: (options) => { sidePanelCalls.setPanelBehavior.push(options); return Promise.resolve(); },
      },
      notifications: { create: () => {} },
      scripting: { executeScript: async () => {} },
      commands: { onCommand: { addListener: (fn) => listeners.command.push(fn) } },
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox, { filename: 'background.js' });

  // Top-level const/let/class live in the context's lexical scope, not on the
  // sandbox object; a second run in the same context still sees them.
  const grab = (expr) => vm.runInContext(expr, sandbox);
  const fns = grab(`({
    vtUrlId: typeof vtUrlId === 'function' ? vtUrlId : null,
    dedupeById: typeof dedupeById === 'function' ? dedupeById : null,
    fetchURLscan: typeof fetchURLscan === 'function' ? fetchURLscan : null,
    fetchVirusTotalUrl: typeof fetchVirusTotalUrl === 'function' ? fetchVirusTotalUrl : null,
    fetchVirusTotalIp: typeof fetchVirusTotalIp === 'function' ? fetchVirusTotalIp : null,
    fetchURLhaus: typeof fetchURLhaus === 'function' ? fetchURLhaus : null,
    agentCacheKeysToPrune: typeof agentCacheKeysToPrune === 'function' ? agentCacheKeysToPrune : null,
    setCachedAgentResult: typeof setCachedAgentResult === 'function' ? setCachedAgentResult : null,
    configureSidePanel: typeof configureSidePanel === 'function' ? configureSidePanel : null,
  })`);

  const messageListener = listeners.message[0];
  if (typeof messageListener !== 'function') {
    throw new Error('background.js loaded but onMessage listener was not registered');
  }

  const dispatch = (request) => new Promise((resolve) => {
    let settled = false;
    const done = (value) => { if (!settled) { settled = true; resolve(value); } };
    const sendResponse = (payload) => done({ payload });
    const returnValue = messageListener(request, {}, sendResponse);
    if (returnValue === false) done({ returnValue });
    setTimeout(() => done({ timeout: true }), 2000);
  });

  const resetState = () => {
    storageArea.clear();
    grab('rateLimiter.requestLog.clear()');
    fetchCalls.length = 0;
    tabsCreated.length = 0;
    fetchImpl = async () => { throw new Error('harness: no fetch impl set'); };
  };

  return {
    sandbox,
    fns,
    RATE_LIMITS: grab('RATE_LIMITS'),
    exhaustRateLimit: grab('((provider, n) => { for (let i = 0; i < n; i++) rateLimiter.recordRequest(provider); })'),
    storageData: storageArea._data,
    tabsCreated,
    menuCreated,
    fetchCalls,
    sidePanelCalls,
    listeners,
    setFetchImpl: (fn) => { fetchImpl = fn; },
    resetState,
    dispatch,
  };
}

function jsonResponse(body, { status = 200, statusText = '' } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    headers: { get: () => null },
    json: async () => body,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  };
}

module.exports = { loadBackgroundToolkit, jsonResponse };
