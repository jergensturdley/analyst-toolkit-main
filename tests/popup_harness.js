'use strict';
// Loads the REAL popup.js into a Node vm sandbox so tests exercise production code.
const fs = require('fs');
const vm = require('vm');
const path = require('path');

function stubEl(id) {
  const classes = new Set();
  const el = {
    id,
    value: '',
    textContent: '',
    innerHTML: '',
    style: {},
    title: '',
    checked: false,
    dataset: {},
    classList: {
      add: (...names) => names.forEach((n) => classes.add(n)),
      remove: (...names) => names.forEach((n) => classes.delete(n)),
      toggle(name, force) {
        const on = force === undefined ? !classes.has(name) : Boolean(force);
        if (on) classes.add(name); else classes.delete(name);
        return on;
      },
      contains: (name) => classes.has(name),
    },
    _listeners: {},
    _attrs: {},
    addEventListener(type, fn) { el._listeners[type] = fn; },
    removeEventListener(type) { delete el._listeners[type]; },
    setAttribute(k, v) { el._attrs[k] = String(v); },
    getAttribute(k) { return k in el._attrs ? el._attrs[k] : null; },
    removeAttribute(k) { delete el._attrs[k]; },
    appendChild() {},
    click() {},
    querySelector(sel) { return (el._qs && el._qs[sel]) || null; },
    querySelectorAll(sel) { return (el._qsa && el._qsa[sel]) || []; },
    // Test hooks: pin querySelector(All) results to this element.
    __setQuerySelector(sel, target) { (el._qs = el._qs || {})[sel] = target; },
    __setQuerySelectorAll(sel, targets) { (el._qsa = el._qsa || {})[sel] = targets; },
    focus() {},
    select() {},
    remove() {},
    setPointerCapture() {},
    releasePointerCapture() {},
  };
  return el;
}

function makeDocument() {
  const elements = {};
  const bySelector = {};
  const bySelectorAll = {};
  const listeners = {};
  const doc = {
    readyState: 'complete',
    getElementById(id) { return (elements[id] = elements[id] || stubEl(id)); },
    querySelector(sel) { return bySelector[sel] || null; },
    querySelectorAll(sel) { return bySelectorAll[sel] || []; },
    __setQuerySelector(sel, el) { bySelector[sel] = el; },
    __setQuerySelectorAll(sel, els) { bySelectorAll[sel] = els; },
    createElement(tag) { return (doc.__lastCreated = stubEl(tag)); },
    addEventListener(type, fn) { listeners[type] = fn; },
    removeEventListener(type) { delete listeners[type]; },
    _listeners: listeners,
    body: stubEl('body'),
    documentElement: stubEl('html'),
  };
  return doc;
}

function makeStorageArea() {
  const data = {};
  return {
    get(keys, cb) {
      const result = {};
      if (keys === null || keys === undefined) {
        Object.assign(result, data);
      } else {
        for (const k of Array.isArray(keys) ? keys : [keys]) {
          if (k in data) result[k] = data[k];
        }
      }
      if (typeof cb === 'function') return cb(result);
      return Promise.resolve(result);
    },
    set(obj, cb) { Object.assign(data, obj); if (typeof cb === 'function') return cb(); return Promise.resolve(); },
    remove(keys, cb) { for (const k of Array.isArray(keys) ? keys : [keys]) delete data[k]; if (typeof cb === 'function') return cb(); return Promise.resolve(); },
  };
}

async function loadPopupToolkit(root, opts = {}) {
  const src = fs.readFileSync(path.join(root, 'popup.js'), 'utf8');
  const document = makeDocument();
  const storageArea = makeStorageArea();
  const tabCreates = [];
  const windowUpdates = [];
  const closeCalls = [];

  const sandbox = {
    console,
    TextEncoder,
    URLSearchParams,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    close: () => { closeCalls.push(true); },
    navigator: { clipboard: { writeText: async () => {} }, userAgent: 'node-harness' },
    location: { href: 'chrome-extension://harness/popup.html', search: opts.float ? '?float=1' : '' },
    document,
    chrome: {
      runtime: {
        getManifest: () => ({ version: '0.0.0' }),
        sendMessage: async () => null,
        onMessage: { addListener() {}, removeListener() {} },
        getURL: (p) => 'chrome-extension://harness/' + p,
        lastError: null,
      },
      storage: { local: { ...storageArea }, sync: { ...storageArea }, onChanged: { addListener() {} } },
      tabs: { create: (createOptions) => { tabCreates.push(createOptions); }, query: async () => [] },
      windows: {
        getCurrent: async () => ({ id: 42 }),
        update: (id, updateInfo) => { windowUpdates.push(Object.assign({ id }, updateInfo)); return Promise.resolve(); },
      },
      contextMenus: { create() {}, onClicked: { addListener() {} } },
    },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
  sandbox.requestAnimationFrame = (cb) => setTimeout(cb, 0);
  sandbox.MutationObserver = class { observe() {} disconnect() {} };
  // Minimal DOM APIs popup.js touches on export/import paths.
  sandbox.Blob = class { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } };
  sandbox.URL = { createObjectURL: () => 'blob:harness', revokeObjectURL() {} };
  sandbox.FileReader = class {
    readAsText(file) { if (this.onload) this.onload({ target: { result: file && file.__text } }); }
  };
  vm.createContext(sandbox);

  vm.runInContext(src, sandbox, { filename: 'popup.js' });

  // Top-level const/let live in the context's lexical scope, not on the sandbox object.
  const toolkit = vm.runInContext('typeof toolkit !== "undefined" ? toolkit : undefined', sandbox);
  if (!toolkit) throw new Error('popup.js loaded but toolkit did not initialize');

  // Let async init settle (storage callbacks, TLD fallback).
  await new Promise(resolve => setTimeout(resolve, 50));

  // popup.js's dynamic import('./tlds.js') cannot run inside a plain vm context,
  // so production falls back to a small set; evaluate the real tlds.js by hand.
  try {
    const tldsSrc = fs.readFileSync(path.join(root, 'tlds.js'), 'utf8')
      .replace(/^export /m, '');
    const validTlds = vm.runInContext(`${tldsSrc}\n;validTlds;`, sandbox, { filename: 'tlds.js' });
    if (validTlds && typeof validTlds.has === 'function' && validTlds.size > 100) {
      toolkit.tlds = validTlds;
    }
  } catch (e) {
    // keep production's own fallback set
  }

  return { toolkit, document, storage: storageArea, globals: sandbox, tabCreates, windowUpdates, closeCalls };
}

module.exports = { loadPopupToolkit };
