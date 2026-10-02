'use strict';
// Loads the REAL popup.js into a Node vm sandbox so tests exercise production code.
const fs = require('fs');
const vm = require('vm');
const path = require('path');

function stubEl(id) {
  const el = {
    id,
    value: '',
    textContent: '',
    innerHTML: '',
    style: {},
    title: '',
    checked: false,
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
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
  };
  return el;
}

function makeDocument() {
  const elements = {};
  const bySelector = {};
  const bySelectorAll = {};
  const doc = {
    readyState: 'complete',
    getElementById(id) { return (elements[id] = elements[id] || stubEl(id)); },
    querySelector(sel) { return bySelector[sel] || null; },
    querySelectorAll(sel) { return bySelectorAll[sel] || []; },
    __setQuerySelector(sel, el) { bySelector[sel] = el; },
    __setQuerySelectorAll(sel, els) { bySelectorAll[sel] = els; },
    createElement(tag) { return (doc.__lastCreated = stubEl(tag)); },
    addEventListener() {},
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

async function loadPopupToolkit(root) {
  const src = fs.readFileSync(path.join(root, 'popup.js'), 'utf8');
  const document = makeDocument();
  const storageArea = makeStorageArea();

  const sandbox = {
    console,
    TextEncoder,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    navigator: { clipboard: { writeText: async () => {} }, userAgent: 'node-harness' },
    location: { href: 'chrome-extension://harness/popup.html' },
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
      tabs: { create() {}, query: async () => [] },
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

  return { toolkit, document, storage: storageArea, globals: sandbox };
}

module.exports = { loadPopupToolkit };
