'use strict';
// Loads the REAL popup.js into a Node vm sandbox so tests exercise production code.
const fs = require('fs');
const vm = require('vm');
const path = require('path');

function stubEl(id) {
  return {
    id,
    value: '',
    textContent: '',
    innerHTML: '',
    style: {},
    title: '',
    checked: false,
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {},
    removeEventListener() {},
    setAttribute() {},
    getAttribute() { return null; },
    removeAttribute() {},
    appendChild() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    focus() {},
    select() {},
    remove() {},
  };
}

function makeDocument() {
  const elements = {};
  return {
    readyState: 'complete',
    getElementById(id) { return (elements[id] = elements[id] || stubEl(id)); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement(tag) { return stubEl(tag); },
    addEventListener() {},
    body: stubEl('body'),
    documentElement: stubEl('html'),
  };
}

function makeStorageArea() {
  const data = {};
  return {
    get(keys, cb) {
      const result = {};
      for (const k of Array.isArray(keys) ? keys : [keys]) {
        if (k in data) result[k] = data[k];
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

  return { toolkit, document };
}

module.exports = { loadPopupToolkit };
