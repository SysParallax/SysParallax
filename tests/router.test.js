const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const routerSource = fs.readFileSync(path.join(__dirname, '..', 'web', 'dashboard', 'router.js'), 'utf8');

function createRuntime(initialPath = '/portfolio') {
  const listeners = new Map();
  const content = {
    scrollTop: 0,
    listeners: new Map(),
    addEventListener(type, listener) { this.listeners.set(type, listener); }
  };
  const location = { pathname: initialPath, search: '', hash: '' };
  const rendered = [];
  const details = [];
  const previews = [];
  const closed = [];
  const toasts = [];

  const history = {
    entries: [{ url: initialPath, state: null }],
    index: 0,
    scrollRestoration: 'auto',
    get state() { return this.entries[this.index].state; },
    pushState(state, _title, url) {
      this.entries = this.entries.slice(0, this.index + 1);
      this.entries.push({ state: structuredClone(state), url });
      this.index += 1;
      updateLocation(location, url);
    },
    replaceState(state, _title, url) {
      this.entries[this.index] = { state: structuredClone(state), url };
      updateLocation(location, url);
    },
    back() {
      if (this.index === 0) return;
      this.index -= 1;
      const entry = this.entries[this.index];
      updateLocation(location, entry.url);
      dispatch('popstate', { state: structuredClone(entry.state) });
    },
    forward() {
      if (this.index >= this.entries.length - 1) return;
      this.index += 1;
      const entry = this.entries[this.index];
      updateLocation(location, entry.url);
      dispatch('popstate', { state: structuredClone(entry.state) });
    }
  };

  function dispatch(type, event) {
    for (const listener of listeners.get(type) || []) listener(event);
  }

  const window = {
    history,
    location,
    state: { activeAuditId: 'audit-1' },
    setTimeout,
    clearTimeout,
    requestAnimationFrame(callback) { callback(); },
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(listener);
    },
    renderPage(page) { rendered.push(page); },
    showToast(message, type) { toasts.push({ message, type }); },
    findingsCenter: {
      async enter() {},
      resetAudit() {},
      openDetail(id, options) { details.push({ id, options }); },
      closeDetail(options) { closed.push({ type: 'detail', options }); },
      openReportPreview(options) { previews.push(options); },
      closeReportPreview(options) { closed.push({ type: 'preview', options }); }
    }
  };
  const document = {
    querySelector(selector) { return selector === '.content' ? content : null; }
  };
  const context = vm.createContext({ window, document, console, setTimeout, clearTimeout, structuredClone });
  vm.runInContext(routerSource, context, { filename: 'router.js' });
  return { window, history, location, rendered, details, previews, closed, toasts, content };
}

function updateLocation(location, relativeURL) {
  const url = new URL(relativeURL, 'http://auditcore.local');
  location.pathname = url.pathname;
  location.search = url.search;
  location.hash = url.hash;
}

function settle() {
  return new Promise(resolve => setTimeout(resolve, 0));
}

test('supports A -> B -> C -> back -> back -> forward', async () => {
  const runtime = createRuntime('/portfolio');
  await settle();
  runtime.window.appRouter.navigate('findings');
  await settle();
  runtime.window.appRouter.navigate('reports');
  await settle();
  assert.equal(runtime.location.pathname, '/reports');

  runtime.history.back();
  await settle();
  assert.equal(runtime.location.pathname, '/findings');
  assert.equal(runtime.rendered.at(-1), 'findings');

  runtime.history.back();
  await settle();
  assert.equal(runtime.location.pathname, '/portfolio');
  assert.equal(runtime.rendered.at(-1), 'portfolio');

  runtime.history.forward();
  await settle();
  assert.equal(runtime.location.pathname, '/findings');
  assert.equal(runtime.rendered.at(-1), 'findings');
});

test('restores a finding panel with back and forward', async () => {
  const runtime = createRuntime('/findings');
  await settle();
  runtime.window.appRouter.openFinding('finding-42');
  await settle();
  assert.equal(runtime.location.pathname, '/findings/finding-42');
  assert.equal(runtime.details.at(-1).id, 'finding-42');

  runtime.history.back();
  await settle();
  assert.equal(runtime.location.pathname, '/findings');
  assert.equal(runtime.rendered.at(-1), 'findings');

  runtime.history.forward();
  await settle();
  assert.equal(runtime.location.pathname, '/findings/finding-42');
  assert.equal(runtime.details.at(-1).id, 'finding-42');
});

test('loads direct internal routes and redirects unknown routes', async () => {
  const direct = createRuntime('/reports');
  await settle();
  assert.equal(direct.rendered.at(-1), 'reports');
  assert.equal(direct.history.state.page, 'reports');

  const unknown = createRuntime('/does-not-exist');
  await settle();
  assert.equal(unknown.location.pathname, '/portfolio');
  assert.equal(unknown.rendered.at(-1), 'portfolio');
  assert.equal(unknown.toasts.at(-1).type, 'info');
  unknown.window.appRouter.navigate('reports');
  await settle();
  unknown.history.back();
  await settle();
  assert.equal(unknown.location.pathname, '/portfolio');
  assert.equal(unknown.rendered.at(-1), 'portfolio');
});

test('closes and restores the report preview through browser history', async () => {
  const runtime = createRuntime('/findings');
  await settle();
  runtime.window.appRouter.openReportPreview();
  await settle();
  assert.equal(runtime.location.pathname, '/findings/report-preview');
  assert.equal(runtime.previews.length, 1);

  runtime.history.back();
  await settle();
  assert.equal(runtime.location.pathname, '/findings');

  runtime.history.forward();
  await settle();
  assert.equal(runtime.location.pathname, '/findings/report-preview');
  assert.equal(runtime.previews.length, 2);
});

test('restores scroll and active audit from history state', async () => {
  const runtime = createRuntime('/portfolio');
  await settle();
  runtime.content.scrollTop = 320;
  runtime.window.appRouter.navigate('assets');
  await settle();
  runtime.history.back();
  await settle();
  assert.equal(runtime.content.scrollTop, 320);
  assert.equal(runtime.window.state.activeAuditId, 'audit-1');
});

test('refreshes the active audit when navigating to the current page', async () => {
  const runtime = createRuntime('/portfolio');
  await settle();
  runtime.window.state.activeAuditId = 'audit-2';
  runtime.window.appRouter.navigate('portfolio');
  await settle();
  assert.equal(runtime.history.state.auditId, 'audit-2');
  assert.equal(runtime.history.entries.length, 1);
});
