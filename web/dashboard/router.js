// @ts-check
(function () {
  'use strict';

  const ROUTES = Object.freeze({
    portfolio: '/portfolio',
    timeline: '/timeline',
    audit: '/audit',
    findings: '/findings',
    assets: '/assets',
    network: '/network',
    grc: '/grc',
    trends: '/trends',
    reports: '/reports',
    'new-audit': '/new-audit',
    profiles: '/profiles'
  });
  const PATH_TO_PAGE = Object.freeze(Object.fromEntries(Object.entries(ROUTES).map(([page, path]) => [path, page])));
  let applySequence = 0;
  let scrollTimer = 0;

  function init() {
    if (!window.history || typeof window.history.pushState !== 'function') {
      window.renderPage('portfolio');
      return;
    }
    if ('scrollRestoration' in window.history) window.history.scrollRestoration = 'manual';
    const parsed = parseLocation(window.location.pathname);
    if (!parsed.valid) {
      const fallback = createState('portfolio', { entryKind: 'redirect' });
      window.history.replaceState(fallback, '', ROUTES.portfolio);
      applyState(fallback);
      window.setTimeout(() => toast('Unknown route. Redirected to Portfolio.', 'info'), 0);
    } else {
      const previous = isAppState(window.history.state) ? window.history.state : {};
      const initial = {
        ...createState(parsed.page, { entryKind: 'initial' }),
        ...parsed,
        auditId: String(previous.auditId || ''),
        scrollTop: Number(previous.scrollTop || 0),
        entryKind: previous.entryKind || 'initial'
      };
      window.history.replaceState(initial, '', currentRelativeURL());
      applyState(initial);
    }
    window.addEventListener('popstate', onPopState);
    const content = document.querySelector('.content');
    if (content) content.addEventListener('scroll', rememberScroll, { passive: true });
  }

  function navigate(page, options) {
    const targetPage = normalizePage(page);
    const opts = options || {};
    const current = currentState();
    const next = createState(targetPage, {
      entryKind: opts.entryKind || 'navigation',
      scrollTop: Number(opts.scrollTop || 0)
    });
    const path = ROUTES[targetPage];
    const sameDestination = current.page === targetPage && !current.overlay && window.location.pathname === path;
    if (sameDestination && !opts.replace) {
      const refreshed = { ...current, auditId: activeAuditId(), scrollTop: Number(current.scrollTop || 0) };
      window.history.replaceState(refreshed, '', path);
      applyState(refreshed);
      return;
    }
    rememberScrollNow();
    if (opts.replace) window.history.replaceState(next, '', path);
    else window.history.pushState(next, '', path);
    applyState(next);
  }

  function openFinding(findingId) {
    if (!findingId) return;
    const current = currentState();
    rememberScrollNow();
    const next = createState('findings', {
      overlay: 'finding',
      findingId: String(findingId),
      entryKind: 'overlay',
      scrollTop: current.scrollTop
    });
    const path = `${ROUTES.findings}/${encodeURIComponent(String(findingId))}`;
    if (current.overlay) window.history.replaceState(next, '', path);
    else window.history.pushState(next, '', path);
    applyState(next);
  }

  function openReportPreview() {
    const current = currentState();
    rememberScrollNow();
    const next = createState('findings', {
      overlay: 'report-preview',
      entryKind: 'overlay',
      scrollTop: current.scrollTop
    });
    const path = `${ROUTES.findings}/report-preview`;
    if (current.overlay) window.history.replaceState(next, '', path);
    else window.history.pushState(next, '', path);
    applyState(next);
  }

  function closeOverlay() {
    const current = currentState();
    if (current.overlay && current.entryKind === 'overlay') {
      window.history.back();
      return;
    }
    navigate(current.page || 'findings', { replace: true, entryKind: 'navigation', scrollTop: current.scrollTop });
  }

  function onPopState(event) {
    const parsed = parseLocation(window.location.pathname);
    if (!parsed.valid) {
      const fallback = createState('portfolio', { entryKind: 'redirect' });
      window.history.replaceState(fallback, '', ROUTES.portfolio);
      applyState(fallback);
      return;
    }
    const eventState = isAppState(event.state) ? event.state : {};
    const restored = {
      ...createState(parsed.page, { entryKind: 'history' }),
      ...eventState,
      ...parsed,
      auditId: String(eventState.auditId || ''),
      scrollTop: Number(eventState.scrollTop || 0)
    };
    applyState(restored);
  }

  async function applyState(routeState) {
    const sequence = ++applySequence;
    closeTransientUI();
    restoreAudit(routeState.auditId);
    window.renderPage(normalizePage(routeState.page));
    if (routeState.page === 'findings' && window.findingsCenter) {
      await window.findingsCenter.enter();
      if (sequence !== applySequence) return;
      if (routeState.overlay === 'finding' && routeState.findingId) {
        window.findingsCenter.openDetail(routeState.findingId, { fromHistory: true });
      } else if (routeState.overlay === 'report-preview') {
        window.findingsCenter.openReportPreview({ fromHistory: true });
      }
    }
    if (sequence !== applySequence) return;
    restoreScroll(Number(routeState.scrollTop || 0));
  }

  function closeTransientUI() {
    if (!window.findingsCenter) return;
    window.findingsCenter.closeDetail({ fromHistory: true });
    window.findingsCenter.closeReportPreview({ fromHistory: true });
  }

  function restoreAudit(auditId) {
    if (!auditId || !window.state || window.state.activeAuditId === auditId) return;
    window.state.activeAuditId = auditId;
    if (window.findingsCenter) window.findingsCenter.resetAudit(auditId);
  }

  function createState(page, options) {
    const opts = options || {};
    return {
      app: 'auditcore',
      version: 1,
      page: normalizePage(page),
      auditId: activeAuditId(),
      overlay: opts.overlay || '',
      findingId: opts.findingId || '',
      scrollTop: Number(opts.scrollTop || 0),
      entryKind: opts.entryKind || 'navigation'
    };
  }

  function currentState() {
    if (isAppState(window.history.state)) return window.history.state;
    const parsed = parseLocation(window.location.pathname);
    return createState(parsed.valid ? parsed.page : 'portfolio', { entryKind: 'initial' });
  }

  function parseLocation(pathname) {
    const cleanPath = normalizePath(pathname);
    if (cleanPath === '/') return { valid: true, page: 'portfolio', overlay: '', findingId: '' };
    const segments = cleanPath.split('/').filter(Boolean).map(safeDecode);
    const basePath = `/${segments[0] || ''}`;
    const page = PATH_TO_PAGE[basePath];
    if (!page) return { valid: false, page: 'portfolio', overlay: '', findingId: '' };
    if (segments.length === 1) return { valid: true, page, overlay: '', findingId: '' };
    if (page === 'findings' && segments.length === 2) {
      if (segments[1] === 'report-preview') return { valid: true, page, overlay: 'report-preview', findingId: '' };
      return { valid: true, page, overlay: 'finding', findingId: segments[1] };
    }
    return { valid: false, page: 'portfolio', overlay: '', findingId: '' };
  }

  function rememberScroll() {
    window.clearTimeout(scrollTimer);
    scrollTimer = window.setTimeout(rememberScrollNow, 80);
  }

  function rememberScrollNow() {
    if (!isAppState(window.history.state)) return;
    const content = document.querySelector('.content');
    const scrollTop = content ? content.scrollTop : 0;
    const state = { ...window.history.state, auditId: activeAuditId(), scrollTop };
    window.history.replaceState(state, '', currentRelativeURL());
  }

  function restoreScroll(scrollTop) {
    window.requestAnimationFrame(() => {
      const content = document.querySelector('.content');
      if (content) content.scrollTop = Math.max(0, scrollTop || 0);
    });
  }

  function normalizePage(page) { return Object.prototype.hasOwnProperty.call(ROUTES, page) ? page : 'portfolio'; }
  function normalizePath(pathname) { const value = String(pathname || '/').replace(/\/{2,}/g, '/'); return value.length > 1 ? value.replace(/\/+$/, '') : value; }
  function safeDecode(value) { try { return decodeURIComponent(value); } catch { return value; } }
  function activeAuditId() { return window.state ? String(window.state.activeAuditId || '') : ''; }
  function currentRelativeURL() { return `${window.location.pathname}${window.location.search}${window.location.hash}`; }
  function isAppState(value) { return Boolean(value && typeof value === 'object' && value.app === 'auditcore'); }
  function toast(message, type) { if (typeof window.showToast === 'function') window.showToast(message, type); }

  window.appRouter = { navigate, openFinding, openReportPreview, closeOverlay, currentState, parseLocation };
  init();
})();
