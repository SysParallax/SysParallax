// @ts-check
(function () {
  'use strict';

  /**
   * @typedef {Object} FindingModel
   * @property {string} id
   * @property {string} title
   * @property {string} description
   * @property {'critical'|'high'|'medium'|'low'|'info'} severity
   * @property {string} status
   * @property {string} confidence
   * @property {string} replayState
   * @property {string} lastReplayAt
   * @property {string} affectedTarget
   * @property {number} occurrenceCount
   * @property {string[]} affectedEndpoints
   * @property {string} module
   * @property {string} category
   * @property {number} cvssScore
   * @property {string} createdAt
   * @property {string} updatedAt
   * @property {{requestRaw:string,responseRaw:string,payload:string,matcherResult:string,screenshots:string[]}} evidence
   * @property {string} impact
   * @property {string} recommendation
   * @property {string[]} references
   * @property {string[]} tags
   * @property {boolean} replayable
   * @property {string} cwe
   * @property {string} owasp
   * @property {string} asvs
   * @property {string[]} cve
   * @property {string} verifiedBy
   * @property {Record<string, any>} raw
   */

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const STATUSES = ['confirmed', 'suspected'];
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const SEVERITY_COLORS = { critical: '#e24b4a', high: '#ef9f27', medium: '#378add', low: '#639922', info: '#7d8590' };
  const DEFAULT_CVSS = { critical: 9.5, high: 8.0, medium: 5.5, low: 2.5, info: 0.0 };

  const data = {
    auditId: '',
    findings: /** @type {FindingModel[]} */ ([]),
    loading: false,
    loaded: false,
    error: '',
    query: '',
    severities: new Set(),
    statuses: new Set(),
    replayableOnly: false,
    tag: 'all',
    sort: 'severity',
    group: 'severity',
    page: 1,
    pageSize: 25,
    selected: new Set(),
    collapsed: new Set(),
    activeFindingId: '',
    revision: 0,
    filterCacheKey: '',
    filteredCache: /** @type {FindingModel[]} */ ([]),
    searchTimer: 0
  };

  function mount() {
    mountFindingsPage();
    mountDetailPanel();
    mountReportPreview();
    bindEvents();
    render();
  }

  function mountFindingsPage() {
    const page = document.getElementById('page-findings');
    if (!page) return;
    page.innerHTML = `
      <div class="ph">
        <div><div class="pt">Findings</div><div class="ps" id="findings-sub">Select an audit to review its findings.</div></div>
        <div class="hrow">
          <button class="btn-s" id="findings-export-json" onclick="findingsCenter.exportJson()">Export JSON</button>
          <button class="btn-s" id="findings-export-pdf" onclick="findingsCenter.exportPdf()">Export PDF</button>
          <button class="btn-p" id="findings-generate-report" onclick="findingsCenter.openReportPreview()">Generate report</button>
        </div>
      </div>
      <div class="sg">
        ${statCard('critical', 'Critical', 'f-crit', '#a32d2d')}
        ${statCard('high', 'High', 'f-high', '#854f0b')}
        ${statCard('medium', 'Medium', 'f-med', '#185fa5')}
        ${statCard('low', 'Low / Info', 'f-low', '')}
      </div>
      <div class="findings-controls">
        <input class="si" id="findings-search" placeholder="Search title, target, category or module..." autocomplete="off" />
        <span class="findings-filter-label">Severity</span>
        ${filterButton('all', 'All', true)}
        ${filterButton('critical', 'Critical')}
        ${filterButton('high', 'High')}
        ${filterButton('medium', 'Medium')}
        ${filterButton('low', 'Low')}
        ${filterButton('info', 'Info')}
        <span class="findings-filter-label">Status</span>
        ${filterButton('confirmed', 'Confirmed')}
        ${filterButton('suspected', 'Suspected')}
        ${filterButton('replayable', 'Replayable')}
        <div style="flex:1"></div>
        <button class="btn-sm" onclick="findingsCenter.selectPage()">Select page</button>
        <select class="findings-select" id="findings-tag" onchange="findingsCenter.setTag(this.value)" aria-label="Filter by tag"><option value="all">All tags</option></select>
        <select class="findings-select" id="findings-sort" onchange="findingsCenter.setSort(this.value)" aria-label="Sort findings">
          <option value="severity">Severity</option><option value="newest">Newest</option><option value="oldest">Oldest</option><option value="cvss-desc">CVSS descending</option><option value="cvss-asc">CVSS ascending</option>
        </select>
        <select class="findings-select" id="findings-group" onchange="findingsCenter.setGroup(this.value)" aria-label="Group findings">
          <option value="severity">Group by severity</option><option value="none">No grouping</option><option value="status">Group by status</option><option value="category">Group by category</option><option value="module">Group by module</option><option value="target">Group by target</option>
        </select>
      </div>
      <div class="findings-bulk" id="findings-bulk">
        <strong id="findings-selected-count">0 selected</strong>
        <button class="btn-sm" onclick="findingsCenter.exportSelected()">Export selection</button>
        <button class="btn-sm" onclick="findingsCenter.bulkStatus('confirmed')">Mark confirmed</button>
        <button class="btn-sm" onclick="findingsCenter.bulkStatus('suspected')">Mark suspected</button>
        <button class="btn-sm" onclick="findingsCenter.clearSelection()">Clear</button>
      </div>
      <div id="findings-table-wrap" aria-live="polite"></div>
      <div class="finding-pagination" id="findings-pagination" style="display:none">
        <span id="findings-page-summary"></span>
        <div class="finding-pagination-actions">
          <select class="findings-select" id="findings-page-size" onchange="findingsCenter.setPageSize(this.value)" aria-label="Findings per page"><option value="25">25 / page</option><option value="50">50 / page</option><option value="100">100 / page</option></select>
          <button class="btn-sm" id="findings-prev" onclick="findingsCenter.changePage(-1)" aria-label="Previous page">&larr;</button>
          <span id="findings-page-number"></span>
          <button class="btn-sm" id="findings-next" onclick="findingsCenter.changePage(1)" aria-label="Next page">&rarr;</button>
        </div>
      </div>`;
  }

  function statCard(key, label, id, color) {
    return `<div class="sc finding-stat" data-stat="${key}"><div class="sl">${label}</div><div class="sv" ${color ? `style="color:${color}"` : ''} id="${id}">0</div><div class="finding-stat-meta" id="${id}-pct">0% of total</div></div>`;
  }

  function filterButton(key, label, active) {
    return `<button class="fbtn${active ? ' on' : ''}" data-finding-filter="${key}" onclick="setFindingFilter('${key}',this)" aria-pressed="${active ? 'true' : 'false'}">${label}</button>`;
  }

  function mountDetailPanel() {
    const panel = document.getElementById('panel');
    if (!panel) return;
    panel.innerHTML = '<div class="panel-body"><div class="empty-state"><div class="empty-state-title">No finding selected</div></div></div>';
  }

  function mountReportPreview() {
    if (document.getElementById('finding-report-preview')) return;
    const modal = document.createElement('div');
    modal.className = 'report-preview-overlay';
    modal.id = 'finding-report-preview';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'finding-report-preview-title');
    modal.innerHTML = `
      <div class="report-preview-dialog">
        <div class="report-preview-header">
          <div><div class="tt" id="finding-report-preview-title" style="margin:0">Findings report preview</div><div class="ps" id="finding-report-preview-sub"></div></div>
          <div class="hrow"><button class="btn-s" onclick="findingsCenter.exportPdf()">Download PDF</button><button class="panel-close" onclick="findingsCenter.closeReportPreview()" aria-label="Close">&times;</button></div>
        </div>
        <div class="report-preview-body"><div class="report-preview-sheet" id="finding-report-preview-body"></div></div>
      </div>`;
    modal.addEventListener('click', event => { if (event.target === modal) closeReportPreview(); });
    document.body.appendChild(modal);
  }

  function bindEvents() {
    const wrap = document.getElementById('findings-table-wrap');
    if (wrap) {
      wrap.addEventListener('click', event => {
        const target = /** @type {HTMLElement} */ (event.target);
        const checkbox = target.closest('[data-finding-check]');
        if (checkbox) {
          event.stopPropagation();
          toggleSelection(String(checkbox.getAttribute('data-finding-check') || ''), /** @type {HTMLInputElement} */ (checkbox).checked);
          return;
        }
        const header = target.closest('[data-finding-group]');
        if (header) { toggleGroup(decodeURIComponent(String(header.getAttribute('data-finding-group') || ''))); return; }
        const row = target.closest('[data-finding-id]');
        if (row) openDetail(String(row.getAttribute('data-finding-id') || ''));
      });
      wrap.addEventListener('keydown', event => {
        const keyboardEvent = /** @type {KeyboardEvent} */ (event);
        if (!['Enter', ' '].includes(keyboardEvent.key)) return;
        const row = /** @type {HTMLElement} */ (keyboardEvent.target).closest('[data-finding-id]');
        if (row) { keyboardEvent.preventDefault(); openDetail(String(row.getAttribute('data-finding-id') || '')); }
      });
    }
    const search = /** @type {HTMLInputElement|null} */ (document.getElementById('findings-search'));
    if (search) search.addEventListener('input', () => setSearch(search.value));
    document.addEventListener('keydown', event => {
      if (event.key !== 'Escape') return;
      const preview = document.getElementById('finding-report-preview');
      const panel = document.getElementById('panel');
      if (preview && preview.classList.contains('open')) closeReportPreview();
      else if (panel && panel.classList.contains('open')) closeDetail();
    });
  }

  async function enter() {
    const activeAuditId = getActiveAuditId();
    if (!activeAuditId) { resetAudit(''); render(); return; }
    if (data.auditId !== activeAuditId) resetAudit(activeAuditId);
    if (!data.loaded && !data.loading) await load(activeAuditId);
    else render();
  }

  function resetAudit(auditId) {
    if (data.auditId === auditId && data.loaded) return;
    data.auditId = auditId || '';
    data.findings = [];
    data.loading = false;
    data.loaded = false;
    data.error = '';
    data.page = 1;
    data.selected.clear();
    data.activeFindingId = '';
    invalidate();
    render();
  }

  async function load(auditId, options) {
    if (!auditId) { resetAudit(''); return; }
    const requestedAudit = auditId;
    data.auditId = auditId;
    data.loading = true;
    data.error = '';
    if (!options || !options.silent) render();
    try {
      const payload = await api(`/audits/${encodeURIComponent(auditId)}/findings`);
      if (data.auditId !== requestedAudit) return;
      data.findings = (Array.isArray(payload) ? payload : []).map(normalizeFinding);
      data.loaded = true;
      data.revision += 1;
      data.selected.clear();
      populateTags();
    } catch (error) {
      if (data.auditId !== requestedAudit) return;
      data.error = error instanceof Error ? error.message : 'Unable to load findings';
      data.loaded = false;
    } finally {
      if (data.auditId === requestedAudit) {
        data.loading = false;
        invalidate();
        render();
      }
    }
  }

  /** @param {Record<string, any>} raw @returns {FindingModel} */
  function normalizeFinding(raw) {
    const severity = normalizeSeverity(raw.severity);
    const evidence = raw.evidence || {};
    const cve = toArray(raw.cve || raw.cves);
    const references = unique([
      ...toArray(raw.references),
      raw.cwe || '', raw.owasp_category || '', raw.asvs_mapping || '', ...cve
    ].filter(Boolean));
    const moduleName = String(raw.module || raw.type || raw.taxonomy_id || 'scanner');
    const category = String(raw.category || raw.owasp_category || raw.cwe || raw.taxonomy_id || 'Uncategorized');
    const target = String(raw.affected_target || raw.endpoint || currentAuditTarget() || 'Unknown target');
    const tags = deriveTags(raw, moduleName, category, target);
    return {
      id: String(raw.id || crypto.randomUUID()),
      title: String(raw.title || raw.type || 'Untitled finding'),
      description: String(raw.description || 'No description was provided by the detection module.'),
      severity,
      status: String(raw.status || 'suspected').toLowerCase(),
      confidence: String(raw.confidence || 'medium').toLowerCase(),
      replayState: String(raw.replay_state || 'not_run').toLowerCase(),
      lastReplayAt: String(raw.last_replay_at || ''),
      affectedTarget: target,
      occurrenceCount: Math.max(1, Number(raw.occurrence_count || 1)),
      affectedEndpoints: toArray(raw.affected_endpoints),
      module: moduleName,
      category,
      cvssScore: normalizeCvss(raw.cvss_score, severity),
      createdAt: String(raw.created_at || new Date().toISOString()),
      updatedAt: String(raw.updated_at || raw.created_at || new Date().toISOString()),
      evidence: {
        requestRaw: String(evidence.request_raw || ''),
        responseRaw: String(evidence.response_raw || ''),
        payload: String(evidence.payload || ''),
        matcherResult: String(evidence.matcher_result || ''),
        screenshots: toArray(evidence.screenshots || raw.screenshots)
      },
      impact: String(raw.impact || impactBySeverity(severity)),
      recommendation: String(raw.recommendation || raw.remediation || 'Review the affected control, remediate the root cause, and validate the correction with a targeted retest.'),
      references,
      tags,
      replayable: Boolean(raw.replayable),
      cwe: String(raw.cwe || ''),
      owasp: String(raw.owasp_category || ''),
      asvs: String(raw.asvs_mapping || ''),
      cve,
      verifiedBy: String(raw.verified_by || ''),
      raw
    };
  }

  function normalizeSeverity(value) {
    const normalized = String(value || 'info').toLowerCase();
    return SEVERITIES.includes(normalized) ? /** @type {FindingModel['severity']} */ (normalized) : 'info';
  }

  function normalizeCvss(value, severity) {
    const score = Number(value);
    if (Number.isFinite(score) && score >= 0 && score <= 10) return Math.round(score * 10) / 10;
    return DEFAULT_CVSS[severity];
  }

  function impactBySeverity(severity) {
    return {
      critical: 'A successful exploitation may cause severe compromise of confidentiality, integrity, or availability and requires immediate action.',
      high: 'Exploitation may materially affect sensitive systems or data and should be prioritized for rapid remediation.',
      medium: 'The weakness creates a meaningful security exposure that should be resolved within the normal remediation cycle.',
      low: 'The issue has limited direct impact but weakens the security baseline.',
      info: 'The observation is primarily relevant for hardening and security assurance.'
    }[severity];
  }

  function deriveTags(raw, moduleName, category, target) {
    const tags = new Set(toArray(raw.tags));
    const text = `${moduleName} ${category} ${target} ${raw.title || ''} ${raw.type || ''}`.toLowerCase();
    if (/api|graphql|rest|json/.test(text)) tags.add('API');
    if (/auth|login|session|cookie|jwt|idor|access/.test(text)) tags.add('Auth');
    if (/network|port|dns|tls|ssl/.test(text)) tags.add('Network');
    if (/cloud|aws|azure|gcp|bucket|storage/.test(text)) tags.add('Cloud');
    if (!tags.size || /http|html|xss|sqli|header|cors|web/.test(text)) tags.add('Web');
    return Array.from(tags).sort();
  }

  function toArray(value) {
    if (Array.isArray(value)) return value.map(String).filter(Boolean);
    if (typeof value === 'string' && value.trim()) return value.split(',').map(item => item.trim()).filter(Boolean);
    return [];
  }

  function unique(values) { return Array.from(new Set(values)); }

  function setSearch(value) {
    window.clearTimeout(data.searchTimer);
    data.searchTimer = window.setTimeout(() => {
      data.query = String(value || '').trim().toLowerCase();
      data.page = 1;
      invalidate();
      render();
    }, 120);
  }

  function toggleFilter(filter, button) {
    if (filter === 'all') {
      data.severities.clear(); data.statuses.clear(); data.replayableOnly = false;
    } else if (SEVERITIES.includes(filter)) {
      toggleSet(data.severities, filter);
    } else if (STATUSES.includes(filter)) {
      toggleSet(data.statuses, filter);
    } else if (filter === 'replayable') {
      data.replayableOnly = !data.replayableOnly;
    }
    data.page = 1;
    invalidate();
    syncFilterButtons(button);
    render();
  }

  function toggleSet(set, value) { if (set.has(value)) set.delete(value); else set.add(value); }

  function syncFilterButtons() {
    const noFilters = !data.severities.size && !data.statuses.size && !data.replayableOnly;
    document.querySelectorAll('#page-findings [data-finding-filter]').forEach(element => {
      const key = element.getAttribute('data-finding-filter') || '';
      const active = key === 'all' ? noFilters : data.severities.has(key) || data.statuses.has(key) || (key === 'replayable' && data.replayableOnly);
      element.classList.toggle('on', active);
      element.setAttribute('aria-pressed', String(active));
    });
  }

  function setTag(tag) { data.tag = tag || 'all'; data.page = 1; invalidate(); render(); }
  function setSort(sort) { data.sort = sort || 'severity'; data.page = 1; invalidate(); render(); }
  function setGroup(group) { data.group = group || 'none'; data.page = 1; render(); }
  function setPageSize(value) { data.pageSize = Math.max(10, Number(value) || 25); data.page = 1; render(); }
  function changePage(delta) {
    const totalPages = Math.max(1, Math.ceil(getFilteredFindings().length / data.pageSize));
    data.page = Math.min(totalPages, Math.max(1, data.page + delta));
    renderList();
  }

  function invalidate() { data.filterCacheKey = ''; }

  /** @returns {FindingModel[]} */
  function getFilteredFindings() {
    const key = JSON.stringify([data.revision, data.query, Array.from(data.severities).sort(), Array.from(data.statuses).sort(), data.replayableOnly, data.tag, data.sort]);
    if (key === data.filterCacheKey) return data.filteredCache;
    const query = data.query;
    const rows = data.findings.filter(finding => {
      if (data.severities.size && !data.severities.has(finding.severity)) return false;
      if (data.statuses.size && !data.statuses.has(finding.status)) return false;
      if (data.replayableOnly && !finding.replayable) return false;
      if (data.tag !== 'all' && !finding.tags.includes(data.tag)) return false;
      if (!query) return true;
      return [finding.title, finding.description, finding.category, finding.affectedTarget, finding.module].join(' ').toLowerCase().includes(query);
    });
    rows.sort(compareFindings);
    data.filterCacheKey = key;
    data.filteredCache = rows;
    return rows;
  }

  function compareFindings(a, b) {
    if (data.sort === 'newest') return dateValue(b.createdAt) - dateValue(a.createdAt);
    if (data.sort === 'oldest') return dateValue(a.createdAt) - dateValue(b.createdAt);
    if (data.sort === 'cvss-desc') return b.cvssScore - a.cvssScore;
    if (data.sort === 'cvss-asc') return a.cvssScore - b.cvssScore;
    return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.cvssScore - a.cvssScore || dateValue(b.createdAt) - dateValue(a.createdAt);
  }

  function dateValue(value) { const timestamp = new Date(value).getTime(); return Number.isFinite(timestamp) ? timestamp : 0; }

  function render() {
    renderStats();
    syncFilterButtons();
    renderList();
    renderBulkActions();
  }

  function renderStats() {
    const counts = countSeverity(data.findings);
    const total = data.findings.length;
    updateStat('f-crit', counts.critical, total);
    updateStat('f-high', counts.high, total);
    updateStat('f-med', counts.medium, total);
    updateStat('f-low', counts.low + counts.info, total);
    const badge = document.getElementById('findings-badge');
    if (badge) { badge.textContent = String(total); badge.style.display = total ? '' : 'none'; }
  }

  function updateStat(id, count, total) {
    const value = document.getElementById(id);
    const percent = document.getElementById(`${id}-pct`);
    if (value && value.textContent !== String(count)) {
      value.textContent = String(count);
      const card = value.closest('.finding-stat');
      if (card) { card.classList.remove('changed'); void /** @type {HTMLElement} */ (card).offsetWidth; card.classList.add('changed'); }
    }
    if (percent) percent.textContent = `${total ? Math.round(count / total * 100) : 0}% of total`;
  }

  function countSeverity(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(finding => { counts[finding.severity] += 1; });
    return counts;
  }

  function occurrenceNote(finding) {
    if (!finding || finding.occurrenceCount <= 1) return '';
    const endpointCount = finding.affectedEndpoints.length || finding.occurrenceCount;
    return ` Consolidated from ${finding.occurrenceCount} observations across ${endpointCount} endpoint(s).`;
  }

  function renderList() {
    const wrap = document.getElementById('findings-table-wrap');
    const sub = document.getElementById('findings-sub');
    const pagination = document.getElementById('findings-pagination');
    if (!wrap || !sub || !pagination) return;
    setExportAvailability(false);
    if (!data.auditId) {
      sub.textContent = 'No audit selected.';
      wrap.innerHTML = premiumEmpty('No audit selected', 'Open an existing audit or launch a scan to populate the vulnerability workspace.', 'Launch scan', "nav('new-audit')");
      pagination.style.display = 'none';
      return;
    }
    if (data.loading && !data.loaded) {
      sub.textContent = 'Loading findings...';
      wrap.innerHTML = premiumEmpty('Loading findings', 'Retrieving normalized findings and evidence from the selected audit.');
      pagination.style.display = 'none';
      return;
    }
    if (data.error) {
      sub.textContent = 'Unable to load findings.';
      wrap.innerHTML = premiumEmpty('Findings unavailable', data.error, 'Retry', `findingsCenter.load('${escapeAttribute(data.auditId)}')`);
      pagination.style.display = 'none';
      return;
    }
    const filtered = getFilteredFindings();
    const audit = currentAudit();
    sub.textContent = `${filtered.length} displayed of ${data.findings.length} findings${audit ? ` - ${audit.target_url}` : ''}`;
    if (!data.findings.length) {
      wrap.innerHTML = premiumEmpty('No findings detected', 'The selected audit completed without reportable findings. Launch a new scan after scope or configuration changes.', 'Launch scan', "nav('new-audit')");
      pagination.style.display = 'none';
      return;
    }
    if (!filtered.length) {
      wrap.innerHTML = premiumEmpty('No matching findings', 'No vulnerability matches the active search and filter combination.', 'Reset filters', 'findingsCenter.resetFilters()');
      pagination.style.display = 'none';
      return;
    }
    setExportAvailability(true);
    const totalPages = Math.max(1, Math.ceil(filtered.length / data.pageSize));
    if (data.page > totalPages) data.page = totalPages;
    const start = (data.page - 1) * data.pageSize;
    const pageRows = filtered.slice(start, start + data.pageSize);
    wrap.innerHTML = `<div class="findings-list">${renderGroups(pageRows)}</div>`;
    pagination.style.display = 'flex';
    setText('findings-page-summary', `${start + 1}-${Math.min(start + pageRows.length, filtered.length)} of ${filtered.length}`);
    setText('findings-page-number', `Page ${data.page} / ${totalPages}`);
    const prev = /** @type {HTMLButtonElement|null} */ (document.getElementById('findings-prev'));
    const next = /** @type {HTMLButtonElement|null} */ (document.getElementById('findings-next'));
    if (prev) prev.disabled = data.page <= 1;
    if (next) next.disabled = data.page >= totalPages;
  }

  function renderGroups(rows) {
    if (data.group === 'none') return rows.map(renderFindingRow).join('');
    const groups = new Map();
    rows.forEach(finding => {
      const key = groupValue(finding);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(finding);
    });
    const entries = Array.from(groups.entries());
    if (data.group === 'severity') entries.sort((a, b) => (SEVERITY_ORDER[a[0]] ?? 99) - (SEVERITY_ORDER[b[0]] ?? 99));
    else entries.sort((a, b) => a[0].localeCompare(b[0]));
    return entries.map(([key, findings]) => {
      const collapsed = data.collapsed.has(`${data.group}:${key}`);
      return `<section class="finding-group${collapsed ? ' collapsed' : ''}">
        <button class="finding-group-header" data-finding-group="${encodeURIComponent(key)}"><span class="finding-group-chevron">&#9662;</span><strong>${escapeHtml(groupLabel(key))}</strong><span class="badge bi">${findings.length}</span></button>
        <div class="finding-group-body">${findings.map(renderFindingRow).join('')}</div>
      </section>`;
    }).join('');
  }

  function groupValue(finding) {
    if (data.group === 'status') return finding.status || 'unknown';
    if (data.group === 'category') return finding.category || 'Uncategorized';
    if (data.group === 'module') return finding.module || 'Unknown module';
    if (data.group === 'target') return finding.affectedTarget || 'Unknown target';
    return finding.severity;
  }

  function groupLabel(value) { return data.group === 'severity' || data.group === 'status' ? titleCase(value.replace(/_/g, ' ')) : value; }

  function renderFindingRow(finding) {
    const selected = data.selected.has(finding.id);
    const summary = firstSentence(finding.description, 180);
    return `<article class="finding-row${selected ? ' selected' : ''}" data-finding-id="${escapeAttribute(finding.id)}" tabindex="0" aria-label="Open ${escapeAttribute(finding.title)}">
      <input class="finding-checkbox" type="checkbox" data-finding-check="${escapeAttribute(finding.id)}" ${selected ? 'checked' : ''} aria-label="Select finding" />
      <span class="finding-severity-line" style="background:${SEVERITY_COLORS[finding.severity]}"></span>
      <div>
        <div class="finding-title">${escapeHtml(finding.title)}</div>
        <div class="finding-summary">${escapeHtml(summary)}</div>
        <div class="finding-subline"><span class="finding-kind">${escapeHtml(kindLabel(finding))}</span><span class="badge ${severityClass(finding.severity)}">${escapeHtml(titleCase(finding.severity))}</span><span>${escapeHtml(finding.category)}</span><span>${escapeHtml(finding.module)}</span>${finding.occurrenceCount > 1 ? `<span class="tag">${finding.occurrenceCount} observations consolidees</span>` : ''}${finding.tags.slice(0, 3).map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}</div>
      </div>
      <div><div class="finding-cvss-label">CVSS</div><div class="finding-cvss">${finding.cvssScore.toFixed(1)}</div></div>
      <div><span class="badge ${statusClass(finding.status)}">${escapeHtml(titleCase(finding.status.replace(/_/g, ' ')))}</span><div class="finding-date">${escapeHtml(titleCase(finding.confidence))} confidence at scan</div>${finding.replayState !== 'not_run' ? `<div class="finding-date">Replay: ${escapeHtml(replayStateLabel(finding.replayState))}</div>` : ''}</div>
      <div class="finding-row-target"><div class="finding-target" title="${escapeAttribute(finding.affectedTarget)}">${escapeHtml(finding.affectedTarget)}</div><div class="finding-date">${escapeHtml(formatDate(finding.createdAt))}</div></div>
      <div style="color:var(--t3);font-size:16px">&rsaquo;</div>
    </article>`;
  }

  function premiumEmpty(title, body, actionLabel, action) {
    return `<div class="findings-list"><div class="empty-state"><div class="empty-state-icon">&#9678;</div><div class="empty-state-title">${escapeHtml(title)}</div><div class="empty-state-sub">${escapeHtml(body)}</div>${actionLabel ? `<button class="btn-p finding-empty-action" onclick="${action}">${escapeHtml(actionLabel)}</button>` : ''}</div></div>`;
  }

  function toggleGroup(key) {
    const id = `${data.group}:${key}`;
    if (data.collapsed.has(id)) data.collapsed.delete(id); else data.collapsed.add(id);
    renderList();
  }

  function toggleSelection(id, checked) {
    if (!id) return;
    if (checked) data.selected.add(id); else data.selected.delete(id);
    const row = document.querySelector(`[data-finding-id="${safeSelectorValue(id)}"]`);
    if (row) row.classList.toggle('selected', checked);
    renderBulkActions();
  }

  function selectPage() {
    const filtered = getFilteredFindings();
    const start = (data.page - 1) * data.pageSize;
    filtered.slice(start, start + data.pageSize).forEach(finding => data.selected.add(finding.id));
    renderList(); renderBulkActions();
  }

  function clearSelection() { data.selected.clear(); renderList(); renderBulkActions(); }

  function renderBulkActions() {
    const bar = document.getElementById('findings-bulk');
    if (!bar) return;
    bar.classList.toggle('visible', data.selected.size > 0);
    setText('findings-selected-count', `${data.selected.size} selected`);
  }

  async function bulkStatus(status) {
    const ids = Array.from(data.selected);
    if (!ids.length) return;
    try {
      await Promise.all(ids.map(id => patchFindingStatus(id, status, false)));
      toast(`${ids.length} findings marked ${status}`, 'ok');
      clearSelection();
    } catch (error) {
      toast(`Bulk update failed: ${errorMessage(error)}`, 'error');
      await load(data.auditId, { silent: true });
    }
  }

  async function patchFindingStatus(id, status, notify = true) {
    await api(`/audits/${encodeURIComponent(data.auditId)}/findings/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ status }) });
    const finding = data.findings.find(item => item.id === id);
    if (finding) { finding.status = status; finding.updatedAt = new Date().toISOString(); finding.raw.status = status; }
    data.revision += 1; invalidate(); render();
    if (notify) toast(`Finding marked ${status}`, 'ok');
  }

  function resetFilters() {
    data.query = ''; data.severities.clear(); data.statuses.clear(); data.replayableOnly = false; data.tag = 'all'; data.page = 1;
    const search = /** @type {HTMLInputElement|null} */ (document.getElementById('findings-search'));
    const tag = /** @type {HTMLSelectElement|null} */ (document.getElementById('findings-tag'));
    if (search) search.value = '';
    if (tag) tag.value = 'all';
    invalidate(); render();
  }

  function populateTags() {
    const select = /** @type {HTMLSelectElement|null} */ (document.getElementById('findings-tag'));
    if (!select) return;
    const tags = unique(data.findings.flatMap(finding => finding.tags)).sort();
    select.innerHTML = '<option value="all">All tags</option>' + tags.map(tag => `<option value="${escapeAttribute(tag)}">${escapeHtml(tag)}</option>`).join('');
    select.value = tags.includes(data.tag) ? data.tag : 'all';
  }

  function setExportAvailability(enabled) {
    ['findings-export-json', 'findings-export-pdf', 'findings-generate-report'].forEach(id => {
      const button = /** @type {HTMLButtonElement|null} */ (document.getElementById(id));
      if (button) button.disabled = !enabled;
    });
  }

  function setText(id, text) { const element = document.getElementById(id); if (element) element.textContent = text; }

  function openDetail(id, options) {
    const finding = data.findings.find(item => item.id === id);
    const panel = document.getElementById('panel');
    const overlay = document.getElementById('overlay');
    if (!finding || !panel || !overlay) return;
    if ((!options || !options.fromHistory) && window.appRouter) {
      window.appRouter.openFinding(id);
      return;
    }
    data.activeFindingId = id;
    const refs = finding.references.length ? finding.references.map(renderReference).join('') : '<span style="color:var(--t3);font-size:11px">No external reference supplied.</span>';
    const screenshots = finding.evidence.screenshots.filter(isSafeHttpUrl).map(url => `<a href="${escapeAttribute(url)}" target="_blank" rel="noopener noreferrer" class="btn-sm">Open screenshot</a>`).join('');
    const hasEvidence = finding.evidence.requestRaw || finding.evidence.responseRaw || finding.evidence.payload || finding.evidence.matcherResult || screenshots;
    panel.innerHTML = `
      <div class="panel-header">
        <div style="flex:1"><div class="row" style="gap:6px;margin-bottom:7px"><span class="badge ${severityClass(finding.severity)}">${escapeHtml(titleCase(finding.severity))}</span><span class="badge ${statusClass(finding.status)}">${escapeHtml(titleCase(finding.status.replace(/_/g, ' ')))}</span><span class="badge bi">${escapeHtml(titleCase(finding.confidence))} confidence at scan</span>${finding.replayState !== 'not_run' ? `<span class="badge ${replayStateClass(finding.replayState)}">Replay: ${escapeHtml(replayStateLabel(finding.replayState))}</span>` : ''}</div><div style="font-size:14px;font-weight:500" id="p-title">${escapeHtml(finding.title)}</div><div style="font-size:10px;color:var(--t3);margin-top:4px;font-family:var(--font-mono)">${escapeHtml(finding.id)}</div></div>
        <button class="panel-close" onclick="findingsCenter.closeDetail()" aria-label="Close">&times;</button>
      </div>
      <div class="panel-body">
        <div class="panel-section"><div class="dl">Overview</div><div class="panel-grid">
          ${panelMetric('CVSS score', finding.cvssScore.toFixed(1))}${panelMetric('Affected target', finding.affectedTarget)}${panelMetric('Module', finding.module)}${panelMetric('Category', finding.category)}${panelMetric('Occurrences', String(finding.occurrenceCount))}${finding.affectedEndpoints.length > 1 ? panelMetric('Affected endpoints', String(finding.affectedEndpoints.length)) : ''}
        </div></div>
        <div class="panel-section"><div class="dl">Description</div><div style="font-size:12px;color:var(--t2);line-height:1.65">${escapeHtml(finding.description)}</div></div>
        <div class="panel-section"><div class="dl">Impact</div><div style="font-size:12px;color:var(--t2);line-height:1.65">${escapeHtml(finding.impact)}</div></div>
        <div class="panel-section"><div class="dl">Evidence</div>${hasEvidence ? `${evidenceBlock('Request', finding.evidence.requestRaw)}${evidenceBlock('Response', finding.evidence.responseRaw)}${evidenceBlock('Payload', finding.evidence.payload)}${evidenceBlock('Matcher result', finding.evidence.matcherResult)}${screenshots ? `<div class="row" style="margin-top:8px;flex-wrap:wrap">${screenshots}</div>` : ''}` : '<div style="font-size:11px;color:var(--t3)">No technical evidence was retained for this finding.</div>'}</div>
        <div class="panel-section"><div class="dl">Replay validation</div><div class="row" style="align-items:flex-start;flex-wrap:wrap"><button class="btn-replay" id="finding-replay-button" ${finding.replayable ? '' : 'disabled'} onclick="findingsCenter.replayActive()">Replay proof request</button><span style="font-size:11px;color:var(--t3)" id="finding-replay-status">${escapeHtml(replayStatusText(finding))}</span></div><div id="finding-replay-result" style="margin-top:8px"></div></div>
        <div class="panel-section"><div class="dl">Remediation</div><div style="font-size:12px;color:var(--t2);line-height:1.65">${escapeHtml(finding.recommendation)}</div></div>
        <div class="panel-section"><div class="dl">References and mappings</div><div class="tag-row">${refs}</div></div>
        <div class="panel-section"><div class="dl">History</div>${historyRow('Created', formatDateTime(finding.createdAt))}${historyRow('Last updated', formatDateTime(finding.updatedAt))}${historyRow('Verified by', finding.verifiedBy || 'Not recorded')}</div>
        <div class="panel-section"><div class="dl">Qualification</div><div class="row" style="gap:8px;flex-wrap:wrap"><button class="btn-sm" onclick="findingsCenter.setActiveStatus('false_positive')">Mark false positive</button><button class="btn-sm" onclick="findingsCenter.setActiveStatus('accepted_risk')">Accept risk</button><button class="btn-sm" onclick="findingsCenter.setActiveStatus('suspected')">Mark suspected</button><button class="btn-p" style="font-size:11px;padding:4px 10px" onclick="findingsCenter.setActiveStatus('confirmed')">Mark confirmed</button></div></div>
      </div>`;
    panel.classList.add('open'); overlay.classList.add('active');
  }

  function panelMetric(label, value) { return `<div class="panel-metric"><div class="panel-metric-label">${escapeHtml(label)}</div><div class="panel-metric-value">${escapeHtml(value)}</div></div>`; }
  function historyRow(label, value) { return `<div class="panel-history"><span style="color:var(--t3)">${escapeHtml(label)}</span><span>${escapeHtml(value)}</span></div>`; }
  function evidenceBlock(label, value) { return value ? `<div style="font-size:10px;color:var(--t3);margin:10px 0 4px">${escapeHtml(label)}</div><pre class="code" style="white-space:pre-wrap;max-height:220px">${escapeHtml(value)}</pre>` : ''; }
  function renderReference(reference) { return isSafeHttpUrl(reference) ? `<a class="tag" href="${escapeAttribute(reference)}" target="_blank" rel="noopener noreferrer">${escapeHtml(reference)}</a>` : `<span class="tag">${escapeHtml(reference)}</span>`; }

  function closeDetail(options) {
    if ((!options || !options.fromHistory) && window.appRouter && window.appRouter.currentState().overlay === 'finding') {
      window.appRouter.closeOverlay();
      return;
    }
    const panel = document.getElementById('panel'); const overlay = document.getElementById('overlay');
    if (panel) panel.classList.remove('open'); if (overlay) overlay.classList.remove('active'); data.activeFindingId = '';
  }

  async function setActiveStatus(status) {
    if (!data.activeFindingId) return;
    const id = data.activeFindingId;
    try { await patchFindingStatus(id, status); openDetail(id); } catch (error) { toast(`Update failed: ${errorMessage(error)}`, 'error'); }
  }

  async function replayActive() {
    const finding = data.findings.find(item => item.id === data.activeFindingId);
    const button = /** @type {HTMLButtonElement|null} */ (document.getElementById('finding-replay-button'));
    const status = document.getElementById('finding-replay-status');
    const resultElement = document.getElementById('finding-replay-result');
    if (!finding || !finding.replayable || !button || !status || !resultElement) return;
    button.disabled = true; button.textContent = 'Replaying...'; status.textContent = 'Executing a controlled validation request...'; resultElement.innerHTML = '';
    try {
      const result = await api(`/audits/${encodeURIComponent(data.auditId)}/findings/${encodeURIComponent(finding.id)}/replay`, { method: 'POST' });
      if (result.new_status) { finding.status = String(result.new_status); finding.raw.status = finding.status; }
      if (result.replay_state) { finding.replayState = String(result.replay_state); finding.raw.replay_state = finding.replayState; }
      if (result.replayed_at) { finding.lastReplayAt = String(result.replayed_at); finding.raw.last_replay_at = finding.lastReplayAt; }
      finding.updatedAt = String(result.replayed_at || new Date().toISOString());
      data.revision += 1; invalidate();
      status.textContent = `${result.success ? 'Replay completed' : 'Replay failed'} - ${formatDateTime(result.replayed_at || new Date().toISOString())}`;
      resultElement.innerHTML = `<div class="code" style="border-color:${result.matcher_hit ? 'var(--ok-t)' : 'var(--warn-t)'}"><div style="color:${result.matcher_hit ? 'var(--ok-t)' : 'var(--warn-t)'};margin-bottom:5px">${escapeHtml(result.message || 'Replay completed')}</div><div>HTTP ${escapeHtml(String(result.status_code || '-'))} - Matcher ${result.matcher_hit ? 'matched' : 'not matched'}</div>${result.response_snippet ? `<div style="margin-top:6px">${escapeHtml(result.response_snippet)}</div>` : ''}</div>`;
      render();
    } catch (error) {
      status.textContent = `Replay error: ${errorMessage(error)}`;
      resultElement.innerHTML = `<div class="code" style="border-color:var(--err-t);color:var(--err-t)">${escapeHtml(errorMessage(error))}</div>`;
    } finally { button.disabled = false; button.textContent = 'Replay proof request'; }
  }

  function exportJson() { exportJsonRows(getFilteredFindings(), 'audit-findings'); }
  function exportSelected() { exportJsonRows(data.findings.filter(finding => data.selected.has(finding.id)), 'audit-findings-selection'); }

  function exportJsonRows(findings, baseName) {
    if (!findings.length) { toast('No findings available for export', 'error'); return; }
    const payload = { generatedAt: new Date().toISOString(), total: findings.length, audit: auditExportContext(), findings: findings.map(exportFinding) };
    const filename = safeFilename(`${baseName}-${auditHost()}-${dateStamp()}.json`);
    download(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), filename);
    toast(`${findings.length} findings exported`, 'ok');
  }

  function exportFinding(finding) {
    return {
      id: finding.id, title: finding.title, description: finding.description, severity: finding.severity, status: finding.status,
      confidence: finding.confidence, affectedTarget: finding.affectedTarget, module: finding.module, category: finding.category,
      occurrenceCount: finding.occurrenceCount, affectedEndpoints: finding.affectedEndpoints,
      cvssScore: finding.cvssScore, createdAt: finding.createdAt, updatedAt: finding.updatedAt, evidence: finding.evidence,
      impact: finding.impact, recommendation: finding.recommendation, references: finding.references, replayable: finding.replayable,
      tags: finding.tags, replayState: finding.replayState, lastReplayAt: finding.lastReplayAt, mappings: { cwe: finding.cwe, owasp: finding.owasp, asvs: finding.asvs, cve: finding.cve }
    };
  }

  function openReportPreview(options) {
    const findings = getFilteredFindings();
    const modal = document.getElementById('finding-report-preview'); const body = document.getElementById('finding-report-preview-body');
    if (!findings.length || !modal || !body) { toast('No findings available for the report', 'error'); return; }
    if ((!options || !options.fromHistory) && window.appRouter) {
      window.appRouter.openReportPreview();
      return;
    }
    const counts = countSeverity(findings); const max = Math.max(1, ...SEVERITIES.map(severity => counts[severity]));
    const previewFindings = findings.slice(0, 50);
    setText('finding-report-preview-sub', `${findings.length} filtered findings - ${auditHost()}`);
    body.innerHTML = `
      <div class="report-preview-cover"><div class="sl">AuditCore security assessment</div><h1 style="font-size:22px;margin:7px 0 8px">Vulnerability Findings Report</h1><div style="font-family:var(--font-mono);font-size:11px;color:var(--t2)">${escapeHtml(currentAuditTarget())}</div><div style="font-size:11px;color:var(--t3);margin-top:8px">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</div></div>
      <h2 style="font-size:15px;margin-bottom:8px">Executive summary</h2><p style="font-size:12px;line-height:1.65;color:var(--t2)">${escapeHtml(executiveSummary(findings, counts))}</p>
      <div class="report-preview-chart">${SEVERITIES.map(severity => `<div class="report-preview-bar"><strong>${counts[severity]}</strong><div class="report-preview-bar-fill" style="height:${Math.max(2, counts[severity] / max * 76)}px;background:${SEVERITY_COLORS[severity]}"></div><span>${titleCase(severity)}</span></div>`).join('')}</div>
      <h2 style="font-size:15px;margin-bottom:8px">Findings</h2>${previewFindings.map((finding, index) => `<div class="report-preview-finding"><div class="rowb"><strong>${index + 1}. ${escapeHtml(finding.title)}</strong><span class="badge ${severityClass(finding.severity)}">${escapeHtml(titleCase(finding.severity))} - ${finding.cvssScore.toFixed(1)}</span></div><div style="font-size:11px;color:var(--t2);line-height:1.55;margin-top:6px">${escapeHtml(firstSentence(finding.description + occurrenceNote(finding), 260))}</div><div style="font-size:10px;color:var(--t3);margin-top:6px">${escapeHtml(finding.affectedTarget)} - ${escapeHtml(finding.recommendation)}</div></div>`).join('')}${findings.length > previewFindings.length ? `<div class="empty-state-sub" style="padding:12px 0">Preview limited to 50 findings. The PDF export includes all ${findings.length} filtered findings.</div>` : ''}
      <h2 style="font-size:15px;margin:22px 0 8px">Conclusion</h2><p style="font-size:12px;line-height:1.65;color:var(--t2)">${escapeHtml(conclusion(findings, counts))}</p>`;
    modal.classList.add('open');
  }

  function closeReportPreview(options) {
    if ((!options || !options.fromHistory) && window.appRouter && window.appRouter.currentState().overlay === 'report-preview') {
      window.appRouter.closeOverlay();
      return;
    }
    const modal = document.getElementById('finding-report-preview');
    if (modal) modal.classList.remove('open');
  }

  function exportPdf() {
    const findings = getFilteredFindings();
    if (!findings.length) { toast('No findings available for the PDF report', 'error'); return; }
    try {
      const model = pdfModel(findings);
      const pdf = window.createPdfWriter(model);
      drawPdf(pdf, model);
      const filename = safeFilename(`auditcore-findings-${auditHost()}-${dateStamp()}.pdf`);
      download(pdf.toBlob(), filename);
      if (typeof window.rememberGeneratedReport === 'function') window.rememberGeneratedReport(model, 'PDF', filename);
      toast('Professional findings PDF downloaded', 'ok');
    } catch (error) { toast(`PDF generation failed: ${errorMessage(error)}`, 'error'); }
  }

  function pdfModel(findings) {
    const audit = currentAudit() || { id: data.auditId, target_url: currentAuditTarget() };
    const counts = countSeverity(findings);
    return {
      audit,
      title: `Vulnerability Findings Report - ${auditHost()}`,
      generatedAt: new Date().toISOString(),
      findings: findings.map(finding => ({ ...finding.raw, title: finding.title, description: finding.description + occurrenceNote(finding), severity: finding.severity, status: finding.status, confidence: finding.confidence, endpoint: finding.affectedTarget, impact: finding.impact, remediation: finding.recommendation, cvss_score: finding.cvssScore, cwe: finding.cwe, owasp_category: finding.owasp, asvs_mapping: finding.asvs, evidence: finding.evidence })),
      allFindings: findings,
      assets: [],
      severityCounts: counts,
      options: { mappings: true, raw: false },
      profile: { key: 'technical', label: 'Security & Technical Teams', subtitle: 'Vulnerability Findings Report', accent: [24, 93, 170], dark: [11, 25, 44] }
    };
  }

  function drawPdf(pdf, model) {
    const counts = model.severityCounts;
    pdf.addPage({ cover: true });
    pdf.rect(0, 0, 595.28, 841.89, { fill: model.profile.dark });
    pdf.rect(0, 0, 136, 841.89, { fill: model.profile.accent });
    pdf.text('AuditCore', 48, 690, { size: 18, bold: true, color: [255, 255, 255] });
    pdf.text('VULNERABILITY FINDINGS REPORT', 184, 690, { size: 10, bold: true, color: [143, 185, 230] });
    pdf.text(model.title, 184, 645, { size: 23, bold: true, color: [255, 255, 255], maxWidth: 340, lineHeight: 28 });
    pdf.text(model.audit.target_url || 'Selected audit', 184, 560, { size: 11, color: [219, 233, 247], maxWidth: 330, lineHeight: 15 });
    pdf.metaCard(184, 430, 154, 72, 'Generated', formatDateTime(model.generatedAt));
    pdf.metaCard(358, 430, 154, 72, 'Findings', String(model.findings.length));
    pdf.addPage({ title: 'Executive summary' });
    pdf.h1('Executive summary');
    pdf.paragraph(executiveSummary(model.allFindings, counts));
    pdf.kpiRow([
      ['TOTAL', String(model.findings.length), 'Filtered findings'], ['CRITICAL', String(counts.critical), 'Immediate action'], ['HIGH', String(counts.high), 'Priority remediation'], ['CONFIRMED', String(model.allFindings.filter(finding => finding.status === 'confirmed').length), 'Validated findings']
    ]);
    pdf.h2('Severity distribution'); pdf.severityBar(counts);
    pdf.h2('Assessment context'); pdf.keyValueTable([['Target', model.audit.target_url || '-'], ['Export scope', `${model.findings.length} findings after active filters`], ['Generated at', formatDateTime(model.generatedAt)]]);
    pdf.addPage({ title: 'Detailed findings' }); pdf.h1('Detailed findings');
    model.findings.forEach((finding, index) => { pdf.findingCard(finding, index + 1, model.options, model.profile); if (finding.impact) pdf.small(`Impact: ${finding.impact}`); if (finding.remediation) pdf.small(`Recommendation: ${finding.remediation}`); });
    pdf.addPage({ title: 'Conclusion' }); pdf.h1('Conclusion'); pdf.paragraph(conclusion(model.allFindings, counts));
    pdf.h2('Recommended next steps'); pdf.keyValueTable([['1. Prioritize', 'Assign owners and target dates to critical and high findings.'], ['2. Remediate', 'Correct root causes and preserve implementation evidence.'], ['3. Validate', 'Retest corrected findings and update their qualification status.'], ['4. Monitor', 'Track residual risk and recurring weaknesses across future audits.']]);
  }

  function executiveSummary(findings, counts) {
    const priority = counts.critical + counts.high;
    const confirmed = findings.filter(finding => finding.status === 'confirmed').length;
    return `The selected audit contains ${findings.length} reportable findings, including ${counts.critical} critical and ${counts.high} high severity issues. ${priority} findings require priority remediation and ${confirmed} findings are currently confirmed. Remediation should focus first on exploitable weaknesses affecting sensitive targets, then address medium and lower severity hardening gaps through the normal security backlog.`;
  }

  function conclusion(findings, counts) {
    if (counts.critical || counts.high) return `The assessment identified ${counts.critical + counts.high} high-priority findings. Owners should be assigned immediately, remediation evidence retained, and targeted retesting completed before risk closure. Lower-severity findings should remain tracked to prevent security debt and recurring exposure.`;
    if (findings.length) return `No critical or high issue is present in the filtered scope. The remaining findings should be incorporated into planned hardening work and revalidated after remediation or material application changes.`;
    return 'No reportable finding is present in the selected scope.';
  }

  function auditExportContext() { const audit = currentAudit(); return audit ? { id: audit.id, target: audit.target_url, status: audit.status, phase: audit.phase, startedAt: audit.started_at } : { id: data.auditId, target: currentAuditTarget() }; }
  function currentAudit() { const state = window.state || {}; return (state.audits || []).find(audit => audit.id === data.auditId) || null; }
  function currentAuditTarget() { const audit = currentAudit(); return audit ? String(audit.target_url || '') : ''; }
  function getActiveAuditId() { const state = window.state || {}; return String(state.activeAuditId || ''); }
  function auditHost() { try { return new URL(currentAuditTarget()).hostname || 'audit'; } catch { return currentAuditTarget().replace(/^https?:\/\//, '').split('/')[0] || 'audit'; } }
  function dateStamp() { return new Date().toISOString().slice(0, 10); }

  async function api(path, options) {
    if (typeof window.apiFetch === 'function') return window.apiFetch(path, options || {});
    const response = await fetch(`/api${path}`, { headers: { 'Content-Type': 'application/json' }, ...(options || {}) });
    if (!response.ok) { const payload = await response.json().catch(() => ({})); throw new Error(payload.error || `HTTP ${response.status}`); }
    return response.json();
  }

  function download(blob, filename) {
    if (typeof window.downloadBlob === 'function') { window.downloadBlob(blob, filename); return; }
    const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = filename; document.body.appendChild(anchor); anchor.click(); anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function toast(message, type) { if (typeof window.showToast === 'function') window.showToast(message, type); }
  function errorMessage(error) { return error instanceof Error ? error.message : String(error || 'Unknown error'); }
  function safeFilename(value) { return String(value).replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, ''); }
  function severityClass(severity) { return { critical: 'bc', high: 'bh', medium: 'bm', low: 'bl', info: 'bi' }[severity] || 'bi'; }
  function statusClass(status) { return { confirmed: 'bconf', validated: 'bval', suspected: 'bsusp', accepted_risk: 'bacc', false_positive: 'bi' }[status] || 'bi'; }
  function replayStateClass(state) { return { confirmed: 'bconf', not_reproduced: 'bsusp', failed: 'bsusp', unavailable: 'bi' }[state] || 'bi'; }
  function replayStateLabel(state) { return { not_run: 'not run', confirmed: 'confirmed', not_reproduced: 'not reproduced - revalidate', failed: 'failed', unavailable: 'unavailable' }[state] || state || 'not run'; }
  function replayStatusText(finding) {
    if (!finding.replayable) return 'No replayable evidence available';
    if (finding.replayState === 'confirmed') return `Last replay confirmed${finding.lastReplayAt ? ` - ${formatDateTime(finding.lastReplayAt)}` : ''}`;
    if (finding.replayState === 'not_reproduced') return `Proof not reproduced - revalidation required${finding.lastReplayAt ? ` - ${formatDateTime(finding.lastReplayAt)}` : ''}`;
    if (finding.replayState === 'failed') return `Last replay failed${finding.lastReplayAt ? ` - ${formatDateTime(finding.lastReplayAt)}` : ''}`;
    return 'Ready for controlled replay';
  }
  function titleCase(value) { return String(value || '').replace(/\b\w/g, char => char.toUpperCase()); }
  function kindLabel(finding) { if (finding.tags.includes('API')) return 'API'; if (finding.tags.includes('Auth')) return 'AUTH'; if (finding.tags.includes('Network')) return 'NET'; if (finding.tags.includes('Cloud')) return 'CLOUD'; return 'WEB'; }
  function firstSentence(value, maxLength) { const clean = String(value || '').replace(/\s+/g, ' ').trim(); return clean.length > maxLength ? `${clean.slice(0, maxLength - 1)}...` : clean; }
  function formatDate(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? '-' : date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); }
  function formatDateTime(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }); }
  function isSafeHttpUrl(value) { try { const url = new URL(value); return url.protocol === 'http:' || url.protocol === 'https:'; } catch { return false; } }
  function safeSelectorValue(value) { return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"'); }
  function escapeHtml(value) { return String(value == null ? '' : value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
  function escapeAttribute(value) { return escapeHtml(value).replace(/`/g, '&#96;'); }

  const controller = {
    enter, resetAudit, load, setTag, setSort, setGroup, setPageSize, changePage, selectPage, clearSelection,
    bulkStatus, resetFilters, openDetail, closeDetail, setActiveStatus, replayActive,
    exportJson, exportSelected, exportPdf, openReportPreview, closeReportPreview, toggleFilter, setSearch,
    getFilteredFindings
  };
  window.findingsCenter = controller;
  window.setFindingFilter = (filter, button) => controller.toggleFilter(filter, button);
  window.filterFindings = value => controller.setSearch(value);
  window.openPanel = finding => controller.openDetail(typeof finding === 'string' ? finding : finding && finding.id);
  window.closePanel = controller.closeDetail;
  window.triggerReplay = controller.replayActive;

  mount();
})();
