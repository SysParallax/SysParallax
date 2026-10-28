/**
 * AuditCore Dashboard — API client V1
 *
 * Principe : ce fichier est la seule couche qui parle à l'API.
 * Il ne modifie jamais directement le moteur de scan.
 * Toutes les données viennent de GET /api/audits/...
 */

const API = '/api';

// ─── État global minimal ───────────────────────────────────────────────────

const state = {
  audits: [],           // liste des AuditRun
  activeAuditId: null,  // audit affiché dans la timeline
  pollTimer: null,      // setInterval du polling
  lastEventTS: null,    // timestamp du dernier event reçu (polling incrémental)
  apiOk: false,
};

// ─── Helpers fetch ─────────────────────────────────────────────────────────

async function apiFetch(path, options = {}) {
  try {
    const res = await fetch(API + path, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `HTTP ${res.status}`);
    }
    return res.json();
  } catch (err) {
    console.error('[api]', path, err.message);
    throw err;
  }
}

// ─── Initialisation ────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  loadAudits();

  // Branchement du wizard — remplace l'onclick simulé de l'étape 4
  patchWizardLaunch();

  // Refresh toutes les 30s si on est sur le portfolio
  setInterval(() => {
    if (document.getElementById('page-portfolio').classList.contains('active')) {
      loadAudits();
    }
  }, 30_000);
});

// ─── Health check ──────────────────────────────────────────────────────────

async function checkHealth() {
  try {
    await apiFetch('/health');
    state.apiOk = true;
    const el = document.querySelector('.sb-foot div:last-child');
    if (el) {
      el.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:currentColor;display:inline-block"></span> Backend connected';
      el.style.color = 'var(--ok-t)';
    }
  } catch {
    const el = document.querySelector('.sb-foot div:last-child');
    if (el) {
      el.textContent = '⚠ Backend unreachable';
      el.style.color = 'var(--err-t)';
    }
  }
}

// ─── Portfolio — liste des audits ──────────────────────────────────────────

async function loadAudits() {
  try {
    state.audits = await apiFetch('/audits');
    renderPortfolio();
    renderRunningBadge();
  } catch (err) {
    console.warn('[portfolio] loadAudits failed:', err.message);
  }
}

function renderPortfolio() {
  const container = document.getElementById('live-audit-list');
  if (!container) return;

  if (!state.audits || state.audits.length === 0) {
    container.innerHTML = `
      <div style="grid-column:1/-1;padding:32px;text-align:center;color:var(--t3);font-size:12px">
        Aucun audit lancé — cliquez sur <strong>+ New audit</strong> pour commencer.
      </div>`;
    return;
  }

  container.innerHTML = state.audits.map(a => {
    const statusBadge = statusToBadge(a.status);
    const phase = a.phase !== 'idle' ? ` · ${a.phase}` : '';
    const dateStr = formatDate(a.started_at);
    return `
      <div class="card" style="cursor:pointer" onclick="openAuditDetail('${a.id}')">
        <div class="rowb mb4">
          <span class="badge ${statusBadge.cls}">${statusBadge.label}</span>
          <span style="font-size:10px;font-family:var(--font-mono);color:var(--t3)">${phase}</span>
        </div>
        <div style="font-size:13.5px;font-weight:500;margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${escHtml(a.target_url)}
        </div>
        <div style="font-size:11px;color:var(--t3);margin-bottom:10px">${dateStr}</div>
        ${a.status === 'failed' && a.error
          ? `<div style="font-size:11px;color:var(--err-t);margin-top:4px">${escHtml(a.error)}</div>`
          : ''}
        <div style="font-size:11px;color:var(--t3)">ID: <span style="font-family:var(--font-mono)">${a.id.slice(0,8)}…</span></div>
      </div>`;
  }).join('');
}

function renderRunningBadge() {
  const running = state.audits.filter(a => a.status === 'running').length;
  const badge = document.getElementById('running-badge-topbar');
  if (badge) {
    badge.textContent = running > 0 ? `${running} audit running` : '';
    badge.style.display = running > 0 ? '' : 'none';
  }
  const navBadge = document.querySelector('#ni-timeline .nb');
  if (navBadge) {
    navBadge.textContent = running > 0 ? 'live' : '';
    navBadge.style.display = running > 0 ? '' : 'none';
  }
}

// ─── Créer un audit (POST /api/audits) ─────────────────────────────────────

async function launchAudit(targetURL) {
  if (!targetURL || !targetURL.trim()) {
    showToast('Renseignez une URL cible', 'error');
    return null;
  }
  try {
    const audit = await apiFetch('/audits', {
      method: 'POST',
      body: JSON.stringify({ target_url: targetURL.trim() }),
    });
    state.audits.unshift(audit);
    renderPortfolio();
    renderRunningBadge();
    showToast(`Audit lancé — ${audit.id.slice(0,8)}`, 'ok');
    return audit;
  } catch (err) {
    showToast(`Erreur: ${err.message}`, 'error');
    return null;
  }
}

// ─── Ouvrir la timeline d'un audit ─────────────────────────────────────────

async function openAuditDetail(auditId) {
  state.activeAuditId = auditId;
  stopPolling();

  // Naviguer vers la timeline
  if (typeof nav === 'function') nav('timeline');

  // Charger le détail immédiatement
  await refreshAuditDetail(auditId);

  // Démarrer le polling si l'audit est en cours
  const audit = state.audits.find(a => a.id === auditId);
  if (audit && (audit.status === 'running' || audit.status === 'pending')) {
    startPolling(auditId);
  }
}

// ─── Polling ───────────────────────────────────────────────────────────────

function startPolling(auditId) {
  stopPolling();
  state.lastEventTS = null;
  state.pollTimer = setInterval(() => pollAudit(auditId), 1500);
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

async function pollAudit(auditId) {
  try {
    const detail = await apiFetch(`/audits/${auditId}`);

    // Mettre à jour la liste locale
    const idx = state.audits.findIndex(a => a.id === auditId);
    if (idx >= 0) state.audits[idx] = detail.audit;

    renderAuditDetail(detail);
    renderRunningBadge();

    // Arrêter le polling quand terminé
    if (detail.audit.status === 'done' || detail.audit.status === 'failed') {
      stopPolling();
    }
  } catch (err) {
    console.warn('[poll]', err.message);
  }
}

async function refreshAuditDetail(auditId) {
  try {
    const detail = await apiFetch(`/audits/${auditId}`);
    renderAuditDetail(detail);
  } catch (err) {
    console.warn('[detail]', err.message);
  }
}

// ─── Rendu de la timeline ──────────────────────────────────────────────────

function renderAuditDetail(detail) {
  const { audit, pre_check, recon, event_count } = detail;

  // ── Header ──────────────────────────────────────────────────────────
  const titleEl = document.getElementById('tl-title');
  if (titleEl) titleEl.textContent = `Live audit — ${audit.target_url}`;

  const subEl = document.getElementById('tl-sub');
  if (subEl) subEl.textContent =
    `Run ${audit.id.slice(0,8)} · ${statusLabel(audit.status)} · Phase: ${audit.phase} · ${formatDate(audit.started_at)}`;

  const bcEl = document.getElementById('tl-breadcrumb');
  if (bcEl) bcEl.textContent = audit.target_url;

  // ── Badge statut ─────────────────────────────────────────────────────
  const statusEl = document.getElementById('tl-status-badge');
  if (statusEl) {
    const b = statusToBadge(audit.status);
    statusEl.className = `badge ${b.cls}`;
    statusEl.textContent = b.label;
  }

  // ── Phase pipeline ───────────────────────────────────────────────────
  renderPhasePipeline(audit.phase, audit.status);

  // ── Progression ──────────────────────────────────────────────────────
  const pct = phaseToPercent(audit.phase, audit.status);
  const progEl = document.getElementById('tl-progress');
  if (progEl) progEl.style.width = pct + '%';
  const pctEl = document.getElementById('tl-pct');
  if (pctEl) pctEl.textContent = pct + '%';

  // ── Stats ──────────────────────────────────────────────────────────
  updateStatCard('tl-stat-events', String(event_count || 0));
  updateStatCard('tl-stat-status', statusLabel(audit.status));
  updateStatCard('tl-stat-phase', audit.phase || '—');

  // Mettre à jour le label % sur le pipeline
  const pctLabelEl = document.getElementById('tl-pct-label');
  if (pctLabelEl) pctLabelEl.textContent = `${phaseToPercent(audit.phase, audit.status)}% complet`;

  // ── Pre-check ────────────────────────────────────────────────────────
  renderPreCheck(pre_check);

  // ── Recon ────────────────────────────────────────────────────────────
  renderRecon(recon);

  // ── Events stream ────────────────────────────────────────────────────
  fetchAndRenderEvents(audit.id);
}

function renderPhasePipeline(currentPhase, status) {
  const phases = ['pre-check', 'recon'];
  phases.forEach(ph => {
    const dot = document.getElementById(`ph-dot-${ph}`);
    const conn = document.getElementById(`ph-conn-${ph}`);
    if (!dot) return;

    if (status === 'done') {
      dot.className = 'ph-dot done';
      dot.textContent = '✓';
    } else if (status === 'failed' && currentPhase === ph) {
      dot.className = 'ph-dot';
      dot.style.borderColor = 'var(--err-t)';
      dot.style.color = 'var(--err-t)';
    } else if (currentPhase === ph) {
      dot.className = 'ph-dot active';
    } else if (isPhaseCompleted(ph, currentPhase, status)) {
      dot.className = 'ph-dot done';
      dot.textContent = '✓';
    } else {
      dot.className = 'ph-dot';
    }

    if (conn) {
      conn.className = isPhaseCompleted(ph, currentPhase, status) ? 'ph-conn done' : 'ph-conn';
    }
  });
}

function isPhaseCompleted(phase, currentPhase, status) {
  if (status === 'done') return true;
  const order = ['pre-check', 'recon', 'idle'];
  return order.indexOf(phase) < order.indexOf(currentPhase);
}

function phaseToPercent(phase, status) {
  if (status === 'done') return 100;
  if (status === 'failed') return phaseToPercent(phase, 'running');
  const map = { idle: 0, pending: 5, 'pre-check': 40, recon: 80 };
  return map[phase] ?? 0;
}

function renderPreCheck(pc) {
  const el = document.getElementById('precheck-result');
  if (!el) return;
  if (!pc) {
    el.innerHTML = '<div style="font-size:12px;color:var(--t3)">En attente…</div>';
    return;
  }
  const reachable = pc.reachable
    ? `<span class="badge bconf">Reachable</span>`
    : `<span class="badge berr">Unreachable</span>`;
  el.innerHTML = `
    <table class="tbl">
      <tr><td style="color:var(--t3);font-size:11px">Status</td><td>${reachable}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">HTTP code</td><td><code style="font-family:var(--font-mono)">${pc.status_code || '—'}</code></td></tr>
      <tr><td style="color:var(--t3);font-size:11px">Response time</td><td>${pc.response_time_ns ? Math.round(Number(pc.response_time_ns) / 1e6) + ' ms' : '—'}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">Final URL</td><td style="font-family:var(--font-mono);font-size:10.5px;word-break:break-all">${escHtml(pc.final_url || '—')}</td></tr>
      ${pc.error ? `<tr><td style="color:var(--t3);font-size:11px">Erreur</td><td style="color:var(--err-t)">${escHtml(pc.error)}</td></tr>` : ''}
    </table>`;
}

function renderRecon(rc) {
  const el = document.getElementById('recon-result');
  if (!el) return;
  if (!rc) {
    el.innerHTML = '<div style="font-size:12px;color:var(--t3)">En attente…</div>';
    return;
  }

  const headerRows = Object.entries(rc.headers || {})
    .map(([k, v]) => `<tr><td style="color:var(--t3);font-size:10px;font-family:var(--font-mono)">${escHtml(k)}</td><td style="font-size:10px;word-break:break-all">${escHtml(v)}</td></tr>`)
    .join('');

  const links = (rc.internal_links || []).slice(0, 10)
    .map(l => `<div style="font-size:10px;font-family:var(--font-mono);color:var(--t2);padding:2px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(l)}</div>`)
    .join('');

  el.innerHTML = `
    <table class="tbl mb8">
      <tr><td style="color:var(--t3);font-size:11px">Title</td><td style="font-weight:500">${escHtml(rc.title || '—')}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">Server</td><td style="font-family:var(--font-mono);font-size:10.5px">${escHtml(rc.server || '—')}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">Content-Type</td><td style="font-size:10.5px">${escHtml(rc.content_type || '—')}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">robots.txt</td><td>${rc.has_robots_txt ? '<span class="badge bconf">found</span>' : '<span class="badge bi">absent</span>'}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">sitemap.xml</td><td>${rc.has_sitemap_xml ? '<span class="badge bconf">found</span>' : '<span class="badge bi">absent</span>'}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">Type détecté</td><td>${rc.looks_like_api ? '<span class="badge bm">API JSON</span>' : '<span class="badge bi">HTML site</span>'}</td></tr>
      <tr><td style="color:var(--t3);font-size:11px">Liens internes</td><td>${(rc.internal_links || []).length}</td></tr>
    </table>
    ${headerRows ? `<div style="font-size:11px;font-weight:500;color:var(--t3);margin:10px 0 5px">Headers collectés</div><table class="tbl">${headerRows}</table>` : ''}
    ${links ? `<div style="font-size:11px;font-weight:500;color:var(--t3);margin:10px 0 5px">Liens internes (10 premiers)</div>${links}` : ''}
  `;
}

async function fetchAndRenderEvents(auditId) {
  try {
    let url = `/audits/${auditId}/events`;
    if (state.lastEventTS) url += `?since=${encodeURIComponent(state.lastEventTS)}`;

    const events = await apiFetch(url);
    if (!events || events.length === 0) return;

    // Mettre à jour le timestamp du dernier event
    state.lastEventTS = events[events.length - 1].timestamp;

    renderEventStream(events, !state.lastEventTS);
  } catch (err) {
    console.warn('[events]', err.message);
  }
}

function renderEventStream(events, replace = false) {
  const el = document.getElementById('event-stream');
  if (!el) return;

  const html = events.map(e => {
    const dotClass = levelToDotClass(e.level);
    const msgClass = levelToMsgClass(e.level);
    const time = formatTime(e.timestamp);
    return `
      <div class="tl-item">
        <div class="tl-dot ${dotClass}"></div>
        <div class="tl-time">${time}</div>
        <div class="tl-msg"><span style="color:${msgClass}">${escHtml(e.message)}</span></div>
        <div class="tl-tag">${e.phase}</div>
      </div>`;
  }).join('');

  if (replace) {
    el.innerHTML = html;
  } else {
    el.insertAdjacentHTML('afterbegin', html);
  }

  // Auto-scroll vers le haut (plus récent en premier)
  el.scrollTop = 0;
}

// ─── Wizard — branchement Launch ───────────────────────────────────────────

function patchWizardLaunch() {
  // On intercepte l'étape 4 du wizard pour brancher le vrai appel API.
  // La fonction wizStep() originale est conservée — on remplace seulement
  // le bouton "Launch" au moment où wizCurrent === 4.

  const origWizStep = window.wizStep;
  window.wizStep = function(dir) {
    origWizStep(dir);
    // Si on vient d'arriver à l'étape 4, rebrancher le bouton
    if (window.wizCurrent === 4) {
      const btn = document.getElementById('wiz-next');
      if (btn) {
        btn.onclick = async () => {
          const urlInput = document.querySelector('#wiz-step-1 .form-input');
          const targetURL = urlInput ? urlInput.value.trim() : '';

          if (!targetURL) {
            showToast('Renseignez une URL cible à l\'étape 1', 'error');
            return;
          }

          btn.textContent = 'Launching…';
          btn.disabled = true;

          const audit = await launchAudit(targetURL);

          btn.textContent = 'Launch audit →';
          btn.disabled = false;

          if (audit) {
            // Reset wizard
            window.wizCurrent = 1;
            document.querySelectorAll('#wizard-dots .step-dot').forEach((d, i) => d.classList.toggle('on', i < 1));
            document.getElementById('wiz-step-4').style.display = 'none';
            document.getElementById('wiz-step-1').style.display = 'block';
            btn.textContent = 'Continue →';
            btn.onclick = () => window.wizStep(1);
            document.getElementById('wiz-back').style.visibility = 'hidden';
            if (urlInput) urlInput.value = '';

            // Ouvrir directement la timeline de cet audit
            await openAuditDetail(audit.id);
          }
        };
      }
    }
  };
}

// ─── Helpers UI ───────────────────────────────────────────────────────────

function statusToBadge(status) {
  const map = {
    pending:  { cls: 'bi',   label: 'pending' },
    running:  { cls: 'brun', label: '● running' },
    done:     { cls: 'bok',  label: '✓ done' },
    failed:   { cls: 'berr', label: '✗ failed' },
  };
  return map[status] || { cls: 'bi', label: status };
}

function statusLabel(s) {
  return { pending: 'En attente', running: 'En cours', done: 'Terminé', failed: 'Échoué' }[s] || s;
}

function levelToDotClass(level) {
  return { ok: 'tl-dot-ok', info: 'tl-dot-run', warn: 'tl-dot-warn', error: 'tl-dot-err' }[level] || 'tl-dot-idle';
}

function levelToMsgClass(level) {
  return { ok: '#1d9e75', info: '#185fa5', warn: '#ba7517', error: '#e24b4a' }[level] || 'inherit';
}

function updateStatCard(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toTimeString().slice(0, 8);
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Toast notifications ───────────────────────────────────────────────────

function showToast(msg, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px';
    document.body.appendChild(container);
  }

  const colors = { ok: '#1d9e75', error: '#a32d2d', info: '#185fa5' };
  const toast = document.createElement('div');
  toast.style.cssText = `
    background:var(--bg2);border:0.5px solid var(--bd2);
    border-left:3px solid ${colors[type] || colors.info};
    border-radius:var(--r);padding:10px 14px;
    font-size:12px;color:var(--t1);
    box-shadow:0 2px 8px rgba(0,0,0,.12);
    max-width:280px;word-break:break-word;
  `;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// ─── Exposition globale (appelée depuis HTML) ─────────────────────────────

window.openAuditDetail = openAuditDetail;
window.launchAudit = launchAudit;
window.showToast = showToast;
