/**
 * AI DLP Agent — Popup Dashboard Logic
 *
 * Communicates with the background script via chrome.runtime.sendMessage
 * to fetch and display security metrics.
 */

(function () {
  'use strict';

  /* ── Color Map ─────────────────────────────────────── */
  const TYPE_COLORS = {
    'AWS Key':        '#FF6B6B',
    'Credit Card':    '#FFD93D',
    'Email':          '#6BCB77',
    'SSN':            '#FF8C42',
    'JWT':            '#4D96FF',
    'GitHub Token':   '#9B59B6',
    'Private Key':    '#E74C3C',
    'Slack Token':    '#1ABC9C',
    'Google API Key': '#F39C12',
    'API Key':        '#3498DB',
  };

  const DEFAULT_COLOR = '#888';

  /* ── DOM References ────────────────────────────────── */
  const statTotalEl    = document.querySelector('#stat-total .stat-card__value');
  const topThreatEl    = document.getElementById('top-threat-value');
  const topDomainEl    = document.getElementById('top-domain-value');
  const barChartEl     = document.getElementById('bar-chart');
  const activityListEl = document.getElementById('activity-list');
  const emptyStateEl   = document.getElementById('empty-state');
  const chartSection   = document.querySelector('.chart-section');
  const activitySection = document.querySelector('.activity-section');
  const btnClear       = document.getElementById('btn-clear');

  /* ── Helpers ───────────────────────────────────────── */

  /**
   * Returns the color associated with a given data type.
   */
  function colorFor(type) {
    return TYPE_COLORS[type] || DEFAULT_COLOR;
  }

  /**
   * Returns a human-readable relative time string.
   */
  function relativeTime(timestamp) {
    const diff = Math.max(0, Date.now() - timestamp);
    const seconds = Math.floor(diff / 1000);
    if (seconds < 60) return 'just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes === 1 ? '1 min ago' : `${minutes} min ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours === 1 ? '1 hr ago' : `${hours} hrs ago`;
    const days = Math.floor(hours / 24);
    return days === 1 ? '1 day ago' : `${days} days ago`;
  }

  /**
   * Animates a number from 0 to `target` inside `el`.
   */
  function animateCount(el, target) {
    if (target === 0) { el.textContent = '0'; return; }
    const duration = 600; // ms
    const start = performance.now();

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(eased * target);
      if (progress < 1) requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
  }

  /**
   * Returns the entry with the highest value from an object map.
   */
  function topEntry(obj) {
    let topKey = null;
    let topVal = -1;
    for (const [key, val] of Object.entries(obj)) {
      if (val > topVal) { topKey = key; topVal = val; }
    }
    return topKey;
  }

  /**
   * Shortens a domain for display (remove www.).
   */
  function shortDomain(domain) {
    return domain.replace(/^www\./, '');
  }

  /* ── Renderers ─────────────────────────────────────── */

  function renderEmpty() {
    chartSection.style.display = 'none';
    activitySection.style.display = 'none';
    emptyStateEl.hidden = false;
    statTotalEl.textContent = '0';
    topThreatEl.textContent = '—';
    topDomainEl.textContent = '—';
  }

  function renderDashboard(metrics) {
    const { totalBlocks, blocksByType, blocksByDomain, recentEvents } = metrics;

    const hasData = totalBlocks > 0;

    if (!hasData) {
      renderEmpty();
      return;
    }

    // Show sections
    emptyStateEl.hidden = true;
    chartSection.style.display = '';
    activitySection.style.display = '';

    // ── Stat Cards ──
    animateCount(statTotalEl, totalBlocks);

    const threat = topEntry(blocksByType || {});
    topThreatEl.textContent = threat || '—';
    if (threat) topThreatEl.style.color = colorFor(threat);

    const domain = topEntry(blocksByDomain || {});
    topDomainEl.textContent = domain ? shortDomain(domain) : '—';

    // ── Bar Chart ──
    renderBarChart(blocksByType || {});

    // ── Recent Events ──
    renderRecentEvents(recentEvents || []);
  }

  function renderBarChart(blocksByType) {
    barChartEl.innerHTML = '';

    const entries = Object.entries(blocksByType).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) return;

    const maxVal = entries[0][1];

    entries.forEach(([type, count]) => {
      const pct = maxVal > 0 ? (count / maxVal) * 100 : 0;
      const color = colorFor(type);

      const row = document.createElement('div');
      row.className = 'chart__row';

      row.innerHTML = `
        <span class="chart__label">${escapeHtml(type)}</span>
        <div class="chart__bar-track">
          <div class="chart__bar-fill" style="background:${color};" data-width="${pct}%"></div>
        </div>
        <span class="chart__count">${count}</span>
      `;

      barChartEl.appendChild(row);
    });

    // Trigger width animation after paint
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        barChartEl.querySelectorAll('.chart__bar-fill').forEach((bar) => {
          bar.style.width = bar.dataset.width;
        });
      });
    });
  }

  function renderRecentEvents(events) {
    activityListEl.innerHTML = '';

    const last10 = events.slice(0, 10);

    if (last10.length === 0) {
      activityListEl.innerHTML = '<li class="activity-item" style="justify-content:center;color:var(--text-muted);font-size:11px;">No recent events</li>';
      return;
    }

    last10.forEach((evt) => {
      const color = colorFor(evt.type);
      const li = document.createElement('li');
      li.className = 'activity-item';
      li.style.setProperty('--item-color', color);

      li.innerHTML = `
        <span class="activity-item__badge" style="background:${color}">${escapeHtml(evt.type)}</span>
        <div class="activity-item__details">
          <div class="activity-item__domain">${escapeHtml(shortDomain(evt.domain))}</div>
          <div class="activity-item__meta">${escapeHtml(evt.inputType || 'input')} · ${relativeTime(evt.timestamp)}</div>
        </div>
      `;

      activityListEl.appendChild(li);
    });
  }

  /**
   * Basic HTML escaping.
   */
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  /* ── Chrome Messaging ──────────────────────────────── */

  function fetchMetrics() {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'getMetrics' }, (response) => {
        if (chrome.runtime.lastError) {
          console.warn('AI DLP Agent: could not fetch metrics', chrome.runtime.lastError.message);
          renderEmpty();
          return;
        }
        renderDashboard(response || getEmptyMetrics());
      });
    } else {
      // Fallback: render with demo data for development / preview
      renderDashboard(getDemoMetrics());
    }
  }

  function clearMetrics() {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'clearMetrics' }, () => {
        fetchMetrics();
      });
    } else {
      renderEmpty();
    }
  }

  function getEmptyMetrics() {
    return { totalBlocks: 0, blocksByType: {}, blocksByDomain: {}, recentEvents: [] };
  }

  /**
   * Demo data used when opened outside the extension context.
   */
  function getDemoMetrics() {
    const now = Date.now();
    return {
      totalBlocks: 42,
      blocksByType: {
        'AWS Key': 10,
        'Credit Card': 8,
        'Email': 15,
        'SSN': 5,
        'JWT': 4,
      },
      blocksByDomain: {
        'chatgpt.com': 20,
        'claude.ai': 12,
        'gemini.google.com': 10,
      },
      recentEvents: [
        { type: 'AWS Key',     domain: 'chatgpt.com',        timestamp: now - 2 * 60000,  inputType: 'paste' },
        { type: 'Credit Card', domain: 'claude.ai',          timestamp: now - 15 * 60000, inputType: 'typed' },
        { type: 'Email',       domain: 'gemini.google.com',  timestamp: now - 45 * 60000, inputType: 'paste' },
        { type: 'SSN',         domain: 'chatgpt.com',        timestamp: now - 2 * 3600000, inputType: 'paste' },
        { type: 'JWT',         domain: 'claude.ai',          timestamp: now - 5 * 3600000, inputType: 'typed' },
        { type: 'Email',       domain: 'chatgpt.com',        timestamp: now - 86400000,    inputType: 'paste' },
      ],
    };
  }

  /* ── Init ──────────────────────────────────────────── */

  document.addEventListener('DOMContentLoaded', () => {
    fetchMetrics();
    btnClear.addEventListener('click', clearMetrics);
  });
})();
