'use strict';

const CIRC = 2 * Math.PI * 34;

let alertCounts = { critical: 0, high: 0, medium: 0, low: 0 };

const $ = id => document.getElementById(id);

function fmtTs(ts) {
  if (!ts) return new Date().toISOString().replace('T', ' ').slice(0, 19);
  return ts.replace('T', ' ').slice(0, 19);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function scoreColor(s) {
  if (s >= 80) return '#22c55e';
  if (s >= 50) return '#eab308';
  if (s >= 25) return '#f97316';
  return '#ef4444';
}

function updateScore(counts) {
  const s = Math.max(0,
    100 - counts.critical * 30 - counts.high * 15
    - counts.medium * 5 - counts.low * 1
  );
  const arc = $('score-arc');
  // Setting via .style lets the CSS transition fire (setAttribute bypasses it)
  arc.style.strokeDashoffset = (CIRC * (1 - s / 100)).toFixed(3);
  arc.style.stroke = scoreColor(s);
  $('score-text').textContent = s;
  ['critical', 'high', 'medium', 'low'].forEach(sev => {
    $('cnt-' + sev).textContent = counts[sev];
  });
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => {
    const on = t.dataset.tab === name;
    t.classList.toggle('active', on);
    t.setAttribute('aria-selected', on);
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === 'panel-' + name);
  });
}

function buildAlertRow(a, animate) {
  const tr = document.createElement('tr');
  if (animate) tr.classList.add('fade-in');
  if (a.resolved) tr.classList.add('resolved');

  const sev = (a.severity || 'low').toLowerCase();
  const resolveBtn = a.id
    ? '<button class="btn-resolve" data-id="' + escapeHtml(a.id) + '">Resolver</button>'
    : '';

  const rec = a.recommendation || '';

  tr.innerHTML =
    '<td class="mono">' + fmtTs(a.timestamp) + '</td>' +
    '<td><span class="badge badge-' + escapeHtml(sev) + '">' + escapeHtml(a.severity || '') + '</span></td>' +
    '<td>' + escapeHtml(a.category || '') + '</td>' +
    '<td class="' + (a.resolved ? 'resolved-title' : '') + '">' + escapeHtml(a.title || '') + '</td>' +
    '<td><div class="detail-cell">' + escapeHtml(a.detail || '') + '</div></td>' +
    '<td><div class="rec-cell">' + escapeHtml(rec || '–') + '</div></td>' +
    '<td>' + resolveBtn + '</td>';

  tr.addEventListener('click', function (e) {
    if (e.target.closest('.btn-resolve')) return;
    tr.querySelectorAll('.detail-cell, .rec-cell').forEach(cell => {
      cell.classList.toggle('expanded');
    });
  });

  if (a.id) {
    tr.querySelector('.btn-resolve').addEventListener('click', async function (e) {
      e.stopPropagation();
      this.disabled = true;
      try {
        const resp = await fetch(apiBase + 'api/alerts/' + a.id + '/resolve', { method: 'POST' });
        if (resp.ok) {
          tr.classList.add('resolved');
          const titleCell = tr.querySelector('td:nth-child(4)');
          if (titleCell) titleCell.classList.add('resolved-title');
        } else {
          this.disabled = false;
        }
      } catch (_) {
        this.disabled = false;
      }
    });
  }
  return tr;
}

function prependAlertRow(a) {
  const tbody = $('alerts-tbody');
  const placeholder = tbody.querySelector('.empty-state');
  if (placeholder) placeholder.closest('tr').remove();
  tbody.prepend(buildAlertRow(a, true));
  const sev = (a.severity || '').toLowerCase();
  if (sev in alertCounts) {
    alertCounts[sev]++;
    updateScore(alertCounts);
  }
}

// HA Ingress serves the panel under /api/hassio_ingress/<token>/; in standalone Docker it's just "/".
const apiBase = location.pathname.replace(/\/?$/, '/');

async function loadAlerts() {
  try {
    const res = await fetch(apiBase + 'api/alerts');
    const alerts = await res.json();
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    const tbody = $('alerts-tbody');
    tbody.innerHTML = '';

    if (!alerts.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Sin alertas activas</td></tr>';
    } else {
      alerts.forEach(a => {
        const sev = (a.severity || '').toLowerCase();
        if (sev in counts) counts[sev]++;
        tbody.appendChild(buildAlertRow(a, false));
      });
    }
    alertCounts = counts;

    // Trigger arc animation: reset to invisible, then on next two frames
    // (to guarantee the browser has painted the reset state) set real value.
    $('score-arc').style.strokeDashoffset = CIRC.toFixed(3);
    requestAnimationFrame(() => requestAnimationFrame(() => updateScore(counts)));
  } catch (_) {
    $('alerts-tbody').innerHTML =
      '<tr><td colspan="7" class="empty-state">Error al cargar alertas</td></tr>';
  }
}

async function loadDevices() {
  try {
    const res = await fetch(apiBase + 'api/devices');
    const devices = await res.json();
    const tbody = $('devices-tbody');
    tbody.innerHTML = '';

    if (!devices.length) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="empty-state">Sin dispositivos detectados</td></tr>';
      return;
    }

    devices.forEach(d => {
      const cves = d.cves || [];
      const ports = d.ports || [];

      const tr = document.createElement('tr');
      tr.dataset.mac = d.mac || '';
      if (cves.length) tr.classList.add('expandable');

      const portStr = ports.length
        ? ports.map(p => escapeHtml(p.port) + '/' + escapeHtml(p.protocol)).join(', ')
        : '–';
      const cveCell = cves.length
        ? '<span class="badge badge-critical">' + cves.length + '</span>'
        : '–';

      tr.innerHTML =
        '<td class="mono">' + escapeHtml(d.mac || '') + '</td>' +
        '<td class="mono">' + escapeHtml(d.ip || '') + '</td>' +
        '<td>' + escapeHtml(d.vendor || '') + '</td>' +
        '<td>' + escapeHtml(d.device_type || '') + '</td>' +
        '<td class="mono">' + portStr + '</td>' +
        '<td>' + cveCell + '</td>';

      tbody.appendChild(tr);

      if (cves.length) {
        const detailRow = document.createElement('tr');
        detailRow.className = 'cve-detail hidden';
        detailRow.innerHTML =
          '<td colspan="6"><div class="cve-list">' +
          cves.map(c =>
            '<div class="cve-item">' +
            '<span class="mono">' + escapeHtml(c.cve_id || '') + '</span>' +
            '<span class="cvss">CVSS ' + escapeHtml(c.cvss_score !== undefined ? c.cvss_score : '?') + '</span>' +
            '<span class="cve-desc">' + escapeHtml(c.description || '') + '</span>' +
            '</div>'
          ).join('') +
          '</div></td>';
        tbody.appendChild(detailRow);
        tr.addEventListener('click', () => detailRow.classList.toggle('hidden'));
      }
    });
  } catch (_) {
    $('devices-tbody').innerHTML =
      '<tr><td colspan="6" class="empty-state">Error al cargar dispositivos</td></tr>';
  }
}

function sparkline(values) {
  if (!values || values.length < 2) return '–';
  const W = 60, H = 20;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * W;
    // 1px top/bottom padding to prevent clipping
    const y = H - ((v - min) / range) * (H - 2) - 1;
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return (
    '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '">' +
    '<polyline points="' + pts + '" fill="none" ' +
    'stroke="var(--color-accent)" stroke-width="1.5" stroke-linejoin="round"/>' +
    '</svg>'
  );
}

async function loadZigbee() {
  try {
    const res = await fetch(apiBase + 'api/zigbee');
    const devices = await res.json();
    const tbody = $('zigbee-tbody');
    tbody.innerHTML = '';

    if (!devices.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-state">Sin dispositivos Zigbee</td></tr>';
      return;
    }

    devices.forEach(d => {
      let lqi = [];
      try { lqi = JSON.parse(d.lqi_history || '[]'); } catch (_) { }

      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="mono">' + escapeHtml(d.ieee || '') + '</td>' +
        '<td>' + escapeHtml(d.friendly_name || '') + '</td>' +
        '<td>' + (d.trusted ? '✓' : '✗') + '</td>' +
        '<td class="mono">' + fmtTs(d.last_seen) + '</td>' +
        '<td>' + sparkline(lqi) + '</td>';
      tbody.appendChild(tr);
    });
  } catch (_) {
    $('zigbee-tbody').innerHTML =
      '<tr><td colspan="5" class="empty-state">Error al cargar Zigbee</td></tr>';
  }
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + apiBase + 'ws/alerts');

  ws.onopen = () => {
    const badge = $('status-badge');
    badge.textContent = 'Activo';
    badge.classList.add('connected');
  };

  ws.onmessage = e => {
    try { prependAlertRow(JSON.parse(e.data)); } catch (_) { }
  };

  ws.onclose = () => {
    const badge = $('status-badge');
    badge.textContent = 'Desconectado';
    badge.classList.remove('connected');
    setTimeout(connectWS, 3000);
  };
}

function initScanButtons() {
  document.querySelectorAll('.btn-scan').forEach(btn => {
    btn.addEventListener('click', async () => {
      document.querySelectorAll('.btn-scan').forEach(b => {
        b.disabled = true;
        b.textContent = 'Escaneando…';
      });
      try {
        await fetch(apiBase + 'api/scan', { method: 'POST' });
      } finally {
        document.querySelectorAll('.btn-scan').forEach(b => {
          b.disabled = false;
          b.textContent = 'Escanear ahora';
        });
        loadDevices();
      }
    });
  });
}

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

loadAlerts();
loadDevices();
loadZigbee();
connectWS();
initScanButtons();
