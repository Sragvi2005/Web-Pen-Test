/* ============================================================
   SECSCAN — FRONTEND JAVASCRIPT
   Simulates scan execution via terminal output, handles all
   edge cases: invalid URL, empty input, no findings, errors.
   ============================================================ */

// ─── STATE ────────────────────────────────────────────────
let scanState = {
  isScanning: false,
  findings: [],
  target: '',
  scanDuration: 0,
  startTime: null,
  currentFilter: 'all',
};

// ─── DEMO FINDINGS BANK ───────────────────────────────────
// Used for UI demonstration when running from browser (no Python backend)
const DEMO_FINDINGS = {
  ssl: [
    {
      title: 'Weak TLS Protocol Enabled',
      type: 'Transport Layer Security',
      severity: 'High',
      cvss: '7.5',
      detail: 'Deprecated or insecure TLS protocol version enabled: TLSv1.1. This version is known to be vulnerable to downgrade attacks.',
      remediation: 'Disable TLS 1.0/1.1 and legacy SSL protocols on web server configurations; enforce TLS 1.2 or TLS 1.3 only.',
    },
    {
      title: 'Expiring SSL/TLS Certificate',
      type: 'Transport Layer Security',
      severity: 'Medium',
      cvss: '5.3',
      detail: 'SSL/TLS Certificate is nearing expiration (expires in 9 days). Clients may begin showing trust errors.',
      remediation: 'Schedule certificate renewal with certificate authority prior to expiration date.',
    },
  ],
  headers: [
    {
      title: 'Missing Header: Content-Security-Policy',
      type: 'HTTP Security Header',
      severity: 'High',
      cvss: '6.5',
      detail: "Missing HTTP Security Header: 'Content-Security-Policy'. Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
      remediation: 'Implement a robust Content-Security-Policy header restricting script execution sources.',
    },
    {
      title: 'Missing Header: Strict-Transport-Security',
      type: 'HTTP Security Header',
      severity: 'Medium',
      cvss: '5.3',
      detail: "Missing HTTP Security Header: 'Strict-Transport-Security'. Enforces secure HTTPS connections.",
      remediation: "Configure HSTS header: 'max-age=31536000; includeSubDomains; preload'.",
    },
    {
      title: 'Missing Header: X-Frame-Options',
      type: 'HTTP Security Header',
      severity: 'Medium',
      cvss: '4.3',
      detail: "Missing HTTP Security Header: 'X-Frame-Options'. Protects application against Clickjacking attacks.",
      remediation: "Set X-Frame-Options header to 'DENY' or 'SAMEORIGIN'.",
    },
    {
      title: 'Missing Header: X-Content-Type-Options',
      type: 'HTTP Security Header',
      severity: 'Low',
      cvss: '3.4',
      detail: "Missing HTTP Security Header: 'X-Content-Type-Options'. Prevents browser MIME-sniffing vulnerabilities.",
      remediation: "Configure 'X-Content-Type-Options: nosniff'.",
    },
    {
      title: 'Missing Header: Referrer-Policy',
      type: 'HTTP Security Header',
      severity: 'Low',
      cvss: '3.1',
      detail: "Missing HTTP Security Header: 'Referrer-Policy'. Controls referrer information disclosure in request headers.",
      remediation: "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
  ],
  cors: [
    {
      title: 'Exploitable CORS Misconfiguration',
      type: 'Cross-Origin Access',
      severity: 'Critical',
      cvss: '8.8',
      detail: "Critical CORS Misconfiguration! Origin reflected ('https://evil-attacker-domain.com') with Access-Control-Allow-Credentials set to true.",
      remediation: 'Avoid reflecting request Origin headers dynamically with credentials enabled; whitelist trusted origins explicitly.',
    },
  ],
  endpoints: [
    {
      title: 'Exposed Sensitive File/Directory: /.env',
      type: 'Information Disclosure',
      severity: 'High',
      cvss: '7.5',
      detail: 'Exposed Sensitive Endpoint: /.env returned HTTP 200 OK. Environment configuration may contain API keys and database credentials.',
      remediation: "Restrict public access to path '/.env' using web server access controls or authenticated route guards.",
    },
    {
      title: 'Exposed Sensitive File/Directory: /.git/HEAD',
      type: 'Information Disclosure',
      severity: 'High',
      cvss: '7.5',
      detail: 'Exposed Sensitive Endpoint: /.git/HEAD returned HTTP 200 OK. Git repository metadata is publicly accessible.',
      remediation: "Block access to /.git/ via web server configuration. Add 'location ~* /\\.git { deny all; }' in nginx.",
    },
  ],
  xss: [
    {
      title: 'Reflected Input Parameter (XSS Indicator)',
      type: 'Input Injection',
      severity: 'High',
      cvss: '7.2',
      detail: "Unsanitized reflected input detected at query parameter 'q' in target URL. Raw <SecTest123> string reflected in HTTP response body.",
      remediation: 'Implement contextual HTML/JavaScript output encoding and validate input parameters against strict allow-lists.',
    },
  ],
};

// ─── UTILITIES ────────────────────────────────────────────

function isValidUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function addTerminalLine(text, cls = '') {
  const output = document.getElementById('terminal-output');
  const line = document.createElement('div');
  line.className = 'tw-line' + (cls ? ' ' + cls : '');
  line.textContent = text;
  // Remove old cursor line, add new line, re-add cursor
  const cursor = output.querySelector('.tw-cursor-line');
  if (cursor) output.removeChild(cursor);
  output.appendChild(line);
  // Re-append cursor
  const cursorLine = document.createElement('div');
  cursorLine.className = 'tw-cursor-line';
  cursorLine.innerHTML = '<span class="tw-prompt">$</span> <span class="tw-cursor">█</span>';
  output.appendChild(cursorLine);
  output.scrollTop = output.scrollHeight;
  return line;
}

function clearTerminal() {
  const output = document.getElementById('terminal-output');
  output.innerHTML = '';
  const cursorLine = document.createElement('div');
  cursorLine.className = 'tw-cursor-line';
  cursorLine.innerHTML = '<span class="tw-prompt">$</span> <span class="tw-cursor">█</span>';
  output.appendChild(cursorLine);
}

function addProgressBar() {
  const output = document.getElementById('terminal-output');
  const cursor = output.querySelector('.tw-cursor-line');
  const wrap = document.createElement('div');
  wrap.className = 'tw-progress-bar';
  const fill = document.createElement('div');
  fill.className = 'tw-progress-fill';
  fill.id = 'tw-progress-fill';
  wrap.appendChild(fill);
  if (cursor) output.insertBefore(wrap, cursor);
  else output.appendChild(wrap);
  return fill;
}

function updateProgress(fill, pct) {
  fill.style.width = pct + '%';
}

function getSeverityRank(sev) {
  return { Critical: 4, High: 3, Medium: 2, Low: 1 }[sev] || 0;
}

function computeRisk(findings) {
  if (!findings.length) return { label: 'CLEAN', pct: 0, color: '#22c55e' };
  const hasCrit = findings.some((f) => f.severity === 'Critical');
  const hasHigh = findings.some((f) => f.severity === 'High');
  const hasMed = findings.some((f) => f.severity === 'Medium');
  if (hasCrit) return { label: 'CRITICAL', pct: 95, color: '#ef4444' };
  if (hasHigh) return { label: 'HIGH', pct: 73, color: '#f97316' };
  if (hasMed) return { label: 'MEDIUM', pct: 48, color: '#eab308' };
  return { label: 'LOW', pct: 22, color: '#60a5fa' };
}

// ─── SCAN SIMULATION ──────────────────────────────────────

async function runScan() {
  if (scanState.isScanning) return;

  const urlInput = document.getElementById('target-url');
  const rawUrl = urlInput.value.trim();
  const errorDiv = document.querySelector('.scan-error');

  // Clear old error
  if (errorDiv) {
    errorDiv.classList.remove('show');
    errorDiv.textContent = '';
  }

  // Validate
  if (!rawUrl) {
    showScanError('Enter a target URL before running the audit.');
    urlInput.focus();
    return;
  }

  if (!isValidUrl(rawUrl)) {
    showScanError('Invalid URL. Use the format: https://example.com');
    urlInput.focus();
    return;
  }

  // Get selected modules
  const mods = {
    ssl: document.getElementById('opt-ssl').checked,
    headers: document.getElementById('opt-headers').checked,
    cors: document.getElementById('opt-cors').checked,
    endpoints: document.getElementById('opt-endpoints').checked,
    xss: document.getElementById('opt-xss').checked,
  };

  const workers = parseInt(document.getElementById('workers').value) || 10;

  if (!Object.values(mods).some(Boolean)) {
    showScanError('Select at least one scan module before running.');
    return;
  }

  // Start scan
  scanState.isScanning = true;
  scanState.findings = [];
  scanState.target = rawUrl;
  scanState.startTime = Date.now();

  const btn = document.getElementById('run-scan-btn');
  btn.textContent = 'RUNNING…';
  btn.disabled = true;

  // Hide results from previous scan
  document.getElementById('results-section').style.display = 'none';

  // Clear and set up terminal
  clearTerminal();
  document.getElementById('tw-title').textContent = `secscan@engine — ${new URL(rawUrl).hostname}`;

  await sleep(60);

  addTerminalLine('SecScan Enterprise Engine v3.5', 'tw-muted');
  addTerminalLine('══════════════════════════════════════════', 'tw-muted');
  await sleep(120);
  addTerminalLine(`[TARGET]   ${rawUrl}`);
  addTerminalLine(`[THREADS]  ${workers} workers`);
  addTerminalLine(`[MODULES]  ${Object.entries(mods).filter(([,v]) => v).map(([k]) => k.toUpperCase()).join(', ')}`);
  addTerminalLine('', '');
  await sleep(200);
  addTerminalLine('[*] Initialising session with SecScan-Enterprise-Engine/3.5 user-agent…', 'tw-muted');
  await sleep(350);
  addTerminalLine('[*] Resolving domain and establishing probe connection…', 'tw-muted');
  await sleep(500);

  const progressFill = addProgressBar();
  let totalModules = Object.values(mods).filter(Boolean).length;
  let doneMods = 0;

  // ── MODULE: SSL/TLS ──
  if (mods.ssl) {
    addTerminalLine('', '');
    addTerminalLine('[MODULE] SSL/TLS Certificate Inspection', 'tw-muted');
    await sleep(300);
    // Simulate connection
    addTerminalLine(`[*] Connecting to ${new URL(rawUrl).hostname}:443 via socket…`, 'tw-dim');
    await sleep(500);

    // Pick random realistic demo outcome
    const roll = Math.random();
    if (rawUrl.startsWith('http://')) {
      addTerminalLine('[INFO] Target is not using HTTPS. Skipping SSL/TLS inspection.', 'tw-muted');
    } else if (roll < 0.35) {
      addTerminalLine('[✓] TLS Version in Use: TLSv1.3 | Cipher: TLS_AES_256_GCM_SHA384', 'tw-ok');
      await sleep(200);
      addTerminalLine('[✓] SSL Certificate is valid for 287 more days.', 'tw-ok');
    } else if (roll < 0.6) {
      addTerminalLine('[✓] TLS Version in Use: TLSv1.3 | Cipher: TLS_AES_256_GCM_SHA384', 'tw-ok');
      await sleep(200);
      addTerminalLine('[VULN] SSL/TLS Certificate is nearing expiration (expires in 9 days).', 'tw-line-vuln');
      scanState.findings.push(DEMO_FINDINGS.ssl[1]);
    } else {
      addTerminalLine('[VULN] Deprecated TLS protocol version in use: TLSv1.1', 'tw-line-vuln');
      scanState.findings.push(DEMO_FINDINGS.ssl[0]);
      await sleep(200);
      addTerminalLine('[✓] SSL Certificate is valid for 91 more days.', 'tw-ok');
    }

    doneMods++;
    updateProgress(progressFill, Math.round((doneMods / totalModules) * 100));
    await sleep(300);
  }

  // ── MODULE: HEADERS ──
  if (mods.headers) {
    addTerminalLine('', '');
    addTerminalLine('[MODULE] HTTP Security Header Audit', 'tw-muted');
    await sleep(250);
    addTerminalLine('[*] GET / — checking OWASP-recommended response headers…', 'tw-dim');
    await sleep(450);

    const allHeaders = DEMO_FINDINGS.headers;
    // Randomly include/exclude headers for realism
    for (const h of allHeaders) {
      await sleep(80);
      if (Math.random() < 0.62) {
        addTerminalLine(`[VULN] ${h.title}`, 'tw-line-vuln');
        scanState.findings.push(h);
      } else {
        const headerName = h.title.replace('Missing Header: ', '');
        addTerminalLine(`[✓] Found Header: ${headerName}`, 'tw-ok');
      }
    }

    doneMods++;
    updateProgress(progressFill, Math.round((doneMods / totalModules) * 100));
    await sleep(300);
  }

  // ── MODULE: CORS ──
  if (mods.cors) {
    addTerminalLine('', '');
    addTerminalLine('[MODULE] CORS Misconfiguration Detection', 'tw-muted');
    await sleep(250);
    addTerminalLine('[*] Injecting forged Origin: https://evil-attacker-domain.com', 'tw-dim');
    await sleep(500);

    const roll = Math.random();
    if (roll < 0.25) {
      addTerminalLine('[VULN] CRITICAL: Origin reflected with Access-Control-Allow-Credentials: true!', 'tw-line-crit');
      scanState.findings.push(DEMO_FINDINGS.cors[0]);
    } else if (roll < 0.45) {
      addTerminalLine('[VULN] Arbitrary Origin Reflection detected without credentials flag.', 'tw-line-vuln');
      scanState.findings.push({
        title: 'Arbitrary CORS Origin Reflection',
        type: 'Cross-Origin Access',
        severity: 'Medium',
        cvss: '5.3',
        detail: "Arbitrary Origin Reflection detected: Access-Control-Allow-Origin reflects arbitrary origin 'https://evil-attacker-domain.com'.",
        remediation: 'Restrict Access-Control-Allow-Origin to static, strictly validated domain lists.',
      });
    } else {
      addTerminalLine('[✓] CORS policy appears properly restricted.', 'tw-ok');
    }

    doneMods++;
    updateProgress(progressFill, Math.round((doneMods / totalModules) * 100));
    await sleep(300);
  }

  // ── MODULE: ENDPOINTS ──
  if (mods.endpoints) {
    addTerminalLine('', '');
    addTerminalLine(`[MODULE] Sensitive Endpoint Discovery (${workers} threads)`, 'tw-muted');
    await sleep(250);
    const paths = ['/.env', '/.git/HEAD', '/config.json', '/admin', '/api/v1/health', '/swagger.json', '/robots.txt', '/server-status', '/.aws/credentials', '/backup.sql'];
    addTerminalLine('[*] Dispatching concurrent probe requests…', 'tw-dim');
    await sleep(300);

    const critPaths = ['/.env', '/.git/HEAD', '/.aws/credentials', '/backup.sql'];
    for (const path of paths) {
      await sleep(60 + Math.random() * 80);
      if (Math.random() < 0.18) {
        addTerminalLine(`[VULN] HTTP 200 — Exposed endpoint: ${path}`, 'tw-line-vuln');
        const isCrit = critPaths.includes(path);
        scanState.findings.push({
          title: `Exposed Sensitive File/Directory: ${path}`,
          type: 'Information Disclosure',
          severity: isCrit ? 'High' : 'Medium',
          cvss: isCrit ? '7.5' : '5.3',
          detail: `Exposed Sensitive Endpoint: ${path} returned HTTP 200 OK.`,
          remediation: `Restrict public access to path '${path}' using web server access controls or authenticated route guards.`,
        });
      } else {
        addTerminalLine(`[—] ${path} → 404`, 'tw-dim');
      }
    }

    doneMods++;
    updateProgress(progressFill, Math.round((doneMods / totalModules) * 100));
    await sleep(300);
  }

  // ── MODULE: XSS ──
  if (mods.xss) {
    addTerminalLine('', '');
    addTerminalLine('[MODULE] Reflected XSS Detection', 'tw-muted');
    await sleep(250);
    addTerminalLine('[*] Injecting payload: /?q=%3CSecTest123%3E', 'tw-dim');
    await sleep(550);

    if (Math.random() < 0.4) {
      addTerminalLine('[VULN] Unsanitized reflected input detected at query parameter q!', 'tw-line-vuln');
      scanState.findings.push(DEMO_FINDINGS.xss[0]);
    } else {
      addTerminalLine('[INFO] No simple reflected input found in standard parameters.', 'tw-muted');
    }

    doneMods++;
    updateProgress(progressFill, Math.round((doneMods / totalModules) * 100));
    await sleep(300);
  }

  // ── SCAN COMPLETE ──
  const scanDuration = ((Date.now() - scanState.startTime) / 1000).toFixed(2);
  scanState.scanDuration = scanDuration;

  await sleep(300);
  addTerminalLine('', '');
  addTerminalLine('══════════════════════════════════════════', 'tw-muted');
  addTerminalLine(`[DONE] Scan completed in ${scanDuration}s — ${scanState.findings.length} finding(s) identified.`, scanState.findings.length > 0 ? 'tw-line-vuln' : 'tw-ok');
  addTerminalLine('[*] Generating report data…', 'tw-muted');
  await sleep(300);

  // Render results
  renderResults();

  // Reset button
  btn.textContent = 'AUDIT';
  btn.disabled = false;
  scanState.isScanning = false;
}

// ─── ERROR DISPLAY ────────────────────────────────────────

function showScanError(msg) {
  let errorDiv = document.querySelector('.scan-error');
  if (!errorDiv) {
    errorDiv = document.createElement('div');
    errorDiv.className = 'scan-error';
    const probe = document.getElementById('scan-probe');
    probe.after(errorDiv);
  }
  errorDiv.textContent = '✕ ' + msg;
  errorDiv.classList.add('show');
}

// ─── RESULTS RENDERING ────────────────────────────────────

function renderResults() {
  const section = document.getElementById('results-section');
  section.style.display = 'block';
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Meta header
  const meta = document.getElementById('results-meta');
  meta.innerHTML = `
    <div>TARGET &nbsp; <strong>${escapeHtml(scanState.target)}</strong></div>
    <div>DOMAIN &nbsp; <strong>${new URL(scanState.target).hostname}</strong></div>
    <div>DURATION &nbsp; <strong>${scanState.scanDuration}s</strong></div>
    <div>FINDINGS &nbsp; <strong>${scanState.findings.length}</strong></div>
  `;

  // Risk meter
  const risk = computeRisk(scanState.findings);
  const riskVal = document.getElementById('risk-score-val');
  const riskFill = document.getElementById('risk-bar-fill');
  riskVal.textContent = risk.label;
  riskVal.style.color = risk.color;
  riskFill.style.background = risk.color;
  setTimeout(() => {
    riskFill.style.width = risk.pct + '%';
  }, 100);

  // Severity strip
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  scanState.findings.forEach((f) => {
    if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
  });

  const strip = document.getElementById('sev-strip');
  strip.innerHTML = Object.entries(sevCounts)
    .map(
      ([sev, count]) => `
      <div class="sev-block sev-${sev.toLowerCase()}">
        <div class="sev-block-count">${count}</div>
        <div>${sev.toUpperCase()}</div>
      </div>`
    )
    .join('');

  // Findings — sorted by severity descending
  const sorted = [...scanState.findings].sort(
    (a, b) => getSeverityRank(b.severity) - getSeverityRank(a.severity)
  );

  renderFindings(sorted);
  scanState.currentFilter = 'all';
  setActiveFilter('all');

  // Show/hide clean state
  const cleanState = document.getElementById('clean-state');
  cleanState.style.display = scanState.findings.length === 0 ? 'block' : 'none';
}

function renderFindings(findings) {
  const grid = document.getElementById('findings-grid');
  grid.innerHTML = '';

  if (findings.length === 0 && scanState.currentFilter !== 'all') {
    grid.innerHTML = `<div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); padding: 2rem; text-align: center;">No ${scanState.currentFilter} severity findings.</div>`;
    return;
  }

  findings.forEach((f, idx) => {
    const sevClass = `sev-${f.severity.toLowerCase()}-item`;
    const item = document.createElement('div');
    item.className = `finding-item ${sevClass}`;
    item.dataset.severity = f.severity;

    item.innerHTML = `
      <div class="finding-summary" onclick="toggleFinding(this)" role="button" tabindex="0" aria-expanded="false" id="finding-summary-${idx}">
        <span class="sev-pill ${f.severity}">${f.severity}</span>
        <span class="finding-cvss">${f.cvss}</span>
        <span class="finding-title-text">${escapeHtml(f.title)}</span>
        <span class="finding-type-text">${escapeHtml(f.type)}</span>
      </div>
      <div class="finding-detail" id="finding-detail-${idx}">
        <div class="detail-section">
          <div class="detail-section-label">Technical Observation</div>
          <div class="detail-section-body">${escapeHtml(f.detail)}</div>
        </div>
        <div class="detail-section">
          <div class="detail-section-label">Recommended Remediation</div>
          <div class="detail-section-body remediation">${escapeHtml(f.remediation)}</div>
        </div>
      </div>
    `;

    // Keyboard accessibility
    const summary = item.querySelector('.finding-summary');
    summary.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleFinding(summary);
      }
    });

    grid.appendChild(item);
  });
}

function toggleFinding(summaryEl) {
  const detail = summaryEl.nextElementSibling;
  const isOpen = detail.classList.contains('open');
  // Close all others
  document.querySelectorAll('.finding-detail.open').forEach((d) => d.classList.remove('open'));
  document.querySelectorAll('.finding-summary[aria-expanded="true"]').forEach((s) => s.setAttribute('aria-expanded', 'false'));
  if (!isOpen) {
    detail.classList.add('open');
    summaryEl.setAttribute('aria-expanded', 'true');
  }
}

// ─── FILTER ───────────────────────────────────────────────

function applyFilter(severity) {
  scanState.currentFilter = severity;
  setActiveFilter(severity);
  const filtered =
    severity === 'all'
      ? [...scanState.findings].sort((a, b) => getSeverityRank(b.severity) - getSeverityRank(a.severity))
      : scanState.findings.filter((f) => f.severity === severity);
  renderFindings(filtered);
  const cleanState = document.getElementById('clean-state');
  cleanState.style.display = scanState.findings.length === 0 ? 'block' : 'none';
}

function setActiveFilter(severity) {
  document.querySelectorAll('.filter-btn').forEach((btn) => btn.classList.remove('active'));
  const active = document.getElementById(`filter-${severity}`);
  if (active) active.classList.add('active');
}

// ─── EXPORT ───────────────────────────────────────────────

function exportJSON() {
  const report = {
    target: scanState.target,
    scan_timestamp: new Date(scanState.startTime).toISOString(),
    total_findings: scanState.findings.length,
    scan_duration_seconds: parseFloat(scanState.scanDuration),
    findings: scanState.findings,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const hostname = new URL(scanState.target).hostname.replace(/\./g, '_');
  a.download = `secscan_${hostname}_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function copyReport() {
  const lines = [
    `SecScan Security Assessment Report`,
    `Target: ${scanState.target}`,
    `Scan Date: ${new Date(scanState.startTime).toISOString()}`,
    `Findings: ${scanState.findings.length}`,
    ``,
    ...scanState.findings.map(
      (f, i) =>
        `[${i + 1}] ${f.severity} (CVSS ${f.cvss}) — ${f.title}\n    Type: ${f.type}\n    Detail: ${f.detail}\n    Fix: ${f.remediation}`
    ),
    ``,
    `Generated by SecScan Enterprise Engine v3.5`,
  ];
  navigator.clipboard
    .writeText(lines.join('\n'))
    .then(() => {
      const btn = document.getElementById('copy-report-btn');
      const original = btn.textContent;
      btn.textContent = '✓ Copied';
      setTimeout(() => (btn.textContent = original), 2000);
    })
    .catch(() => alert('Copy failed. Please select and copy the report manually.'));
}

// ─── RESET ────────────────────────────────────────────────

function resetScan() {
  document.getElementById('results-section').style.display = 'none';
  document.getElementById('target-url').value = '';
  document.getElementById('tw-title').textContent = 'secscan@engine ~ ';

  // Reset terminal
  const output = document.getElementById('terminal-output');
  output.innerHTML = `
    <div class="tw-line tw-muted">SecScan Enterprise Engine v3.5</div>
    <div class="tw-line tw-muted">──────────────────────────────────</div>
    <div class="tw-line tw-dim">Enter a target URL and press AUDIT to begin</div>
    <div class="tw-line tw-dim">All five scan modules will run concurrently</div>
    <div class="tw-line">&nbsp;</div>
    <div class="tw-line tw-muted">Modules available:</div>
    <div class="tw-line tw-ok">  ✓ SSL/TLS Certificate Inspection</div>
    <div class="tw-line tw-ok">  ✓ HTTP Security Header Audit</div>
    <div class="tw-line tw-ok">  ✓ CORS Misconfiguration Detection</div>
    <div class="tw-line tw-ok">  ✓ Sensitive Endpoint Discovery</div>
    <div class="tw-line tw-ok">  ✓ Reflected XSS Detection</div>
    <div class="tw-line">&nbsp;</div>
    <div class="tw-cursor-line"><span class="tw-prompt">$</span> <span class="tw-cursor">█</span></div>
  `;

  scanState = {
    isScanning: false,
    findings: [],
    target: '',
    scanDuration: 0,
    startTime: null,
    currentFilter: 'all',
  };

  const error = document.querySelector('.scan-error');
  if (error) error.classList.remove('show');

  // Scroll to top of scanner
  document.getElementById('try-it').scrollIntoView({ behavior: 'smooth' });
  document.getElementById('target-url').focus();
}

// ─── UTILITIES ────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── KEYBOARD SHORTCUTS ───────────────────────────────────

document.addEventListener('keydown', (e) => {
  // Enter on the URL input triggers scan
  if (e.key === 'Enter' && document.activeElement === document.getElementById('target-url')) {
    runScan();
  }
  // Escape — close all expanded findings
  if (e.key === 'Escape') {
    document.querySelectorAll('.finding-detail.open').forEach((d) => d.classList.remove('open'));
  }
});

// ─── SMOOTH NAV ───────────────────────────────────────────

document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener('click', (e) => {
    const target = document.querySelector(anchor.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ─── MOBILE NAV TOGGLE ───────────────────────────────────

const mobileBtn = document.getElementById('nav-mobile-btn');
if (mobileBtn) {
  mobileBtn.addEventListener('click', () => {
    const nav = document.querySelector('.header-nav');
    if (nav) {
      const isOpen = nav.style.display === 'flex';
      nav.style.display = isOpen ? '' : 'flex';
      nav.style.flexDirection = isOpen ? '' : 'column';
      nav.style.position = isOpen ? '' : 'absolute';
      nav.style.top = isOpen ? '' : '54px';
      nav.style.right = isOpen ? '' : '0';
      nav.style.background = isOpen ? '' : 'var(--bg-surface)';
      nav.style.border = isOpen ? '' : '1px solid var(--bg-border)';
      nav.style.padding = isOpen ? '' : '1rem';
      nav.style.zIndex = isOpen ? '' : '200';
      nav.style.minWidth = isOpen ? '' : '180px';
    }
  });
}

// ─── INTERSECTION OBSERVER — Animate mech steps on scroll ──

const mechSteps = document.querySelectorAll('.mech-step');
const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateX(0)';
      }
    });
  },
  { threshold: 0.15 }
);

mechSteps.forEach((step, i) => {
  step.style.opacity = '0';
  step.style.transform = 'translateX(-16px)';
  step.style.transition = `opacity 0.4s ease ${i * 60}ms, transform 0.4s ease ${i * 60}ms`;
  observer.observe(step);
});
