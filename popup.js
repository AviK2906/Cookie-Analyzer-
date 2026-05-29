// ─── Known Trackers (mirrored from background for display purposes) ─────────────
const KNOWN_TRACKERS = new Set([
  "_ga","_gid","_gat","__utma","__utmb","__utmc","__utmz",
  "_fbp","_fbc","fr","xs","datr","sb","c_user",
  "_gcl_au","_gcl_aw","IDE","DSID","test_cookie",
  "_ttp","tt_webid","ttwid","mbox","s_cc","s_sq","s_vi",
  "ajs_user_id","ajs_anonymous_id","amplitude_id",
  "intercom-id","intercom-session"
]);

const TRACKER_DOMAINS = [
  "doubleclick.net","googleadservices.com","googlesyndication.com",
  "facebook.com","fbcdn.net","hotjar.com","fullstory.com",
  "mixpanel.com","segment.io","amplitude.com","intercom.io",
  "tiktok.com","ads-twitter.com"
];

const RISK_COLORS = {
  critical: "#e24b4a",
  high:     "#ef9f27",
  medium:   "#378add",
  low:      "#1d9e75"
};

// ─── Scoring (mirrors background.js) ──────────────────────────────────────────
function scoreCookie(cookie) {
  let score = 0;
  const flags = [];
  if (!cookie.secure)   { score += 25; flags.push("Missing Secure flag"); }
  if (!cookie.httpOnly) { score += 20; flags.push("Missing HttpOnly flag"); }
  if (!cookie.sameSite || cookie.sameSite === "no_restriction") {
    score += 20; flags.push("Weak SameSite (CSRF risk)");
  }
  if (!cookie.expirationDate) { score += 10; flags.push("Session cookie (no expiry)"); }
  const isTracker = KNOWN_TRACKERS.has(cookie.name) ||
    TRACKER_DOMAINS.some(d => cookie.domain.includes(d));
  if (isTracker) { score += 15; flags.push("Known tracking cookie"); }
  if (cookie.domain.startsWith(".")) { score += 10; flags.push("Broad domain scope"); }
  return { score: Math.min(score, 100), flags, isTracker };
}

function getRiskLevel(score) {
  if (score >= 60) return "critical";
  if (score >= 40) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function computeThreatScore(cookieAvg, headerScore) {
  if (cookieAvg === null && headerScore === null) return 0;
  if (cookieAvg === null) return headerScore;
  if (headerScore === null) return cookieAvg;
  return Math.round(cookieAvg * 0.5 + headerScore * 0.5);
}

// ─── Gauge Canvas ─────────────────────────────────────────────────────────────
function drawGauge(canvas, score, level) {
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cx = W / 2, cy = H - 10;
  const r = 72, lineW = 14;

  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, 0, false);
  ctx.strokeStyle = "rgba(255,255,255,0.07)";
  ctx.lineWidth = lineW;
  ctx.lineCap = "round";
  ctx.stroke();

  const fraction = score / 100;
  const arcEnd = Math.PI + fraction * Math.PI;
  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, arcEnd, false);
  ctx.strokeStyle = RISK_COLORS[level] || "#888";
  ctx.lineWidth = lineW;
  ctx.lineCap = "round";
  ctx.stroke();

  for (let i = 0; i <= 10; i++) {
    const angle = Math.PI + (i / 10) * Math.PI;
    const inner = r - 20, outer = r - 26;
    ctx.beginPath();
    ctx.moveTo(cx + inner * Math.cos(angle), cy + inner * Math.sin(angle));
    ctx.lineTo(cx + outer * Math.cos(angle), cy + outer * Math.sin(angle));
    ctx.strokeStyle = "rgba(255,255,255,0.12)";
    ctx.lineWidth = 1.5;
    ctx.lineCap = "butt";
    ctx.stroke();
  }
}

function animateScore(canvas, targetScore, level) {
  let current = 0;
  const scoreEl = document.getElementById("gauge-score");
  scoreEl.style.color = RISK_COLORS[level];
  const step = () => {
    current = Math.min(current + 2, targetScore);
    drawGauge(canvas, current, level);
    scoreEl.textContent = current;
    if (current < targetScore) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});

// ─── Alert Filter ─────────────────────────────────────────────────────────────
let currentFilter = "all";
let cachedAlerts = [];

document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    currentFilter = btn.dataset.filter;
    renderAlerts(cachedAlerts);
  });
});

// ─── Overview ─────────────────────────────────────────────────────────────────
function renderOverview(domain, cookies, headerSummary, patternAlerts) {
  const scoredList = cookies.map(c => ({ ...c, ...scoreCookie(c) }));
  const risky = scoredList.filter(c => c.flags.length > 0);
  const trackers = scoredList.filter(c => c.isTracker);

  const cookieAvg = scoredList.length
    ? Math.round(scoredList.reduce((s, c) => s + c.score, 0) / scoredList.length)
    : null;
  const headerScore = headerSummary ? headerSummary.score : null;
  const threatScore = computeThreatScore(cookieAvg, headerScore);
  const level = getRiskLevel(threatScore);

  document.getElementById("current-domain").textContent = domain;

  const canvas = document.getElementById("gauge-canvas");
  animateScore(canvas, threatScore, level);

  const badge = document.getElementById("risk-badge");
  badge.className = "risk-badge " + level;
  const labels = { critical: "⚠ Critical Risk", high: "▲ High Risk", medium: "● Medium Risk", low: "✓ Low Risk" };
  badge.textContent = labels[level];

  // Score breakdown pills
  document.getElementById("breakdown-cookies").textContent = cookieAvg !== null ? cookieAvg : "—";
  document.getElementById("breakdown-headers").textContent = headerScore !== null ? headerScore : "—";

  document.getElementById("stat-total").textContent = cookies.length;
  document.getElementById("stat-risky").textContent = risky.length;
  document.getElementById("stat-trackers").textContent = trackers.length;

  // ── Attack Patterns ──────────────────────────────────────────────────────
  const patternsSection = document.getElementById("patterns-section");
  const patternList = document.getElementById("pattern-list");

  // patternAlerts = alerts of type ATTACK_PATTERN for this domain
  const domainPatterns = (patternAlerts || []).filter(a =>
    a.type === "ATTACK_PATTERN" && a.domain === domain
  );

  if (domainPatterns.length > 0) {
    patternsSection.style.display = "block";
    patternList.innerHTML = domainPatterns.map(p => `
      <div class="pattern-item ${p.level}">
        <div class="pattern-name">
          ${escHtml(p.pattern)}
          <span class="pattern-attack-tag ${p.level}">${escHtml(p.level.toUpperCase())}</span>
        </div>
        <div class="pattern-detail">${escHtml(p.detail)}</div>
        ${p.affectedCookies && p.affectedCookies.length > 0
          ? `<div style="font-size:10px;color:var(--muted);margin-top:4px">
              Affected: ${p.affectedCookies.map(c => `<code style="color:var(--text)">${escHtml(c)}</code>`).join(", ")}
             </div>`
          : ""}
      </div>
    `).join("");
  } else {
    patternsSection.style.display = "none";
  }

  // ── Cookie Flags ──────────────────────────────────────────────────────────
  const flagMap = {};
  scoredList.forEach(c => {
    c.flags.forEach(f => {
      if (!flagMap[f]) flagMap[f] = { count: 0, level: getRiskLevel(c.score) };
      flagMap[f].count++;
    });
  });

  const flagList = document.getElementById("flag-list");
  const entries = Object.entries(flagMap);
  if (entries.length === 0) {
    flagList.innerHTML = `<div class="empty"><div class="empty-icon">✓</div><p>No cookie risks detected.</p></div>`;
  } else {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    entries.sort((a, b) => severityOrder[a[1].level] - severityOrder[b[1].level]);
    flagList.innerHTML = entries.map(([flag, { count, level }]) => `
      <div class="flag-item">
        <div class="flag-dot ${level}"></div>
        <div class="flag-text">${flag}</div>
        <div class="flag-meta">${count} cookie${count > 1 ? "s" : ""}</div>
      </div>
    `).join("");
  }
}

// ─── Cookies Tab ──────────────────────────────────────────────────────────────
function renderCookies(domain, cookies) {
  document.getElementById("cookie-domain-label").textContent = domain;
  const list = document.getElementById("cookie-list");
  if (!cookies.length) {
    list.innerHTML = `<div class="empty"><p>No cookies found for this domain.</p></div>`;
    return;
  }

  const scored = cookies
    .map(c => ({ ...c, ...scoreCookie(c) }))
    .sort((a, b) => b.score - a.score);

  list.innerHTML = scored.map(c => {
    const level = getRiskLevel(c.score);
    const tags = [
      `<span class="tag ${c.secure ? "ok" : "bad"}">Secure: ${c.secure ? "✓" : "✗"}</span>`,
      `<span class="tag ${c.httpOnly ? "ok" : "bad"}">HttpOnly: ${c.httpOnly ? "✓" : "✗"}</span>`,
      `<span class="tag ${c.sameSite && c.sameSite !== "no_restriction" ? "ok" : "bad"}">SameSite: ${c.sameSite || "none"}</span>`,
      c.isTracker ? `<span class="tag tracker">Tracker</span>` : ""
    ].join("");

    const flagSummary = c.flags.length > 0 ? c.flags.join(" · ") : "No issues detected";

    return `
      <div class="cookie-row">
        <div class="cookie-row-top">
          <div class="cookie-name">${escHtml(c.name)}</div>
          <div class="cookie-score-pill ${level}">${c.score}/100</div>
        </div>
        <div class="cookie-flags">${flagSummary}</div>
        <div class="cookie-tags">${tags}</div>
      </div>
    `;
  }).join("");
}

// ─── Headers Tab ──────────────────────────────────────────────────────────────
function renderHeaders(headerSummary) {
  const list = document.getElementById("header-list");
  const scoreVal = document.getElementById("header-score-val");
  const headerBadge = document.getElementById("header-risk-badge");

  if (!headerSummary || !headerSummary.findings) {
    list.innerHTML = `<div class="empty"><div class="empty-icon">🔍</div><p>No header data yet. Navigate to a page and refresh.</p></div>`;
    scoreVal.textContent = "—";
    headerBadge.className = "risk-badge";
    headerBadge.textContent = "—";
    return;
  }

  const { score, level, findings } = headerSummary;

  scoreVal.textContent = score;
  headerBadge.className = "risk-badge " + level;
  const labels = { critical: "⚠ Critical", high: "▲ High", medium: "● Medium", low: "✓ Low" };
  headerBadge.textContent = labels[level];

  // Sort: missing first, weak second, ok last
  const statusOrder = { missing: 0, weak: 1, ok: 2 };
  const sorted = [...findings].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

  list.innerHTML = sorted.map(f => {
    const barColor = f.status === "ok" ? "var(--green)" : f.status === "weak" ? "var(--amber)" : "var(--red)";
    const barWidth = f.status === "ok" ? 100 : Math.round((f.score / 30) * 100);

    return `
      <div class="header-card">
        <div class="header-card-top">
          <div class="header-name">${escHtml(f.header)}</div>
          <div class="header-attack-tag">${escHtml(f.attack)}</div>
          <div class="header-status-pill ${f.status}">${f.status.toUpperCase()}</div>
        </div>
        <div class="header-detail">${escHtml(f.detail)}</div>
        ${f.recommendation
          ? `<div class="header-recommendation">${escHtml(f.recommendation)}</div>`
          : ""}
        <div class="header-score-bar">
          <div class="header-score-bar-fill" style="width:${barWidth}%;background:${barColor}"></div>
        </div>
      </div>
    `;
  }).join("");
}

// ─── Alerts Tab ───────────────────────────────────────────────────────────────
function renderAlerts(alerts) {
  cachedAlerts = alerts;
  const list = document.getElementById("alert-list");
  const countEl = document.getElementById("alert-count");

  const filtered = currentFilter === "all"
    ? alerts
    : alerts.filter(a => a.type === currentFilter);

  if (!filtered.length) {
    list.innerHTML = `<div class="empty"><div class="empty-icon">🔕</div><p>${
      currentFilter === "all" ? "No security events recorded yet." : `No ${currentFilter.replace("_", " ").toLowerCase()} events.`
    }</p></div>`;
    countEl.textContent = alerts.length ? `${alerts.length} total` : "";
    return;
  }

  countEl.textContent = `${filtered.length}${currentFilter !== "all" ? ` / ${alerts.length}` : ""} event${filtered.length !== 1 ? "s" : ""}`;

  const TYPE_LABELS = {
    COOKIE_RISK:      "Cookie Risk",
    JS_COOKIE_ACCESS: "JS Cookie Access",
    SESSION_MUTATION: "Session Mutation",
    HEADER_RISK:      "Header Risk",
    ATTACK_PATTERN:   "Attack Pattern",
    MIXED_CONTENT:    "Mixed Content"
  };

  const recent = [...filtered].reverse().slice(0, 60);
  list.innerHTML = recent.map(a => {
    const level = a.level || "medium";
    const typeLabel = TYPE_LABELS[a.type] || a.type;

    let msg = "";
    if (a.type === "ATTACK_PATTERN") {
      msg = `<b>${escHtml(a.pattern)}</b> — ${escHtml(a.detail || "")}`;
    } else if (a.type === "HEADER_RISK") {
      msg = `<b>${escHtml(a.header)}</b> — ${escHtml((a.risks || []).join(", "))}`;
      if (a.recommendation) {
        msg += `<div style="font-size:10px;color:var(--accent);margin-top:3px;font-family:monospace">${escHtml(a.recommendation)}</div>`;
      }
    } else if (a.type === "MIXED_CONTENT") {
      msg = `HTTP resource on HTTPS page: ${escHtml(a.url || "")}`;
    } else {
      const entity = a.cookie
        ? `<b>${escHtml(a.cookie)}</b> on ${escHtml(a.domain || "")}`
        : escHtml(a.domain || a.url || "");
      const detail = a.message || (a.risks ? a.risks.join(", ") : "");
      msg = `${entity}${detail ? " — " + detail : ""}`;
    }

    const time = a.time ? new Date(a.time).toLocaleTimeString() : "";

    return `
      <div class="alert-item ${level}">
        <div class="alert-type">${typeLabel}</div>
        <div class="alert-msg">${msg}</div>
        <div class="alert-time">${escHtml(a.domain || "")} · ${time}</div>
      </div>
    `;
  }).join("");
}

// ─── Export ───────────────────────────────────────────────────────────────────
document.getElementById("export-btn").addEventListener("click", () => {
  chrome.storage.local.get({ alerts: [], domainSummaries: {}, headerSummaries: {} }, (data) => {
    const report = {
      exportedAt: new Date().toISOString(),
      version: "3.0",
      domainSummaries: data.domainSummaries,
      headerSummaries: data.headerSummaries,
      events: data.alerts
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cookie-security-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
});

// ─── Clear ────────────────────────────────────────────────────────────────────
document.getElementById("clear-btn").addEventListener("click", () => {
  chrome.storage.local.set({ alerts: [], domainSummaries: {}, headerSummaries: {} }, () => {
    renderAlerts([]);
    renderHeaders(null);
  });
});

// ─── Refresh ─────────────────────────────────────────────────────────────────
document.getElementById("refresh-btn").addEventListener("click", loadData);

// ─── Helpers ─────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Init ─────────────────────────────────────────────────────────────────────
function loadData() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) return;

    let domain = "unknown";
    try { domain = new URL(tab.url).hostname; } catch (e) {}

    chrome.cookies.getAll({ domain }, (cookies) => {
      cookies = cookies || [];

      // Fetch header summary from storage
      chrome.storage.local.get({ alerts: [], headerSummaries: {} }, (data) => {
        const headerSummary = data.headerSummaries[domain] || null;
        const patternAlerts = data.alerts.filter(a => a.type === "ATTACK_PATTERN" && a.domain === domain);

        renderOverview(domain, cookies, headerSummary, patternAlerts);
        renderCookies(domain, cookies);
        renderHeaders(headerSummary);
        renderAlerts(data.alerts);
      });
    });
  });
}

loadData();
