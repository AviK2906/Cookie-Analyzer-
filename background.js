// ─── Known Tracker Fingerprints ───────────────────────────────────────────────
const KNOWN_TRACKERS = new Set([
  "_ga", "_gid", "_gat", "_gat_UA", "__utma", "__utmb", "__utmc", "__utmz",
  "_fbp", "_fbc", "fr", "xs", "datr", "sb", "c_user",
  "_gcl_au", "_gcl_aw", "IDE", "DSID", "test_cookie",
  "_ttp", "tt_webid", "ttwid",
  "__Secure-3PAPISID", "__Secure-3PSID", "SAPISID", "SSID",
  "mbox", "s_cc", "s_sq", "s_vi",
  "ajs_user_id", "ajs_anonymous_id", "amplitude_id",
  "intercom-id", "intercom-session"
]);

const TRACKER_DOMAINS = [
  "doubleclick.net", "googleadservices.com", "googlesyndication.com",
  "facebook.com", "fbcdn.net", "connect.facebook.net",
  "scorecardresearch.com", "quantserve.com", "chartbeat.com",
  "hotjar.com", "fullstory.com", "mouseflow.com",
  "mixpanel.com", "segment.io", "amplitude.com",
  "intercom.io", "crisp.chat", "tiktok.com", "ads-twitter.com"
];

// ─── Session Mutation Tracking ─────────────────────────────────────────────────
const cookieSnapshots = {}; // domain -> { cookieName -> value }

// ─── In-memory header store (domain -> latest scored headers) ─────────────────
const headerStore = {}; // domain -> { score, level, findings[], raw{} }

// ─── Mixed Content Tracker ────────────────────────────────────────────────────
const mixedContentTracker = {}; // domain -> count

// ─── Risk Scoring Engine ───────────────────────────────────────────────────────
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

// ─── Security Header Scoring ───────────────────────────────────────────────────
//
// Each header check returns: { name, status, score, severity, detail, attack }
//   status  : "missing" | "weak" | "ok"
//   score   : risk points added (0 = safe)
//   severity: "critical" | "high" | "medium" | "low"
//   attack  : which attack this defends against

function scoreHeaders(responseHeaders, url) {
  const h = {};
  responseHeaders.forEach(({ name, value }) => {
    h[name.toLowerCase()] = value;
  });

  const findings = [];
  let totalScore = 0;

  // ── 1. Content-Security-Policy ─────────────────────────────────────────────
  const csp = h["content-security-policy"];
  if (!csp) {
    findings.push({
      header: "Content-Security-Policy",
      status: "missing",
      score: 30,
      severity: "critical",
      detail: "No CSP defined. Inline scripts and arbitrary external sources are allowed.",
      attack: "XSS",
      recommendation: "Add a strict CSP: default-src 'self'; script-src 'self'; object-src 'none';"
    });
    totalScore += 30;
  } else {
    const weaknesses = [];
    if (csp.includes("unsafe-inline")) {
      weaknesses.push("'unsafe-inline' allows inline script execution (XSS)");
    }
    if (csp.includes("unsafe-eval")) {
      weaknesses.push("'unsafe-eval' allows eval() calls (XSS)");
    }
    if (csp.includes("*")) {
      weaknesses.push("Wildcard (*) source allows any origin");
    }
    if (!csp.includes("default-src") && !csp.includes("script-src")) {
      weaknesses.push("No script-src or default-src directive");
    }
    if (weaknesses.length > 0) {
      const pts = weaknesses.length >= 2 ? 20 : 10;
      findings.push({
        header: "Content-Security-Policy",
        status: "weak",
        score: pts,
        severity: weaknesses.length >= 2 ? "high" : "medium",
        detail: weaknesses.join("; "),
        attack: "XSS",
        recommendation: "Remove unsafe-inline/unsafe-eval. Use nonces or hashes instead."
      });
      totalScore += pts;
    } else {
      findings.push({
        header: "Content-Security-Policy",
        status: "ok",
        score: 0,
        severity: "low",
        detail: "CSP is present and reasonably strict.",
        attack: "XSS",
        recommendation: null
      });
    }
  }

  // ── 2. X-Frame-Options (Clickjacking) ─────────────────────────────────────
  const xfo = h["x-frame-options"];
  const cspFrameAncestors = csp && csp.toLowerCase().includes("frame-ancestors");
  if (!xfo && !cspFrameAncestors) {
    findings.push({
      header: "X-Frame-Options",
      status: "missing",
      score: 25,
      severity: "high",
      detail: "Page can be embedded in iframes on any origin — vulnerable to clickjacking.",
      attack: "Clickjacking",
      recommendation: "Add: X-Frame-Options: DENY  or use CSP frame-ancestors 'none';"
    });
    totalScore += 25;
  } else if (xfo && xfo.toUpperCase() === "ALLOWALL") {
    findings.push({
      header: "X-Frame-Options",
      status: "weak",
      score: 20,
      severity: "high",
      detail: "ALLOWALL permits framing from any origin.",
      attack: "Clickjacking",
      recommendation: "Change to DENY or SAMEORIGIN."
    });
    totalScore += 20;
  } else {
    findings.push({
      header: "X-Frame-Options",
      status: "ok",
      score: 0,
      severity: "low",
      detail: xfo ? `X-Frame-Options: ${xfo}` : "Protected via CSP frame-ancestors.",
      attack: "Clickjacking",
      recommendation: null
    });
  }

  // ── 3. Strict-Transport-Security (HSTS / MITM) ────────────────────────────
  const hsts = h["strict-transport-security"];
  const isHttps = url && url.startsWith("https://");
  if (!hsts && isHttps) {
    findings.push({
      header: "Strict-Transport-Security",
      status: "missing",
      score: 20,
      severity: "high",
      detail: "No HSTS. Browsers may silently downgrade to HTTP, enabling MITM attacks.",
      attack: "MITM / SSL Stripping",
      recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    });
    totalScore += 20;
  } else if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    if (maxAge < 2592000) { // less than 30 days
      findings.push({
        header: "Strict-Transport-Security",
        status: "weak",
        score: 10,
        severity: "medium",
        detail: `HSTS max-age is only ${maxAge}s (< 30 days). Too short to be effective.`,
        attack: "MITM / SSL Stripping",
        recommendation: "Set max-age to at least 31536000 (1 year) with includeSubDomains."
      });
      totalScore += 10;
    } else {
      findings.push({
        header: "Strict-Transport-Security",
        status: "ok",
        score: 0,
        severity: "low",
        detail: `HSTS max-age: ${maxAge}s${hsts.includes("includeSubDomains") ? ", includeSubDomains" : ""}`,
        attack: "MITM / SSL Stripping",
        recommendation: null
      });
    }
  }

  // ── 4. X-Content-Type-Options (MIME sniffing) ─────────────────────────────
  const xcto = h["x-content-type-options"];
  if (!xcto || xcto.toLowerCase() !== "nosniff") {
    findings.push({
      header: "X-Content-Type-Options",
      status: xcto ? "weak" : "missing",
      score: 10,
      severity: "medium",
      detail: "Browser may MIME-sniff responses, allowing scripts disguised as other content types.",
      attack: "MIME Sniffing / XSS",
      recommendation: "Add: X-Content-Type-Options: nosniff"
    });
    totalScore += 10;
  } else {
    findings.push({
      header: "X-Content-Type-Options",
      status: "ok",
      score: 0,
      severity: "low",
      detail: "nosniff is set.",
      attack: "MIME Sniffing / XSS",
      recommendation: null
    });
  }

  // ── 5. Referrer-Policy (Data leakage) ─────────────────────────────────────
  const rp = h["referrer-policy"];
  const weakReferrerPolicies = ["unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"];
  if (!rp) {
    findings.push({
      header: "Referrer-Policy",
      status: "missing",
      score: 8,
      severity: "low",
      detail: "No Referrer-Policy. Full URL may leak in Referer headers to third parties.",
      attack: "Information Leakage",
      recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin"
    });
    totalScore += 8;
  } else if (weakReferrerPolicies.includes(rp.toLowerCase())) {
    findings.push({
      header: "Referrer-Policy",
      status: "weak",
      score: 5,
      severity: "low",
      detail: `Policy "${rp}" can expose full URLs to cross-origin destinations.`,
      attack: "Information Leakage",
      recommendation: "Use strict-origin-when-cross-origin or no-referrer."
    });
    totalScore += 5;
  } else {
    findings.push({
      header: "Referrer-Policy",
      status: "ok",
      score: 0,
      severity: "low",
      detail: `Referrer-Policy: ${rp}`,
      attack: "Information Leakage",
      recommendation: null
    });
  }

  // ── 6. Permissions-Policy (formerly Feature-Policy) ───────────────────────
  const pp = h["permissions-policy"] || h["feature-policy"];
  if (!pp) {
    findings.push({
      header: "Permissions-Policy",
      status: "missing",
      score: 7,
      severity: "low",
      detail: "No Permissions-Policy. Browser features (camera, mic, geolocation) are unrestricted.",
      attack: "Feature Abuse",
      recommendation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    });
    totalScore += 7;
  } else {
    findings.push({
      header: "Permissions-Policy",
      status: "ok",
      score: 0,
      severity: "low",
      detail: "Permissions-Policy is defined.",
      attack: "Feature Abuse",
      recommendation: null
    });
  }

  // ── 7. Mixed Content Detection ─────────────────────────────────────────────
  // (detected separately via webRequest — flagged here if seen for this domain)

  const score = Math.min(totalScore, 100);
  return {
    score,
    level: getRiskLevel(score),
    findings,
    raw: h
  };
}

// ─── Attack Pattern Detection (on top of header + cookie data) ────────────────
function detectAttackPatterns(hostname, headerResult, cookieList) {
  const patterns = [];

  if (!headerResult) return patterns;
  const { findings, raw } = headerResult;

  const cspFinding   = findings.find(f => f.header === "Content-Security-Policy");
  const hstsFinding  = findings.find(f => f.header === "Strict-Transport-Security");
  const xfoFinding   = findings.find(f => f.header === "X-Frame-Options");

  // ── XSS Attack Surface ────────────────────────────────────────────────────
  const noHttpOnlyCookies = cookieList.filter(c => !c.httpOnly);
  const hasWeakCSP = cspFinding && cspFinding.status !== "ok";
  if (hasWeakCSP && noHttpOnlyCookies.length > 0) {
    patterns.push({
      type: "ATTACK_PATTERN",
      pattern: "XSS Cookie Theft Surface",
      severity: "critical",
      score: 90,
      level: "critical",
      domain: hostname,
      detail: `Weak/missing CSP combined with ${noHttpOnlyCookies.length} JS-accessible cookie(s). An XSS attack could exfiltrate session tokens.`,
      affectedCookies: noHttpOnlyCookies.map(c => c.name),
      time: new Date().toISOString()
    });
  }

  // ── CSRF Risk ─────────────────────────────────────────────────────────────
  const csrfCookies = cookieList.filter(c =>
    (!c.sameSite || c.sameSite === "no_restriction") && !c.httpOnly
  );
  if (csrfCookies.length > 0) {
    patterns.push({
      type: "ATTACK_PATTERN",
      pattern: "CSRF Vulnerable Cookies",
      severity: "high",
      score: 75,
      level: "high",
      domain: hostname,
      detail: `${csrfCookies.length} cookie(s) lack SameSite protection and are JS-accessible. Cross-site requests can carry these cookies without user consent.`,
      affectedCookies: csrfCookies.map(c => c.name),
      time: new Date().toISOString()
    });
  }

  // ── Clickjacking ──────────────────────────────────────────────────────────
  if (xfoFinding && xfoFinding.status !== "ok") {
    patterns.push({
      type: "ATTACK_PATTERN",
      pattern: "Clickjacking Exposure",
      severity: "high",
      score: 70,
      level: "high",
      domain: hostname,
      detail: "Page can be embedded in an attacker-controlled iframe. UI redressing attacks can trick users into performing unintended actions.",
      affectedCookies: [],
      time: new Date().toISOString()
    });
  }

  // ── SSL Stripping / MITM ──────────────────────────────────────────────────
  if (hstsFinding && hstsFinding.status !== "ok") {
    const hasSecureCookies = cookieList.some(c => c.secure);
    if (hasSecureCookies) {
      patterns.push({
        type: "ATTACK_PATTERN",
        pattern: "SSL Stripping Risk",
        severity: "high",
        score: 80,
        level: "high",
        domain: hostname,
        detail: "No HSTS + Secure cookies present. An SSL stripping attack can downgrade HTTPS to HTTP, exposing Secure-flagged cookies in plaintext.",
        affectedCookies: cookieList.filter(c => c.secure).map(c => c.name),
        time: new Date().toISOString()
      });
    }
  }

  // ── Mixed Content ─────────────────────────────────────────────────────────
  const mixedCount = mixedContentTracker[hostname] || 0;
  if (mixedCount > 0) {
    patterns.push({
      type: "ATTACK_PATTERN",
      pattern: "Mixed Content Detected",
      severity: "high",
      score: 65,
      level: "high",
      domain: hostname,
      detail: `${mixedCount} HTTP resource(s) loaded on an HTTPS page. Attackers on the network can intercept and tamper with these resources.`,
      affectedCookies: [],
      time: new Date().toISOString()
    });
  }

  // ── Session Fixation Risk ─────────────────────────────────────────────────
  const broadSessionCookies = cookieList.filter(c =>
    !c.expirationDate && c.domain.startsWith(".")
  );
  if (broadSessionCookies.length > 0) {
    patterns.push({
      type: "ATTACK_PATTERN",
      pattern: "Session Fixation Risk",
      severity: "medium",
      score: 55,
      level: "medium",
      domain: hostname,
      detail: `${broadSessionCookies.length} session cookie(s) use broad domain scope. An attacker who can set cookies for a parent domain may fix the session before login.`,
      affectedCookies: broadSessionCookies.map(c => c.name),
      time: new Date().toISOString()
    });
  }

  return patterns;
}

// ─── Unified Threat Surface Score ─────────────────────────────────────────────
// Combines cookie risk + header risk into a single score for the badge/overview
function computeThreatScore(cookieAvg, headerScore) {
  // Weighted: cookies 50%, headers 50%
  // If either is missing, use what's available
  if (cookieAvg === null && headerScore === null) return 0;
  if (cookieAvg === null) return headerScore;
  if (headerScore === null) return cookieAvg;
  return Math.round(cookieAvg * 0.5 + headerScore * 0.5);
}

// ─── Domain Risk Aggregation ───────────────────────────────────────────────────
function aggregateDomainRisk(cookies) {
  if (!cookies.length) return { score: 0, level: "low", cookieCount: 0, trackerCount: 0, flags: [] };

  let totalScore = 0;
  let trackerCount = 0;
  const allFlags = new Set();

  cookies.forEach(c => {
    const { score, flags, isTracker } = scoreCookie(c);
    totalScore += score;
    if (isTracker) trackerCount++;
    flags.forEach(f => allFlags.add(f));
  });

  const avgScore = Math.round(totalScore / cookies.length);
  return {
    score: avgScore,
    level: getRiskLevel(avgScore),
    cookieCount: cookies.length,
    trackerCount,
    flags: [...allFlags]
  };
}

// ─── Cookie Analysis ───────────────────────────────────────────────────────────
function analyzeCookies(url, tabId) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;

    chrome.cookies.getAll({ domain: hostname }, (cookies) => {
      if (!cookies) return;

      // Session mutation detection
      const prev = cookieSnapshots[hostname] || {};
      const curr = {};
      const mutations = [];

      cookies.forEach(c => {
        curr[c.name] = c.value;
        if (prev[c.name] !== undefined && prev[c.name] !== c.value) {
          mutations.push(c.name);
        }
      });

      if (mutations.length > 0) {
        const alert = {
          type: "SESSION_MUTATION",
          domain: hostname,
          cookies: mutations,
          message: `Session token changed mid-visit: ${mutations.join(", ")}`,
          risks: ["Possible session hijacking or token rotation"],
          score: 85,
          level: "critical",
          time: new Date().toISOString()
        };
        storeAlert(alert);
        sendNotification("Session Token Changed!", alert.message);
      }

      cookieSnapshots[hostname] = curr;

      // Per-cookie scoring
      const scoredCookies = cookies.map(c => {
        const { score, flags, isTracker } = scoreCookie(c);
        return {
          type: "COOKIE_RISK",
          cookie: c.name,
          domain: c.domain,
          risks: flags,
          score,
          level: getRiskLevel(score),
          isTracker,
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite || "none",
          session: !c.expirationDate,
          time: new Date().toISOString()
        };
      }).filter(c => c.risks.length > 0);

      const cookieSummary = aggregateDomainRisk(cookies);

      // Attack pattern detection (combines cookie + header data)
      const headerResult = headerStore[hostname] || null;
      const patterns = detectAttackPatterns(hostname, headerResult, cookies);

      // Unified threat score
      const headerScore = headerResult ? headerResult.score : null;
      const threatScore = computeThreatScore(cookieSummary.score, headerScore);
      const threatLevel = getRiskLevel(threatScore);

      chrome.storage.local.get({ alerts: [], domainSummaries: {} }, (data) => {
        const patternAlerts = patterns.filter(p => {
          // Deduplicate: only add if not already stored for this domain+pattern recently
          const key = `${p.domain}:${p.pattern}`;
          const exists = data.alerts.some(a => a.type === "ATTACK_PATTERN" &&
            `${a.domain}:${a.pattern}` === key &&
            (Date.now() - new Date(a.time).getTime()) < 60000 // within last minute
          );
          return !exists;
        });

        const newAlerts = [...data.alerts, ...scoredCookies, ...patternAlerts].slice(-200);
        const summaries = data.domainSummaries;
        summaries[hostname] = {
          ...cookieSummary,
          headerScore,
          headerLevel: headerResult ? headerResult.level : null,
          threatScore,
          threatLevel,
          hostname,
          time: new Date().toISOString()
        };

        chrome.storage.local.set({ alerts: newAlerts, domainSummaries: summaries });

        // Badge shows unified threat score
        updateBadge(tabId, threatLevel, threatScore);

        if (threatLevel === "critical" && !data.domainSummaries[hostname]) {
          sendNotification(
            "High Risk Site Detected",
            `${hostname} threat score: ${threatScore}/100. ${cookieSummary.trackerCount} trackers, ${patterns.length} attack patterns found.`
          );
        }
      });
    });
  } catch (e) {
    // Invalid URL (chrome://, etc.)
  }
}

// ─── Header Interception ───────────────────────────────────────────────────────
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // Only main document responses (not sub-resources)
    if (details.type !== "main_frame") return;

    try {
      const urlObj = new URL(details.url);
      const hostname = urlObj.hostname;

      const result = scoreHeaders(details.responseHeaders, details.url);
      headerStore[hostname] = result;

      // Store header findings as alerts
      const headerAlerts = result.findings
        .filter(f => f.status !== "ok")
        .map(f => ({
          type: "HEADER_RISK",
          header: f.header,
          domain: hostname,
          risks: [f.detail],
          score: f.score,
          severity: f.severity,
          level: getRiskLevel(f.score),
          attack: f.attack,
          recommendation: f.recommendation,
          time: new Date().toISOString()
        }));

      if (headerAlerts.length > 0) {
        chrome.storage.local.get({ alerts: [] }, (data) => {
          // Deduplicate: replace old header alerts for this domain
          const filtered = data.alerts.filter(a =>
            !(a.type === "HEADER_RISK" && a.domain === hostname)
          );
          const newAlerts = [...filtered, ...headerAlerts].slice(-200);
          chrome.storage.local.set({ alerts: newAlerts });
        });
      }

      // Store header summary per domain
      chrome.storage.local.get({ headerSummaries: {} }, (data) => {
        const summaries = data.headerSummaries;
        summaries[hostname] = {
          score: result.score,
          level: result.level,
          findings: result.findings,
          time: new Date().toISOString()
        };
        chrome.storage.local.set({ headerSummaries: summaries });
      });

    } catch (e) { /* skip */ }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ─── Mixed Content Detection ───────────────────────────────────────────────────
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // HTTP resource loaded inside an HTTPS page = mixed content
    if (details.initiator && details.initiator.startsWith("https://") &&
        details.url.startsWith("http://")) {
      try {
        const initiatorHost = new URL(details.initiator).hostname;
        mixedContentTracker[initiatorHost] = (mixedContentTracker[initiatorHost] || 0) + 1;

        storeAlert({
          type: "MIXED_CONTENT",
          domain: initiatorHost,
          url: details.url,
          risks: [`HTTP resource loaded on HTTPS page: ${details.url}`],
          score: 65,
          level: "high",
          time: new Date().toISOString()
        });
      } catch (e) { /* skip */ }
    }
  },
  { urls: ["http://*/*"] }
);

// ─── Badge ─────────────────────────────────────────────────────────────────────
const BADGE_COLORS = {
  critical: "#E24B4A",
  high:     "#EF9F27",
  medium:   "#378ADD",
  low:      "#1D9E75"
};

function updateBadge(tabId, level, score) {
  if (!tabId) return;
  chrome.action.setBadgeText({ text: String(score), tabId });
  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS[level] || "#888", tabId });
}

// ─── Notifications ─────────────────────────────────────────────────────────────
function sendNotification(title, message) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon48.png",
    title,
    message
  });
}

// ─── Store Alert ───────────────────────────────────────────────────────────────
function storeAlert(alert) {
  chrome.storage.local.get({ alerts: [] }, (data) => {
    const alerts = [...data.alerts, alert].slice(-200);
    chrome.storage.local.set({ alerts });
  });
}

// ─── Tab Listeners ─────────────────────────────────────────────────────────────
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (!tab || !tab.url) return;
    analyzeCookies(tab.url, activeInfo.tabId);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyzeCookies(tab.url, tabId);
  }
});

// ─── JS Cookie Access Messages ─────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type === "COOKIE_ACCESS_DETECTED") {
    storeAlert({
      type: "JS_COOKIE_ACCESS",
      domain: sender.tab?.url ? new URL(sender.tab.url).hostname : "unknown",
      url: message.url,
      risks: ["JavaScript accessed document.cookie (XSS vector)"],
      score: 50,
      level: "high",
      time: message.time
    });
  }
});

// ─── Popup Data Request ────────────────────────────────────────────────────────
// Popup can request the header summary for the current domain
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_HEADER_SUMMARY") {
    const result = headerStore[message.domain] || null;
    sendResponse({ headerSummary: result });
    return true;
  }
});
