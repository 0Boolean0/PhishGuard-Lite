/**
 * PhishGuard Lite — Popup Script
 *
 * 1. Asks the background worker for cached analysis of the active tab.
 * 2. If no cache exists, triggers a fresh scan.
 * 3. Renders the risk score, verdict, and feature breakdown.
 */

// ─── Constants ───────────────────────────────────────────────────────────────

const RING_RADIUS = 45;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;   // ≈ 282.7

const SCORE_COLOR = {
  safe:       "#22c55e",
  suspicious: "#f59e0b",
  phishing:   "#ef4444",
  unknown:    "#6b7280",
};

// Features to display in the grid (key → display label)
const FEATURE_DISPLAY = {
  has_ip:                   "IP Address",
  has_at_symbol:            "@ Symbol",
  suspicious_tld:           "Suspicious TLD",
  https:                    "HTTPS",
  trusted_domain:           "Trusted Domain",
  suspicious_keyword_count: "Phish Keywords",
  subdomain_count:          "Subdomains",
  hyphen_count:             "Hyphens",
  url_length:               "URL Length",
  entropy:                  "Entropy",
};

// ─── Render helpers ───────────────────────────────────────────────────────────

function renderScore(score, verdict) {
  const colour    = SCORE_COLOR[verdict] ?? SCORE_COLOR.unknown;
  const pct       = Math.min(score ?? 0, 100) / 100;
  const dashOffset = RING_CIRCUMFERENCE * (1 - pct);

  return `
    <div class="score-section">
      <div class="ring-wrap">
        <svg width="110" height="110" viewBox="0 0 110 110">
          <circle class="ring-bg"   cx="55" cy="55" r="${RING_RADIUS}" />
          <circle class="ring-fill" cx="55" cy="55" r="${RING_RADIUS}"
            stroke="${colour}"
            stroke-dasharray="${RING_CIRCUMFERENCE}"
            stroke-dashoffset="${dashOffset}"
          />
        </svg>
        <div class="ring-text">
          <span class="ring-score" style="color:${colour}">
            ${score !== null ? Math.round(score) : "?"}
          </span>
          <span class="ring-max">/100</span>
        </div>
      </div>
      <span class="verdict-badge verdict-${verdict}">
        ${verdict === "unknown" ? "Offline" : verdict}
      </span>
    </div>`;
}

function renderFeatureCard(label, value) {
  let displayValue, cls;

  if (typeof value === "boolean") {
    displayValue = value ? "Yes" : "No";
    cls          = value ? "feat-true" : "feat-false";
  } else if (typeof value === "number") {
    displayValue = value;
    cls          = "feat-num";
  } else {
    displayValue = value ?? "—";
    cls          = "feat-num";
  }

  return `
    <div class="feat-card">
      <div class="feat-name">${label}</div>
      <div class="feat-value ${cls}">${displayValue}</div>
    </div>`;
}

function renderFeatures(features) {
  if (!features || !Object.keys(features).length) return "";

  const cards = Object.entries(FEATURE_DISPLAY)
    .map(([key, label]) => renderFeatureCard(label, features[key]))
    .join("");

  return `
    <div class="features-title">Signal Breakdown</div>
    <div class="features-grid">${cards}</div>`;
}

function renderUrl(url) {
  const display = url.length > 60 ? url.slice(0, 57) + "…" : url;
  return `
    <div class="url-card">
      <div class="url-label">Analysed URL</div>
      <div class="url-text">${escapeHtml(display)}</div>
    </div>`;
}

function renderError(message) {
  return `
    <div class="state-box">
      <span style="font-size:28px">⚠️</span>
      <span>${escapeHtml(message)}</span>
    </div>`;
}

function renderUnsupported() {
  return `
    <div class="state-box">
      <span style="font-size:28px">🌐</span>
      <span style="text-align:center">
        Unsupported page.<br>
        Open a standard website (HTTP/HTTPS) to scan.
      </span>
    </div>`;
}

function renderOffline() {
  return `
    <div class="state-box">
      <span style="font-size:28px">🔌</span>
      <span style="text-align:center">
        Backend offline.<br>
        Run <code style="color:#60a5fa">python main.py</code> first.
      </span>
    </div>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Main render ─────────────────────────────────────────────────────────────

function render(data) {
  const app = document.getElementById("app");

  if (!data) {
    app.innerHTML = renderError("No data available for this tab.");
    return;
  }

  if (data.verdict === "unknown") {
    app.innerHTML =
      renderUrl(data.url) +
      renderOffline() +
      `<div class="footer">PhishGuard Lite v1.0</div>`;
    return;
  }

  app.innerHTML =
    renderUrl(data.url) +
    renderScore(data.risk_score, data.verdict) +
    renderFeatures(data.features) +
    `<div class="footer">PhishGuard Lite v1.0 · Local heuristic engine</div>`;
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

(async () => {
  try {
    // Get the active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) {
      document.getElementById("app").innerHTML =
        renderError("Could not determine the active tab.");
      return;
    }

    if (!tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) {
      document.getElementById("app").innerHTML = renderUnsupported();
      return;
    }

    // Ask the background worker for results
    chrome.runtime.sendMessage({ type: "GET_RESULT", tabId: tab.id }, (response) => {
      if (chrome.runtime.lastError) {
        document.getElementById("app").innerHTML =
          renderError("Extension error: " + chrome.runtime.lastError.message);
        return;
      }

      if (response?.status === "ok") {
        render(response.data);
      } else {
        document.getElementById("app").innerHTML =
          renderError(response?.message ?? "Unknown error.");
      }
    });

  } catch (err) {
    document.getElementById("app").innerHTML = renderError(err.message);
  }
})();
