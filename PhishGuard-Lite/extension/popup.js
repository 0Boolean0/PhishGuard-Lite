/**
 * PhishGuard Lite — Popup Script
 *
 * 1. Fetches analysis for active tab (standard web page or Data URI).
 * 2. Displays the risk score ring, verdict badge, and warnings.
 * 3. Highlights detected threat signals and breaks down all 16 criteria.
 */

// ─── Constants ───────────────────────────────────────────────────────────────

const RING_RADIUS = 40;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;   // ≈ 251.3

const SCORE_COLOR = {
  safe:       "#22c55e",
  suspicious: "#f59e0b",
  phishing:   "#ef4444",
  unknown:    "#6b7280",
};

// All 16 criteria mapping
const FEATURE_DISPLAY = {
  is_typosquat:         "Brand Impersonation",
  deceptive_subdomain:  "Subdomain Spoof",
  has_homograph:        "Homograph / IDN",
  has_ip:               "IP in Hostname",
  has_at_symbol:        "@ Symbol",
  non_standard_port:    "Non-Standard Port",
  has_open_redirect:    "Open Redirect",
  is_url_shortener:     "URL Shortener",
  has_data_uri:         "Data URI Execution",
  keyword_stacking:     "Keyword Stacking",
  suspicious_tld:       "Suspicious TLD",
  excessive_subdomains: "Excessive Subdomains",
  excessive_hyphens:    "Excessive Hyphens",
  abnormal_url_length:  "Abnormal Length",
  high_entropy:         "High Entropy",
  https:                "HTTPS Encryption",
  trusted_domain:       "Trusted Domain",
};

// Positive signals where "Yes" is GOOD (safe) and "No" is bad/warning
const POSITIVE_SIGNALS = new Set(["https", "trusted_domain"]);

// ─── Render helpers ───────────────────────────────────────────────────────────

function renderScore(score, verdict) {
  const colour     = SCORE_COLOR[verdict] ?? SCORE_COLOR.unknown;
  const pct        = Math.min(score ?? 0, 100) / 100;
  const dashOffset = RING_CIRCUMFERENCE * (1 - pct);

  return `
    <div class="score-section">
      <div class="ring-wrap">
        <svg width="100" height="100" viewBox="0 0 100 100">
          <circle class="ring-bg"   cx="50" cy="50" r="${RING_RADIUS}" />
          <circle class="ring-fill" cx="50" cy="50" r="${RING_RADIUS}"
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

function renderWarning(warning) {
  if (!warning) return "";
  return `
    <div class="warning-alert">
      <span class="warning-icon">🚨</span>
      <span>${escapeHtml(warning)}</span>
    </div>`;
}

function renderSignals(signals) {
  if (!signals || !signals.length) return "";
  const pills = signals
    .map((s) => `<span class="signal-pill">⚠️ ${escapeHtml(s)}</span>`)
    .join("");
  return `
    <div class="features-title" style="margin-bottom:4px;color:#f87171">Active Threat Signals</div>
    <div class="signals-box">${pills}</div>`;
}

function renderFeatureCard(key, label, value, allFeatures) {
  let displayValue, cls;

  if (key === "is_typosquat") {
    if (value) {
      displayValue = allFeatures?.spoofed_brand ? `Yes (${allFeatures.spoofed_brand})` : "Yes";
      cls = "feat-danger";
    } else {
      displayValue = "No";
      cls = "feat-safe";
    }
  } else if (key === "non_standard_port") {
    if (value) {
      displayValue = allFeatures?.port ? `Yes (:${allFeatures.port})` : "Yes";
      cls = "feat-danger";
    } else {
      displayValue = "No";
      cls = "feat-safe";
    }
  } else if (key === "suspicious_tld") {
    if (value) {
      displayValue = allFeatures?.tld ? `Yes (${allFeatures.tld})` : "Yes";
      cls = "feat-danger";
    } else {
      displayValue = "No";
      cls = "feat-safe";
    }
  } else if (typeof value === "boolean") {
    displayValue = value ? "Yes" : "No";
    if (POSITIVE_SIGNALS.has(key)) {
      cls = value ? "feat-safe" : "feat-danger";
    } else {
      cls = value ? "feat-danger" : "feat-safe";
    }
  } else if (typeof value === "number") {
    displayValue = value;
    cls = "feat-num";
  } else {
    displayValue = value ?? "—";
    cls = "feat-num";
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
    .map(([key, label]) => renderFeatureCard(key, label, features[key], features))
    .join("");

  return `
    <div class="features-title">16-Criteria Breakdown</div>
    <div class="features-grid">${cards}</div>`;
}

function renderUrl(url) {
  let display = url;
  if (url.startsWith("data:")) {
    display = url.slice(0, 45) + "… [Encoded Data URI]";
  } else if (url.length > 55) {
    display = url.slice(0, 52) + "…";
  }
  return `
    <div class="url-card">
      <div class="url-label">Analysed URL</div>
      <div class="url-text">${escapeHtml(display)}</div>
    </div>`;
}

function renderError(message) {
  return `
    <div class="state-box">
      <span style="font-size:26px">⚠️</span>
      <span>${escapeHtml(message)}</span>
    </div>`;
}

function renderUnsupported() {
  return `
    <div class="state-box">
      <span style="font-size:26px">🌐</span>
      <span>
        Unsupported internal page.<br>
        Navigate to a web page or URL to scan.
      </span>
    </div>`;
}

function renderOffline(url) {
  return `
    <div class="state-box">
      <span style="font-size:26px">🔌</span>
      <span>
        FastAPI backend offline.<br>
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
    app.innerHTML = renderError("No analysis data available for this tab.");
    return;
  }

  if (data.verdict === "unknown") {
    app.innerHTML =
      renderUrl(data.url) +
      renderOffline(data.url) +
      `<div class="footer">PhishGuard Lite v2.0 · 16 Threat Criteria</div>`;
    return;
  }

  app.innerHTML =
    renderUrl(data.url) +
    renderScore(data.risk_score, data.verdict) +
    renderWarning(data.warning) +
    renderSignals(data.signals) +
    renderFeatures(data.features) +
    `<div class="footer">PhishGuard Lite v2.0 · 16 Threat Criteria Engine</div>`;
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

(async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) {
      document.getElementById("app").innerHTML =
        renderError("Could not determine the active tab.");
      return;
    }

    const url = tab.url || "";
    const isAnalyzable =
      url.startsWith("http://") || url.startsWith("https://") || url.startsWith("data:");

    if (!isAnalyzable) {
      document.getElementById("app").innerHTML = renderUnsupported();
      return;
    }

    chrome.runtime.sendMessage({ type: "GET_RESULT", tabId: tab.id }, (response) => {
      if (chrome.runtime.lastError) {
        document.getElementById("app").innerHTML =
          renderError("Extension communication error: " + chrome.runtime.lastError.message);
        return;
      }

      if (response?.status === "ok") {
        render(response.data);
      } else {
        document.getElementById("app").innerHTML =
          renderError(response?.message ?? "Unknown analysis error.");
      }
    });

  } catch (err) {
    document.getElementById("app").innerHTML = renderError(err.message);
  }
})();
