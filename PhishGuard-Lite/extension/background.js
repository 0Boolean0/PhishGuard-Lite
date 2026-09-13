/**
 * PhishGuard Lite — Background Service Worker (MV3)
 *
 * Responsibilities:
 *  - Listen for tab URL changes (navigation committed)
 *  - POST the URL to the local FastAPI backend
 *  - Update the extension badge colour and text with the risk score
 *  - Cache the last result per tab so the popup can read it instantly
 */

const API_URL = "http://127.0.0.1:8000/check";

// In-memory cache: tabId → { url, risk_score, verdict, features }
const tabCache = {};

// Badge colour map
const BADGE_COLORS = {
  safe:       "#22c55e",  // green
  suspicious: "#f59e0b",  // amber
  phishing:   "#ef4444",  // red
  unknown:    "#6b7280",  // grey (API unreachable)
};

// ─── Helpers ────────────────────────────────────────────────────────────────

async function analyseUrl(url, tabId) {
  // Skip internal / empty pages
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")
      || url.startsWith("about:") || url.startsWith("edge://")) {
    clearBadge(tabId);
    return;
  }

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const data = await res.json();
    tabCache[tabId] = data;
    updateBadge(tabId, data);
  } catch (err) {
    console.warn("[PhishGuard] API unreachable:", err.message);
    tabCache[tabId] = { url, risk_score: null, verdict: "unknown", features: {} };
    setBadge(tabId, "?", BADGE_COLORS.unknown);
  }
}

function updateBadge(tabId, data) {
  const score  = Math.round(data.risk_score ?? 0);
  const colour = BADGE_COLORS[data.verdict] ?? BADGE_COLORS.unknown;
  setBadge(tabId, String(score), colour);
}

function setBadge(tabId, text, colour) {
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: colour });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ tabId, text: "" });
}

// ─── Event Listeners ─────────────────────────────────────────────────────────

// Fires when a tab finishes navigating to a new URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyseUrl(tab.url, tabId);
  }
});

// Clean up cache when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabCache[tabId];
});

// Respond to popup requests for cached data
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_RESULT") {
    const cached = tabCache[msg.tabId];
    if (cached) {
      sendResponse({ status: "ok", data: cached });
    } else {
      // No cache yet — trigger a fresh analysis and respond once done
      chrome.tabs.get(msg.tabId, async (tab) => {
        if (chrome.runtime.lastError || !tab?.url) {
          sendResponse({ status: "error", message: "Tab not found" });
          return;
        }
        await analyseUrl(tab.url, msg.tabId);
        sendResponse({ status: "ok", data: tabCache[msg.tabId] ?? null });
      });
    }
    return true; // keep message channel open for async response
  }
});
