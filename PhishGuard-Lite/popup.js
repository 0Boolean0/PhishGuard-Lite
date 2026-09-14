document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const titleEl = document.getElementById("status-title");
  const urlEl = document.getElementById("site-url");
  const confEl = document.getElementById("confidence");
  const cardEl = document.getElementById("status-card");

  const url = tab?.url || "";
  const isAnalyzable = url.startsWith("http://") || url.startsWith("https://") || url.startsWith("data:");

  if (!tab || !isAnalyzable) {
    titleEl.innerText = "Unsupported Page";
    urlEl.innerText = "Navigate to a standard web page or URL.";
    return;
  }

  urlEl.innerText = url.startsWith("data:") ? url.slice(0, 50) + "..." : url;

  try {
    const response = await fetch("http://127.0.0.1:8000/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    
    if (!response.ok) {
      throw new Error(`Server status: ${response.status}`);
    }

    const data = await response.json();

    // Check verdict ("phishing", "suspicious", or "safe")
    if (data.verdict === "phishing") {
      cardEl.className = "card danger";
      titleEl.innerText = "⚠️ Phishing Warning!";
      confEl.innerText = `Risk Score: ${data.risk_score}/100`;
    } else if (data.verdict === "suspicious") {
      cardEl.className = "card warning";
      titleEl.innerText = "⚡ Suspicious Website!";
      confEl.innerText = `Risk Score: ${data.risk_score}/100`;
    } else {
      cardEl.className = "card safe";
      titleEl.innerText = "✅ Safe Website";
      confEl.innerText = `Risk Score: ${data.risk_score}/100`;
    }

    if (data.warning) {
      confEl.innerText += `\n${data.warning}`;
    }

    if (data.signals && data.signals.length) {
      confEl.innerText += `\nSignals: ${data.signals.join(", ")}`;
    }
  } catch (err) {
    titleEl.innerText = "Server Error";
    confEl.innerText = "Start the FastAPI backend server (python main.py).";
    console.error(err);
  }
});