document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const titleEl = document.getElementById("status-title");
  const urlEl = document.getElementById("site-url");
  const confEl = document.getElementById("confidence");
  const cardEl = document.getElementById("status-card");

  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    titleEl.innerText = "Unsupported Page";
    urlEl.innerText = "Navigate to a standard web page.";
    return;
  }

  urlEl.innerText = tab.url;

  try {
    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await response.json();

    if (data.is_phishing) {
      cardEl.className = "card danger";
      titleEl.innerText = "⚠️ Phishing Warning!";
      confEl.innerText = `Confidence: ${data.confidence}%`;
    } else {
      cardEl.className = "card safe";
      titleEl.innerText = "✅ Safe Website";
      confEl.innerText = `Confidence: ${data.confidence}%`;
    }
  } catch (err) {
    titleEl.innerText = "Server Error";
    confEl.innerText = "Start the FastAPI backend server.";
  }
});