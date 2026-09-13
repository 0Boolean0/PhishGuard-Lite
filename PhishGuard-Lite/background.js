chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    try {
      const response = await fetch("http://127.0.0.1:8000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: tab.url })
      });
      const data = await response.json();
      
      if (data.is_phishing) {
        chrome.action.setBadgeText({ text: "!", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#D9534F", tabId: tabId });
      } else {
        chrome.action.setBadgeText({ text: "OK", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#5CB85C", tabId: tabId });
      }
    } catch (err) {
      console.error("API connection error:", err);
    }
  }
});