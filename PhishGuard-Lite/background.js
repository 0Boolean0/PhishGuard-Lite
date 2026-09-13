// PhishGuard-Lite Background Service Worker (MV3)
// For real-time badge updates and full features, load the /extension folder into Chrome.
chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard-Lite extension installed.");
});
