# 🛡️ PhishGuard-Lite

**PhishGuard-Lite** is a lightweight, real-time phishing URL detection tool consisting of a **FastAPI backend** heuristic engine and a **Google Chrome Extension (Manifest V3)**.

---

## 📁 Project Structure

```text
PhishGuard-Lite/
├── main.py              # FastAPI backend API & heuristic risk scoring engine
├── requirements.txt     # Python dependencies (fastapi, uvicorn, pydantic)
├── README.md            # Documentation & setup guide
│
├── extension/           # ✨ Primary Chrome Extension (Recommended)
│   ├── manifest.json    # Manifest V3 configuration with icons & service worker
│   ├── background.js    # Service worker: monitors navigation & updates badge in real-time
│   ├── popup.html       # Modern dark-mode UI with SVG risk gauge
│   ├── popup.js         # Popup logic & signal breakdown renderer
│   └── icons/           # Extension toolbar icons (16x16, 48x48, 128x128)
│
├── popup.html           # Minimal starter popup
├── popup.js             # Minimal starter popup script
├── background.js        # Minimal service worker
└── manifest.json        # Minimal manifest
```

---

## 🚀 Getting Started

### 1. Start the Backend API

Make sure you have **Python 3.8+** installed.

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the FastAPI server
python main.py
```

The API will start at **`http://127.0.0.1:8000`**. You can verify it by opening `http://127.0.0.1:8000/` in your browser.

---

### 2. Install the Chrome Extension

1. Open Google Chrome (or any Chromium browser like Edge, Brave, etc.).
2. Navigate to: `chrome://extensions`
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select the **`extension`** folder inside this repository:
   ```text
   d:\New Sem\CS\Project\PhishGuard-Lite\extension
   ```
6. Pin **PhishGuard Lite** to your Chrome toolbar.

---

## 🔍 How Risk Scoring Works

When you navigate to any website, the background worker automatically sends the URL to the `/check` endpoint. The heuristic engine analyzes:

1. **Exact Domain Validation**: Verifies against trusted domains (`google.com`, `paypal.com`, `github.com`, etc.) without false suffix bypasses.
2. **IP Host Detection**: Flags raw IPv4 addresses (`http://192.168.1.1/login`).
3. **Shannon Entropy**: Measures character randomness in the hostname to catch algorithmically generated domains (DGA).
4. **Suspicious Keywords**: Detects credential-harvesting triggers (`login`, `verify`, `account`, `banking`, `prize`, etc.).
5. **Suspicious TLDs**: Flags high-risk top-level domains (`.xyz`, `.top`, `.tk`, `.click`, etc.).
6. **URL Structural Signals**: Evaluates `@` symbol usage, double slashes (`//`), excessive subdomains, and URL length.

### Risk Verdicts:
* **Safe (`0 - 24`)**: Green badge (`22c55e`)
* **Suspicious (`25 - 54`)**: Amber badge (`f59e0b`)
* **Phishing (`55 - 100`)**: Red badge (`ef4444`)

---

## 🧪 Testing Examples

You can test URLs with the backend using Python:

```python
import requests

res = requests.post("http://127.0.0.1:8000/check", json={"url": "https://fakegoogle.com/login"})
print(res.json())
```
