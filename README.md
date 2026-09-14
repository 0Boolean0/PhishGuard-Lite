# 🛡️ PhishGuard-Lite

**PhishGuard-Lite** is a real-time phishing detection system consisting of a **FastAPI backend** heuristic risk engine and a **Google Chrome Extension (Manifest V3)** that actively evaluates **16 threat criteria across 4 categories**.

---

## 📁 Project Structure

```text
PhishGuard-Lite/
├── main.py              # FastAPI backend API & 16-criteria heuristic risk scoring engine
├── test_engine.py       # Automated test suite covering all 16 detection criteria
├── requirements.txt     # Python dependencies (fastapi, uvicorn, pydantic)
├── README.md            # Documentation & setup guide
│
├── extension/           # ✨ Primary Chrome Extension (Recommended)
│   ├── manifest.json    # Manifest V3 configuration with icons & service worker
│   ├── background.js    # Service worker: monitors navigation & updates badge in real-time
│   ├── popup.html       # Modern dark-mode UI with SVG risk gauge & 16-criteria breakdown
│   ├── popup.js         # Popup logic, active threat signals pills, & signal breakdown renderer
│   └── icons/           # Extension toolbar icons (16x16, 48x48, 128x128)
│
├── popup.html           # Starter popup
├── popup.js             # Starter popup script
├── background.js        # Starter service worker
└── manifest.json        # Starter manifest
```

---

## 🔍 Comprehensive 16-Criteria Detection Engine

PhishGuard-Lite checks URLs across **4 key categories**:

### 1. Domain & Hostname Anomaly Criteria
* **IP Address in Hostname**: Detects raw IPv4, IPv6, and hexadecimal/integer notations (`http://192.168.1.1/login`, `http://185.220.101.5/chase`).
* **Excessive Subdomains**: Flags deep subdomains used to push deceptive brand names early in the URL (`http://login.paypal.com.user-verify.account.ru`).
* **Homograph Characters (Punycode / IDN)**: Detects Cyrillic and Greek lookalikes (`gооgle.com` using Cyrillic `о` U+043E) and punycode (`xn--`).
* **Typosquatting & Misspellings**: Analyzes Levenshtein distance, Leetspeak substitutions (`g00gle.com`, `paypaI.com`), and character combinations (`rn` mimicking `m`).
* **Suspicious/Abused TLDs**: Flags high-risk TLDs commonly abused in automated spam/phish campaigns (`.xyz`, `.top`, `.tk`, `.click`, `.buzz`, etc.).
* **High Domain Entropy**: Shannon entropy calculation detects algorithmically generated domains (DGA) such as `a9x8k2lmq0v7.com`.

### 2. URL Structural & Syntactical Criteria
* **Presence of `@` Symbol**: Detects `@` character in URL, which causes browsers to ignore all prefix text and navigate to the address following it (`http://google.com@evil.com`).
* **Abnormal URL & Hostname Length**: Flags overly long URLs (>75 chars) and long hostnames (>30 chars) designed to push real domains off-screen on mobile devices.
* **Double Slashes in Path**: Detects `//` inside path components (`http://site.com//redirect//login`).
* **Excessive Hyphens**: Flags hostnames with 3 or more hyphens chained together (`www.secure-apple-id-login-verification-support.com`).
* **Non-Standard Ports**: Detects traffic served on non-standard ports (`:8080`, `:8888`, `:3000`) rather than standard HTTP (80) or HTTPS (443).

### 3. Protocol & Security Criteria
* **Lack of HTTPS Encryption**: Flags sensitive or credential-related URLs served over unencrypted HTTP.
* **Mismatched SSL/TLS Certificate**: Detects invalid SNI, self-signed, expired, or mismatched certificates via fast timeout-guarded TLS handshakes.
* **Data URI Usage**: Intercepts `data:text/html` URLs that execute local encoded page content without querying a remote host, instantly assigning maximum risk (100).

### 4. Content & Semantic Criteria
* **Suspicious Keyword Stacking**: Detects clustering of urgent security, banking, or credential terms (`banking/account/verify/update/confirm/login`).
* **Open Redirect Parameters**: Identifies redirect parameters (`?dest=`, `?redirect=`, `?url=`, `?next=`, `?goto=`) pointing to external destinations and revokes trusted-domain whitelist bypasses.
* **URL Shorteners**: Identifies link shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.) that obscure the true destination domain.

---

## 🚦 Risk Verdicts & Badge Indicators

* **Safe (`0 - 24`)**: Green badge (`#22c55e`) — Genuine, verified domain with valid encryption.
* **Suspicious (`25 - 54`)**: Amber badge (`#f59e0b`) — Mild risk factors or single anomaly detected.
* **Phishing (`55 - 100`)**: Red badge (`#ef4444`) — Severe threat signals, brand spoofing, or credential traps.

---

## 🚀 Getting Started

### 1. Start the Backend API

Make sure you have **Python 3.8+** installed:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the FastAPI server
python main.py
```

The API will start at **`http://127.0.0.1:8000`**.

### 2. Run the 16-Criteria Test Suite

You can verify all 16 detection criteria anytime by running:

```bash
python test_engine.py
```

All 17 automated tests will run and display detailed signal and score breakdowns.

---

### 3. Install the Chrome Extension

1. Open Google Chrome (or any Chromium browser like Edge, Brave, etc.).
2. Navigate to: `chrome://extensions`
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select the **`extension`** folder inside this repository:
   ```text
   d:\New Sem\CS\Project\PhishGuard-Lite\extension
   ```
6. Pin **PhishGuard Lite** to your Chrome toolbar.
