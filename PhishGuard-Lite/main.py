"""
PhishGuard-Lite - FastAPI Backend
Phishing URL detection using heuristic + ML-based feature extraction.
Run with: python main.py
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import math
from urllib.parse import urlparse
from collections import Counter

app = FastAPI(title="PhishGuard-Lite API", version="1.0.0")

# Allow requests from the Chrome extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Known safe / suspicious TLDs & keywords
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "paypal", "ebay", "amazon", "apple", "microsoft", "google", "facebook",
    "password", "credential", "confirm", "support", "alert", "suspend",
    "unusual", "activity", "validate", "click", "free", "winner", "prize",
]

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
                   ".cc", ".info", ".biz", ".click", ".link", ".work"}

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "reddit.com", "netflix.com", "paypal.com",
}

# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(url: str) -> dict:
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

    tld = ""
    parts = hostname.split(".")
    if len(parts) >= 2 and not has_ip:
        tld = "." + parts[-1]

    # Verify if hostname is an exact match or valid subdomain of a trusted domain
    is_trusted = any(hostname == td or hostname.endswith("." + td) for td in TRUSTED_DOMAINS)

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "digit_count": sum(c.isdigit() for c in hostname),
        "has_ip": has_ip,
        "has_at_symbol": "@" in url,
        "has_double_slash": "//" in path,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "subdomain_count": 0 if has_ip else max(len(parts) - 2, 0),
        "path_depth": len([p for p in path.split("/") if p]),
        "suspicious_keyword_count": sum(kw in full for kw in SUSPICIOUS_KEYWORDS),
        "entropy": round(_entropy(hostname), 4),
        "https": parsed.scheme == "https",
        "trusted_domain": is_trusted,
    }
    return features



# ---------------------------------------------------------------------------
# Risk scoring (weighted heuristic)
# ---------------------------------------------------------------------------

def compute_risk(features: dict) -> tuple[float, str]:
    """
    Returns (score 0-100, verdict).
    Higher score = more likely phishing.
    """
    score = 0.0

    # Instant trust shortcut
    if features["trusted_domain"] and not features["has_ip"] and features["https"]:
        return 5.0, "safe"

    # Penalise / reward individual signals
    if features["has_ip"]:
        score += 35
    if features["has_at_symbol"]:
        score += 20
    if features["suspicious_tld"]:
        score += 20
    if features["has_double_slash"]:
        score += 10
    if not features["https"]:
        score += 10

    score += min(features["url_length"] / 10, 15)          # long URLs → up to +15
    score += min(features["hyphen_count"] * 5, 15)         # hyphens   → up to +15
    score += min(features["subdomain_count"] * 8, 24)      # subdomains→ up to +24
    score += min(features["suspicious_keyword_count"] * 8, 24)  # keywords→ up to +24
    score += min(max(features["entropy"] - 3.5, 0) * 10, 15)    # entropy  → up to +15
    score += min(features["digit_count"] * 2, 10)          # digits in host

    score = round(min(score, 100), 1)

    if score < 25:
        verdict = "safe"
    elif score < 55:
        verdict = "suspicious"
    else:
        verdict = "phishing"

    return score, verdict


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    url: str


class CheckResponse(BaseModel):
    url: str
    risk_score: float          # 0 – 100
    verdict: str               # "safe" | "suspicious" | "phishing"
    features: dict


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {"message": "PhishGuard-Lite API is running. POST /check to analyse a URL."}


@app.post("/check", response_model=CheckResponse)
def check_url(req: CheckRequest):
    url = req.url.strip()
    features = extract_features(url)
    risk_score, verdict = compute_risk(features)
    return CheckResponse(url=url, risk_score=risk_score, verdict=verdict, features=features)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
