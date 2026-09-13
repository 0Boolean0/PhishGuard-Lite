"""
PhishGuard-Lite - FastAPI Backend
Phishing URL detection using heuristic + brand spoofing + typosquatting detection.
Run with: python main.py
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import math
from urllib.parse import urlparse
from collections import Counter
from difflib import SequenceMatcher
from typing import Optional, Tuple

app = FastAPI(title="PhishGuard-Lite API", version="1.1.0")

# Allow requests from the Chrome extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# High-Value Target Brands & Authorized Domains
# ---------------------------------------------------------------------------
TARGET_BRANDS = {
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "google": ["google.com", "google.co.uk", "google.ca", "google.com.au", "google.de", "google.fr", "google.co.jp"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "msn.com", "bing.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com"],
    "stackoverflow": ["stackoverflow.com"],
    "reddit": ["reddit.com"],
    "bankofamerica": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "discord": ["discord.com", "discord.gg"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "roblox": ["roblox.com"],
    "dropbox": ["dropbox.com"],
    "yahoo": ["yahoo.com"],
    "tiktok": ["tiktok.com"],
    "ebay": ["ebay.com"],
}

# Consolidate all official domains into the trusted set
TRUSTED_DOMAINS = {
    domain
    for domain_list in TARGET_BRANDS.values()
    for domain in domain_list
} | {
    "youtube.com", "wikipedia.org", "cloudflare.com", "fastapi.tiangolo.com",
    "python.org", "w3schools.com", "mozilla.org", "archive.org", "medium.com"
}

# Leetspeak / homoglyph substitution mapping
LEET_MAP = str.maketrans({
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '@': 'a',
    '$': 's',
    '!': 'i',
})

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "account",
    "update", "security", "secure", "banking", "authenticate", "auth",
    "password", "credential", "confirm", "support", "alert", "suspend",
    "unusual", "activity", "validate", "click", "free", "winner", "prize",
    "claim", "bonus", "wallet", "restore", "recovery", "airdrop", "fake",
    "billing", "invoice", "payment", "session", "suspended", "unlock"
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".info", ".biz", ".click", ".link", ".work",
    ".buzz", ".cam", ".live", ".shop", ".icu", ".sbs", ".monster",
    ".fit", ".rest", ".country", ".kim", ".stream", ".date", ".party",
    ".racing", ".science", ".review", ".download", ".accountant", ".cricket"
}

DECEPTIVE_TERMS = ["fake", "phish", "scam", "spoof", "unauthorized", "clone"]


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


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_brand_spoofing(hostname: str) -> Tuple[bool, Optional[str], Optional[str], bool]:
    """
    Detects typosquatting, brand impersonation, and deceptive subdomain injection.
    Returns: (is_spoof, brand_name, reason, is_subdomain_spoof)
    """
    if not hostname:
        return False, None, None, False

    host_lower = hostname.lower()

    # Split domain into subdomains, SLD, and TLD
    parts = host_lower.split(".")
    if len(parts) < 2:
        return False, None, None, False

    # Handle common two-part TLDs (e.g., .co.uk, .com.au)
    two_part_tlds = {"co.uk", "com.au", "co.jp", "com.br", "org.uk", "gov.uk", "ac.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        sld = parts[-3]
        subdomains = parts[:-3]
    else:
        sld = parts[-2]
        subdomains = parts[:-2]

    subdomains_str = ".".join(subdomains)
    sld_clean = re.sub(r"[^a-z0-9]", "", sld)
    sld_leet = sld_clean.translate(LEET_MAP)

    for brand, official_domains in TARGET_BRANDS.items():
        # Check 1: Deceptive Subdomain Injection (e.g. facebook.com.evil.com or login.paypal.com.tracker.xyz)
        for sub in subdomains:
            if brand in sub or any(od in subdomains_str for od in official_domains):
                return True, brand.capitalize(), f"Deceptive subdomain injection of '{brand}'", True

        # Check 2: Leetspeak substitution (e.g. g00gle.com, paypa1.com)
        if sld_leet == brand:
            return True, brand.capitalize(), f"Leetspeak / character substitution of '{brand}'", False

        # Check 3: Brand name embedded in untrusted domain (e.g. facebook-security.com, paypal-verify.com)
        if brand in sld_clean or brand in sld_leet:
            return True, brand.capitalize(), f"Unauthorized brand '{brand}' embedded in domain", False

        # Check 4: Typosquatting / Edit distance / Fuzzy match (e.g. fakecbook.com, faceboook.com)
        dist = _levenshtein(sld_clean, brand)
        dist_leet = _levenshtein(sld_leet, brand)
        min_dist = min(dist, dist_leet)

        sim = max(
            SequenceMatcher(None, sld_clean, brand).ratio(),
            SequenceMatcher(None, sld_leet, brand).ratio()
        )

        # Typosquatting threshold:
        # - Edit distance 1 or 2 with comparable length
        # - Or SequenceMatcher ratio >= 0.75 for brands of length >= 5
        if (min_dist <= 2 and len(brand) >= 5 and abs(len(sld_clean) - len(brand)) <= 2) or \
           (sim >= 0.75 and len(brand) >= 5):
            return True, brand.capitalize(), f"Typosquatting of '{brand}' (similarity: {int(sim * 100)}%)", False

    return False, None, None, False


def extract_features(url: str) -> dict:
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    has_punycode = hostname.startswith("xn--") or ".xn--" in hostname or any(ord(c) > 127 for c in hostname)

    tld = ""
    parts = hostname.split(".")
    if len(parts) >= 2 and not has_ip:
        tld = "." + parts[-1]

    # Verify if hostname is an exact match or valid subdomain of a trusted domain
    is_trusted = any(hostname == td or hostname.endswith("." + td) for td in TRUSTED_DOMAINS)

    # Detect brand spoofing & typosquatting only if domain is NOT in the official trusted list
    is_spoof = False
    spoofed_brand = None
    spoof_reason = None
    is_subdomain_spoof = False
    if not is_trusted and not has_ip:
        is_spoof, spoofed_brand, spoof_reason, is_subdomain_spoof = detect_brand_spoofing(hostname)

    # Deceptive terms in hostname (e.g. fake-login, scam-alert)
    has_deceptive_terms = any(d in hostname.lower() for d in DECEPTIVE_TERMS)

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
        "is_typosquat": is_spoof,
        "spoofed_brand": spoofed_brand,
        "spoof_reason": spoof_reason,
        "deceptive_subdomain": is_subdomain_spoof,
        "has_punycode": has_punycode,
        "has_deceptive_terms": has_deceptive_terms,
    }
    return features


# ---------------------------------------------------------------------------
# Risk scoring (weighted heuristic + brand protection)
# ---------------------------------------------------------------------------

def compute_risk(features: dict) -> Tuple[float, str, Optional[str]]:
    """
    Returns (score 0-100, verdict, warning_message).
    Higher score = more likely phishing.
    """
    warning = None

    # Instant trust shortcut for genuine verified domains
    if features["trusted_domain"] and not features["has_ip"] and features["https"]:
        return 5.0, "safe", None

    score = 0.0

    # CRITICAL THREAT: Brand Impersonation / Typosquatting
    if features["is_typosquat"] or features["deceptive_subdomain"]:
        score += 75.0
        reason = features.get("spoof_reason") or "Impersonation detected"
        warning = f"Brand Impersonation: {reason}"

    # Punycode / Homoglyph attack
    if features["has_punycode"]:
        score += 45.0
        warning = warning or "Internationalized Domain / Homoglyph attack detected"

    # Deceptive keywords (fake, phish, scam, etc.)
    if features["has_deceptive_terms"]:
        score += 35.0

    # Penalise / reward individual signals
    if features["has_ip"]:
        score += 40.0
    if features["has_at_symbol"]:
        score += 25.0
    if features["suspicious_tld"]:
        score += 25.0
    if features["has_double_slash"]:
        score += 15.0
    if not features["https"]:
        score += 15.0

    score += min(features["url_length"] / 10, 15)                # long URLs → up to +15
    score += min(features["hyphen_count"] * 5, 15)               # hyphens   → up to +15
    score += min(features["subdomain_count"] * 8, 24)            # subdomains→ up to +24
    score += min(features["suspicious_keyword_count"] * 10, 30)  # keywords  → up to +30
    score += min(max(features["entropy"] - 3.5, 0) * 10, 15)     # entropy   → up to +15
    score += min(features["digit_count"] * 2, 10)                # digits in host

    score = round(min(score, 100.0), 1)

    # If typosquatting or brand spoofing is detected, strictly enforce "phishing"
    if features["is_typosquat"] or features["deceptive_subdomain"]:
        score = max(score, 85.0)
        verdict = "phishing"
    elif score < 25:
        verdict = "safe"
    elif score < 55:
        verdict = "suspicious"
    else:
        verdict = "phishing"

    return score, verdict, warning


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    url: str


class CheckResponse(BaseModel):
    url: str
    risk_score: float          # 0 – 100
    verdict: str               # "safe" | "suspicious" | "phishing"
    warning: Optional[str] = None
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
    risk_score, verdict, warning = compute_risk(features)
    return CheckResponse(
        url=url,
        risk_score=risk_score,
        verdict=verdict,
        warning=warning,
        features=features
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

