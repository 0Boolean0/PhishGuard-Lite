"""
PhishGuard-Lite - FastAPI Backend
Real-time phishing URL detection engine covering 16 criteria across 4 categories:
1. Domain & Hostname Anomaly (IP Host, Subdomains, Homographs, Typosquatting, TLDs, Entropy)
2. URL Structural & Syntactical (@ Symbol, Length, Double Slashes, Hyphens, Non-Standard Ports)
3. Protocol & Security (Lack of HTTPS, SSL/TLS Mismatch, Data URIs)
4. Content & Semantic (Keyword Stacking, Open Redirect Parameters, URL Shorteners)

Run with: python main.py
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import math
import ipaddress
import ssl
import socket
import urllib.parse
from collections import Counter
from difflib import SequenceMatcher
from typing import Optional, Tuple, List, Dict, Any

app = FastAPI(title="PhishGuard-Lite API", version="2.0.0")

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

# Homoglyph lookalike mapping (Cyrillic & Greek characters visually resembling ASCII)
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I',
    'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T',
    'Υ': 'Y', 'Χ': 'X',
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
}

# Leetspeak / visual character substitution mapping
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
    '|': 'l',
    'i': 'l',  # Visual confusion in sans-serif fonts (capital I vs lowercase l)
})

# Credential harvesting, urgent banking, and account keywords
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "account",
    "update", "security", "secure", "banking", "authenticate", "auth",
    "password", "credential", "confirm", "support", "alert", "suspend",
    "unusual", "activity", "validate", "click", "free", "winner", "prize",
    "claim", "bonus", "wallet", "restore", "recovery", "airdrop", "fake",
    "billing", "invoice", "payment", "session", "suspended", "unlock"
]

# High-risk / spam-abused TLDs
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".info", ".biz", ".click", ".link", ".work",
    ".buzz", ".cam", ".live", ".shop", ".icu", ".sbs", ".monster",
    ".fit", ".rest", ".country", ".kim", ".stream", ".date", ".party",
    ".racing", ".science", ".review", ".download", ".accountant", ".cricket",
    ".quest", ".boats", ".autos", ".beauty", ".hair", ".makeup", ".skin",
    ".cheap", ".vip", ".loan", ".win", ".bid"
}

# Known URL shortener domains
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "tiny.cc", "cutt.ly", "rebrand.ly",
    "shorturl.at", "soo.gd", "s.id", "v.gd", "trib.al", "linktr.ee"
}

# Common open redirect query parameter names
OPEN_REDIRECT_PARAMS = {
    "redirect", "redirect_url", "redirect_uri", "dest", "destination",
    "next", "target", "r", "goto", "link", "continue", "out", "view",
    "to", "url", "return", "return_url", "forward", "forward_url"
}

DECEPTIVE_TERMS = ["fake", "phish", "scam", "spoof", "unauthorized", "clone"]


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------

def is_ip_address(host: str) -> bool:
    """Detects raw IPv4, IPv6, hex, or decimal integer IP in hostname."""
    if not host:
        return False
    clean = host.strip("[]").split(":")[0]
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        pass
    if re.match(r"^0x[0-9a-fA-F]+$", clean):
        return True
    if clean.isdigit() and len(clean) >= 8:
        try:
            ipaddress.ip_address(int(clean))
            return True
        except ValueError:
            pass
    return False


def normalize_homoglyphs(s: str) -> Tuple[str, bool]:
    """Translates known Cyrillic/Greek homoglyphs to ASCII. Returns (normalized, has_homoglyphs)."""
    has_homo = False
    chars = []
    for ch in s:
        if ch in HOMOGLYPH_MAP:
            chars.append(HOMOGLYPH_MAP[ch])
            has_homo = True
        else:
            chars.append(ch)
    return "".join(chars), has_homo


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
    Detects typosquatting, brand impersonation, homoglyphs, and deceptive subdomains.
    Returns: (is_spoof, brand_name, reason, is_subdomain_spoof)
    """
    if not hostname:
        return False, None, None, False

    host_lower = hostname.lower()
    norm_host, has_homo = normalize_homoglyphs(host_lower)

    # Check Punycode IDN (xn--)
    if host_lower.startswith("xn--") or ".xn--" in host_lower:
        try:
            decoded = host_lower.encode("ascii").decode("idna")
            norm_host, _ = normalize_homoglyphs(decoded)
        except Exception:
            pass

    # Split domain into subdomains, SLD, and TLD
    parts = norm_host.split(".")
    if len(parts) < 2:
        return False, None, None, False

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
    sld_visual = sld_leet.replace("rn", "m").replace("vv", "w")

    for brand, official_domains in TARGET_BRANDS.items():
        # Check 1: Deceptive Subdomain Injection
        for sub in subdomains:
            if brand in sub or any(od in subdomains_str for od in official_domains):
                return True, brand.capitalize(), f"Deceptive subdomain injection of '{brand}'", True

        # Check 2: Leetspeak / Homoglyph / Visual substitution
        if sld_leet == brand or sld_visual == brand or (has_homo and sld_clean == brand):
            reason = f"Homoglyph / character substitution of '{brand}'" if has_homo else f"Leetspeak substitution of '{brand}'"
            return True, brand.capitalize(), reason, False

        # Check 3: Brand name embedded in untrusted domain
        if brand in sld_clean or brand in sld_leet or brand in sld_visual:
            return True, brand.capitalize(), f"Unauthorized brand '{brand}' embedded in domain", False

        # Check 4: Typosquatting / Edit distance / Fuzzy match
        dist = min(_levenshtein(sld_clean, brand), _levenshtein(sld_leet, brand), _levenshtein(sld_visual, brand))
        sim = max(
            SequenceMatcher(None, sld_clean, brand).ratio(),
            SequenceMatcher(None, sld_leet, brand).ratio(),
            SequenceMatcher(None, sld_visual, brand).ratio()
        )

        if (dist <= 2 and len(brand) >= 5 and abs(len(sld_clean) - len(brand)) <= 2) or \
           (sim >= 0.75 and len(brand) >= 5):
            return True, brand.capitalize(), f"Typosquatting of '{brand}' (similarity: {int(sim * 100)}%)", False

    return False, None, None, False


def check_open_redirect(parsed_url) -> Tuple[bool, Optional[str]]:
    """Detect open redirect parameters pointing to external URLs."""
    if not parsed_url.query:
        return False, None
    query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
    for param_name, values in query_params.items():
        if param_name.lower() in OPEN_REDIRECT_PARAMS:
            for val in values:
                val_clean = val.strip()
                if val_clean.startswith("http://") or val_clean.startswith("https://") or val_clean.startswith("//"):
                    try:
                        target = val_clean if not val_clean.startswith("//") else "http:" + val_clean
                        target_parsed = urllib.parse.urlparse(target)
                        if target_parsed.hostname and target_parsed.hostname.lower() != (parsed_url.hostname or "").lower():
                            return True, val_clean
                    except Exception:
                        pass
    return False, None


def check_keyword_stacking(domain_part: str, path_part: str) -> Tuple[bool, int, List[str]]:
    """
    Checks for stacking of urgent credentials / banking / security keywords.
    Returns: (is_stacked, count, matched_keywords)
    """
    text_domain = domain_part.lower()
    text_path = path_part.lower()
    domain_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_domain]
    path_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_path]
    all_unique = list(set(domain_matches + path_matches))
    is_stacked = len(domain_matches) >= 2 or len(all_unique) >= 3
    return is_stacked, len(all_unique), all_unique


def check_ssl_certificate(hostname: str, port: int = 443, timeout: float = 1.5) -> Tuple[Optional[bool], Optional[str]]:
    """
    Verify SSL certificate for HTTPS hostname.
    Returns (is_valid, error_reason).
    is_valid:
      True if handshake succeeded and certificate is valid for hostname.
      False if certificate is expired, self-signed, or mismatched.
      None if host is unreachable, timed out, or not applicable.
    """
    if not hostname or hostname in ("localhost", "127.0.0.1") or is_ip_address(hostname):
        return None, None
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True, None
    except ssl.CertificateError as e:
        return False, f"Certificate hostname mismatch: {e}"
    except ssl.SSLCertVerificationError as e:
        return False, f"SSL verification failed: {e.verify_message}"
    except ssl.SSLError as e:
        return False, f"SSL error: {str(e)}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return None, None


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------

def extract_features(url: str, check_ssl: bool = False) -> Dict[str, Any]:
    url_lower = url.strip().lower()

    # Special handling for Data URIs
    if url_lower.startswith("data:"):
        is_html = "text/html" in url_lower
        return {
            "url_length": len(url),
            "hostname_length": 0,
            "has_ip": False,
            "has_at_symbol": False,
            "has_double_slash": False,
            "suspicious_tld": False,
            "tld": "",
            "subdomain_count": 0,
            "excessive_subdomains": False,
            "hyphen_count": 0,
            "excessive_hyphens": False,
            "non_standard_port": False,
            "port": None,
            "entropy": 0.0,
            "high_entropy": False,
            "https": False,
            "lacks_https": True,
            "ssl_valid": None,
            "ssl_reason": None,
            "trusted_domain": False,
            "is_typosquat": False,
            "spoofed_brand": None,
            "spoof_reason": None,
            "deceptive_subdomain": False,
            "has_punycode": False,
            "has_homograph": False,
            "has_deceptive_terms": False,
            "has_open_redirect": False,
            "open_redirect_target": None,
            "is_url_shortener": False,
            "keyword_stacking": False,
            "suspicious_keyword_count": 0,
            "abnormal_url_length": False,
            "abnormal_hostname_length": False,
            "has_data_uri": True,
            "is_data_html": is_html,
        }

    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    port = parsed.port

    has_ip = is_ip_address(hostname)
    has_punycode = hostname.startswith("xn--") or ".xn--" in hostname or any(ord(c) > 127 for c in hostname)
    _, has_homograph = normalize_homoglyphs(hostname)

    tld = ""
    parts = hostname.split(".")
    if len(parts) >= 2 and not has_ip:
        tld = "." + parts[-1]

    # Subdomain calculation
    two_part_tlds = {"co.uk", "com.au", "co.jp", "com.br", "org.uk", "gov.uk", "ac.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        subdomain_count = max(len(parts) - 3, 0)
    else:
        subdomain_count = max(len(parts) - 2, 0) if not has_ip else 0

    excessive_subdomains = subdomain_count >= 3

    # Hyphen calculation
    hyphen_count = hostname.count("-")
    excessive_hyphens = hyphen_count >= 3

    # Non-standard port
    non_standard_port = bool(port and port not in (80, 443))

    # Open redirect parameter
    has_open_redirect, open_redirect_target = check_open_redirect(parsed)

    # URL Shorteners
    is_url_shortener = (hostname.lower() in KNOWN_SHORTENERS) or any(hostname.lower().endswith("." + s) for s in KNOWN_SHORTENERS)

    # Keyword Stacking
    keyword_stacking, kw_count, kw_list = check_keyword_stacking(hostname, path + (parsed.query or ""))

    # Entropy
    entropy = round(_entropy(hostname), 4)
    high_entropy = (entropy >= 3.8 and len(hostname) >= 8) or (entropy >= 3.5 and len(hostname) >= 14)

    # Abnormal lengths
    abnormal_url_length = len(url) >= 75
    abnormal_hostname_length = len(hostname) >= 30

    # Trusted domain
    is_trusted = any(hostname == td or hostname.endswith("." + td) for td in TRUSTED_DOMAINS)

    # Brand spoofing / typosquatting
    is_spoof = False
    spoofed_brand = None
    spoof_reason = None
    is_subdomain_spoof = False
    if not is_trusted and not has_ip:
        is_spoof, spoofed_brand, spoof_reason, is_subdomain_spoof = detect_brand_spoofing(hostname)

    has_deceptive_terms = any(d in hostname.lower() for d in DECEPTIVE_TERMS)

    # SSL check (performed when scheme is https)
    ssl_valid, ssl_reason = None, None
    if check_ssl and parsed.scheme == "https" and hostname and not has_ip:
        ssl_valid, ssl_reason = check_ssl_certificate(hostname, port=port or 443)

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "dot_count": hostname.count("."),
        "hyphen_count": hyphen_count,
        "excessive_hyphens": excessive_hyphens,
        "digit_count": sum(c.isdigit() for c in hostname),
        "has_ip": has_ip,
        "has_at_symbol": "@" in url,
        "has_double_slash": "//" in path,
        "suspicious_tld": tld.lower() in SUSPICIOUS_TLDS,
        "tld": tld,
        "subdomain_count": subdomain_count,
        "excessive_subdomains": excessive_subdomains,
        "non_standard_port": non_standard_port,
        "port": port,
        "entropy": entropy,
        "high_entropy": high_entropy,
        "https": parsed.scheme == "https",
        "lacks_https": parsed.scheme != "https",
        "ssl_valid": ssl_valid,
        "ssl_reason": ssl_reason,
        "trusted_domain": is_trusted,
        "is_typosquat": is_spoof,
        "spoofed_brand": spoofed_brand,
        "spoof_reason": spoof_reason,
        "deceptive_subdomain": is_subdomain_spoof,
        "has_punycode": has_punycode,
        "has_homograph": has_homograph,
        "has_deceptive_terms": has_deceptive_terms,
        "has_open_redirect": has_open_redirect,
        "open_redirect_target": open_redirect_target,
        "is_url_shortener": is_url_shortener,
        "keyword_stacking": keyword_stacking,
        "suspicious_keyword_count": kw_count,
        "abnormal_url_length": abnormal_url_length,
        "abnormal_hostname_length": abnormal_hostname_length,
        "has_data_uri": False,
        "is_data_html": False,
    }


# ---------------------------------------------------------------------------
# Risk Scoring & Verdict Engine
# ---------------------------------------------------------------------------

def compute_risk(features: Dict[str, Any]) -> Tuple[float, str, Optional[str], List[str]]:
    """
    Returns (score 0-100, verdict, warning_message, signals_list).
    Higher score = more likely phishing.
    """
    signals = []
    warning = None

    # CRITICAL HAZARD 1: Data URI Phishing
    if features.get("has_data_uri"):
        return 100.0, "phishing", "Critical: Data URI execution. Web page executes local string content without contacting a legitimate host.", ["Data URI Execution"]

    # Genuine Trusted Domain: Instant pass ONLY IF NO open redirect, no IP, and HTTPS
    if features["trusted_domain"] and not features["has_ip"] and features["https"] and not features["has_open_redirect"]:
        return 5.0, "safe", None, []

    score = 0.0

    # CRITICAL HAZARD 2: Brand Impersonation / Typosquatting
    if features["is_typosquat"] or features["deceptive_subdomain"]:
        score += 75.0
        reason = features.get("spoof_reason") or "Brand impersonation detected"
        warning = f"Brand Impersonation: {reason}"
        signals.append("Brand Impersonation / Typosquatting")

    # CRITICAL HAZARD 3: Open Redirect Parameter
    if features["has_open_redirect"]:
        score += 40.0
        target = features.get("open_redirect_target")
        warning = warning or f"Open Redirect: forwards visitors to external destination '{target}'"
        signals.append("Open Redirect Parameter")

    # Homoglyphs / Punycode
    if features["has_homograph"] or features["has_punycode"]:
        score += 45.0
        warning = warning or "Homograph / Punycode: lookalike characters detected in domain"
        signals.append("Homograph Characters / IDN")

    # Raw IP Hostname
    if features["has_ip"]:
        score += 40.0
        warning = warning or "Raw IP Address used as hostname instead of a registered domain"
        signals.append("IP Address in Hostname")

    # SSL Certificate Mismatch
    if features.get("ssl_valid") is False:
        score += 40.0
        warning = warning or f"SSL Certificate Mismatch: {features.get('ssl_reason') or 'Untrusted certificate'}"
        signals.append("Mismatched SSL/TLS Certificate")

    # URL Shortener
    if features["is_url_shortener"]:
        score += 30.0
        warning = warning or "URL Shortener hides true destination domain"
        signals.append("URL Shortener")

    # Non-Standard Port
    if features["non_standard_port"]:
        score += 25.0
        warning = warning or f"Non-standard web port detected (:{features.get('port')})"
        signals.append("Non-Standard Port")

    # Deceptive Terms
    if features["has_deceptive_terms"]:
        score += 35.0
        signals.append("Deceptive Terms")

    # Presence of '@' Symbol
    if features["has_at_symbol"]:
        score += 25.0
        warning = warning or "'@' symbol in URL causes browser to navigate to the host following it"
        signals.append("Presence of '@' Symbol")

    # Suspicious TLD
    if features["suspicious_tld"]:
        score += 25.0
        signals.append(f"Suspicious TLD ({features.get('tld')})")

    # Keyword Stacking
    if features["keyword_stacking"]:
        score += 25.0
        signals.append("Keyword Stacking")
    elif features["suspicious_keyword_count"] > 0:
        score += min(features["suspicious_keyword_count"] * 8, 20)
        signals.append(f"Phish Keywords ({features['suspicious_keyword_count']})")

    # Double Slashes in Path
    if features["has_double_slash"]:
        score += 15.0
        signals.append("Double Slashes in Path")

    # Lack of HTTPS
    if features["lacks_https"]:
        penalty = 25.0 if features["suspicious_keyword_count"] > 0 else 15.0
        score += penalty
        signals.append("Lack of HTTPS Encryption")

    # Excessive Subdomains
    if features["excessive_subdomains"]:
        score += 15.0
        signals.append(f"Excessive Subdomains ({features['subdomain_count']})")
    elif features["subdomain_count"] > 0:
        score += min(features["subdomain_count"] * 5, 10)

    # Excessive Hyphens
    if features["excessive_hyphens"]:
        score += 15.0
        signals.append(f"Excessive Hyphens ({features['hyphen_count']})")
    elif features["hyphen_count"] > 0:
        score += min(features["hyphen_count"] * 3, 10)

    # Abnormal Lengths
    if features["abnormal_url_length"]:
        score += 10.0
        signals.append("Abnormal URL Length")
    if features["abnormal_hostname_length"]:
        score += 10.0
        signals.append("Abnormal Hostname Length")

    # High Entropy
    if features["high_entropy"]:
        score += 15.0
        signals.append(f"High Domain Entropy ({features['entropy']})")

    score += min(features["digit_count"] * 2, 10)
    score = round(min(score, 100.0), 1)

    # Hard overrides for critical phishing categories
    if features["is_typosquat"] or features["deceptive_subdomain"] or features.get("has_data_uri"):
        score = max(score, 85.0)
        verdict = "phishing"
    elif score < 25.0:
        verdict = "safe"
    elif score < 55.0:
        verdict = "suspicious"
    else:
        verdict = "phishing"

    return score, verdict, warning, signals


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    url: str
    check_ssl: Optional[bool] = False


class CheckResponse(BaseModel):
    url: str
    risk_score: float                # 0 – 100
    verdict: str                     # "safe" | "suspicious" | "phishing"
    warning: Optional[str] = None
    signals: List[str] = []
    features: Dict[str, Any]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "engine": "PhishGuard-Lite API v2.0",
        "status": "online",
        "description": "Comprehensive real-time heuristic phishing detection covering 16 threat criteria."
    }


@app.post("/check", response_model=CheckResponse)
def check_url(req: CheckRequest):
    url = req.url.strip()
    features = extract_features(url, check_ssl=bool(req.check_ssl))
    risk_score, verdict, warning, signals = compute_risk(features)
    return CheckResponse(
        url=url,
        risk_score=risk_score,
        verdict=verdict,
        warning=warning,
        signals=signals,
        features=features
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
