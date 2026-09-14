"""
PhishGuard-Lite — Automated Test Suite
Verifies all 16 phishing detection criteria across 4 categories against the backend engine in main.py.
Run with: python test_engine.py
"""

import sys
from main import extract_features, compute_risk

TEST_CASES = [
    # 1. IP in Hostname
    {
        "name": "Criterion 1: IP Address in Hostname",
        "url": "http://192.168.1.1/login",
        "expected_signal": "IP Address in Hostname",
        "expected_verdict": "phishing",
    },
    # 2. Excessive Subdomains
    {
        "name": "Criterion 2: Excessive Subdomains",
        "url": "http://login.paypal.com.user-verify.ru/session",
        "expected_signal": "Excessive Subdomains",
        "expected_verdict": "phishing",
    },
    # 3. Homograph Characters / Lookalikes
    {
        "name": "Criterion 3: Homograph Characters (Cyrillic lookalikes)",
        "url": "http://gооgle.com",  # contains Cyrillic 'о'
        "expected_signal": "Homograph Characters / IDN",
        "expected_verdict": "phishing",
    },
    # 4. Typosquatting / Misspellings
    {
        "name": "Criterion 4: Typosquatting (Leetspeak / visual)",
        "url": "http://paypaI.com",  # capital I for l
        "expected_signal": "Brand Impersonation / Typosquatting",
        "expected_verdict": "phishing",
    },
    # 5. Suspicious / Abused TLDs
    {
        "name": "Criterion 5: Suspicious TLD",
        "url": "http://security-update.xyz/login",
        "expected_signal": "Suspicious TLD",
        "expected_verdict": "phishing",
    },
    # 6. High Domain Entropy (DGA)
    {
        "name": "Criterion 6: High Domain Entropy (DGA)",
        "url": "http://a9x8k2lmq0v7wz.com/auth",
        "expected_signal": "High Domain Entropy",
        "expected_verdict": "phishing",
    },
    # 7. Presence of @ Symbol
    {
        "name": "Criterion 7: Presence of @ Symbol",
        "url": "http://google.com@evil-portal.com/login",
        "expected_signal": "Presence of '@' Symbol",
        "expected_verdict": "phishing",
    },
    # 8. Abnormal Length
    {
        "name": "Criterion 8: Abnormal URL & Hostname Length",
        "url": "http://login.microsoftonline.com.auth-token-verification-session-9982.service-portal.cc/login",
        "expected_signal": "Abnormal URL Length",
        "expected_verdict": "phishing",
    },
    # 9. Double Slashes in Path
    {
        "name": "Criterion 9: Double Slashes in Path",
        "url": "http://evil-site.com//redirect//login",
        "expected_signal": "Double Slashes in Path",
        "expected_verdict": "suspicious",
    },
    # 10. Excessive Hyphens
    {
        "name": "Criterion 10: Excessive Hyphens",
        "url": "http://www.secure-apple-id-login-verification-support.com",
        "expected_signal": "Excessive Hyphens",
        "expected_verdict": "phishing",
    },
    # 11. Non-Standard Port
    {
        "name": "Criterion 11: Non-Standard Port",
        "url": "http://secure-bank.com:8080/login",
        "expected_signal": "Non-Standard Port",
        "expected_verdict": "phishing",
    },
    # 12. Lack of HTTPS Encryption
    {
        "name": "Criterion 12: Lack of HTTPS Encryption",
        "url": "http://chase-security-login.com",
        "expected_signal": "Lack of HTTPS Encryption",
        "expected_verdict": "phishing",
    },
    # 13. Data URI Usage
    {
        "name": "Criterion 14: Data URI Execution",
        "url": "data:text/html;base64,PGh0bWw+PGJvZHk+PGgxPkhlbGxvPC9oMT48L2JvZHk+PC9odG1sPg==",
        "expected_signal": "Data URI Execution",
        "expected_verdict": "phishing",
    },
    # 14. Suspicious Keyword Stacking
    {
        "name": "Criterion 15: Keyword Stacking",
        "url": "http://portal.com/banking/account/verify/update/confirm/login",
        "expected_signal": "Keyword Stacking",
        "expected_verdict": "suspicious",
    },
    # 15. Open Redirect Parameters
    {
        "name": "Criterion 16: Open Redirect Parameter",
        "url": "https://google.com/url?dest=http://phishing-site.com",
        "expected_signal": "Open Redirect Parameter",
        "expected_verdict": "suspicious",
    },
    # 16. URL Shorteners
    {
        "name": "Criterion 17: URL Shortener",
        "url": "https://bit.ly/3xY8z",
        "expected_signal": "URL Shortener",
        "expected_verdict": "suspicious",
    },
    # Baseline: Genuine Safe URL
    {
        "name": "Baseline: Legitimate Verified Domain",
        "url": "https://google.com/search?q=cybersecurity",
        "expected_signal": None,
        "expected_verdict": "safe",
    },
]


def run_tests():
    print("=" * 70)
    print("  PHISHGUARD-LITE — 16 CRITERIA VERIFICATION TEST SUITE")
    print("=" * 70)
    
    passed_count = 0
    total_count = len(TEST_CASES)

    for case in TEST_CASES:
        url = case["url"]
        name = case["name"]
        expected_signal = case["expected_signal"]
        expected_verdict = case["expected_verdict"]

        feats = extract_features(url, check_ssl=False)
        score, verdict, warning, signals = compute_risk(feats)

        # Check conditions
        signal_ok = True
        if expected_signal:
            signal_ok = any(expected_signal.lower() in s.lower() for s in signals) or (expected_signal.lower() in (warning or "").lower())
        
        verdict_ok = (verdict == expected_verdict) if expected_verdict != "suspicious" else (verdict in ("suspicious", "phishing"))

        if signal_ok and verdict_ok:
            passed_count += 1
            status = "[PASS]"
        else:
            status = "[FAIL]"

        print(f"\n{status} {name}")
        print(f"  URL: {url[:60]}{'...' if len(url) > 60 else ''}")
        print(f"  Risk Score: {score}/100 | Verdict: {verdict.upper()}")
        if warning:
            print(f"  Warning: {warning}")
        print(f"  Signals: {signals}")

        if not (signal_ok and verdict_ok):
            print(f"  --> Failure reason: signal_ok={signal_ok}, verdict_ok={verdict_ok} (expected {expected_verdict})")

    print("\n" + "=" * 70)
    print(f"RESULT: {passed_count}/{total_count} tests passed successfully.")
    print("=" * 70)

    if passed_count != total_count:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
