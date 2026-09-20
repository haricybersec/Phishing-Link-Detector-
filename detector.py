from urllib.parse import urlparse
import ipaddress


# Words commonly seen in suspicious URLs
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "confirm",
    "password",
    "signin",
]


def check_url(url):
    score = 0
    reasons = []

    # Add a scheme if the user didn't provide one
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    # ---------------------------------
    # Check 1: HTTPS
    # ---------------------------------
    if parsed.scheme != "https":
        score += 10
        reasons.append("URL does not use HTTPS")

    # ---------------------------------
    # Check 2: Very long URL
    # ---------------------------------
    if len(url) > 100:
        score += 10
        reasons.append("URL is unusually long")

    # ---------------------------------
    # Check 3: IP address as hostname
    # ---------------------------------
    hostname = parsed.hostname

    if hostname:
        try:
            ipaddress.ip_address(hostname)
            score += 30
            reasons.append("URL uses an IP address instead of a domain name")
        except ValueError:
            pass

    # ---------------------------------
    # Check 4: Too many subdomains
    # ---------------------------------
    if hostname:
        parts = hostname.split(".")

        if len(parts) > 3:
            score += 15
            reasons.append("Domain contains many subdomains")

    # ---------------------------------
    # Check 5: Suspicious words
    # ---------------------------------
    url_lower = url.lower()

    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in url_lower:
            found_words.append(word)

    if found_words:
        score += 10
        reasons.append(
            "Contains suspicious keyword(s): "
            + ", ".join(found_words)
        )

    # ---------------------------------
    # Check 6: @ symbol
    # ---------------------------------
    if "@" in url:
        score += 20
        reasons.append("URL contains '@'")

    # ---------------------------------
    # Limit score to 100
    # ---------------------------------
    score = min(score, 100)

    # ---------------------------------
    # Determine result
    # ---------------------------------
    if score < 30:
        result = "LIKELY SAFE"
    elif score < 60:
        result = "SUSPICIOUS"
    else:
        result = "HIGH RISK"

    return result, score, reasons


# =====================================
# Main program
# =====================================

print("=" * 45)
print("       PHISHING URL DETECTOR")
print("=" * 45)

url = input("\nEnter a URL: ").strip()

result, score, reasons = check_url(url)

print("\nResult:", result)
print("Risk Score:", str(score) + "/100")

if reasons:
    print("\nReasons:")

    for reason in reasons:
        print("-", reason)
else:
    print("\nNo suspicious indicators detected.")

print("\nNote: This is a basic rule-based detector.")
print("A 'safe' result does NOT guarantee that a URL is safe.")
