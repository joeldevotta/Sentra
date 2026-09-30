import re
from urllib.parse import urlparse


URGENCY_TERMS = [
    "urgent", "immediately", "act now", "right now", "hurry",
    "within minutes", "today only", "do it now"
]

CREDENTIAL_TERMS = [
    "otp", "one time password", "pin", "upi pin", "password",
    "cvv", "card number", "verification code"
]

THREAT_TERMS = [
    "account blocked", "account will be blocked", "account suspended",
    "police", "legal action", "arrest", "penalty", "fine"
]

SUSPICIOUS_URL_TERMS = [
    "verify", "verification", "secure", "login", "update",
    "account", "refund", "claim", "kyc", "payment"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "rebrand.ly"
}


def _contains_any(text: str, terms: list[str]) -> str | None:
    for term in terms:
        if term in text:
            return term
    return None


def analyze_url(link: str) -> tuple[int, list[str]]:
    if not link.strip():
        return 0, []

    value = link.strip().lower()
    score = 0
    signals = []

    try:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        host = (parsed.hostname or "").lower()

        if parsed.scheme == "http":
            score += 8
            signals.append("Unencrypted payment URL")

        if host in SHORTENERS:
            score += 8
            signals.append("URL shortener detected")

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            score += 8
            signals.append("IP-address URL detected")

        if "xn--" in host:
            score += 8
            signals.append("Punycode domain detected")

        if any(term in value for term in SUSPICIOUS_URL_TERMS):
            score += 8
            signals.append("Sensitive-action URL")

    except ValueError:
        score += 10
        signals.append("Malformed payment URL")

    return min(score, 20), signals


def analyze_payment(amount: float, recipient: str, message: str, link: str):
    text = message.lower().strip()
    recipient_text = recipient.lower().strip()

    score = 0
    signals = []

    # Amount: a large amount alone should raise caution, not imply fraud.
    if amount > 10000:
        score += 20
        signals.append("High-value payment")
    elif amount > 5000:
        score += 12
        signals.append("Elevated payment amount")

    # Prototype recipient trust signal.
    if any(word in recipient_text for word in ["unknown", "new recipient", "unverified"]):
        score += 15
        signals.append("Unfamiliar recipient")

    # Message categories are capped so repeated words cannot inflate the score.
    if _contains_any(text, URGENCY_TERMS):
        score += 20
        signals.append("Urgency language")

    if _contains_any(text, CREDENTIAL_TERMS):
        score += 25
        signals.append("Credential or OTP request")

    if _contains_any(text, THREAT_TERMS):
        score += 20
        signals.append("Threat or account-block language")

    url_score, url_signals = analyze_url(link)
    score += url_score
    signals.extend(url_signals)

    # Cross-signal correlation: urgency + credential request is especially suspicious.
    if _contains_any(text, URGENCY_TERMS) and _contains_any(text, CREDENTIAL_TERMS):
        score += 10
        signals.append("Urgency combined with credential request")

    # Keep the score bounded and deterministic.
    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "REVIEW"
    else:
        level = "SAFE"

    return score, level, signals
