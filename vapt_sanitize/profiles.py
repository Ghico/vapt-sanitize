import re

from .models import ProfileResult

PROFILES = (
    "GENERIC",
    "NMAP",
    "BURP",
    "GOBUSTER",
    "NUCLEI",
    "WINDOWS",
    "LINUX",
    "AWS",
    "SECRETS",
    "PII",
)
EXPLICIT_DOCUMENT_HINTS = (
    (
        "SECRETS",
        re.compile(r"(?i)\A(?:\ufeff)?\s*SECRETS\s+ENUMERATION\s*(?:\r?\n|$)"),
    ),
    (
        "PII",
        re.compile(r"(?i)\A(?:\ufeff)?\s*PII\s+ENUMERATION\s*(?:\r?\n|$)"),
    ),
    (
        "GENERIC",
        re.compile(r"(?i)\A(?:\ufeff)?\s*GENERIC\s+SECURITY\s+TESTING\s+OUTPUT\s*(?:\r?\n|$)"),
    ),
)


def detect_explicit_document_hint(text: str) -> str | None:
    for profile, pattern in EXPLICIT_DOCUMENT_HINTS:
        if pattern.search(text):
            return profile
    return None


PROFILE_SIGNATURES = {
    "NMAP": [
        (re.compile(r"(?i)\bnmap\b"), 5),
        (re.compile(r"(?i)port\s+state\s+service"), 5),
        (re.compile(r"(?i)\bhost is up\b"), 3),
        (re.compile(r"(?i)nmap scan report"), 5),
    ],

    "BURP": [
        (re.compile(r"(?i)\bGET\s+\S+\s+HTTP/1\.[01]"), 4),
        (re.compile(r"(?i)\bPOST\s+\S+\s+HTTP/1\.[01]"), 4),
        (re.compile(r"(?i)^Host:\s*", re.MULTILINE), 4),
        (re.compile(r"(?i)^User-Agent:\s*", re.MULTILINE), 3),
        (re.compile(r"(?i)^Content-Type:\s*", re.MULTILINE), 2),
        (re.compile(r"(?i)^Authorization:\s*", re.MULTILINE), 3),
    ],

    "GOBUSTER": [
        (re.compile(r"(?i)\bgobuster\b"), 5),
        (re.compile(r"(?i)\bFound:\s+https?://"), 4),
        (re.compile(r"(?i)\bProgress:\s*"), 2),
    ],


    "NUCLEI": [
        (re.compile(r"(?i)\bnuclei\b"), 5),
        (re.compile(r"(?i)\bnuclei-templates\b"), 5),
        (re.compile(r"(?im)^\[INF\]\s+Current nuclei version:"), 5),
        (re.compile(r"(?im)^\[INF\]\s+Matched-at:"), 3),
        (re.compile(r"(?m)^\[[^\]\r\n]+\]\s+\[(?:http|ssl|dns|tcp|file|network)\]\s+\[(?:info|low|medium|high|critical|unknown)\]"), 4),
    ],

    "WINDOWS": [
        (re.compile(r"(?i)\bWindows Server\b"), 5),
        (re.compile(r"(?i)\bDomain Controller\b"), 5),
        (re.compile(r"(?i)\bKerberos\b"), 3),
        (re.compile(r"(?i)\bNTLM\b"), 3),
        (re.compile(r"(?i)\bSMB\b"), 3),
        (re.compile(r"(?i)\bmicrosoft-ds\b"), 3),
    ],

    "LINUX": [
        (re.compile(r"(?i)\bLinux\b"), 4),
        (re.compile(r"(?i)\bUbuntu\b"), 4),
        (re.compile(r"(?i)\bDebian\b"), 4),
        (re.compile(r"(?i)\bCentOS\b"), 4),
        (re.compile(r"(?i)\bsshd\b"), 3),
        (re.compile(r"(?i)\bsystemd\b"), 3),
        (re.compile(r"(?i)\bbash\b"), 2),
    ],

    "AWS": [
        (re.compile(r"(?i)\baws\b"), 5),
        (re.compile(r"(?i)\baws_access_key_id\b"), 5),
        (re.compile(r"(?i)\baws_secret_access_key\b"), 5),
        (re.compile(r"(?i)\biam\b"), 3),
        (re.compile(r"(?i)\bs3\b"), 3),
        (re.compile(r"(?i)\bec2\b"), 3),
        (re.compile(r"(?i)\bsts\b"), 3),
    ],

    "SECRETS": [
        (re.compile(r"(?i)\bprivate key\b"), 5),
        (re.compile(r"(?i)\bprivate_key\b"), 5),
        (re.compile(r"(?i)\bsecret\b"), 3),
        (re.compile(r"(?i)\bcredential"), 3),
        (re.compile(r"(?i)\btoken\b"), 2),
    ],

    "PII": [
        (re.compile(r"(?i)\bcredit card\b"), 5),
        (re.compile(r"(?i)\bemail\b"), 3),
        (re.compile(r"(?i)\bpersonal data\b"), 5),
    ],
}


def detect_profile(text: str) -> ProfileResult:
    explicit_profile = detect_explicit_document_hint(text)

    scores = {
        profile: 0
        for profile in PROFILES
        if profile != "GENERIC"
    }

    if explicit_profile is not None:
        return ProfileResult(
            name=explicit_profile,
            scores=scores,
            confidence=1.0,
        )

    for profile, signatures in PROFILE_SIGNATURES.items():
        for pattern, weight in signatures:
            if pattern.search(text):
                scores[profile] += weight

    best_profile = max(
       (
        "NMAP",
        "BURP",
        "GOBUSTER",
        "NUCLEI",
        "WINDOWS",
        "LINUX",
        "AWS",
        "SECRETS",
        "PII",
    ),
    key=lambda profile: scores[profile],
)

    best_score = scores[best_profile]
    total_score = sum(scores.values())

    if best_score <= 0:
        return ProfileResult(
            name="GENERIC",
            scores=scores,
            confidence=0.0,
        )

    # Confidence is intentionally conservative.
    # It represents the share of detected profile evidence
    # belonging to the winning profile.
    confidence = best_score / total_score

    return ProfileResult(
        name=best_profile,
        scores=scores,
        confidence=confidence,
    )
