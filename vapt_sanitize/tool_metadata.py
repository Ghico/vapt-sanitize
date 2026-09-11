import re


_NMAP_BANNER_RE = re.compile(
    r"(?im)^Starting\s+Nmap\b[^\r\n]*"
    r"\(\s*https?://nmap\.org/?\s*\)"
    r"[^\r\n]*$"
)

_GOBUSTER_WORDLIST_LINE_RE = re.compile(
    r"(?im)^\[\+\]\s+Wordlist:\s+[^\r\n]+$"
)

_GOBUSTER_RESULT_PATH_RE = re.compile(
    r"(?m)^/\S*(?=\s+\(Status:\s*\d+\))"
)


_NUCLEI_REFERENCE_LINE_RE = re.compile(
    r"(?im)^\[INF\]\s+Reference:\s+https?://[^\r\n]+$"
)

_NUCLEI_TEMPLATE_REPOSITORY_LINE_RE = re.compile(
    r"(?im)^\[INF\]\s+Template repository:\s+https?://[^\r\n]+$"
)

_NUCLEI_URL_PATH_RE = re.compile(
    r"(?i)https?://[^/\s\]]+(?P<path>/[^\s\]]*)"
)

_WINDOWS_FILE_TOKEN_RE = re.compile(
    r"(?i)\b(?:[A-Za-z0-9_-]+\.)+"
    r"(?:bak|config|exe|dll|sys|ps1|psm1|bat|cmd|vbs|ini|xml|json|yml|yaml)\b"
)




_AWS_HANDLER_VALUE_RE = re.compile(
    r'(?im)^[ \t]*["\']Handler["\'][ \t]*:[ \t]*["\']'
    r'(?P<value>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)'
    r'["\'][ \t]*,?[ \t]*$'
)

_LINUX_FILE_TOKEN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9-])(?:[A-Za-z0-9_-]+\.)+"
    r"(?:conf|config|yml|yaml|service|slice|socket|target|timer|mount|path|"
    r"scope|automount|swap|rules|ini|json|xml|toml|properties|log|bak)\b"
)

_PII_PUBLIC_REFERENCE_LINE_RE = re.compile(
    r"(?im)^\s*Public reference:[ \t]+https?://[^\r\n]+$"
)

_GENERIC_PUBLIC_REFERENCE_LINE_RE = re.compile(
    r"(?im)^\s*(?:OWASP|NVD|Vendor docs|Public reference|Reference|Documentation)"
    r":[ \t]+https?://[^\r\n]+$"
)

# Public AWS control-plane/service endpoints. Deliberately narrow: this is
# only used for explicit ``Endpoint:`` metadata in GENERIC input, and the
# service label must be from this fixed set. Customer-specific AWS hostnames
# such as EC2 public DNS names are not protected by this rule.
_GENERIC_AWS_PUBLIC_SERVICE_ENDPOINT_RE = re.compile(
    r"(?im)^[ \t]*Endpoint:[ \t]+(?:https?://)?"
    r"(?P<host>"
    r"(?:ec2|ec2-fips|ecs|eks|elasticloadbalancing|autoscaling|"
    r"iam|sts|sts-fips|lambda|logs|monitoring|cloudwatch|"
    r"ssm|kms|secretsmanager|rds|dynamodb|sns|sqs|"
    r"cloudformation|cloudtrail|events|ecr|s3|s3-control)"
    r"(?:\.[a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?"
    r")(?::\d+)?(?:/[^\r\n]*)?[ \t]*$"
)

_GENERIC_PATH_FILE_TOKEN_RE = re.compile(
    r"(?i)(?:(?<=/)|(?<=\\))"
    r"(?P<value>(?:[A-Za-z0-9_-]+\.)+"
    r"(?:conf|config|yml|yaml|json|xml|toml|ini|properties|log|bak|"
    r"exe|dll|sys|ps1|psm1|bat|cmd|vbs|sh|py|php|js|html?|txt|"
    r"pem|key|crt|cer|pub|service|socket|target|timer|mount|path|slice))\b"
)


def protected_tool_metadata_ranges(
    text: str,
    profile: str,
) -> list[tuple[int, int]]:
    """
    Return ranges that belong to known tool-generated metadata.

    These ranges are not target/customer data and should not be
    pseudonymized merely because they happen to match a generic
    detector. Protection is deliberately profile- and context-specific.
    """

    normalized_profile = profile.upper()

    if normalized_profile == "NMAP":
        return [
            match.span()
            for match in _NMAP_BANNER_RE.finditer(text)
        ]

    if normalized_profile == "GOBUSTER":
        ranges = [
            match.span()
            for match in _GOBUSTER_WORDLIST_LINE_RE.finditer(text)
        ]

        ranges.extend(
            match.span()
            for match in _GOBUSTER_RESULT_PATH_RE.finditer(text)
        )

        return ranges

    if normalized_profile == "NUCLEI":
        ranges = [
            match.span()
            for match in _NUCLEI_REFERENCE_LINE_RE.finditer(text)
        ]

        ranges.extend(
            match.span()
            for match in _NUCLEI_TEMPLATE_REPOSITORY_LINE_RE.finditer(text)
        )

        ranges.extend(
            match.span("path")
            for match in _NUCLEI_URL_PATH_RE.finditer(text)
        )

        return ranges

    if normalized_profile == "WINDOWS":
        return [
            match.span()
            for match in _WINDOWS_FILE_TOKEN_RE.finditer(text)
        ]

    if normalized_profile == "LINUX":
        return [
            match.span()
            for match in _LINUX_FILE_TOKEN_RE.finditer(text)
        ]

    if normalized_profile == "AWS":
        return [
            match.span("value")
            for match in _AWS_HANDLER_VALUE_RE.finditer(text)
        ]

    if normalized_profile == "PII":
        return [
            match.span()
            for match in _PII_PUBLIC_REFERENCE_LINE_RE.finditer(text)
        ]

    if normalized_profile == "GENERIC":
        ranges = [
            match.span()
            for match in _GENERIC_PUBLIC_REFERENCE_LINE_RE.finditer(text)
        ]
        ranges.extend(
            match.span("host")
            for match in _GENERIC_AWS_PUBLIC_SERVICE_ENDPOINT_RE.finditer(text)
        )
        ranges.extend(
            match.span("value")
            for match in _GENERIC_PATH_FILE_TOKEN_RE.finditer(text)
        )
        return ranges

    return []


def finding_is_protected_tool_metadata(
    *,
    text: str,
    profile: str,
    category: str,
    start: int,
    end: int,
) -> bool:
    """
    Decide whether a finding belongs entirely to protected tool metadata.

    Only HOSTNAME findings inside narrowly defined, profile-specific tool
    metadata or path regions are exempted. Secrets are never exempted here.
    """

    if category != "HOSTNAME":
        return False

    return any(
        start >= protected_start
        and end <= protected_end
        for protected_start, protected_end
        in protected_tool_metadata_ranges(
            text,
            profile,
        )
    )
