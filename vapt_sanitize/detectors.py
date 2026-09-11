import ipaddress
import re

from .models import Finding
from .policy import Policy


PATTERNS = {
    "EMAIL": {
        "regex": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "severity": "medium",
        "action": "pseudonymize",
    },

    "PRIVATE_IP": {
        "regex": re.compile(
            r"\b(?:"
            r"10\.(?:\d{1,3}\.){2}\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3}"
            r"|192\.168\.(?:\d{1,3}\.)\d{1,3}"
            r")\b"
        ),
        "severity": "medium",
        "action": "pseudonymize",
    },

    "PASSWORD": {
        "regex": re.compile(
            r"(?im)(?<![A-Za-z0-9])['\"]?"
            r"(?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd)['\"]?"
            r"[ \t]*(?:=|:)[ \t]*['\"]?"
            r"([^'\"\s,;]+)"
        ),
        "severity": "critical",
        "action": "redact",
        "replace_group": 1,
    },

    "BEARER_TOKEN": {
        "regex": re.compile(
            r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"
        ),
        "severity": "critical",
        "action": "redact",
    },

    "SESSION": {
        "regex": re.compile(
            r"(?i)\b(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session(?:_?id)?)"
            r"[ \t]*=[ \t]*[A-Za-z0-9._~+/=\-]+"
        ),
        "severity": "critical",
        "action": "redact",
    },

    "JWT": {
        "regex": re.compile(
            r"\beyJ[A-Za-z0-9_-]{5,}"
            r"\.[A-Za-z0-9_-]{5,}"
            r"\.[A-Za-z0-9_-]{5,}\b"
        ),
        "severity": "critical",
        "action": "redact",
    },

    "API_KEY": {
        "regex": re.compile(
            r"(?im)(?<![A-Za-z0-9])['\"]?"
            r"(?:[A-Za-z0-9]+[_-])*api[_-]?key['\"]?"
            r"[ \t]*(?:=|:)[ \t]*['\"]?"
            r"([A-Za-z0-9._~+/=\-]{8,})"
        ),
        "severity": "critical",
        "action": "redact",
        "replace_group": 1,
    },

    "AWS_ACCESS_KEY": {
        "regex": re.compile(
            r"\b(?:AKIA|ASIA)[0-9A-Z]{12,28}\b"
        ),
        "severity": "critical",
        "action": "redact",
    },

    "AWS_SECRET_KEY": {
        "regex": re.compile(
            r"(?im)(?:"
            r"\bAWS_SECRET_ACCESS_KEY"
            r"|[\"']?SecretAccessKey[\"']?"
            r"|^[ \t]*secret_key"
            r")"
            r"[ \t]*(?:=|:)?[ \t]*[\"']?"
            r"([A-Za-z0-9+/=_\-]{20,})"
        ),
        "severity": "critical",
        "action": "redact",
        "replace_group": 1,
    },

    "AWS_SESSION_TOKEN": {
        "regex": re.compile(
            r"(?im)(?:"
            r"\bAWS_(?:SESSION|SECURITY)_TOKEN"
            r"|[\"']Token[\"']"
            r")"
            r"[ \t]*(?:=|:)[ \t]*[\"']?"
            r"([A-Za-z0-9+/=_.\-]{20,})"
        ),
        "severity": "critical",
        "action": "redact",
        "replace_group": 1,
    },

    "AUTH_CREDENTIAL": {
        "regex": re.compile(
            r"(?im)^(?:Proxy-)?Authorization:[ \t]*"
            r"(?:Basic|Token|ApiKey|Digest)[ \t]+([^\r\n]+)"
        ),
        "severity": "critical",
        "action": "redact",
        "replace_group": 1,
    },

    "DATABASE_PASSWORD": {
        "regex": re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss)://"
            r"(?:[^:@/\s]+)?:([^@/\s]+)@"
        ),
        "severity": "critical",
        "action": "redact",
        "replace_group": 1,
    },

    "PROVIDER_TOKEN": {
        "regex": re.compile(
            r"\b(?:"
            r"gh[pousr]_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{20,}"
            r"|glpat-[A-Za-z0-9_-]{20,}"
            r"|xox[baprs]-[A-Za-z0-9-]{20,}"
            r")\b"
        ),
        "severity": "critical",
        "action": "redact",
    },

    "GENERIC_SECRET": {
        "regex": re.compile(
            r"(?im)(?<![A-Za-z0-9_./:-])['\"]?"
            r"(?:"
            r"(?:[A-Za-z0-9]+[_-])*(?:secret|token|session)"
            r"|clientSecret|accessToken|refreshToken|bearerToken"
            r")[\"']?[ \t]*(?:=|:)[ \t]*[\"']?"
            r"((?!\[[A-Z0-9_]+_(?:REDACTED|\d{3})\])[^'\"\s,;]+)"
        ),
        "severity": "critical",
        "action": "redact",
        "replace_group": 1,
    },

    "AWS_ACCOUNT_ID": {
        "regex": re.compile(r"\b\d{12}\b"),
        "severity": "medium",
        "action": "pseudonymize",
        "profiles": {"AWS"},
    },

    "AWS_RESOURCE_ID": {
        "regex": re.compile(
            r"\b(?:"
            r"i|ami|vpc|subnet|sg|eni|vol|snap|rtb|igw|nat|"
            r"eipalloc|acl|vpce|pcx|tgw|lt|fs"
            r")-[0-9a-f]{8,32}\b",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "action": "pseudonymize",
        "profiles": {"AWS"},
    },

    "AWS_PRINCIPAL_ID": {
        "regex": re.compile(
            r"\b(?:AIDA|AIPA|AROA|ANPA|AGPA|ASCA)[A-Z0-9]{8,32}\b"
        ),
        "severity": "medium",
        "action": "pseudonymize",
        "profiles": {"AWS"},
    },

    "PRIVATE_KEY": {
        "regex": re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            r".*?"
            r"-----END "
            r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "severity": "critical",
        "action": "redact",
    },

    "WINDOWS_SID": {
        "regex": re.compile(
            r"\bS-1-5-21-(?:\d+-){3}\d+\b"
        ),
        "severity": "medium",
        "action": "pseudonymize",
        "profiles": {"WINDOWS"},
    },

    "MAC_ADDRESS": {
        "regex": re.compile(
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}"
            r"[0-9A-Fa-f]{2}\b"
        ),
        "severity": "medium",
        "action": "pseudonymize",
    },

    "CREDIT_CARD": {
        "regex": re.compile(
            r"\b(?:"
            r"\d{4}[- ]?"
            r"\d{4}[- ]?"
            r"\d{4}[- ]?"
            r"\d{4}"
            r")\b"
        ),
        "severity": "high",
        "action": "redact",
    },

    "USERNAME": {
        "regex": re.compile(
            r'(?i)(?<![A-Za-z0-9_])'
            r'"?username"?\s*(?::|=)\s*"?'
            r'([A-Za-z0-9._-]{2,64})"?'
        ),
        "severity": "medium",
        "action": "pseudonymize",
        "replace_group": 1,
    },

    "HOSTNAME": {
        "regex": re.compile(
            r"\b(?:"
            r"[A-Za-z0-9]"
            r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"\.)+"
            r"[A-Za-z]{2,63}"
            r"\b"
        ),
        "severity": "medium",
        "action": "pseudonymize",
    },
}


_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)

_LINUX_ID_RE = re.compile(
    r"(?im)^\s*(?:Machine ID|Boot ID):[ \t]*"
    r"(?P<value>[0-9a-f]{32})[ \t]*$"
)

_LINUX_STATIC_HOST_RE = re.compile(
    r"(?im)^\s*Static hostname:[ \t]*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62})[ \t]*$"
)

_LINUX_HOSTS_LINE_RE = re.compile(
    r"(?m)^[ \t]*(?:\d{1,3}\.){3}\d{1,3}[ \t]+"
    r"(?P<hosts>[^#\r\n]+)"
)

_LINUX_SUDO_HOST_PATTERNS = (
    re.compile(
        r"(?im)^Matching Defaults entries for[ \t]+\S+[ \t]+on[ \t]+"
        r"(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62}):"
    ),
    re.compile(
        r"(?im)^User[ \t]+\S+[ \t]+may run the following commands on[ \t]+"
        r"(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62}):"
    ),
)

_LINUX_STANDARD_ACCOUNTS = {
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "_apt",
    "messagebus",
    "systemd-network",
    "systemd-timesync",
    "sshd",
    "nginx",
    "postgres",
}

_LINUX_USERNAME_TOKEN_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_-]{0,31}"
)


_AWS_IAM_NAME_PATTERNS = (
    re.compile(r"(?im)(?<!\\S)--user-name[ \\t]+(?P<value>[A-Za-z0-9+=,.@_/-]+)"),
    re.compile(
        r"arn:aws(?:-[a-z]+)?:iam::\d{12}:"
        r"(?:user|role|instance-profile)/"
        r"(?P<value>[A-Za-z0-9+=,.@_/-]+)"
    ),
    re.compile(
        r"(?i)/latest/meta-data/iam/security-credentials/"
        r"(?P<value>[A-Za-z0-9+=,.@_-]+)"
    ),
)

_AWS_FUNCTION_NAME_PATTERNS = (
    re.compile(
        r"(?im)^[ \t]*[\"']FunctionName[\"'][ \t]*:[ \t]*[\"']"
        r"(?P<value>[^\"'\r\n]+)[\"']"
    ),
    re.compile(
        r"arn:aws(?:-[a-z]+)?:lambda:[^:\s]+:\d{12}:function:"
        r"(?P<value>[A-Za-z0-9-_./]+)"
    ),
)

_AWS_SECURITY_GROUP_NAME_RE = re.compile(
    r"(?im)^[ \t]*[\"']GroupName[\"'][ \t]*:[ \t]*[\"']"
    r"(?P<value>[^\"'\r\n]+)[\"']"
)

_AWS_TAG_NAME_RE = re.compile(
    r"(?i)[{][ \t]*[\"']Key[\"'][ \t]*:[ \t]*[\"']Name[\"']"
    r"[ \t]*,[ \t]*[\"']Value[\"'][ \t]*:[ \t]*[\"']"
    r"(?P<value>[^\"'\r\n]+)[\"']"
)

_AWS_DISPLAY_NAME_RE = re.compile(
    r"(?i)[\"']DisplayName[\"'][ \t]*:[ \t]*[\"']"
    r"(?P<value>[^\"'\r\n]+)[\"']"
)

_AWS_OWNER_BLOCK_RE = re.compile(
    r"(?is)[\"']Owner[\"'][ \t]*:[ \t]*[{](?P<body>.*?)[}]"
)

_AWS_LONG_ID_RE = re.compile(
    r"(?i)[\"']ID[\"'][ \t]*:[ \t]*[\"']"
    r"(?P<value>[A-Za-z0-9]{24,128})[\"']"
)

_AWS_BUCKETS_BLOCK_RE = re.compile(
    r"(?is)[\"']Buckets[\"'][ \t]*:[ \t]*\[(?P<body>.*?)\]"
)

_AWS_SECRET_LIST_BLOCK_RE = re.compile(
    r"(?is)[\"']SecretList[\"'][ \t]*:[ \t]*\[(?P<body>.*?)\]"
)

_AWS_NAME_VALUE_RE = re.compile(
    r"(?i)[\"']Name[\"'][ \t]*:[ \t]*[\"']"
    r"(?P<value>[^\"'\r\n]+)[\"']"
)

_AWS_BUCKET_COMMAND_RE = re.compile(
    r"(?im)(?<!\\S)--bucket[ \\t]+(?P<value>[A-Za-z0-9][A-Za-z0-9.-]{1,62})"
)

_AWS_SECRET_ARN_RE = re.compile(
    r"arn:aws(?:-[a-z]+)?:secretsmanager:[^:\s]+:\d{12}:secret:"
    r"(?P<value>[^\s\"']+)"
)


_AWS_CLI_SESSION_TOKEN_RE = re.compile(
    r"(?im)^[ \t]*session_token[ \t]*(?:=|:)[ \t]*[\"']?"
    r"(?P<value>[A-Za-z0-9+/=_.-]{20,})"
)

_GENERIC_CONTEXT_USERNAME_PATTERNS = (
    re.compile(
        r"(?im)\b(?:user|db_user)[ \t]*=[ \t]*"
        r"(?P<value>[A-Za-z0-9._-]{2,64})"
    ),
    re.compile(
        r"(?i)(?<=/home/)"
        r"(?P<value>[A-Za-z0-9._-]{2,64})(?=/)"
    ),
    re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss)://"
        r"(?P<value>[^:@/\s]+):"
    ),
)


_GENERIC_IDENTITY_JSON_RE = re.compile(
    r"[{](?P<body>[^{}]{0,4096})[}]",
    re.DOTALL,
)

_GENERIC_IDENTITY_HINT_RE = re.compile(
    r"(?i)[\"'](?:username|email|phone|mobile|employee_id|customer_id)[\"']\s*:"
)

_GENERIC_JSON_NAME_RE = re.compile(
    r"(?i)[\"']name[\"'][ \t]*:[ \t]*[\"'](?P<value>[^\"'\r\n]+)[\"']"
)

_GENERIC_RECORD_ID_PATTERNS = (
    re.compile(
        r"(?im)^\s*Employee ID:[ \t]*(?P<value>[A-Za-z0-9][A-Za-z0-9._-]+)\s*$"
    ),
    re.compile(
        r"(?i)[\"']employee_id[\"'][ \t]*:[ \t]*[\"'](?P<value>[^\"'\r\n]+)[\"']"
    ),
    re.compile(
        r"(?i)[\"']customer_id[\"'][ \t]*:[ \t]*[\"'](?P<value>[^\"'\r\n]+)[\"']"
    ),
    re.compile(
        r"(?im)^(?:employee_id|customer_id)[ \t]*=[ \t]*(?P<value>[^\s\r\n]+)[ \t]*$"
    ),
)

_PII_FISCAL_CODE_RE = re.compile(
    r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b",
    re.IGNORECASE,
)

_PII_IBAN_RE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[ \t]?[A-Z0-9]){11,30}\b",
    re.IGNORECASE,
)

_PII_FIELD_PATTERNS = {
    "PERSON_NAME": (
        re.compile(r"(?im)^\s*Full Name:[ \t]*(?P<value>[^\r\n]+?)\s*$"),
        re.compile(r"(?im)^\s*Cardholder:[ \t]*(?P<value>[^\r\n]+?)\s*$"),
        re.compile(r'(?i)["\']name["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
        re.compile(r'(?i)["\']first_name["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
        re.compile(r'(?i)["\']last_name["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
        re.compile(r"(?im)^(?:first_name|last_name)[ \t]*=[ \t]*(?P<value>[^\s\r\n]+)"),
        re.compile(r'(?im)\bcontact=["\'](?P<value>[^<>"\'\r\n]+?)[ \t]*<'),
    ),
    "PHONE": (
        re.compile(r"(?im)^\s*(?:Office Phone|Phone):[ \t]*(?P<value>\+?\d[\d .()\-/]{6,}\d)\s*$"),
        re.compile(r'(?i)["\'](?:phone|mobile)["\'][ \t]*:[ \t]*["\'](?P<value>\+?\d[\d .()\-/]{6,}\d)["\']'),
        re.compile(r"(?im)\bphone[ \t]*=[ \t]*(?P<value>\+?\d[\d .()\-/]{6,}\d)(?=$|[ \t])"),
    ),
    "DATE_OF_BIRTH": (
        re.compile(r"(?im)^\s*(?:Date of Birth|DOB|Birth Date):[ \t]*(?P<value>\d{1,2}[/-]\d{1,2}[/-]\d{4})\s*$"),
        re.compile(r'(?i)["\'](?:date_of_birth|dob|birth_date)["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
    ),
    "FISCAL_CODE": (
        re.compile(r"(?im)^\s*(?:Fiscal Code|Tax ID|National ID):[ \t]*(?P<value>[^\s\r\n]+)\s*$"),
        re.compile(r'(?i)["\'](?:fiscal_code|tax_id|national_id)["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
        re.compile(r"(?im)^(?:fiscal_code|tax_id|national_id)[ \t]*=[ \t]*(?P<value>[^\s\r\n]+)[ \t]*$"),
    ),
    "PII_RECORD_ID": (
        re.compile(r"(?im)^\s*Employee ID:[ \t]*(?P<value>[A-Za-z0-9][A-Za-z0-9._-]+)\s*$"),
        re.compile(r'(?i)["\']customer_id["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
        re.compile(r"(?im)\bcustomer[ \t]*=[ \t]*(?P<value>[A-Za-z0-9][A-Za-z0-9._-]+)"),
        re.compile(r"(?i)/customers/(?P<value>\d+)\b"),
        re.compile(r"(?im)^id[ \t]*=[ \t]*(?P<value>[A-Za-z0-9][A-Za-z0-9._-]+)[ \t]*$"),
    ),
    "ADDRESS": (
        re.compile(r'(?i)["\']address["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
        re.compile(r'(?im)^address[ \t]*=[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
    ),
    "CITY": (
        re.compile(r'(?i)["\']city["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
    ),
    "POSTAL_CODE": (
        re.compile(r'(?i)["\']postal_code["\'][ \t]*:[ \t]*["\'](?P<value>[^"\'\r\n]+)["\']'),
    ),
}

_PII_CONTEXT_USERNAME_PATTERNS = (
    re.compile(r"(?im)\buser[ \t]*=[ \t]*(?P<value>[A-Za-z0-9._-]{2,64})"),
)

_WINDOWS_STANDARD_NAMESPACES = {
    "BUILTIN",
}


_WINDOWS_DOMAIN_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9_.\\-])"
    r"(?P<value>[A-Za-z][A-Za-z0-9-]{1,14})"
    r"(?=\\[A-Za-z0-9])"
)


_WINDOWS_CONTEXT_HOST_PATTERNS = (
    re.compile(
        r"(?im)^\s*Host Name:\s*(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62})\s*$"
    ),
    re.compile(
        r"(?im)^\s*Logon Server:\s*\\\\(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62})\s*$"
    ),
    re.compile(
        r"\\\\(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62})\\"
    ),
    re.compile(
        r"(?im)^\s*ComputerName\s*:\s*(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62})\s*$"
    ),
    re.compile(
        r"(?im)\bTest-NetConnection\s+(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62})\s+-Port\b"
    ),
    re.compile(
        r"(?m)^(?P<value>[A-Za-z0-9][A-Za-z0-9-]{0,62})[ \t]+\S+[ \t]+[A-Za-z][A-Za-z0-9-]{1,14}\\[A-Za-z0-9._$-]+[ \t]+[A-Za-z][A-Za-z0-9-]{1,14}\\[A-Za-z0-9._$-]+[ \t]*$"
    ),
)


def _contextual_private_ipv6_findings(
    text: str,
    profile: str,
    policy: Policy,
) -> list[Finding]:
    """Pseudonymize IPv6 ULA/link-local addresses, but preserve ::/::1."""

    action, reason = policy.explain(
        profile=profile,
        category="PRIVATE_IPV6",
        default_action="pseudonymize",
    )

    findings = []
    ula_network = ipaddress.ip_network("fc00::/7")

    for match in _IPV6_CANDIDATE_RE.finditer(text):
        value = match.group(0)

        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue

        if address.version != 6:
            continue

        if address.is_loopback or address.is_unspecified:
            continue

        if not (address.is_link_local or address in ula_network):
            continue

        findings.append(
            Finding(
                category="PRIVATE_IPV6",
                original=value,
                replacement="",
                severity="medium",
                start=match.start(),
                end=match.end(),
                action=action,
                profile=profile,
                reason=reason,
            )
        )

    return findings


def _contextual_linux_id_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    action, reason = policy.explain(
        profile="LINUX",
        category="LINUX_ID",
        default_action="pseudonymize",
    )

    return [
        Finding(
            category="LINUX_ID",
            original=match.group("value"),
            replacement="",
            severity="medium",
            start=match.start("value"),
            end=match.end("value"),
            action=action,
            profile="LINUX",
            reason=reason,
        )
        for match in _LINUX_ID_RE.finditer(text)
    ]


def _contextual_linux_hostname_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    action, reason = policy.explain(
        profile="LINUX",
        category="HOSTNAME",
        default_action="pseudonymize",
    )

    findings = []
    seen_spans = set()

    def add(start: int, end: int, value: str) -> None:
        if (start, end) in seen_spans:
            return
        if value.lower() == "localhost":
            return
        seen_spans.add((start, end))
        findings.append(
            Finding(
                category="HOSTNAME",
                original=value,
                replacement="",
                severity="medium",
                start=start,
                end=end,
                action=action,
                profile="LINUX",
                reason=reason,
            )
        )

    for match in _LINUX_STATIC_HOST_RE.finditer(text):
        add(match.start("value"), match.end("value"), match.group("value"))

    for pattern in _LINUX_SUDO_HOST_PATTERNS:
        for match in pattern.finditer(text):
            add(match.start("value"), match.end("value"), match.group("value"))

    for match in _LINUX_HOSTS_LINE_RE.finditer(text):
        hosts_start = match.start("hosts")
        hosts_text = match.group("hosts")
        for token in re.finditer(r"\S+", hosts_text):
            value = token.group(0)
            # Dotted hostnames are already handled by the generic HOSTNAME
            # detector; short aliases need Linux /etc/hosts context.
            if "." in value:
                continue
            add(
                hosts_start + token.start(),
                hosts_start + token.end(),
                value,
            )

    return findings


def _contextual_linux_username_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    """
    Pseudonymize environment-specific Linux accounts while preserving
    well-known system/service accounts that carry technical meaning.
    """

    action, reason = policy.explain(
        profile="LINUX",
        category="USERNAME",
        default_action="pseudonymize",
    )

    candidate_names = set()

    whoami_re = re.compile(
        r"(?m)^\$[ \t]+whoami[ \t]*\r?\n"
        r"(?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})[ \t]*$"
    )
    for match in whoami_re.finditer(text):
        candidate_names.add(match.group("value"))

    for match in re.finditer(
        r"\buid=\d+\((?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})\)",
        text,
    ):
        candidate_names.add(match.group("value"))

    allow_users_re = re.compile(r"(?im)^AllowUsers[ \t]+(?P<values>[^#\r\n]+)")
    for match in allow_users_re.finditer(text):
        candidate_names.update(_LINUX_USERNAME_TOKEN_RE.findall(match.group("values")))

    for match in re.finditer(
        r"(?im)^Matching Defaults entries for[ \t]+"
        r"(?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})[ \t]+on\b",
        text,
    ):
        candidate_names.add(match.group("value"))

    for match in re.finditer(
        r"(?im)^User[ \t]+(?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})"
        r"[ \t]+may run the following commands on\b",
        text,
    ):
        candidate_names.add(match.group("value"))

    candidate_names = {
        name
        for name in candidate_names
        if name.lower() not in _LINUX_STANDARD_ACCOUNTS
    }

    if not candidate_names:
        return []

    findings = []
    seen_spans = set()

    def add_span(start: int, end: int, value: str) -> None:
        if value not in candidate_names or (start, end) in seen_spans:
            return
        seen_spans.add((start, end))
        findings.append(
            Finding(
                category="USERNAME",
                original=value,
                replacement="",
                severity="medium",
                start=start,
                end=end,
                action=action,
                profile="LINUX",
                reason=reason,
            )
        )

    # Known account-bearing contexts.
    context_patterns = (
        re.compile(
            r"(?m)^\$[ \t]+whoami[ \t]*\r?\n"
            r"(?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})[ \t]*$"
        ),
        re.compile(r"\b(?:uid|gid)=\d+\((?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})\)"),
        re.compile(r"\b\d+\((?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})\)"),
        re.compile(
            r"(?im)^Matching Defaults entries for[ \t]+"
            r"(?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})[ \t]+on\b"
        ),
        re.compile(
            r"(?im)^User[ \t]+(?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})"
            r"[ \t]+may run the following commands on\b"
        ),
        re.compile(r"(?<=/home/)(?P<value>[A-Za-z_][A-Za-z0-9_-]{0,31})(?=/)"),
    )

    for pattern in context_patterns:
        for match in pattern.finditer(text):
            add_span(match.start("value"), match.end("value"), match.group("value"))

    for match in allow_users_re.finditer(text):
        values_start = match.start("values")
        for token in _LINUX_USERNAME_TOKEN_RE.finditer(match.group("values")):
            add_span(
                values_start + token.start(),
                values_start + token.end(),
                token.group(0),
            )

    # Owner/group columns in long ls output. Only replace names already
    # identified as environment-specific accounts above.
    ls_line_re = re.compile(
        r"(?m)^[bcdlps-][rwxStTs-]{9}[+.]?[ \t]+\d+[ \t]+"
        r"(?P<owner>\S+)[ \t]+(?P<group>\S+)[ \t]+"
    )
    for match in ls_line_re.finditer(text):
        for group_name in ("owner", "group"):
            value = match.group(group_name)
            add_span(match.start(group_name), match.end(group_name), value)

    return findings


def _contextual_aws_identifier_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    """Pseudonymize customer-specific AWS names while retaining cloud structure."""

    findings = []
    seen = set()

    def add(category: str, start: int, end: int, value: str) -> None:
        key = (category, start, end)
        if key in seen:
            return
        seen.add(key)
        action, reason = policy.explain(
            profile="AWS",
            category=category,
            default_action="pseudonymize",
        )
        findings.append(
            Finding(
                category=category,
                original=value,
                replacement="",
                severity="medium",
                start=start,
                end=end,
                action=action,
                profile="AWS",
                reason=reason,
            )
        )

    for pattern in _AWS_IAM_NAME_PATTERNS:
        for match in pattern.finditer(text):
            add("AWS_IAM_NAME", match.start("value"), match.end("value"), match.group("value"))

    for pattern in _AWS_FUNCTION_NAME_PATTERNS:
        for match in pattern.finditer(text):
            add("AWS_FUNCTION_NAME", match.start("value"), match.end("value"), match.group("value"))

    for match in _AWS_SECURITY_GROUP_NAME_RE.finditer(text):
        add("AWS_SECURITY_GROUP_NAME", match.start("value"), match.end("value"), match.group("value"))

    for match in _AWS_TAG_NAME_RE.finditer(text):
        add("AWS_TAG_NAME", match.start("value"), match.end("value"), match.group("value"))

    for match in _AWS_DISPLAY_NAME_RE.finditer(text):
        add("AWS_DISPLAY_NAME", match.start("value"), match.end("value"), match.group("value"))

    for match in _AWS_BUCKET_COMMAND_RE.finditer(text):
        add("AWS_BUCKET", match.start("value"), match.end("value"), match.group("value"))

    for block in _AWS_BUCKETS_BLOCK_RE.finditer(text):
        body_start = block.start("body")
        for match in _AWS_NAME_VALUE_RE.finditer(block.group("body")):
            add("AWS_BUCKET", body_start + match.start("value"), body_start + match.end("value"), match.group("value"))

    for block in _AWS_SECRET_LIST_BLOCK_RE.finditer(text):
        body_start = block.start("body")
        for match in _AWS_NAME_VALUE_RE.finditer(block.group("body")):
            add("AWS_SECRET_NAME", body_start + match.start("value"), body_start + match.end("value"), match.group("value"))

    for match in _AWS_SECRET_ARN_RE.finditer(text):
        add("AWS_SECRET_NAME", match.start("value"), match.end("value"), match.group("value"))

    for block in _AWS_OWNER_BLOCK_RE.finditer(text):
        body_start = block.start("body")
        for match in _AWS_LONG_ID_RE.finditer(block.group("body")):
            add("AWS_OWNER_ID", body_start + match.start("value"), body_start + match.end("value"), match.group("value"))

    return findings


def _contextual_windows_domain_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    """
    Detect environment-specific NetBIOS-style namespace prefixes such as
    CORP\\svc_web while preserving the account/group name after the slash.

    Standard Windows namespaces such as BUILTIN are deliberately preserved.
    Windows path components and UNC server names are excluded by context.
    """

    action, reason = policy.explain(
        profile="WINDOWS",
        category="WINDOWS_DOMAIN",
        default_action="pseudonymize",
    )

    findings = []

    for match in _WINDOWS_DOMAIN_PREFIX_RE.finditer(text):
        value = match.group("value")

        if value.upper() in _WINDOWS_STANDARD_NAMESPACES:
            continue

        # A token like ``Files\\Backup`` or ``Agent\\backup-agent.exe``
        # inside ``C:\\Program Files\\Backup Agent\\...`` is a path
        # component, not a NetBIOS domain.  If the candidate occurs on a line
        # that already contains a local drive-path prefix before the match,
        # preserve it as Windows path metadata.  UNC server names are already
        # excluded by the regex look-behind and handled by the hostname logic.
        line_start = text.rfind("\n", 0, match.start()) + 1
        prefix_on_line = text[line_start:match.start()]
        if re.search(r"(?i)(?:^|[ \t:=\"'])\b[A-Z]:\\", prefix_on_line):
            continue

        start, end = match.span("value")

        findings.append(
            Finding(
                category="WINDOWS_DOMAIN",
                original=value,
                replacement="",
                severity="medium",
                start=start,
                end=end,
                action=action,
                profile="WINDOWS",
                reason=reason,
            )
        )

    return findings


def _contextual_windows_hostname_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    action, reason = policy.explain(
        profile="WINDOWS",
        category="HOSTNAME",
        default_action="pseudonymize",
    )

    findings = []
    seen_spans = set()

    for pattern in _WINDOWS_CONTEXT_HOST_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span("value")
            if (start, end) in seen_spans:
                continue
            seen_spans.add((start, end))
            findings.append(
                Finding(
                    category="HOSTNAME",
                    original=match.group("value"),
                    replacement="",
                    severity="medium",
                    start=start,
                    end=end,
                    action=action,
                    profile="WINDOWS",
                    reason=reason,
                )
            )

    return findings


def _contextual_generic_username_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    """Pseudonymize high-confidence account identifiers in generic input."""

    action, reason = policy.explain(
        profile="GENERIC",
        category="USERNAME",
        default_action="pseudonymize",
    )

    findings = []
    seen = set()

    for pattern in _GENERIC_CONTEXT_USERNAME_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span("value")
            if (start, end) in seen:
                continue
            seen.add((start, end))
            findings.append(
                Finding(
                    category="USERNAME",
                    original=match.group("value"),
                    replacement="",
                    severity="medium",
                    start=start,
                    end=end,
                    action=action,
                    profile="GENERIC",
                    reason=reason,
                )
            )

    return findings



def _contextual_generic_pii_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    """Protect high-confidence personal identifiers in generic fallback data.

    Ambiguous technical ``name`` fields are preserved unless the same JSON
    object also contains identity-oriented keys such as username/email/phone.
    """

    findings = []
    seen = set()

    def add(category: str, start: int, end: int, value: str) -> None:
        key = (category, start, end)
        if key in seen:
            return
        seen.add(key)
        action, reason = policy.explain(
            profile="GENERIC",
            category=category,
            default_action="pseudonymize",
        )
        findings.append(
            Finding(
                category=category,
                original=value,
                replacement="",
                severity="medium",
                start=start,
                end=end,
                action=action,
                profile="GENERIC",
                reason=reason,
            )
        )

    for pattern in _PII_FIELD_PATTERNS["PHONE"]:
        for match in pattern.finditer(text):
            add(
                "PHONE",
                match.start("value"),
                match.end("value"),
                match.group("value").strip(),
            )

    for pattern in _GENERIC_RECORD_ID_PATTERNS:
        for match in pattern.finditer(text):
            add(
                "PII_RECORD_ID",
                match.start("value"),
                match.end("value"),
                match.group("value"),
            )

    for object_match in _GENERIC_IDENTITY_JSON_RE.finditer(text):
        body = object_match.group("body")
        if not _GENERIC_IDENTITY_HINT_RE.search(body):
            continue
        body_start = object_match.start("body")
        for name_match in _GENERIC_JSON_NAME_RE.finditer(body):
            add(
                "PERSON_NAME",
                body_start + name_match.start("value"),
                body_start + name_match.end("value"),
                name_match.group("value"),
            )

    return findings


def _contextual_aws_cli_session_token_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    """Handle AWS CLI's unprefixed ``session_token`` setting safely."""

    action, reason = policy.explain(
        profile="AWS",
        category="AWS_SESSION_TOKEN",
        default_action="redact",
    )

    return [
        Finding(
            category="AWS_SESSION_TOKEN",
            original=match.group("value"),
            replacement="",
            severity="critical",
            start=match.start("value"),
            end=match.end("value"),
            action=action,
            profile="AWS",
            reason=reason,
        )
        for match in _AWS_CLI_SESSION_TOKEN_RE.finditer(text)
    ]


def _contextual_pii_findings(
    text: str,
    policy: Policy,
) -> list[Finding]:
    """Detect direct personal identifiers in PII-oriented material."""

    findings = []
    seen = set()

    def add(category: str, start: int, end: int, value: str, default_action: str = "pseudonymize") -> None:
        key = (category, start, end)
        if key in seen:
            return
        seen.add(key)
        action, reason = policy.explain(
            profile="PII",
            category=category,
            default_action=default_action,
        )
        findings.append(
            Finding(
                category=category,
                original=value,
                replacement="",
                severity="high" if category in {"IBAN", "FISCAL_CODE"} else "medium",
                start=start,
                end=end,
                action=action,
                profile="PII",
                reason=reason,
            )
        )

    for match in _PII_FISCAL_CODE_RE.finditer(text):
        add("FISCAL_CODE", match.start(), match.end(), match.group(0))

    for match in _PII_IBAN_RE.finditer(text):
        add("IBAN", match.start(), match.end(), match.group(0), "redact")

    for category, patterns in _PII_FIELD_PATTERNS.items():
        for pattern in patterns:
            for match in pattern.finditer(text):
                value = match.group("value").strip()
                if not value:
                    continue
                value_start = match.start("value")
                # Preserve any whitespace excluded by strip() outside replacement.
                leading = len(match.group("value")) - len(match.group("value").lstrip())
                trailing = len(match.group("value")) - len(match.group("value").rstrip())
                start = value_start + leading
                end = match.end("value") - trailing
                add(
                    category,
                    start,
                    end,
                    value,
                    "redact" if category == "IBAN" else "pseudonymize",
                )

    action, reason = policy.explain(
        profile="PII",
        category="USERNAME",
        default_action="pseudonymize",
    )
    for pattern in _PII_CONTEXT_USERNAME_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span("value")
            key = ("USERNAME", start, end)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    category="USERNAME",
                    original=match.group("value"),
                    replacement="",
                    severity="medium",
                    start=start,
                    end=end,
                    action=action,
                    profile="PII",
                    reason=reason,
                )
            )

    return findings


def remove_overlapping_findings(
    findings: list[Finding],
) -> list[Finding]:

    priority = {
        "AWS_SESSION_TOKEN": 125,
        "AUTH_CREDENTIAL": 125,
        "DATABASE_PASSWORD": 125,
        "PROVIDER_TOKEN": 125,
        "PASSWORD": 125,
        "BEARER_TOKEN": 125,
        "JWT": 125,
        "PRIVATE_KEY": 125,
        "AWS_ACCESS_KEY": 125,
        "AWS_SECRET_KEY": 125,
        "API_KEY": 125,
        "GENERIC_SECRET": 120,
        "SESSION": 120,
        "IBAN": 115,
        "CREDIT_CARD": 110,
        "FISCAL_CODE": 105,
        "EMAIL": 90,
        "PHONE": 88,
        "PERSON_NAME": 86,
        "ADDRESS": 84,
        "DATE_OF_BIRTH": 82,
        "CITY": 80,
        "POSTAL_CODE": 79,
        "PII_RECORD_ID": 78,
        "PRIVATE_IP": 80,
        "PRIVATE_IPV6": 80,
        "USERNAME": 75,
        "MAC_ADDRESS": 70,
        "WINDOWS_SID": 65,
        "LINUX_ID": 65,
        "AWS_ACCOUNT_ID": 65,
        "AWS_RESOURCE_ID": 65,
        "AWS_PRINCIPAL_ID": 65,
        "AWS_IAM_NAME": 64,
        "AWS_BUCKET": 64,
        "AWS_FUNCTION_NAME": 64,
        "AWS_SECURITY_GROUP_NAME": 64,
        "AWS_TAG_NAME": 64,
        "AWS_DISPLAY_NAME": 64,
        "AWS_SECRET_NAME": 64,
        "AWS_OWNER_ID": 64,
        "HOSTNAME": 60,
        "WINDOWS_DOMAIN": 55,
    }

    findings = sorted(
        findings,
        key=lambda finding: (
            -priority.get(finding.category, 0),
            finding.start,
            -(finding.end - finding.start),
        ),
    )

    selected = []

    def effective_span(finding: Finding) -> tuple[int, int]:
        return (
            finding.replace_start
            if finding.replace_start is not None
            else finding.start,
            finding.replace_end
            if finding.replace_end is not None
            else finding.end,
        )

    for finding in findings:
        finding_start, finding_end = effective_span(finding)
        overlaps = any(
            finding_start < existing_end
            and finding_end > existing_start
            for existing_start, existing_end in (
                effective_span(existing)
                for existing in selected
            )
        )

        if not overlaps:
            selected.append(finding)

    return sorted(
        selected,
        key=lambda finding: finding.start,
    )


def detect(
    text: str,
    profile: str = "GENERIC",
    policy: Policy | None = None,
) -> list[Finding]:

    if policy is None:
        policy = Policy()

    findings = []

    for category, config in PATTERNS.items():

        allowed_profiles = config.get("profiles")

        if (
            allowed_profiles is not None
            and profile not in allowed_profiles
        ):
            continue

        for match in config["regex"].finditer(text):

            if category == "MAC_ADDRESS":
                normalized_mac = match.group(0).lower().replace("-", ":")
                if normalized_mac in {
                    "ff:ff:ff:ff:ff:ff",
                    "00:00:00:00:00:00",
                }:
                    continue

            replace_start = None
            replace_end = None

            replace_group = config.get("replace_group")

            if replace_group is not None:
                replace_start = match.start(replace_group)
                replace_end = match.end(replace_group)

            action, reason = policy.explain(
                profile=profile,
                category=category,
                default_action=config["action"],
            )

            original_value = (
                match.group(replace_group)
                if replace_group is not None
                else match.group(0)
            )

            findings.append(
                Finding(
                    category=category,
                    original=original_value,
                    replacement="",
                    severity=config["severity"],
                    start=match.start(),
                    end=match.end(),
                    action=action,
                    replace_start=replace_start,
                    replace_end=replace_end,
                    profile=profile,
                    reason=reason,
                )
            )

    findings.extend(
        _contextual_private_ipv6_findings(
            text,
            profile,
            policy,
        )
    )

    if profile == "AWS":
        findings.extend(
            _contextual_aws_identifier_findings(
                text,
                policy,
            )
        )
        findings.extend(
            _contextual_aws_cli_session_token_findings(
                text,
                policy,
            )
        )

    if profile == "WINDOWS":
        findings.extend(
            _contextual_windows_hostname_findings(
                text,
                policy,
            )
        )
        findings.extend(
            _contextual_windows_domain_findings(
                text,
                policy,
            )
        )

    if profile == "LINUX":
        findings.extend(
            _contextual_linux_id_findings(
                text,
                policy,
            )
        )
        findings.extend(
            _contextual_linux_hostname_findings(
                text,
                policy,
            )
        )
        findings.extend(
            _contextual_linux_username_findings(
                text,
                policy,
            )
        )

    if profile == "PII":
        findings.extend(
            _contextual_pii_findings(
                text,
                policy,
            )
        )

    if profile == "GENERIC":
        findings.extend(
            _contextual_generic_username_findings(
                text,
                policy,
            )
        )
        findings.extend(
            _contextual_generic_pii_findings(
                text,
                policy,
            )
        )

    return remove_overlapping_findings(findings)
