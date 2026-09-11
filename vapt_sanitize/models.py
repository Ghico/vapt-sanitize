from dataclasses import dataclass


@dataclass
class Finding:
    category: str
    original: str
    replacement: str
    severity: str
    start: int
    end: int
    action: str = "pseudonymize"

    # Optional sub-range to replace inside the full match.
    replace_start: int | None = None
    replace_end: int | None = None

    # Context / policy metadata.
    profile: str = "GENERIC"
    reason: str = ""


@dataclass
class ProfileResult:
    name: str
    scores: dict[str, int]
    confidence: float
