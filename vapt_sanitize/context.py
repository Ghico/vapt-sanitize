import re
from dataclasses import dataclass

from .profiles import detect_profile


@dataclass
class ContextBlock:
    text: str
    start: int
    end: int
    profile: str
    confidence: float


class ContextEngine:
    SECTION_PATTERNS = (
        (
            "NMAP",
            re.compile(
                r"(?i)^\s*NMAP\s+ENUMERATION\s*$"
            ),
        ),
        (
            "BURP",
            re.compile(
                r"(?i)^\s*BURP\s+HTTP\s+REQUEST\s*$"
            ),
        ),
        (
            "GOBUSTER",
            re.compile(
                r"(?i)^\s*GOBUSTER(?:\s+ENUMERATION)?\s*$"
            ),
        ),
        (
            "NUCLEI",
            re.compile(
                r"(?i)^\s*NUCLEI(?:\s+SCAN\s+OUTPUT)?\s*$"
            ),
        ),
        (
            "WINDOWS",
            re.compile(
                r"(?i)^\s*WINDOWS\s+ENUMERATION\s*$"
            ),
        ),
        (
            "LINUX",
            re.compile(
                r"(?i)^\s*LINUX(?:\s+ENUMERATION)?\s*$"
            ),
        ),
        (
            "AWS",
            re.compile(
                r"(?i)^\s*AWS(?:\s+ENUMERATION)?\s*$"
            ),
        ),
        (
            "SECRETS",
            re.compile(
                r"(?i)^\s*(?:PRIVATE\s+KEY|SECRETS?(?:\s+ENUMERATION)?|CREDENTIALS?(?:\s+ENUMERATION)?)\s*$"
            ),
        ),
        (
            "PII",
            re.compile(
                r"(?i)^\s*(?:PII(?:\s+ENUMERATION)?|PERSONAL\s+DATA|CREDIT\s+CARD(?:\s+TEST)?)\s*$"
            ),
        ),
        (
            "GENERIC",
            re.compile(
                r"(?i)^\s*GENERIC\s+SECURITY\s+TESTING\s+OUTPUT\s*$"
            ),
        ),
    )

    SEPARATOR_RE = re.compile(r"^\s*[=]{10,}\s*$")

    def detect_section_header(
        self,
        line: str,
    ) -> str | None:

        stripped = line.strip()

        for profile, pattern in self.SECTION_PATTERNS:
            if pattern.match(stripped):
                return profile

        return None

    def split_sections(
        self,
        text: str,
    ) -> list[tuple[str, int, int, str | None]]:

        lines = text.splitlines(keepends=True)

        sections = []

        current_start = None
        current_profile = None

        position = 0

        for line in lines:

            detected_profile = self.detect_section_header(
                line
            )

            if detected_profile is not None:

                if current_start is not None:
                    sections.append(
                        (
                            text[current_start:position],
                            current_start,
                            position,
                            current_profile,
                        )
                    )

                current_start = position
                current_profile = detected_profile

            position += len(line)

        if current_start is not None:
            sections.append(
                (
                    text[current_start:],
                    current_start,
                    len(text),
                    current_profile,
                )
            )

        # If there are no explicit section headers,
        # fall back to the complete document as one block.
        if not sections and text.strip():
            sections.append(
                (
                    text,
                    0,
                    len(text),
                    None,
                )
            )

        return sections

    def analyze(
        self,
        text: str,
    ) -> list[ContextBlock]:

        blocks = []

        for (
            section_text,
            start,
            end,
            explicit_profile,
        ) in self.split_sections(text):

            profile_result = detect_profile(
                section_text
            )

            if explicit_profile is not None:
                profile = explicit_profile

                # An explicit section header is strong evidence.
                confidence = max(
                    profile_result.confidence,
                    1.0,
                )

            else:
                profile = profile_result.name
                confidence = profile_result.confidence

            blocks.append(
                ContextBlock(
                    text=section_text,
                    start=start,
                    end=end,
                    profile=profile,
                    confidence=confidence,
                )
            )

        return blocks
