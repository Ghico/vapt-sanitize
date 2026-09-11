from collections import defaultdict

from .models import Finding


class Anonymizer:

    def __init__(self, mapping_store=None):
        self.mapping_store = mapping_store

        self.mapping = {}

        if mapping_store is None:
            self.counters = defaultdict(int)
        else:
            self.counters = defaultdict(
                int,
                mapping_store.counters,
            )

    @staticmethod
    def _canonical_mapping_value(
        category: str,
        original: str,
    ) -> str:
        """Return a stable correlation key without changing rendered text.

        Phone numbers are frequently represented with spaces, dashes,
        parentheses, or an international ``00`` prefix.  These formatting
        differences must not create different pseudonyms for the same number.
        Other categories intentionally keep their exact original value.
        """

        if category == "PHONE":
            digits = "".join(
                character
                for character in original
                if character.isdigit()
            )

            if digits.startswith("00"):
                digits = digits[2:]

            return digits

        return original

    def placeholder(
        self,
        category: str,
        original: str,
    ) -> str:

        key = (
            category,
            self._canonical_mapping_value(
                category,
                original,
            ),
        )

        if self.mapping_store is not None:
            placeholder = self.mapping_store.get_or_create_placeholder(
                category,
                key[1],
                original,
            )
            self.mapping[key] = placeholder
            self.counters[category] = max(
                self.counters[category],
                int(placeholder.rsplit("_", 1)[1].rstrip("]")),
            )
            return placeholder

        if key not in self.mapping:
            self.counters[category] += 1
            number = self.counters[category]

            self.mapping[key] = (
                f"[{category}_{number:03d}]"
            )

        return self.mapping[key]

    def sanitize(
        self,
        text: str,
        findings: list[Finding],
    ) -> str:

        # -----------------------------------------------------
        # STEP 1
        # Assign placeholders in document order.
        # This guarantees deterministic numbering.
        # -----------------------------------------------------

        for finding in findings:

            if finding.action == "preserve":
                continue

            if finding.action == "redact":
                finding.replacement = (
                    f"[{finding.category}_REDACTED]"
                )

            else:
                finding.replacement = self.placeholder(
                    finding.category,
                    finding.original,
                )

        # -----------------------------------------------------
        # STEP 2
        # Apply replacements from right to left.
        # This preserves the original string indexes.
        # -----------------------------------------------------

        result = text

        replacement_order = sorted(
            findings,
            key=lambda finding: (
                finding.replace_start
                if finding.replace_start is not None
                else finding.start
            ),
            reverse=True,
        )

        for finding in replacement_order:

            if finding.action == "preserve":
                continue

            start = (
                finding.replace_start
                if finding.replace_start is not None
                else finding.start
            )

            end = (
                finding.replace_end
                if finding.replace_end is not None
                else finding.end
            )

            result = (
                result[:start]
                + finding.replacement
                + result[end:]
            )

        return result
