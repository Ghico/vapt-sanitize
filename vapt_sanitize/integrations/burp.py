import argparse
import base64
import sys

from ..detectors import detect
from ..engine import sanitize
from ..engagement import EngagementError, EngagementVault
from ..policy import MANDATORY_REDACT, Policy


def encode(value: str) -> str:
    """Encode text safely for the Burp bridge protocol."""
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")


def detect_residual_mandatory_secret(
    sanitized: str,
    *,
    profile: str,
    policy: Policy,
) -> str | None:
    """
    Re-scan sanitized output for mandatory secret patterns.

    Returns the first residual mandatory secret category,
    otherwise None.
    """

    residual_findings = detect(
        sanitized,
        profile=profile,
        policy=policy,
    )

    for finding in residual_findings:

        if finding.category not in MANDATORY_REDACT:
            continue

        placeholder = (
            f"[{finding.category}_REDACTED]"
        )

        if placeholder in finding.original:
            continue

        return finding.category

    return None


def determine_security_gate(
    findings,
    *,
    sanitized: str,
    profile: str,
    policy: Policy,
):
    """
    Determine the post-sanitization security gate.

    Critical conditions are always BLOCKED and cannot be
    weakened by YAML policy.

    Non-critical conditions are controlled by GATE rules:

        PRESERVED_FINDING
        NO_FINDINGS

    Normal successfully sanitized findings produce PASS.
    """

    # Mandatory secret categories must always be redacted.
    for finding in findings:

        if (
            finding.category in MANDATORY_REDACT
            and finding.action != "redact"
        ):
            return (
                "BLOCKED",
                (
                    "Mandatory secret category "
                    f"{finding.category} was not redacted."
                ),
            )

    # Post-sanitization verification.
    residual_category = (
        detect_residual_mandatory_secret(
            sanitized,
            profile=profile,
            policy=policy,
        )
    )

    if residual_category is not None:
        return (
            "BLOCKED",
            (
                "Residual mandatory secret pattern detected "
                f"after sanitization: {residual_category}."
            ),
        )

    # Policy-controlled handling of preserved findings.
    if any(
        finding.action == "preserve"
        for finding in findings
    ):
        state = policy.gate_state(
            "PRESERVED_FINDING"
        )

        return (
            state,
            (
                "At least one detected value is preserved "
                f"by policy. Gate policy resolved to {state}."
            ),
        )

    # Policy-controlled handling of zero findings.
    if not findings:

        state = policy.gate_state(
            "NO_FINDINGS"
        )

        return (
            state,
            (
                "No sensitive values were detected. "
                f"Gate policy resolved to {state}."
            ),
        )

    return (
        "PASS",
        (
            "All detected values are handled according "
            "to policy and no residual mandatory secret "
            "pattern was detected."
        ),
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description="Burp Suite bridge for vapt-sanitize."
    )

    parser.add_argument(
        "--profile",
        default="BURP",
        help="Sanitization profile.",
    )

    parser.add_argument(
        "--policy",
        default=None,
        help="Optional policy YAML file.",
    )

    parser.add_argument(
        "--engagement",
        default=None,
        help="Optional encrypted engagement mapping vault ID.",
    )

    parser.add_argument(
        "--preview",
        action="store_true",
        help=(
            "Return sanitized text plus safe finding "
            "metadata."
        ),
    )

    args = parser.parse_args()

    text = sys.stdin.read()

    if not text:
        print(
            "No input received.",
            file=sys.stderr,
        )
        return 2

    try:

        policy = (
            Policy.from_file(args.policy)
            if args.policy
            else Policy()
        )

        mapping_store = (
            EngagementVault.open(args.engagement)
            if args.engagement
            else None
        )

        (
            sanitized,
            findings,
            _mapping,
            _global_profile,
        ) = sanitize(
            text,
            profile=args.profile,
            policy=policy,
            mapping_store=mapping_store,
        )

    except Exception as exc:

        # EngagementError messages contain only local vault diagnostics
        # (engagement ID/path/key state), never sanitized input values.
        # Surface that safe detail so Burp does not collapse every vault
        # failure into the unhelpful string "EngagementError".
        if isinstance(exc, EngagementError):
            detail = str(exc).strip()
            message = (
                "Sanitization failed: EngagementError"
                + (f": {detail}" if detail else "")
            )
        else:
            # Keep arbitrary exception messages hidden because they could
            # accidentally contain raw input data.
            message = (
                "Sanitization failed: "
                f"{type(exc).__name__}"
            )

        print(
            message,
            file=sys.stderr,
        )

        return 1

    if not sanitized:

        print(
            "Sanitization produced empty output.",
            file=sys.stderr,
        )

        return 1

    if not args.preview:

        sys.stdout.write(
            sanitized
        )

        return 0

    security_gate, gate_reason = (
        determine_security_gate(
            findings,
            sanitized=sanitized,
            profile=args.profile,
            policy=policy,
        )
    )

    print(
        "VAPT_SANITIZER_PREVIEW_V1"
    )

    print(
        "SANITIZED_B64:"
        + encode(sanitized)
    )

    print(
        "FINDINGS_COUNT:"
        + str(len(findings))
    )

    print(
        "SECURITY_GATE:"
        + security_gate
    )

    print(
        "SECURITY_GATE_REASON:"
        + encode(gate_reason)
    )

    for finding in findings:

        print(
            "FINDING:"
            + encode(finding.category)
            + ":"
            + encode(finding.action)
            + ":"
            + encode(finding.reason)
        )

    print(
        "END"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
