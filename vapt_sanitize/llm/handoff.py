import argparse
import base64
import sys

from ..detectors import detect
from ..policy import MANDATORY_REDACT, Policy
from .dispatch import LLMDispatchBlocked, authorize
from .models import LLMRequest, LLMRequestError
from .tasks import build_prompt


PROTOCOL_HEADER = "VAPT_AI_HANDOFF_V1"


def encode(value: str) -> str:
    return base64.b64encode(
        value.encode("utf-8")
    ).decode("ascii")


def decode_optional_base64(
    value: str | None,
) -> str | None:

    if value is None:
        return None

    try:
        return base64.b64decode(
            value.encode("ascii")
        ).decode("utf-8")

    except Exception as exc:
        raise LLMRequestError(
            "Invalid base64 value."
        ) from exc


def residual_mandatory_secret(
    content: str,
    *,
    profile: str,
    policy: Policy,
) -> str | None:
    """
    Defense-in-depth check at the final AI handoff boundary.

    Even if the caller claims PASS, content containing a
    residual mandatory secret is rejected before it can be
    copied for external AI use.

    The caller's actual sanitization profile is reused here;
    the handoff layer is not Burp-specific.
    """

    findings = detect(
        content,
        profile=profile,
        policy=policy,
    )

    for finding in findings:

        if finding.category not in MANDATORY_REDACT:
            continue

        placeholder = (
            f"[{finding.category}_REDACTED]"
        )

        if placeholder in finding.original:
            continue

        return finding.category

    return None


def build_authorized_prompt(
    sanitized_content: str,
    *,
    task: str,
    gate_state: str,
    review_approved: bool,
    policy: Policy,
    profile: str,
    source: str,
    question: str | None = None,
    policy_name: str | None = None,
) -> str:
    """
    Build an AI-ready prompt from already-sanitized content.

    This is the reusable security boundary for Burp and the
    general CLI. It performs a final mandatory-secret scan,
    enforces the Security Gate, and only then builds the prompt.
    """

    residual = residual_mandatory_secret(
        sanitized_content,
        profile=profile,
        policy=policy,
    )

    if residual is not None:
        raise LLMDispatchBlocked(
            "Residual mandatory secret detected "
            f"at AI handoff boundary: {residual}."
        )

    request = LLMRequest(
        sanitized_content=sanitized_content,
        task=task,
        gate_state=gate_state,
        review_approved=review_approved,
        question=question,
        policy_name=policy_name,
        source=source,
    )

    authorize(
        request
    )

    return build_prompt(
        request
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Build a safe, provider-neutral AI handoff prompt "
            "from already-sanitized content."
        )
    )

    parser.add_argument(
        "--task",
        required=True,
    )

    parser.add_argument(
        "--gate",
        required=True,
        choices=[
            "PASS",
            "REVIEW",
            "BLOCKED",
        ],
    )

    parser.add_argument(
        "--review-approved",
        action="store_true",
    )

    parser.add_argument(
        "--profile",
        default="BURP",
        help=(
            "Sanitization profile used for the final residual-secret "
            "check. Defaults to BURP for backward compatibility."
        ),
    )

    parser.add_argument(
        "--policy",
        default=None,
    )

    parser.add_argument(
        "--policy-name",
        default=None,
    )

    parser.add_argument(
        "--question-b64",
        default=None,
    )

    parser.add_argument(
        "--source-b64",
        default=None,
    )

    args = parser.parse_args()

    sanitized_content = sys.stdin.read()

    if not sanitized_content:
        print(
            "AI handoff rejected empty input.",
            file=sys.stderr,
        )
        return 2

    try:

        policy = (
            Policy.from_file(args.policy)
            if args.policy
            else Policy()
        )

        question = decode_optional_base64(
            args.question_b64
        )

        source = (
            decode_optional_base64(
                args.source_b64
            )
            or "Security testing input"
        )

        prompt = build_authorized_prompt(
            sanitized_content,
            task=args.task,
            gate_state=args.gate,
            review_approved=args.review_approved,
            policy=policy,
            profile=args.profile.upper(),
            source=source,
            question=question,
            policy_name=args.policy_name,
        )

    except LLMDispatchBlocked as exc:

        print(
            str(exc),
            file=sys.stderr,
        )
        return 3

    except (
        LLMRequestError,
        OSError,
    ) as exc:

        print(
            str(exc),
            file=sys.stderr,
        )
        return 1

    print(
        PROTOCOL_HEADER
    )

    print(
        "PROMPT_B64:"
        + encode(prompt)
    )

    print(
        "END"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
