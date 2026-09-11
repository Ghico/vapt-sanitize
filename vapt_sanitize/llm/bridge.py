import argparse
import base64
import sys

from ..detectors import detect
from ..policy import MANDATORY_REDACT, Policy
from .dispatch import LLMDispatchBlocked, dispatch
from .models import LLMRequest, LLMRequestError
from .providers import (
    DisabledProvider,
    LLMProviderDisabled,
    LocalTestProvider,
)


PROTOCOL_HEADER = "VAPT_LLM_RESPONSE_V1"


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
            "Invalid base64 question."
        ) from exc


def residual_mandatory_secret(
    content: str,
    *,
    policy: Policy,
) -> str | None:
    """
    Defense-in-depth check at the LLM boundary.

    Even if the caller claims PASS, content containing a
    residual mandatory secret is rejected before any provider
    can receive it.
    """

    findings = detect(
        content,
        profile="BURP",
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


def provider_from_name(
    name: str,
):
    normalized = name.upper()

    if normalized == "NONE":
        return DisabledProvider()

    if normalized == "LOCAL_TEST":
        return LocalTestProvider()

    raise LLMRequestError(
        f"Unsupported provider: {name}"
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Local LLM dispatch bridge for VAPT Sanitizer."
        )
    )

    parser.add_argument(
        "--provider",
        required=True,
        choices=[
            "NONE",
            "LOCAL_TEST",
        ],
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

    args = parser.parse_args()

    sanitized_content = sys.stdin.read()

    if not sanitized_content:
        print(
            "LLM bridge rejected empty input.",
            file=sys.stderr,
        )
        return 2

    try:

        policy = (
            Policy.from_file(args.policy)
            if args.policy
            else Policy()
        )

        residual = residual_mandatory_secret(
            sanitized_content,
            policy=policy,
        )

        if residual is not None:
            raise LLMDispatchBlocked(
                "Residual mandatory secret detected "
                f"at LLM boundary: {residual}."
            )

        question = decode_optional_base64(
            args.question_b64
        )

        request = LLMRequest(
            sanitized_content=sanitized_content,
            task=args.task,
            gate_state=args.gate,
            review_approved=args.review_approved,
            question=question,
            policy_name=args.policy_name,
        )

        provider = provider_from_name(
            args.provider
        )

        response = dispatch(
            request,
            provider,
        )

    except LLMDispatchBlocked as exc:

        print(
            str(exc),
            file=sys.stderr,
        )
        return 3

    except LLMProviderDisabled as exc:

        print(
            str(exc),
            file=sys.stderr,
        )
        return 4

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
        "PROVIDER_B64:"
        + encode(response.provider)
    )

    print(
        "TEXT_B64:"
        + encode(response.text)
    )

    print(
        "END"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
