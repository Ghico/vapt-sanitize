from .models import LLMRequest, LLMResponse
from .providers import LLMProvider


class LLMDispatchBlocked(Exception):
    """Raised when the Security Gate prevents AI handoff or dispatch."""


def authorize(
    request: LLMRequest,
) -> None:
    """
    Enforce the Security Gate before content can cross
    the sanitizer -> AI boundary.

    PASS:
        allowed.

    REVIEW:
        allowed only after explicit user approval.

    BLOCKED:
        never allowed.
    """

    if request.gate_state == "BLOCKED":

        raise LLMDispatchBlocked(
            "AI handoff blocked by Security Gate."
        )

    if (
        request.gate_state == "REVIEW"
        and not request.review_approved
    ):

        raise LLMDispatchBlocked(
            "AI handoff requires explicit review approval."
        )


def dispatch(
    request: LLMRequest,
    provider: LLMProvider,
) -> LLMResponse:
    """
    Authorize and send an already-sanitized request
    to a configured provider.
    """

    authorize(
        request
    )

    response = provider.send(
        request
    )

    if not isinstance(
        response,
        LLMResponse,
    ):

        raise TypeError(
            "Provider returned an invalid response."
        )

    return response
