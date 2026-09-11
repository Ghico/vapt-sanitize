from dataclasses import dataclass

from ..policy import VALID_GATE_STATES


VALID_LLM_TASKS = {
    "ANALYZE_SECURITY",
    "EXPLAIN_RESPONSE",
    "FIND_ATTACK_SURFACE",
    "SUGGEST_NEXT_TESTS",
    "CUSTOM",
}


class LLMRequestError(ValueError):
    """Raised when an LLM request is invalid."""


@dataclass(frozen=True)
class LLMRequest:
    """
    Data allowed to cross the sanitizer -> AI boundary.

    IMPORTANT:
    This object intentionally has no field for original
    request/response/tool content.
    """

    sanitized_content: str
    task: str
    gate_state: str
    review_approved: bool = False
    question: str | None = None
    policy_name: str | None = None
    source: str = "Security testing input"

    def __post_init__(self):

        if not self.sanitized_content.strip():
            raise LLMRequestError(
                "Sanitized content cannot be empty."
            )

        normalized_task = self.task.upper()

        if normalized_task not in VALID_LLM_TASKS:
            raise LLMRequestError(
                f"Unsupported LLM task: {self.task}"
            )

        normalized_gate = self.gate_state.upper()

        if normalized_gate not in VALID_GATE_STATES:
            raise LLMRequestError(
                f"Unsupported gate state: {self.gate_state}"
            )

        if (
            normalized_task == "CUSTOM"
            and (
                self.question is None
                or not self.question.strip()
            )
        ):
            raise LLMRequestError(
                "CUSTOM task requires a question."
            )

        normalized_source = (
            self.source.strip()
            if self.source is not None
            else ""
        )

        if not normalized_source:
            normalized_source = (
                "Security testing input"
            )

        object.__setattr__(
            self,
            "task",
            normalized_task,
        )

        object.__setattr__(
            self,
            "gate_state",
            normalized_gate,
        )

        object.__setattr__(
            self,
            "source",
            normalized_source,
        )


@dataclass(frozen=True)
class LLMResponse:
    """Provider-independent LLM response."""

    text: str
    provider: str

    def __post_init__(self):

        if not self.text.strip():
            raise LLMRequestError(
                "LLM response cannot be empty."
            )

        if not self.provider.strip():
            raise LLMRequestError(
                "LLM provider name cannot be empty."
            )
