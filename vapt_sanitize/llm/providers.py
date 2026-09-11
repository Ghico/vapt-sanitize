from abc import ABC, abstractmethod

from .models import LLMRequest, LLMResponse


class LLMProviderError(Exception):
    """Base error for LLM providers."""


class LLMProviderDisabled(LLMProviderError):
    """Raised when no external provider is enabled."""


class LLMProvider(ABC):
    """
    Provider boundary.

    Providers receive LLMRequest only.
    LLMRequest contains sanitized content and never
    the original Burp message.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider display name."""

    @abstractmethod
    def send(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        """Send an already authorized sanitized request."""


class DisabledProvider(LLMProvider):
    """
    Default provider.

    It performs no network communication.
    """

    @property
    def name(self) -> str:
        return "None"

    def send(
        self,
        request: LLMRequest,
    ) -> LLMResponse:

        raise LLMProviderDisabled(
            "No LLM provider is enabled."
        )


class LocalTestProvider(LLMProvider):
    """
    Deterministic local-only provider used to validate
    the complete Burp -> sanitizer -> LLM flow.

    No socket, HTTP client, subprocess, or network API is used.
    """

    @property
    def name(self) -> str:
        return "Local Test"

    def send(
        self,
        request: LLMRequest,
    ) -> LLMResponse:

        policy = (
            request.policy_name
            if request.policy_name
            else "unspecified"
        )

        question_state = (
            "present"
            if (
                request.question is not None
                and request.question.strip()
            )
            else "none"
        )

        text = (
            "LOCAL TEST PROVIDER\n"
            "No network communication was performed.\n\n"
            f"Task: {request.task}\n"
            f"Gate: {request.gate_state}\n"
            f"Policy: {policy}\n"
            f"Question: {question_state}\n"
            f"Sanitized characters: "
            f"{len(request.sanitized_content)}"
        )

        return LLMResponse(
            text=text,
            provider=self.name,
        )
