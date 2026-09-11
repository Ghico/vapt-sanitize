from .models import LLMRequest


TASK_INSTRUCTIONS = {
    "ANALYZE_SECURITY": (
        "Analyze this sanitized security-testing data from the "
        "perspective of an authorized penetration tester. Identify "
        "relevant attack surface, anomalies, and security tests worth "
        "performing. Do not assume vulnerabilities that are not "
        "supported by the supplied evidence."
    ),

    "EXPLAIN_RESPONSE": (
        "Explain this sanitized security-testing data from a security "
        "testing perspective. Highlight security-relevant behavior, "
        "headers, errors, application details, and anything that "
        "deserves further investigation."
    ),

    "FIND_ATTACK_SURFACE": (
        "Identify the attack surface visible in this sanitized "
        "security-testing data. Focus on parameters, endpoints, "
        "services, headers, authentication state, input locations, "
        "trust boundaries, and exposed functionality."
    ),

    "SUGGEST_NEXT_TESTS": (
        "Based only on this sanitized security-testing data, suggest "
        "the next useful penetration-testing steps. Prioritize tests "
        "and briefly explain the reason for each one."
    ),
}


def build_prompt(
    request: LLMRequest,
) -> str:
    """
    Build a provider-neutral, tool-agnostic prompt
    using sanitized content only.
    """

    if request.task == "CUSTOM":

        instruction = request.question.strip()

    else:

        instruction = TASK_INSTRUCTIONS[
            request.task
        ]

        if (
            request.question is not None
            and request.question.strip()
        ):

            instruction += (
                "\n\nAdditional analyst question:\n"
                + request.question.strip()
            )

    return (
        "You are assisting with an authorized security assessment."
        + "\n"
        + "Source: "
        + request.source
        + "\n\n"
        + instruction
        + "\n\n"
        + "The content below has already passed through "
        + "VAPT Sanitizer. Values such as "
        + "[EMAIL_REDACTED], [HOSTNAME_001], or "
        + "[BEARER_TOKEN_REDACTED] are intentional placeholders. "
        + "Do not attempt to reconstruct, infer, or guess their "
        + "original values."
        + "\n\n"
        + "--- SANITIZED DATA ---\n"
        + request.sanitized_content
    )
