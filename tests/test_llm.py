import base64
import subprocess
import sys
import unittest

from vapt_sanitize.llm import (
    DisabledProvider,
    LLMDispatchBlocked,
    LLMProvider,
    LLMProviderDisabled,
    LLMRequest,
    LLMResponse,
    LocalTestProvider,
    build_prompt,
    dispatch,
)


class RecordingProvider(LLMProvider):

    def __init__(self):
        self.requests = []

    @property
    def name(self):
        return "Recording"

    def send(self, request):

        self.requests.append(
            request
        )

        return LLMResponse(
            text="TEST RESPONSE",
            provider=self.name,
        )


class TestLLMSecurityBoundary(unittest.TestCase):

    def test_pass_can_reach_provider(self):

        provider = RecordingProvider()

        request = LLMRequest(
            sanitized_content=(
                "Authorization: "
                "[BEARER_TOKEN_REDACTED]"
            ),
            task="ANALYZE_SECURITY",
            gate_state="PASS",
        )

        response = dispatch(
            request,
            provider,
        )

        self.assertEqual(
            response.text,
            "TEST RESPONSE",
        )

        self.assertEqual(
            len(provider.requests),
            1,
        )


    def test_blocked_never_reaches_provider(self):

        provider = RecordingProvider()

        request = LLMRequest(
            sanitized_content="TEST",
            task="ANALYZE_SECURITY",
            gate_state="BLOCKED",
        )

        with self.assertRaises(
            LLMDispatchBlocked
        ):

            dispatch(
                request,
                provider,
            )

        self.assertEqual(
            provider.requests,
            [],
        )


    def test_review_requires_explicit_approval(self):

        provider = RecordingProvider()

        request = LLMRequest(
            sanitized_content="TEST",
            task="ANALYZE_SECURITY",
            gate_state="REVIEW",
            review_approved=False,
        )

        with self.assertRaises(
            LLMDispatchBlocked
        ):

            dispatch(
                request,
                provider,
            )

        self.assertEqual(
            provider.requests,
            [],
        )


    def test_review_with_approval_can_reach_provider(self):

        provider = RecordingProvider()

        request = LLMRequest(
            sanitized_content="TEST",
            task="ANALYZE_SECURITY",
            gate_state="REVIEW",
            review_approved=True,
        )

        dispatch(
            request,
            provider,
        )

        self.assertEqual(
            len(provider.requests),
            1,
        )


    def test_llm_request_has_no_original_field(self):

        request = LLMRequest(
            sanitized_content=(
                "Host: [HOSTNAME_001]"
            ),
            task="FIND_ATTACK_SURFACE",
            gate_state="PASS",
        )

        self.assertFalse(
            hasattr(
                request,
                "original",
            )
        )

        self.assertFalse(
            hasattr(
                request,
                "original_content",
            )
        )


    def test_disabled_provider_performs_no_dispatch(self):

        request = LLMRequest(
            sanitized_content="TEST",
            task="ANALYZE_SECURITY",
            gate_state="PASS",
        )

        with self.assertRaises(
            LLMProviderDisabled
        ):

            dispatch(
                request,
                DisabledProvider(),
            )


    def test_prompt_contains_sanitized_content(self):

        sanitized = (
            "Host: [HOSTNAME_001]\n"
            "Email: [EMAIL_REDACTED]"
        )

        request = LLMRequest(
            sanitized_content=sanitized,
            task="SUGGEST_NEXT_TESTS",
            gate_state="PASS",
        )

        prompt = build_prompt(
            request
        )

        self.assertIn(
            sanitized,
            prompt,
        )

        self.assertIn(
            "intentional placeholders",
            prompt,
        )


    def test_local_test_provider_is_local_and_deterministic(self):

        provider = LocalTestProvider()

        request = LLMRequest(
            sanitized_content=(
                "Host: [HOSTNAME_001]"
            ),
            task="ANALYZE_SECURITY",
            gate_state="PASS",
            policy_name="Strict LLM",
        )

        response = dispatch(
            request,
            provider,
        )

        self.assertEqual(
            response.provider,
            "Local Test",
        )

        self.assertIn(
            "No network communication was performed.",
            response.text,
        )

        self.assertIn(
            "Task: ANALYZE_SECURITY",
            response.text,
        )


    def test_llm_bridge_pass_local_test(self):

        sanitized = (
            "Authorization: "
            "[BEARER_TOKEN_REDACTED]"
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.bridge",
                "--provider",
                "LOCAL_TEST",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "PASS",
                "--policy-name",
                "Strict LLM",
            ],
            input=sanitized,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "VAPT_LLM_RESPONSE_V1",
            result.stdout,
        )

        self.assertIn(
            "PROVIDER_B64:",
            result.stdout,
        )

        self.assertIn(
            "TEXT_B64:",
            result.stdout,
        )


    def test_llm_bridge_review_without_approval_is_blocked(self):

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.bridge",
                "--provider",
                "LOCAL_TEST",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "REVIEW",
            ],
            input="Host: [HOSTNAME_001]",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            3,
        )

        self.assertIn(
            "requires explicit review approval",
            result.stderr,
        )


    def test_llm_bridge_rejects_residual_mandatory_secret(self):

        raw_secret = (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.test.signature"
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.bridge",
                "--provider",
                "LOCAL_TEST",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "PASS",
            ],
            input=raw_secret,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            3,
        )

        self.assertNotIn(
            raw_secret,
            result.stdout,
        )

        self.assertIn(
            "Residual mandatory secret",
            result.stderr,
        )


    def test_prompt_is_tool_agnostic_and_preserves_source(self):

        request = LLMRequest(
            sanitized_content=(
                "22/tcp open ssh OpenSSH 9.x"
            ),
            task="ANALYZE_SECURITY",
            gate_state="PASS",
            source="Nmap enumeration",
        )

        prompt = build_prompt(
            request
        )

        self.assertIn(
            "Source: Nmap enumeration",
            prompt,
        )

        self.assertIn(
            "--- SANITIZED DATA ---",
            prompt,
        )

        self.assertNotIn(
            "SANITIZED BURP CONTENT",
            prompt,
        )


    def test_ai_handoff_pass_builds_clipboard_prompt(self):

        sanitized = (
            "Host: [HOSTNAME_001]\n"
            "Authorization: [BEARER_TOKEN_REDACTED]"
        )

        source = base64.b64encode(
            b"Burp HTTP Request"
        ).decode("ascii")

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.handoff",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "PASS",
                "--source-b64",
                source,
            ],
            input=sanitized,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "VAPT_AI_HANDOFF_V1",
            result.stdout,
        )

        prompt_line = next(
            line
            for line in result.stdout.splitlines()
            if line.startswith(
                "PROMPT_B64:"
            )
        )

        prompt = base64.b64decode(
            prompt_line.split(
                ":",
                1,
            )[1]
        ).decode("utf-8")

        self.assertIn(
            "Source: Burp HTTP Request",
            prompt,
        )

        self.assertIn(
            sanitized,
            prompt,
        )


    def test_ai_handoff_review_requires_approval(self):

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.handoff",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "REVIEW",
            ],
            input="Host: [HOSTNAME_001]",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            3,
        )

        self.assertIn(
            "requires explicit review approval",
            result.stderr,
        )


    def test_ai_handoff_blocked_never_builds_prompt(self):

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.handoff",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "BLOCKED",
            ],
            input="Host: [HOSTNAME_001]",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            3,
        )

        self.assertNotIn(
            "PROMPT_B64:",
            result.stdout,
        )


    def test_ai_handoff_rejects_residual_mandatory_secret(self):

        raw_secret = (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.test.signature"
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.handoff",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "PASS",
            ],
            input=raw_secret,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            3,
        )

        self.assertNotIn(
            raw_secret,
            result.stdout,
        )

        self.assertNotIn(
            "PROMPT_B64:",
            result.stdout,
        )

        self.assertIn(
            "Residual mandatory secret",
            result.stderr,
        )





    def test_ai_handoff_rejects_residual_aws_session_token(self):
        raw_secret = (
            "AWS_SESSION_TOKEN="
            "IQoJb3JpZ2luX2VjEExampleSyntheticSessionTokenForTestingOnly1234567890"
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.handoff",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "PASS",
                "--profile",
                "AWS",
            ],
            input=raw_secret,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 3)
        self.assertNotIn("PROMPT_B64:", result.stdout)
        self.assertIn("Residual mandatory secret", result.stderr)
        self.assertIn("AWS_SESSION_TOKEN", result.stderr)


    def test_ai_handoff_rejects_residual_generic_secret(self):
        raw_secret = "CLIENT_SECRET=still_raw_secret_value_123456"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.handoff",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "PASS",
                "--profile",
                "SECRETS",
            ],
            input=raw_secret,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 3)
        self.assertNotIn("PROMPT_B64:", result.stdout)
        self.assertIn("Residual mandatory secret", result.stderr)
        self.assertIn("GENERIC_SECRET", result.stderr)


    def test_ai_handoff_rejects_residual_basic_authorization(self):
        raw_secret = "Authorization: Basic dXNlcjpTVElMTF9SQVdfU0VDUkVU"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.llm.handoff",
                "--task",
                "ANALYZE_SECURITY",
                "--gate",
                "PASS",
                "--profile",
                "SECRETS",
            ],
            input=raw_secret,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 3)
        self.assertNotIn("PROMPT_B64:", result.stdout)
        self.assertIn("Residual mandatory secret", result.stderr)
        self.assertIn("AUTH_CREDENTIAL", result.stderr)

if __name__ == "__main__":
    unittest.main()
