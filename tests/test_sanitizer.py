import unittest
from unittest.mock import MagicMock

from vapt_sanitize.engine import sanitize


class TestSanitizer(unittest.TestCase):

    # ---------------------------------------------------------
    # PII / NETWORK
    # ---------------------------------------------------------

    def test_email(self):
        text = "Contact admin@cliente.it"

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn("[EMAIL_001]", sanitized)
        self.assertNotIn("admin@cliente.it", sanitized)
        self.assertEqual(len(findings), 1)

    def test_private_ip_consistency(self):
        text = """
        Target: 10.10.10.5
        Gateway: 10.10.10.1
        Target again: 10.10.10.5
        """

        sanitized, _, _, _ = sanitize(text)

        self.assertEqual(
            sanitized.count("[PRIVATE_IP_001]"),
            2,
        )

        self.assertIn(
            "[PRIVATE_IP_002]",
            sanitized,
        )

    def test_hostname_consistency(self):
        text = """
        Target: dc01.acme.local
        DC: dc01.acme.local
        API: api.acme.local
        """

        sanitized, _, _, _ = sanitize(text)

        self.assertEqual(
            sanitized.count("[HOSTNAME_001]"),
            2,
        )

        self.assertIn(
            "[HOSTNAME_002]",
            sanitized,
        )

    def test_mac_address(self):
        text = "MAC Address: 00:11:22:33:44:55"

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "[MAC_ADDRESS_001]",
            sanitized,
        )

        self.assertNotIn(
            "00:11:22:33:44:55",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "MAC_ADDRESS",
        )

    def test_security_gate_pass(self):
        from vapt_sanitize.engine import sanitize
        from vapt_sanitize.integrations.burp import (
            determine_security_gate,
        )
        from vapt_sanitize.policy import Policy

        policy = Policy()

        text = (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.test.signature\n"
            "Email: admin@cliente.it\n"
        )

        sanitized, findings, _, _ = sanitize(
            text,
            profile="BURP",
            policy=policy,
        )

        gate, _ = determine_security_gate(
            findings,
            sanitized=sanitized,
            profile="BURP",
            policy=policy,
        )

        self.assertEqual(
            gate,
            "PASS",
        )


    def test_security_gate_review_when_no_findings(self):
        from vapt_sanitize.engine import sanitize
        from vapt_sanitize.integrations.burp import (
            determine_security_gate,
        )
        from vapt_sanitize.policy import Policy

        policy = Policy()

        text = (
            "GET / HTTP/1.1\n"
            "User-Agent: Mozilla/5.0\n"
        )

        sanitized, findings, _, _ = sanitize(
            text,
            profile="BURP",
            policy=policy,
        )

        gate, _ = determine_security_gate(
            findings,
            sanitized=sanitized,
            profile="BURP",
            policy=policy,
        )

        self.assertEqual(
            gate,
            "REVIEW",
        )


    def test_security_gate_blocks_residual_secret(self):
        from vapt_sanitize.detectors import detect
        from vapt_sanitize.integrations.burp import (
            determine_security_gate,
        )
        from vapt_sanitize.policy import Policy

        policy = Policy()

        unsafe_output = (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.test.signature"
        )

        findings = detect(
            unsafe_output,
            profile="BURP",
            policy=policy,
        )

        gate, reason = determine_security_gate(
            findings,
            sanitized=unsafe_output,
            profile="BURP",
            policy=policy,
        )

        self.assertEqual(
            gate,
            "BLOCKED",
        )

        self.assertIn(
            "BEARER_TOKEN",
            reason,
        )

    # ---------------------------------------------------------
    # CREDENTIALS / SECRETS
    # ---------------------------------------------------------

    def test_password(self):
        text = "password=P@ssw0rd123!"

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "[PASSWORD_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            "P@ssw0rd123!",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "PASSWORD",
        )

        self.assertEqual(
            findings[0].action,
            "redact",
        )

    def test_bearer_token(self):
        text = (
            "Authorization: "
            "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature"
        )

        sanitized, findings, _, _ = sanitize(text)

        self.assertEqual(
            sanitized,
            "Authorization: [BEARER_TOKEN_REDACTED]",
        )

        self.assertNotIn(
            "eyJhbGciOiJIUzI1NiJ9.test.signature",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "BEARER_TOKEN",
        )

    def test_session_cookie(self):
        text = "Cookie: PHPSESSID=abc123xyz"

        sanitized, findings, _, _ = sanitize(text)

        self.assertEqual(
            sanitized,
            "Cookie: [SESSION_REDACTED]",
        )

        self.assertNotIn(
            "abc123xyz",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "SESSION",
        )

    def test_api_key_preserves_header(self):
        text = (
            "X-API-Key: "
            "1234567890abcdefABCDEF123456"
        )

        sanitized, findings, _, _ = sanitize(text)

        self.assertEqual(
            sanitized,
            "X-API-Key: [API_KEY_REDACTED]",
        )

        self.assertNotIn(
            "1234567890abcdefABCDEF123456",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "API_KEY",
        )

    def test_aws_access_key(self):
        text = (
            "AWS_ACCESS_KEY_ID="
            "AKIAIOSFODNN7EXAMPLE"
        )

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "[AWS_ACCESS_KEY_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            "AKIAIOSFODNN7EXAMPLE",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "AWS_ACCESS_KEY",
        )

    def test_aws_secret_preserves_variable_name(self):
        text = (
            "AWS_SECRET_ACCESS_KEY="
            "exampleSecretValue123456789"
        )

        sanitized, findings, _, _ = sanitize(text)

        self.assertEqual(
            sanitized,
            "AWS_SECRET_ACCESS_KEY="
            "[AWS_SECRET_KEY_REDACTED]",
        )

        self.assertNotIn(
            "exampleSecretValue123456789",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "AWS_SECRET_KEY",
        )

    def test_private_key_entire_block(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "THIS_IS_FAKE_TEST_DATA\n"
            "-----END RSA PRIVATE KEY-----"
        )

        sanitized, findings, _, _ = sanitize(text)

        self.assertEqual(
            sanitized,
            "[PRIVATE_KEY_REDACTED]",
        )

        self.assertNotIn(
            "THIS_IS_FAKE_TEST_DATA",
            sanitized,
        )

        self.assertNotIn(
            "BEGIN RSA PRIVATE KEY",
            sanitized,
        )

        self.assertNotIn(
            "END RSA PRIVATE KEY",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "PRIVATE_KEY",
        )

    # ---------------------------------------------------------
    # PII
    # ---------------------------------------------------------

    def test_credit_card(self):
        text = "Card: 4111 1111 1111 1111"

        sanitized, findings, _, _ = sanitize(text)

        self.assertEqual(
            sanitized,
            "Card: [CREDIT_CARD_REDACTED]",
        )

        self.assertNotIn(
            "4111 1111 1111 1111",
            sanitized,
        )

        self.assertEqual(
            findings[0].category,
            "CREDIT_CARD",
        )

    # ---------------------------------------------------------
    # TECHNICAL CONTEXT MUST SURVIVE
    # ---------------------------------------------------------

    def test_vapt_technical_context_preserved(self):
        text = """
        22/tcp open ssh OpenSSH 9.2
        445/tcp open microsoft-ds Windows Server 2022
        CVE-2026-1234
        Apache/2.4.58
        Kerberos
        NTLM
        administrator
        eu-west-1
        """

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn("22/tcp", sanitized)
        self.assertIn("445/tcp", sanitized)
        self.assertIn("OpenSSH 9.2", sanitized)
        self.assertIn(
            "Windows Server 2022",
            sanitized,
        )
        self.assertIn(
            "CVE-2026-1234",
            sanitized,
        )
        self.assertIn(
            "Apache/2.4.58",
            sanitized,
        )
        self.assertIn("Kerberos", sanitized)
        self.assertIn("NTLM", sanitized)
        self.assertIn(
            "administrator",
            sanitized,
        )
        self.assertIn(
            "eu-west-1",
            sanitized,
        )

    # ---------------------------------------------------------
    # HTTP / CONTEXT PRESERVATION
    # ---------------------------------------------------------

    def test_http_context_preservation(self):
        text = (
            "GET /api/v1/users HTTP/1.1\n"
            "Host: api.acme.local\n"
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.test.signature\n"
            "X-API-Key: "
            "1234567890abcdefABCDEF123456\n"
            "Cookie: PHPSESSID=abc123xyz\n"
            "Content-Type: application/json"
        )

        sanitized, _, _, _ = sanitize(text)

        self.assertIn(
            "GET /api/v1/users HTTP/1.1",
            sanitized,
        )

        self.assertIn(
            "Host: [HOSTNAME_001]",
            sanitized,
        )

        self.assertIn(
            "Authorization: [BEARER_TOKEN_REDACTED]",
            sanitized,
        )

        self.assertIn(
            "X-API-Key: [API_KEY_REDACTED]",
            sanitized,
        )

        self.assertIn(
            "Cookie: [SESSION_REDACTED]",
            sanitized,
        )

        self.assertIn(
            "Content-Type: application/json",
            sanitized,
        )

    # ---------------------------------------------------------
    # NEVER LEAK
    # ---------------------------------------------------------

    def test_no_secret_leak(self):
        secrets = [
            "SuperSecretPassword123!",
            "BearerSecretXYZ987654",
            "APISECRET123456789",
            "awsSecretValue987654",
            "THIS_IS_PRIVATE_KEY_DATA",
            "4111 1111 1111 1111",
            "admin@cliente.it",
        ]

        text = """
        password=SuperSecretPassword123!
        Authorization: Bearer BearerSecretXYZ987654
        X-API-Key: APISECRET123456789
        AWS_SECRET_ACCESS_KEY=awsSecretValue987654
        admin@cliente.it
        Card: 4111 1111 1111 1111
        """

        sanitized, _, _, _ = sanitize(text)

        for secret in secrets:
            self.assertNotIn(
                secret,
                sanitized,
                msg=f"SECRET LEAKED: {secret}",
            )

    # ---------------------------------------------------------
    # CONTEXT ENGINE
    # ---------------------------------------------------------

    def test_nmap_profile(self):
        text = """
        Nmap scan report for dc01.acme.local
        PORT     STATE SERVICE
        445/tcp  open  microsoft-ds
        """

        sanitized, _, _, _ = sanitize(text)

        self.assertIn(
            "[HOSTNAME_001]",
            sanitized,
        )

        self.assertIn(
            "445/tcp",
            sanitized,
        )

    def test_nmap_banner_preserves_official_tool_url(self):
        text = (
            "Starting Nmap 7.95 ( https://nmap.org ) at "
            "2026-09-09 16:30 CEST\n"
            "Nmap scan report for srv-app.interno.local "
            "(192.168.56.20)\n"
            "PORT     STATE SERVICE\n"
            "443/tcp  open  https\n"
        )

        sanitized, findings, _, _ = sanitize(
            text,
            profile="NMAP",
        )

        self.assertIn(
            "https://nmap.org",
            sanitized,
        )

        self.assertNotIn(
            "srv-app.interno.local",
            sanitized,
        )

        self.assertIn(
            "[HOSTNAME_001]",
            sanitized,
        )

        self.assertFalse(
            any(
                finding.category == "HOSTNAME"
                and finding.original == "nmap.org"
                for finding in findings
            )
        )

    def test_nmap_org_is_not_globally_whitelisted(self):
        text = (
            "Nmap scan report for nmap.org\n"
            "Host is up.\n"
            "PORT     STATE SERVICE\n"
            "443/tcp  open  https\n"
        )

        sanitized, _, _, _ = sanitize(
            text,
            profile="NMAP",
        )

        self.assertNotIn(
            "Nmap scan report for nmap.org",
            sanitized,
        )

        self.assertIn(
            "Nmap scan report for [HOSTNAME_001]",
            sanitized,
        )

    def test_gobuster_wordlist_filename_is_not_treated_as_hostname(self):
        text = (
            "GOBUSTER ENUMERATION\n"
            "[+] Url: https://portal.interno.local\n"
            "[+] Wordlist: /usr/share/wordlists/dirb/common.txt\n"
        )

        sanitized, findings, _, _ = sanitize(
            text,
            profile="GOBUSTER",
        )

        self.assertIn(
            "/usr/share/wordlists/dirb/common.txt",
            sanitized,
        )

        self.assertNotIn(
            "portal.interno.local",
            sanitized,
        )

        self.assertFalse(
            any(
                finding.category == "HOSTNAME"
                and finding.original == "common.txt"
                for finding in findings
            )
        )

    def test_gobuster_result_filename_is_not_treated_as_hostname(self):
        text = (
            "GOBUSTER ENUMERATION\n"
            "/robots.txt           (Status: 200) [Size: 87]\n"
        )

        sanitized, findings, _, _ = sanitize(
            text,
            profile="GOBUSTER",
        )

        self.assertIn(
            "/robots.txt",
            sanitized,
        )

        self.assertFalse(
            any(
                finding.category == "HOSTNAME"
                and finding.original == "robots.txt"
                for finding in findings
            )
        )

    def test_gobuster_redirect_hostname_is_still_sanitized(self):
        text = (
            "GOBUSTER ENUMERATION\n"
            "/admin (Status: 301) [Size: 169] "
            "[--> https://admin.interno.local/login]\n"
        )

        sanitized, _, _, _ = sanitize(
            text,
            profile="GOBUSTER",
        )

        self.assertNotIn(
            "admin.interno.local",
            sanitized,
        )

        self.assertIn(
            "https://[HOSTNAME_001]/login",
            sanitized,
        )

    def test_windows_profile_preserves_username(self):
        text = """
        Windows Server 2022
        Username: administrator
        """

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "Username: administrator",
            sanitized,
        )

        username_findings = [
            finding
            for finding in findings
            if finding.category == "USERNAME"
        ]

        self.assertEqual(
            len(username_findings),
            1,
        )

        self.assertEqual(
            username_findings[0].action,
            "preserve",
        )

    def test_generic_profile_anonymizes_username(self):
        text = "Username: mario.rossi"

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "Username: [USERNAME_001]",
            sanitized,
        )

        self.assertNotIn(
            "mario.rossi",
            sanitized,
        )

        self.assertTrue(
            any(
                finding.category == "USERNAME"
                for finding in findings
            )
        )

    def test_burp_profile_anonymizes_username(self):
        text = """GET /login HTTP/1.1
Host: app.acme.local
Content-Type: application/json

Username: mario.rossi
"""

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "Username: [USERNAME_001]",
            sanitized,
        )

        self.assertIn(
            "GET /login HTTP/1.1",
            sanitized,
        )

        self.assertIn(
            "Host: [HOSTNAME_001]",
            sanitized,
        )

        self.assertTrue(
            any(
                finding.category == "USERNAME"
                for finding in findings
            )
        )

    def test_windows_context_does_not_break_secrets(self):
        text = """
        Windows Server 2022
        Domain Controller: dc01.acme.local
        Username: administrator
        Password: SuperSecretPassword123!
        """

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "Username: administrator",
            sanitized,
        )

        self.assertIn(
            "[PASSWORD_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            "SuperSecretPassword123!",
            sanitized,
        )

    # ---------------------------------------------------------
    # PROFILE RESULT
    # ---------------------------------------------------------

    def test_profile_result_nmap(self):
        text = """
        Nmap scan report for dc01.acme.local
        PORT     STATE SERVICE
        445/tcp  open microsoft-ds
        """

        _, _, _, profile = sanitize(text)

        self.assertEqual(
            profile.name,
            "NMAP",
        )

        self.assertGreater(
            profile.confidence,
            0.0,
        )

        self.assertGreater(
            profile.scores["NMAP"],
            0,
        )

    def test_profile_result_burp(self):
        text = """GET /login HTTP/1.1
Host: app.acme.local
User-Agent: Mozilla/5.0
Content-Type: application/json
"""

        _, _, _, profile = sanitize(text)

        self.assertEqual(
            profile.name,
            "BURP",
        )

        self.assertGreater(
            profile.scores["BURP"],
            0,
        )

    def test_profile_result_generic(self):
        text = "hello world"

        _, _, _, profile = sanitize(text)

        self.assertEqual(
            profile.name,
            "GENERIC",
        )

        self.assertEqual(
            profile.confidence,
            0.0,
        )

    def test_context_engine_detects_multiple_profiles(self):
        from vapt_sanitize.context import ContextEngine

        text = """NMAP ENUMERATION

Nmap scan report for dc01.acme.local
PORT     STATE SERVICE
445/tcp  open microsoft-ds

BURP HTTP REQUEST

GET /login HTTP/1.1
Host: app.acme.local
Authorization: Bearer SECRET123456789

WINDOWS ENUMERATION

Windows Server 2022
Domain Controller: dc01.acme.local
Username: administrator
"""

        engine = ContextEngine()
        blocks = engine.analyze(text)

        profiles = [
            block.profile
            for block in blocks
        ]

        self.assertIn("NMAP", profiles)
        self.assertIn("BURP", profiles)
        self.assertIn("WINDOWS", profiles)

    # ---------------------------------------------------------
    # MIXED CONTEXT SANITIZATION
    # ---------------------------------------------------------

    def test_mixed_context_uses_block_profiles(self):
        text = """NMAP ENUMERATION

Nmap scan report for dc01.acme.local
PORT     STATE SERVICE
445/tcp  open microsoft-ds

BURP HTTP REQUEST

GET /login HTTP/1.1
Host: app.acme.local
Authorization: Bearer SECRET123456789

Username: mario.rossi

WINDOWS ENUMERATION

Windows Server 2022
Domain Controller: dc01.acme.local
Username: administrator
Password: SuperSecretPassword123!
"""

        sanitized, findings, _, _ = sanitize(text)

        # NMAP / Windows technical context survives.
        self.assertIn(
            "445/tcp",
            sanitized,
        )

        self.assertIn(
            "Windows Server 2022",
            sanitized,
        )

        # BURP username is contextualized/anonymized.
        self.assertIn(
            "Username: [USERNAME_001]",
            sanitized,
        )

        self.assertNotIn(
            "mario.rossi",
            sanitized,
        )

        # Windows username remains useful technical context.
        self.assertIn(
            "Username: administrator",
            sanitized,
        )

        # Secret protection remains unconditional.
        self.assertIn(
            "[PASSWORD_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            "SuperSecretPassword123!",
            sanitized,
        )

        self.assertNotIn(
            "SECRET123456789",
            sanitized,
        )

        username_findings = [
            finding
            for finding in findings
            if finding.category == "USERNAME"
        ]

        self.assertEqual(
            len(username_findings),
            2,
        )

        self.assertEqual(
            username_findings[0].action,
            "pseudonymize",
        )

        self.assertEqual(
            username_findings[1].action,
            "preserve",
        )

    def test_windows_context_survives_blank_line(self):
        text = """WINDOWS ENUMERATION

Windows Server 2022
Domain Controller: dc01.acme.local

Username: administrator
Password: SuperSecretPassword123!

SMB:
445/tcp open microsoft-ds
"""

        sanitized, findings, _, _ = sanitize(text)

        self.assertIn(
            "Username: administrator",
            sanitized,
        )

        self.assertIn(
            "[PASSWORD_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            "SuperSecretPassword123!",
            sanitized,
        )

        self.assertNotIn(
            "[USERNAME_001]",
            sanitized,
        )

        self.assertTrue(
            any(
                finding.category == "PASSWORD"
                for finding in findings
            )
        )

    def test_context_engine_groups_section(self):
        from vapt_sanitize.context import ContextEngine

        text = """WINDOWS ENUMERATION

Windows Server 2022
Domain Controller: dc01.acme.local

Username: administrator

Password: SuperSecretPassword123!

SMB:
445/tcp open microsoft-ds

GOBUSTER

http://portal.acme.local/admin

Found: http://portal.acme.local/.git/
"""

        engine = ContextEngine()
        blocks = engine.analyze(text)

        self.assertEqual(
            len(blocks),
            2,
        )

        self.assertEqual(
            blocks[0].profile,
            "WINDOWS",
        )

        self.assertEqual(
            blocks[1].profile,
            "GOBUSTER",
        )

        self.assertIn(
            "Username: administrator",
            blocks[0].text,
        )

        self.assertIn(
            "Password: SuperSecretPassword123!",
            blocks[0].text,
        )

        self.assertIn(
            ".git/",
            blocks[1].text,
        )

    def test_context_engine_preserves_section_boundaries(self):
        from vapt_sanitize.context import ContextEngine

        text = """NMAP ENUMERATION

Nmap scan report for dc01.acme.local
445/tcp open microsoft-ds

BURP HTTP REQUEST

GET /login HTTP/1.1
Host: app.acme.local
Authorization: Bearer SECRET123456789

WINDOWS ENUMERATION

Windows Server 2022
Username: administrator
"""

        engine = ContextEngine()
        blocks = engine.analyze(text)

        self.assertEqual(
            len(blocks),
            3,
        )

        self.assertEqual(
            [block.profile for block in blocks],
            [
                "NMAP",
                "BURP",
                "WINDOWS",
            ],
        )

    def test_realistic_fixture_sections(self):
        from vapt_sanitize.context import ContextEngine

        text = """NMAP ENUMERATION

Nmap scan report for dc01.acme.local (10.10.10.5)

BURP HTTP REQUEST

GET /api/v1/users HTTP/1.1

WINDOWS ENUMERATION

Windows Server 2022

GOBUSTER

http://portal.acme.local/admin

AWS

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

PRIVATE KEY

-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----

CREDIT CARD TEST

Card: 4111 1111 1111 1111

LINUX

Ubuntu Linux
"""

        engine = ContextEngine()
        blocks = engine.analyze(text)

        profiles = [
            block.profile
            for block in blocks
        ]

        self.assertEqual(
            profiles,
            [
                "NMAP",
                "BURP",
                "WINDOWS",
                "GOBUSTER",
                "AWS",
                "SECRETS",
                "PII",
                "LINUX",
            ],
        )

    def test_aws_section_preserves_context(self):
        from vapt_sanitize.context import ContextEngine

        text = """AWS

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

AWS_SECRET_ACCESS_KEY=exampleSecretValue123456789

Region: eu-west-1
"""

        engine = ContextEngine()
        blocks = engine.analyze(text)

        self.assertEqual(
            len(blocks),
            1,
        )

        self.assertEqual(
            blocks[0].profile,
            "AWS",
        )

        self.assertIn(
            "Region: eu-west-1",
            blocks[0].text,
        )

    def test_secrets_section(self):
        from vapt_sanitize.context import ContextEngine

        text = """PRIVATE KEY

-----BEGIN RSA PRIVATE KEY-----
FAKE
-----END RSA PRIVATE KEY-----
"""

        engine = ContextEngine()
        blocks = engine.analyze(text)

        self.assertEqual(
            len(blocks),
            1,
        )

        self.assertEqual(
            blocks[0].profile,
            "SECRETS",
        )

    def test_pii_section(self):
        from vapt_sanitize.context import ContextEngine

        text = """CREDIT CARD TEST

Card: 4111 1111 1111 1111
"""

        engine = ContextEngine()
        blocks = engine.analyze(text)

        self.assertEqual(
            len(blocks),
            1,
        )

        self.assertEqual(
            blocks[0].profile,
            "PII",
        )

    # ---------------------------------------------------------
    # POLICY ENGINE
    # ---------------------------------------------------------

    def test_policy_windows_preserves_username(self):
        from vapt_sanitize.policy import Policy

        policy = Policy()

        text = """
        Windows Server 2022
        Username: administrator
        Password: SuperSecretPassword123!
        """

        sanitized, findings, _, _ = sanitize(
            text,
            policy=policy,
        )

        self.assertIn(
            "Username: administrator",
            sanitized,
        )

        self.assertIn(
            "[PASSWORD_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            "SuperSecretPassword123!",
            sanitized,
        )

    def test_policy_can_change_noncritical_action(self):
        from vapt_sanitize.policy import Policy

        custom_policy = Policy(
            {
                "GLOBAL": {
                    "EMAIL": "redact",
                },
                "GENERIC": {},
            }
        )

        text = "Contact admin@cliente.it"

        sanitized, findings, _, _ = sanitize(
            text,
            policy=custom_policy,
        )

        self.assertIn(
            "[EMAIL_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            "admin@cliente.it",
            sanitized,
        )

    def test_policy_cannot_disable_secret_redaction(self):
        from vapt_sanitize.policy import Policy, PolicyError

        with self.assertRaises(PolicyError):
            Policy(
                {
                    "GLOBAL": {
                        "BEARER_TOKEN": "preserve",
                    }
                }
            )

    def test_pii_policy_can_redact_username(self):
        from vapt_sanitize.policy import Policy

        policy = Policy(
            {
                "PII": {
                    "USERNAME": "redact",
                }
            }
        )

        text = "Username: mario.rossi"

        sanitized, findings, _, _ = sanitize(
            text,
            profile="PII",
            policy=policy,
        )

        self.assertEqual(
            sanitized,
            "Username: [USERNAME_REDACTED]",
        )

        self.assertEqual(
            findings[0].category,
            "USERNAME",
        )

        self.assertEqual(
            findings[0].action,
            "redact",
        )

    # ---------------------------------------------------------
    # EXPLAIN
    # ---------------------------------------------------------

    def test_explain_mandatory_secret(self):
        from vapt_sanitize.policy import Policy

        text = "Password: SuperSecretPassword123!"

        _, findings, _, _ = sanitize(
            text,
            policy=Policy(),
        )

        self.assertEqual(
            len(findings),
            1,
        )

        self.assertEqual(
            findings[0].action,
            "redact",
        )

        self.assertEqual(
            findings[0].reason,
            "mandatory security rule",
        )

        self.assertNotIn(
            "SuperSecretPassword123!",
            findings[0].replacement,
        )

    def test_explain_profile_policy(self):
        from vapt_sanitize.policy import Policy

        policy = Policy(
            {
                "WINDOWS": {
                    "USERNAME": "preserve",
                }
            }
        )

        text = """
        Windows Server 2022
        Username: administrator
        """

        _, findings, _, _ = sanitize(
            text,
            profile="WINDOWS",
            policy=policy,
        )

        username_findings = [
            finding
            for finding in findings
            if finding.category == "USERNAME"
        ]

        self.assertEqual(
            len(username_findings),
            1,
        )

        self.assertEqual(
            username_findings[0].action,
            "preserve",
        )

        self.assertEqual(
            username_findings[0].reason,
            "profile policy",
        )

    def test_explain_does_not_contain_original_value(self):
        text = "password=SuperSecretPassword123!"

        _, findings, _, _ = sanitize(text)

        self.assertNotIn(
            "SuperSecretPassword123!",
            findings[0].replacement,
        )

        self.assertNotIn(
            "SuperSecretPassword123!",
            findings[0].reason,
        )

    # ---------------------------------------------------------
    # CLIPBOARD
    # ---------------------------------------------------------
    def test_clipboard_roundtrip_with_mock(self):
        from unittest.mock import MagicMock, patch

        import vapt_sanitize.clipboard as clipboard

        clipboard_data = (
            "password=SuperSecretPassword123!\n"
            "Email: admin@cliente.it\n"
        )

        mock_backend = MagicMock()

        mock_backend.read.return_value = clipboard_data

        with patch(
            "vapt_sanitize.clipboard.get_clipboard_backend",
            return_value=mock_backend,
        ):

            result = clipboard.read_clipboard()

            self.assertEqual(
                result,
                clipboard_data,
            )

            sanitized = (
                "[PASSWORD_REDACTED]\n"
                "Email: [EMAIL_001]\n"
            )

            clipboard.write_clipboard(
                sanitized
            )

            mock_backend.write.assert_called_once_with(
                sanitized
            )

    def test_clipboard_never_writes_original_secret(self):
        from unittest.mock import MagicMock, patch

        import vapt_sanitize.clipboard as clipboard

        original = "SuperSecretPassword123!"
        sanitized = "[PASSWORD_REDACTED]"

        mock_backend = MagicMock()

        with patch(
            "vapt_sanitize.clipboard.get_clipboard_backend",
            return_value=mock_backend,
        ):

            clipboard.write_clipboard(
                sanitized
            )

            mock_backend.write.assert_called_once_with(
                sanitized
            )

            written = (
                mock_backend.write.call_args.args[0]
            )

            self.assertNotIn(
                original,
                written,
            )

    # ---------------------------------------------------------
    # CLIPBOARD FAIL-CLOSED
    # ---------------------------------------------------------

    def test_empty_clipboard_is_rejected(self):
        from unittest.mock import patch

        from vapt_sanitize.clipboard import (
            ClipboardError,
            read_clipboard,
        )

        with patch(
            "vapt_sanitize.clipboard.get_clipboard_backend"
        ) as mock_backend:

            mock_backend.return_value.read.return_value = ""

            with self.assertRaises(
                ClipboardError
            ):
                read_clipboard()

    def test_empty_clipboard_write_is_rejected(self):
        from unittest.mock import patch

        from vapt_sanitize.clipboard import (
            ClipboardError,
            write_clipboard,
        )

        with patch(
            "vapt_sanitize.clipboard.get_clipboard_backend"
        ) as mock_backend:

            with self.assertRaises(
                ClipboardError
            ):
                write_clipboard("")

            mock_backend.assert_not_called()

    def test_clipboard_verification_detects_mismatch(self):
        from unittest.mock import patch

        from vapt_sanitize.clipboard import (
            ClipboardError,
            verify_clipboard,
        )

        with patch(
            "vapt_sanitize.clipboard.read_clipboard",
            return_value="WRONG_DATA",
        ):

            with self.assertRaises(
                ClipboardError
            ):
                verify_clipboard(
                    "EXPECTED_DATA"
                )

    def test_clipboard_verification_accepts_match(self):
        from unittest.mock import patch

        from vapt_sanitize.clipboard import (
            verify_clipboard,
        )

        with patch(
            "vapt_sanitize.clipboard.read_clipboard",
            return_value="EXPECTED_DATA",
        ):

            verify_clipboard(
                "EXPECTED_DATA"
            )

    def test_burp_preview_does_not_expose_original_values(self):
        import subprocess
        import sys

        secret = "SuperSecretPassword123!"
        email = "admin@cliente.it"

        input_data = (
            "POST /login HTTP/1.1\n"
            "Host: api.cliente.it\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.signature\n"
            f"Email: {email}\n"
            f"Password: {secret}\n"
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.integrations.burp",
                "--preview",
            ],
            input=input_data,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)

        output = result.stdout

        self.assertIn(
            "VAPT_SANITIZER_PREVIEW_V1",
            output,
        )

        self.assertIn(
            "FINDINGS_COUNT:",
            output,
        )

        self.assertIn(
            "SANITIZED_B64:",
            output,
        )

        self.assertNotIn(
            secret,
            output,
        )

        self.assertNotIn(
            email,
            output,
        )

    def test_username_detected_in_json_burp(self):
        from vapt_sanitize.engine import sanitize
        from vapt_sanitize.policy import Policy

        text = '{"username": "administrator"}'

        sanitized, findings, _, _ = sanitize(
            text,
            profile="BURP",
            policy=Policy(),
        )

        self.assertEqual(
            sanitized,
            '{"username": "[USERNAME_001]"}',
        )

        self.assertTrue(
            any(
                finding.category == "USERNAME"
                for finding in findings
            )
        )

    def test_username_detected_in_form_burp(self):
        from vapt_sanitize.engine import sanitize
        from vapt_sanitize.policy import Policy

        text = "username=administrator"

        sanitized, findings, _, _ = sanitize(
            text,
            profile="BURP",
            policy=Policy(),
        )

        self.assertEqual(
            sanitized,
            "username=[USERNAME_001]",
        )

        self.assertTrue(
            any(
                finding.category == "USERNAME"
                for finding in findings
            )
        )

    def test_gate_policy_can_block_preserved_finding(self):
        from vapt_sanitize.engine import sanitize
        from vapt_sanitize.integrations.burp import (
            determine_security_gate,
        )
        from vapt_sanitize.policy import Policy

        policy = Policy(
            data={
                "BURP": {
                    "USERNAME": "preserve",
                },
            },
            gate={
                "PRESERVED_FINDING": "BLOCKED",
            },
        )

        sanitized, findings, _, _ = sanitize(
            "Username: administrator",
            profile="BURP",
            policy=policy,
        )

        gate, _ = determine_security_gate(
            findings,
            sanitized=sanitized,
            profile="BURP",
            policy=policy,
        )

        self.assertEqual(
            gate,
            "BLOCKED",
        )


    def test_gate_policy_can_block_no_findings(self):
        from vapt_sanitize.engine import sanitize
        from vapt_sanitize.integrations.burp import (
            determine_security_gate,
        )
        from vapt_sanitize.policy import Policy

        policy = Policy(
            gate={
                "NO_FINDINGS": "BLOCKED",
            },
        )

        sanitized, findings, _, _ = sanitize(
            "GET / HTTP/1.1\nUser-Agent: Mozilla/5.0\n",
            profile="BURP",
            policy=policy,
        )

        gate, _ = determine_security_gate(
            findings,
            sanitized=sanitized,
            profile="BURP",
            policy=policy,
        )

        self.assertEqual(
            gate,
            "BLOCKED",
        )


    def test_gate_policy_cannot_weaken_residual_secret_block(self):
        from vapt_sanitize.detectors import detect
        from vapt_sanitize.integrations.burp import (
            determine_security_gate,
        )
        from vapt_sanitize.policy import Policy

        policy = Policy(
            gate={
                "PRESERVED_FINDING": "PASS",
                "NO_FINDINGS": "PASS",
            },
        )

        unsafe_output = (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.test.signature"
        )

        findings = detect(
            unsafe_output,
            profile="BURP",
            policy=policy,
        )

        gate, _ = determine_security_gate(
            findings,
            sanitized=unsafe_output,
            profile="BURP",
            policy=policy,
        )

        self.assertEqual(
            gate,
            "BLOCKED",
        )


    def test_profile_result_nuclei(self):
        text = (
            "[INF] Current nuclei version: v3.4.10\n"
            "[tech-detect:nginx] [http] [info] "
            "https://portal.interno.local\n"
            "[INF] Matched-at: https://portal.interno.local/login\n"
        )

        _, _, _, profile = sanitize(text)

        self.assertEqual(
            profile.name,
            "NUCLEI",
        )

        self.assertGreater(
            profile.scores["NUCLEI"],
            0,
        )


    def test_context_engine_explicit_nuclei_section(self):
        from vapt_sanitize.context import ContextEngine

        text = (
            "NUCLEI SCAN OUTPUT\n\n"
            "[tech-detect:nginx] [http] [info] "
            "https://portal.interno.local\n"
        )

        blocks = ContextEngine().analyze(text)

        self.assertEqual(
            len(blocks),
            1,
        )

        self.assertEqual(
            blocks[0].profile,
            "NUCLEI",
        )


    def test_nuclei_profile_preserves_public_references_and_path_files(self):
        text = (
            "NUCLEI SCAN OUTPUT\n"
            "[api-docs:swagger-ui] [http] [info] "
            "https://api.interno.local/swagger/index.html\n"
            "[INF] Reference: "
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773\n"
            "[INF] Reference: "
            "https://httpd.apache.org/security/vulnerabilities_24.html\n"
            "[INF] Template repository: "
            "https://github.com/projectdiscovery/nuclei-templates\n"
        )

        sanitized, _, _, _ = sanitize(
            text,
            profile="NUCLEI",
        )

        self.assertIn(
            "https://[HOSTNAME_001]/swagger/index.html",
            sanitized,
        )

        self.assertIn(
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            sanitized,
        )

        self.assertIn(
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            sanitized,
        )

        self.assertIn(
            "https://github.com/projectdiscovery/nuclei-templates",
            sanitized,
        )

        self.assertNotIn(
            "api.interno.local",
            sanitized,
        )


    def test_nuclei_reference_protection_is_profile_specific(self):
        text = (
            "[INF] Reference: "
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773\n"
        )

        sanitized, _, _, _ = sanitize(
            text,
            profile="GENERIC",
        )

        self.assertNotIn(
            "nvd.nist.gov",
            sanitized,
        )

        self.assertIn(
            "[HOSTNAME_001]",
            sanitized,
        )


    def test_windows_single_label_hostnames_are_pseudonymized_consistently(self):
        text = r"""WINDOWS ENUMERATION
Host Name: APP-SRV01
Logon Server: \\DC01
C:\> dir \\FILE01\Deploy$
 Directory of \\FILE01\Deploy$
PS C:\> Get-SmbConnection
ServerName ShareName UserName Credential
---------- --------- -------- ----------
FILE01 Deploy$ CORP\svc_web CORP\svc_web
DC01 SYSVOL CORP\svc_web CORP\svc_web
PS C:\> Test-NetConnection DC01 -Port 445
ComputerName : DC01
"""

        sanitized, _, _, _ = sanitize(
            text,
            profile="WINDOWS",
        )

        self.assertIn("Host Name: [HOSTNAME_001]", sanitized)
        self.assertIn(r"Logon Server: \\[HOSTNAME_002]", sanitized)
        self.assertIn(r"dir \\[HOSTNAME_003]\Deploy$", sanitized)
        self.assertIn("[HOSTNAME_003] Deploy$", sanitized)
        self.assertIn("[HOSTNAME_002] SYSVOL", sanitized)
        self.assertIn("Test-NetConnection [HOSTNAME_002] -Port 445", sanitized)
        self.assertIn("ComputerName : [HOSTNAME_002]", sanitized)

        self.assertNotIn("APP-SRV01", sanitized)
        self.assertNotIn("FILE01", sanitized)
        self.assertNotIn("DC01", sanitized)


    def test_windows_file_like_tokens_are_preserved(self):
        text = r"""WINDOWS ENUMERATION
05/09/2026  11:03            18,422 web.config.bak
05/09/2026  11:03             4,118 deploy.ps1
BINARY_PATH_NAME : C:\Program Files\Backup Agent\backup-agent.exe
"""

        sanitized, _, _, _ = sanitize(
            text,
            profile="WINDOWS",
        )

        self.assertIn("web.config.bak", sanitized)
        self.assertIn("deploy.ps1", sanitized)
        self.assertIn("backup-agent.exe", sanitized)
        self.assertNotIn("[HOSTNAME_", sanitized)


    def test_windows_domain_sid_is_pseudonymized(self):
        text = """WINDOWS ENUMERATION
User SID: S-1-5-21-1111111111-2222222222-3333333333-1105
"""

        sanitized, findings, _, _ = sanitize(
            text,
            profile="WINDOWS",
        )

        self.assertIn("User SID: [WINDOWS_SID_001]", sanitized)
        self.assertNotIn(
            "S-1-5-21-1111111111-2222222222-3333333333-1105",
            sanitized,
        )
        self.assertTrue(
            any(f.category == "WINDOWS_SID" for f in findings)
        )


    def test_windows_netbios_domain_is_pseudonymized_but_username_is_preserved(self):
        text = r"""WINDOWS ENUMERATION
Current User: CORP\svc_web
Username: svc_web
SERVICE_START_NAME : CORP\svc_backup
CORP\Domain Users
BUILTIN\Administrators
"""

        sanitized, findings, _, _ = sanitize(
            text,
            profile="WINDOWS",
        )

        self.assertIn(r"Current User: [WINDOWS_DOMAIN_001]\svc_web", sanitized)
        self.assertIn("Username: svc_web", sanitized)
        self.assertIn(r"SERVICE_START_NAME : [WINDOWS_DOMAIN_001]\svc_backup", sanitized)
        self.assertIn(r"[WINDOWS_DOMAIN_001]\Domain Users", sanitized)
        self.assertIn(r"BUILTIN\Administrators", sanitized)
        self.assertNotIn("CORP\\", sanitized)
        self.assertTrue(
            any(f.category == "WINDOWS_DOMAIN" for f in findings)
        )


    def test_windows_standard_namespace_builtin_is_preserved(self):
        text = r"""WINDOWS ENUMERATION
BUILTIN\Administrators
BUILTIN\Users
"""

        sanitized, findings, _, _ = sanitize(
            text,
            profile="WINDOWS",
        )

        self.assertEqual(sanitized, text)
        self.assertFalse(
            any(f.category == "WINDOWS_DOMAIN" for f in findings)
        )


    def test_windows_paths_are_not_treated_as_netbios_domains(self):
        text = r"""WINDOWS ENUMERATION
BINARY_PATH_NAME : C:\Windows\System32\cmd.exe
Resource: D:\WebData\Current
Directory: \\FILE01\Deploy$
"""

        sanitized, findings, _, _ = sanitize(
            text,
            profile="WINDOWS",
        )

        self.assertIn(r"C:\Windows\System32\cmd.exe", sanitized)
        self.assertIn(r"D:\WebData\Current", sanitized)
        self.assertIn(r"Directory: \\[HOSTNAME_001]\Deploy$", sanitized)
        self.assertNotIn("[WINDOWS_DOMAIN_", sanitized)
        self.assertFalse(
            any(f.category == "WINDOWS_DOMAIN" for f in findings)
        )


    def test_windows_paths_with_spaces_are_not_treated_as_netbios_domains(self):
        text = r"""WINDOWS ENUMERATION
BINARY_PATH_NAME   : C:\Program Files\Backup Agent\backup-agent.exe
OTHER_PATH         : D:\Application Data\Vendor Name\agent.exe
"""

        sanitized, findings, _, _ = sanitize(
            text,
            profile="WINDOWS",
        )

        self.assertIn(
            r"C:\Program Files\Backup Agent\backup-agent.exe",
            sanitized,
        )
        self.assertIn(
            r"D:\Application Data\Vendor Name\agent.exe",
            sanitized,
        )
        self.assertNotIn("[WINDOWS_DOMAIN_", sanitized)
        self.assertFalse(
            any(f.category == "WINDOWS_DOMAIN" for f in findings)
        )


    def test_nopasswd_is_not_treated_as_password_secret(self):
        text = "(root) NOPASSWD: /usr/bin/systemctl restart web-prod.service"

        sanitized, findings, _, _ = sanitize(
            text,
            profile="LINUX",
        )

        self.assertIn("NOPASSWD:", sanitized)
        self.assertNotIn("[PASSWORD_REDACTED]", sanitized)
        self.assertFalse(any(f.category == "PASSWORD" for f in findings))


    def test_linux_file_like_tokens_are_preserved(self):
        text = """LINUX ENUMERATION
$ cat /etc/resolv.conf
app.conf
database.yml
nginx.conf
web-prod.service
/system.slice/web-prod.service
"""

        sanitized, _, _, _ = sanitize(
            text,
            profile="LINUX",
        )

        for expected in (
            "resolv.conf",
            "app.conf",
            "database.yml",
            "nginx.conf",
            "web-prod.service",
            "system.slice",
        ):
            self.assertIn(expected, sanitized)


    def test_linux_short_hostnames_are_pseudonymized(self):
        text = """LINUX ENUMERATION
 Static hostname: web-prod-01
$ cat /etc/hosts
127.0.1.1 web-prod-01
10.40.50.10 db-prod-01.corp.local db-prod-01
10.40.50.15 gitlab.corp.local gitlab
Matching Defaults entries for deploy on web-prod-01:
User deploy may run the following commands on web-prod-01:
"""

        sanitized, _, _, _ = sanitize(
            text,
            profile="LINUX",
        )

        self.assertNotIn("web-prod-01", sanitized)
        self.assertNotIn("db-prod-01.corp.local", sanitized)
        self.assertNotIn(" db-prod-01\n", sanitized)
        self.assertNotIn("gitlab.corp.local", sanitized)
        self.assertNotIn(" gitlab\n", sanitized)
        self.assertGreaterEqual(sanitized.count("[HOSTNAME_001]"), 4)


    def test_linux_environment_users_are_pseudonymized_but_system_accounts_preserved(self):
        text = """LINUX ENUMERATION
$ whoami
deploy
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),33(www-data)
AllowUsers deploy adminops
$ ps aux
root 1 0.0 0.0 /sbin/init
www-data 2 0.0 0.0 nginx
postgres 3 0.0 0.0 postgres
$ ls -la /home/deploy/.ssh
-rw------- 1 deploy deploy 419 id_ed25519
"""

        sanitized, _, _, _ = sanitize(
            text,
            profile="LINUX",
        )

        self.assertNotIn("\ndeploy\n", sanitized)
        self.assertIn("[USERNAME_001]", sanitized)
        self.assertIn("[USERNAME_002]", sanitized)
        self.assertNotIn("adminops", sanitized)
        self.assertIn("www-data", sanitized)
        self.assertIn("postgres", sanitized)
        self.assertIn("root", sanitized)


    def test_linux_machine_and_boot_ids_are_pseudonymized(self):
        text = """LINUX ENUMERATION
Machine ID: 8f1a2b3c4d5e67890123456789abcdef
Boot ID: 1234567890abcdef1234567890abcdef
"""

        sanitized, _, _, _ = sanitize(
            text,
            profile="LINUX",
        )

        self.assertIn("Machine ID: [LINUX_ID_001]", sanitized)
        self.assertIn("Boot ID: [LINUX_ID_002]", sanitized)
        self.assertNotIn("8f1a2b3c4d5e67890123456789abcdef", sanitized)
        self.assertNotIn("1234567890abcdef1234567890abcdef", sanitized)


    def test_private_ipv6_is_pseudonymized_but_loopback_is_preserved(self):
        text = """inet6 fe80::5054:ff:feab:cdef/64 scope link
inet6 fd12:3456:789a::10/64 scope global
listen [::1]:5432
listen [::]:80
"""

        sanitized, _, _, _ = sanitize(
            text,
            profile="LINUX",
        )

        self.assertIn("[PRIVATE_IPV6_001]/64", sanitized)
        self.assertIn("[PRIVATE_IPV6_002]/64", sanitized)
        self.assertNotIn("fe80::5054:ff:feab:cdef", sanitized)
        self.assertNotIn("fd12:3456:789a::10", sanitized)
        self.assertIn("[::1]:5432", sanitized)
        self.assertIn("[::]:80", sanitized)


    def test_broadcast_and_null_mac_are_preserved(self):
        text = """link/ether 52:54:00:ab:cd:ef brd ff:ff:ff:ff:ff:ff
null 00:00:00:00:00:00
"""

        sanitized, findings, _, _ = sanitize(
            text,
            profile="LINUX",
        )

        self.assertIn("[MAC_ADDRESS_001]", sanitized)
        self.assertIn("ff:ff:ff:ff:ff:ff", sanitized)
        self.assertIn("00:00:00:00:00:00", sanitized)
        self.assertEqual(
            sum(f.category == "MAC_ADDRESS" for f in findings),
            1,
        )


    def test_aws_all_credential_shapes_are_redacted(self):
        text = '''AWS ENUMERATION
access_key     AKIAIOSFODNN7EXAMPLE shared-credentials-file
secret_key     wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY shared-credentials-file
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEExampleSyntheticSessionTokenForTestingOnly1234567890
"AccessKeyId": "ASIAEXAMPLESESSION1234",
"SecretAccessKey": "SyntheticSecretAccessKeyForTestingOnlyEXAMPLE123456",
"Token": "SyntheticTemporarySessionTokenForTestingOnlyEXAMPLE987654321"
'''

        sanitized, findings, _, _ = sanitize(text, profile="AWS")

        self.assertGreaterEqual(sanitized.count("[AWS_ACCESS_KEY_REDACTED]"), 2)
        self.assertGreaterEqual(sanitized.count("[AWS_SECRET_KEY_REDACTED]"), 2)
        self.assertGreaterEqual(sanitized.count("[AWS_SESSION_TOKEN_REDACTED]"), 2)

        for raw_secret in (
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "IQoJb3JpZ2luX2VjEExampleSyntheticSessionTokenForTestingOnly1234567890",
            "ASIAEXAMPLESESSION1234",
            "SyntheticSecretAccessKeyForTestingOnlyEXAMPLE123456",
            "SyntheticTemporarySessionTokenForTestingOnlyEXAMPLE987654321",
        ):
            self.assertNotIn(raw_secret, sanitized)

        categories = {finding.category for finding in findings}
        self.assertIn("AWS_ACCESS_KEY", categories)
        self.assertIn("AWS_SECRET_KEY", categories)
        self.assertIn("AWS_SESSION_TOKEN", categories)


    def test_aws_opaque_environment_identifiers_are_pseudonymized(self):
        text = '''AWS ENUMERATION
"UserId": "AIDAEXAMPLEUSER1234",
"Account": "123456789012",
"Arn": "arn:aws:iam::123456789012:user/redteam-audit",
"InstanceId": "i-0abc123def4567890",
"VpcId": "vpc-0a1b2c3d4e5f67890",
"SubnetId": "subnet-0123456789abcdef0",
"GroupId": "sg-0123456789abcdef0",
"Id": "AIPAXAMPLEINSTANCE123"
'''

        sanitized, _, _, _ = sanitize(text, profile="AWS")

        self.assertEqual(sanitized.count("[AWS_ACCOUNT_ID_001]"), 2)
        self.assertIn("[AWS_PRINCIPAL_ID_001]", sanitized)
        self.assertIn("[AWS_PRINCIPAL_ID_002]", sanitized)
        self.assertIn("[AWS_RESOURCE_ID_001]", sanitized)
        self.assertIn("[AWS_RESOURCE_ID_002]", sanitized)
        self.assertIn("[AWS_RESOURCE_ID_003]", sanitized)
        self.assertIn("[AWS_RESOURCE_ID_004]", sanitized)
        self.assertNotIn("123456789012", sanitized)
        self.assertNotIn("i-0abc123def4567890", sanitized)
        self.assertNotIn("vpc-0a1b2c3d4e5f67890", sanitized)


    def test_aws_lambda_handler_is_preserved_as_code_metadata(self):
        text = '''AWS ENUMERATION
{
    "FunctionName": "invoice-processor-prod",
    "Runtime": "python3.12",
    "Handler": "app.handler"
}
'''

        sanitized, _, _, _ = sanitize(text, profile="AWS")

        self.assertIn('"Handler": "app.handler"', sanitized)
        self.assertNotIn("[HOSTNAME_", sanitized)


    def test_aws_session_token_mandatory_rule_cannot_be_weakened(self):
        from vapt_sanitize.policy import Policy, PolicyError

        with self.assertRaises(PolicyError):
            Policy({"GLOBAL": {"AWS_SESSION_TOKEN": "preserve"}})


    def test_aws_customer_resource_names_are_pseudonymized_but_provider_metadata_is_preserved(self):
        text = '''AWS ENUMERATION
$ aws iam list-attached-user-policies --user-name redteam-audit
"Arn": "arn:aws:iam::123456789012:user/redteam-audit"
"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
"Buckets": [{"Name": "acme-prod-backups"}]
$ aws s3api get-bucket-location --bucket acme-prod-backups
"Owner": {"DisplayName": "acme-cloud-admin", "ID": "79a59df900b949e55d96a1e698fba64dEXAMPLE"}
"GroupName": "prod-web-sg"
{"Key": "Name", "Value": "prod-web-01"}
"FunctionName": "invoice-processor-prod"
"FunctionArn": "arn:aws:lambda:eu-west-1:123456789012:function:invoice-processor-prod"
"Role": "arn:aws:iam::123456789012:role/lambda-invoice-role"
"ARN": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/database/password-AbCdEf"
"Name": "prod/database/password"
$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/WebServerRole
"Handler": "app.handler"
'''

        sanitized, _, _, _ = sanitize(text, profile="AWS")

        for raw_name in (
            "redteam-audit",
            "acme-prod-backups",
            "acme-cloud-admin",
            "prod-web-sg",
            "prod-web-01",
            "invoice-processor-prod",
            "lambda-invoice-role",
            "WebServerRole",
        ):
            self.assertNotIn(raw_name, sanitized)

        self.assertIn("[AWS_IAM_NAME_001]", sanitized)
        self.assertIn("[AWS_BUCKET_001]", sanitized)
        self.assertIn("[AWS_DISPLAY_NAME_001]", sanitized)
        self.assertIn("[AWS_SECURITY_GROUP_NAME_001]", sanitized)
        self.assertIn("[AWS_TAG_NAME_001]", sanitized)
        self.assertIn("[AWS_FUNCTION_NAME_001]", sanitized)
        self.assertIn("[AWS_SECRET_NAME_", sanitized)
        self.assertIn("arn:aws:iam::aws:policy/ReadOnlyAccess", sanitized)
        self.assertIn("169.254.169.254", sanitized)
        self.assertIn('"Handler": "app.handler"', sanitized)


    def test_secrets_profile_redacts_assignment_and_json_credentials(self):
        text = '''SECRETS ENUMERATION
DB_PASSWORD=SuperSecretPassword123!
X_API_KEY=abcdef1234567890ABCDEF1234567890
CLIENT_SECRET=clientSecret_FAKE_qwerty987654321
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEFAKESESSIONTOKEN1234567890abcdefghijklmnop
{
  "password": "P@ssw0rd-FAKE-2026",
  "api_key": "json_FAKE_api_key_123456789",
  "access_token": "access_FAKE_1234567890",
  "refresh_token": "refresh_FAKE_0987654321",
  "clientSecret": "camelCase_FAKE_client_secret_123456"
}
'''
        raw_values = (
            "SuperSecretPassword123!",
            "abcdef1234567890ABCDEF1234567890",
            "clientSecret_FAKE_qwerty987654321",
            "IQoJb3JpZ2luX2VjEFAKESESSIONTOKEN1234567890abcdefghijklmnop",
            "P@ssw0rd-FAKE-2026",
            "json_FAKE_api_key_123456789",
            "access_FAKE_1234567890",
            "refresh_FAKE_0987654321",
            "camelCase_FAKE_client_secret_123456",
        )

        sanitized, findings, _, _ = sanitize(text, profile="SECRETS")

        for raw in raw_values:
            self.assertNotIn(raw, sanitized)
        self.assertIn("DB_PASSWORD=[PASSWORD_REDACTED]", sanitized)
        self.assertIn("X_API_KEY=[API_KEY_REDACTED]", sanitized)
        self.assertIn("CLIENT_SECRET=[GENERIC_SECRET_REDACTED]", sanitized)
        self.assertIn("AWS_SESSION_TOKEN=[AWS_SESSION_TOKEN_REDACTED]", sanitized)
        self.assertIn('"password": "[PASSWORD_REDACTED]"', sanitized)
        self.assertIn('"api_key": "[API_KEY_REDACTED]"', sanitized)
        self.assertTrue(any(f.category == "GENERIC_SECRET" for f in findings))


    def test_secrets_profile_redacts_database_dsn_passwords(self):
        text = '''DATABASE_URL=postgresql://appsvc:AnotherFakePass987!@db01.internal.example:5432/appdb
mysql://root:FakeMysqlPassword!@10.10.10.20:3306/prod
mongodb://dbadmin:FakeMongoPassword!@mongo.internal.example:27017/admin
redis://:FakeRedisPassword!@10.10.10.30:6379/0
'''
        sanitized, findings, _, _ = sanitize(text, profile="SECRETS")

        for raw in (
            "AnotherFakePass987!",
            "FakeMysqlPassword!",
            "FakeMongoPassword!",
            "FakeRedisPassword!",
        ):
            self.assertNotIn(raw, sanitized)
        self.assertEqual(sanitized.count("[DATABASE_PASSWORD_REDACTED]"), 4)
        self.assertTrue(any(f.category == "DATABASE_PASSWORD" for f in findings))


    def test_secrets_profile_redacts_non_bearer_authorization_credentials(self):
        text = '''Proxy-Authorization: Basic YWRtaW46RkFLRV9QQVNTV09SRA==
Authorization: Basic dXNlcjpGQUtFX1BBU1NXT1JE
Authorization: Token token_FAKE_1234567890
Authorization: ApiKey apikey_FAKE_0987654321
'''
        sanitized, findings, _, _ = sanitize(text, profile="SECRETS")

        self.assertEqual(sanitized.count("[AUTH_CREDENTIAL_REDACTED]"), 4)
        self.assertNotIn("YWRtaW46RkFLRV9QQVNTV09SRA==", sanitized)
        self.assertNotIn("dXNlcjpGQUtFX1BBU1NXT1JE", sanitized)
        self.assertNotIn("token_FAKE_1234567890", sanitized)
        self.assertNotIn("apikey_FAKE_0987654321", sanitized)
        self.assertTrue(any(f.category == "AUTH_CREDENTIAL" for f in findings))


    def test_secrets_profile_redacts_session_variants_and_provider_tokens(self):
        # Build the Slack-shaped token at runtime so public repository secret
        # scanners do not mistake the synthetic fixture for a live credential.
        slack_token = (
            "xox"
            + "b-"
            + "111111111111-222222222222-FAKEabcdefghijklmnop"
        )
        text = f'''Cookie: PHPSESSID=abc123xyz789; sessionid=sess_FAKE_987654321
GITHUB_TOKEN=ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz
GITLAB_TOKEN=glpat-FAKE1234567890abcdefghijklmnop
SLACK_TOKEN={slack_token}
session_id=log_session_FAKE_123456
'''
        sanitized, findings, _, _ = sanitize(text, profile="SECRETS")

        for raw in (
            "abc123xyz789",
            "sess_FAKE_987654321",
            "ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz",
            "glpat-FAKE1234567890abcdefghijklmnop",
            slack_token,
            "log_session_FAKE_123456",
        ):
            self.assertNotIn(raw, sanitized)
        self.assertGreaterEqual(sanitized.count("[SESSION_REDACTED]"), 3)
        self.assertTrue(any(f.category in {"GENERIC_SECRET", "PROVIDER_TOKEN"} for f in findings))


    def test_provider_token_is_redacted_even_without_assignment(self):
        token = "ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz"
        sanitized, findings, _, _ = sanitize(
            f"leaked credential: {token}",
            profile="SECRETS",
        )

        self.assertNotIn(token, sanitized)
        self.assertIn("[PROVIDER_TOKEN_REDACTED]", sanitized)
        self.assertTrue(any(f.category == "PROVIDER_TOKEN" for f in findings))


    def test_secret_mandatory_rules_cannot_be_weakened(self):
        from vapt_sanitize.policy import Policy, PolicyError

        for category in (
            "SESSION",
            "AUTH_CREDENTIAL",
            "DATABASE_PASSWORD",
            "PROVIDER_TOKEN",
            "GENERIC_SECRET",
        ):
            with self.subTest(category=category):
                with self.assertRaises(PolicyError):
                    Policy({"GLOBAL": {category: "preserve"}})


    def test_password_and_api_key_redaction_preserves_field_names(self):
        text = '''DB_PASSWORD=SuperSecretPassword123!
"password": "P@ssw0rd-FAKE-2026"
X_API_KEY=abcdef1234567890ABCDEF1234567890
"apiKey": "camelCase_FAKE_api_key_123456789"
'''
        sanitized, _, _, _ = sanitize(text, profile="SECRETS")

        self.assertIn("DB_PASSWORD=[PASSWORD_REDACTED]", sanitized)
        self.assertIn('"password": "[PASSWORD_REDACTED]"', sanitized)
        self.assertIn("X_API_KEY=[API_KEY_REDACTED]", sanitized)
        self.assertIn('"apiKey": "[API_KEY_REDACTED]"', sanitized)


    def test_pii_direct_identifiers_are_pseudonymized(self):
        text = '''PII ENUMERATION
Username: m.rossi
Full Name: Mario Rossi
Phone: +39 333 123 4567
Date of Birth: 15/04/1986
Fiscal Code: RSSMRA86D15F839X
Employee ID: EMP-004281
{
  "customer_id": "CUS-2026-000184",
  "first_name": "Mario",
  "last_name": "Rossi",
  "address": "Via Roma 123",
  "city": "Napoli",
  "postal_code": "80100"
}
'''
        sanitized, findings, _, _ = sanitize(text, profile="PII")

        for raw in (
            "m.rossi",
            "Mario Rossi",
            "+39 333 123 4567",
            "15/04/1986",
            "RSSMRA86D15F839X",
            "EMP-004281",
            "CUS-2026-000184",
            "Via Roma 123",
            '"city": "Napoli"',
            '"postal_code": "80100"',
        ):
            self.assertNotIn(raw, sanitized)

        for category in (
            "USERNAME",
            "PERSON_NAME",
            "PHONE",
            "DATE_OF_BIRTH",
            "FISCAL_CODE",
            "PII_RECORD_ID",
            "ADDRESS",
            "CITY",
            "POSTAL_CODE",
        ):
            self.assertTrue(any(f.category == category for f in findings))


    def test_pii_phone_mapping_is_consistent_across_formatting(self):
        text = """PII ENUMERATION
Phone: +39 333 123 4567
phone=+39-333-123-4567
{"mobile": "+393331234567"}
Phone: 0039 333 123 4567
"""

        sanitized, _, _, _ = sanitize(text, profile="PII")

        self.assertEqual(sanitized.count("[PHONE_001]"), 4)
        self.assertNotIn("[PHONE_002]", sanitized)
        for raw in (
            "+39 333 123 4567",
            "+39-333-123-4567",
            "+393331234567",
            "0039 333 123 4567",
        ):
            self.assertNotIn(raw, sanitized)

    def test_pii_distinct_phone_numbers_keep_distinct_placeholders(self):
        text = """PII ENUMERATION
Phone: +39 333 123 4567
Phone: +39 347 765 4321
"""

        sanitized, _, _, _ = sanitize(text, profile="PII")

        self.assertEqual(sanitized.count("[PHONE_001]"), 1)
        self.assertEqual(sanitized.count("[PHONE_002]"), 1)


    def test_pii_iban_is_redacted(self):
        iban = "IT60X0542811101000000123456"
        sanitized, findings, _, _ = sanitize(
            f"IBAN: {iban}",
            profile="PII",
        )

        self.assertNotIn(iban, sanitized)
        self.assertIn("[IBAN_REDACTED]", sanitized)
        self.assertTrue(any(f.category == "IBAN" for f in findings))


    def test_pii_username_mapping_is_consistent_across_syntaxes(self):
        text = '''PII ENUMERATION
Username: m.rossi
login user=m.rossi
{"username": "m.rossi"}
username=m.rossi
'''
        sanitized, _, _, _ = sanitize(text, profile="PII")

        self.assertEqual(sanitized.count("[USERNAME_001]"), 4)
        self.assertNotIn("[USERNAME_002]", sanitized)
        self.assertNotIn("m.rossi", sanitized)


    def test_pii_public_reference_is_preserved_but_target_hostname_is_not(self):
        text = '''PII ENUMERATION
Target hostname: crm.internal.example
Public reference: https://owasp.org/www-project-top-ten/
'''
        sanitized, _, _, _ = sanitize(text, profile="PII")

        self.assertNotIn("crm.internal.example", sanitized)
        self.assertIn("Target hostname: [HOSTNAME_001]", sanitized)
        self.assertIn("https://owasp.org/www-project-top-ten/", sanitized)


    def test_pii_numeric_record_id_is_consistent_between_url_and_row(self):
        text = '''PII ENUMERATION
POST /api/v1/customers/184 HTTP/1.1
id=184
'''
        sanitized, _, _, _ = sanitize(text, profile="PII")

        self.assertEqual(sanitized.count("[PII_RECORD_ID_001]"), 2)
        self.assertNotIn("customers/184", sanitized)
        self.assertNotIn("id=184", sanitized)

    def test_pii_labeled_tax_id_is_protected_even_when_not_italian_cf_format(self):
        text = '''PII ENUMERATION
Tax ID: FOREIGN-TAX-778899
{"national_id": "ID-99887766"}
'''
        sanitized, findings, _, _ = sanitize(text, profile="PII")

        self.assertNotIn("FOREIGN-TAX-778899", sanitized)
        self.assertNotIn("ID-99887766", sanitized)
        self.assertEqual(sanitized.count("[FISCAL_CODE_"), 2)
        self.assertTrue(any(f.category == "FISCAL_CODE" for f in findings))


    def test_pii_formatted_iban_with_spaces_is_redacted(self):
        iban = "IT60 X054 2811 1010 0000 0123 456"
        sanitized, _, _, _ = sanitize(f"IBAN: {iban}", profile="PII")

        self.assertNotIn(iban, sanitized)
        self.assertIn("[IBAN_REDACTED]", sanitized)


    def test_aggressive_pii_policy_redacts_new_pii_categories(self):
        from vapt_sanitize.policy import Policy

        policy = Policy.from_file("policies/aggressive_pii.yml")
        text = '''PII ENUMERATION
Full Name: Mario Rossi
Phone: +39 333 123 4567
Date of Birth: 15/04/1986
Fiscal Code: RSSMRA86D15F839X
Employee ID: EMP-004281
{"address": "Via Roma 123", "city": "Napoli", "postal_code": "80100"}
'''
        sanitized, _, _, _ = sanitize(text, profile="PII", policy=policy)

        self.assertIn("[PERSON_NAME_REDACTED]", sanitized)
        self.assertIn("[PHONE_REDACTED]", sanitized)
        self.assertIn("[DATE_OF_BIRTH_REDACTED]", sanitized)
        self.assertIn("[FISCAL_CODE_REDACTED]", sanitized)
        self.assertIn("[PII_RECORD_ID_REDACTED]", sanitized)
        self.assertIn("[ADDRESS_REDACTED]", sanitized)
        self.assertIn("[CITY_REDACTED]", sanitized)
        self.assertIn("[POSTAL_CODE_REDACTED]", sanitized)


    def test_generic_username_mapping_is_consistent_across_log_json_and_home_path(self):
        text = '''GENERIC SECURITY TESTING OUTPUT
login user=j.smith
{"username": "j.smith"}
/home/j.smith/.ssh/authorized_keys
DB_USER=appsvc
DATABASE_URL=postgresql://appsvc:FakePassword123!@db01.internal.example:5432/prod
'''
        sanitized, _, _, _ = sanitize(text, profile="GENERIC")

        self.assertEqual(sanitized.count("[USERNAME_001]"), 3)
        self.assertEqual(sanitized.count("[USERNAME_002]"), 2)
        self.assertNotIn("j.smith", sanitized)
        self.assertNotIn("appsvc", sanitized)

    def test_generic_path_filenames_are_preserved_without_preserving_target_hostnames(self):
        text = r'''GENERIC SECURITY TESTING OUTPUT
Target: app01.internal.example
/etc/nginx/nginx.conf
/var/www/app/config.yml
C:\\Program Files\\Generic Agent\\agent.exe
'''
        sanitized, _, _, _ = sanitize(text, profile="GENERIC")

        self.assertIn("Target: [HOSTNAME_001]", sanitized)
        self.assertIn("/etc/nginx/nginx.conf", sanitized)
        self.assertIn("/var/www/app/config.yml", sanitized)
        self.assertIn(r"C:\\Program Files\\Generic Agent\\agent.exe", sanitized)

    def test_generic_public_reference_urls_are_preserved_but_target_is_not(self):
        text = '''GENERIC SECURITY TESTING OUTPUT
Target: app01.internal.example
OWASP: https://owasp.org/www-project-top-ten/
NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
Vendor docs: https://nginx.org/en/docs/
'''
        sanitized, _, _, _ = sanitize(text, profile="GENERIC")

        self.assertNotIn("app01.internal.example", sanitized)
        self.assertIn("https://owasp.org/www-project-top-ten/", sanitized)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2021-41773", sanitized)
        self.assertIn("https://nginx.org/en/docs/", sanitized)

    def test_generic_session_token_uses_generic_secret_not_aws_category(self):
        raw = "generic_session_token_FAKE_654321"
        sanitized, findings, _, _ = sanitize(
            f"SESSION_TOKEN={raw}",
            profile="GENERIC",
        )

        self.assertNotIn(raw, sanitized)
        self.assertIn("[GENERIC_SECRET_REDACTED]", sanitized)
        self.assertFalse(any(f.category == "AWS_SESSION_TOKEN" for f in findings))

    def test_aws_cli_unprefixed_session_token_remains_mandatory_aws_redaction(self):
        raw = "IQoJb3JpZ2luX2VjEFAKESESSIONTOKEN1234567890"
        sanitized, findings, _, _ = sanitize(
            f"session_token = {raw}",
            profile="AWS",
        )

        self.assertNotIn(raw, sanitized)
        self.assertIn("[AWS_SESSION_TOKEN_REDACTED]", sanitized)
        self.assertTrue(any(f.category == "AWS_SESSION_TOKEN" for f in findings))


    def test_generic_identity_json_pseudonymizes_high_confidence_pii(self):
        text = '''GENERIC SECURITY TESTING OUTPUT
{
  "username": "j.smith",
  "name": "John Smith",
  "email": "john.smith@example.internal",
  "phone": "+39 333 765 4321",
  "employee_id": "EMP-009931"
}
'''
        sanitized, _, _, _ = sanitize(text, profile="GENERIC")

        self.assertNotIn("John Smith", sanitized)
        self.assertNotIn("+39 333 765 4321", sanitized)
        self.assertNotIn("EMP-009931", sanitized)
        self.assertIn('"name": "[PERSON_NAME_001]"', sanitized)
        self.assertIn('"phone": "[PHONE_001]"', sanitized)
        self.assertIn('"employee_id": "[PII_RECORD_ID_001]"', sanitized)

    def test_generic_technical_json_name_is_preserved_without_identity_context(self):
        text = '''GENERIC SECURITY TESTING OUTPUT
{"name": "nginx", "version": "1.24.0", "port": 443}
'''
        sanitized, _, _, _ = sanitize(text, profile="GENERIC")

        self.assertIn('"name": "nginx"', sanitized)
        self.assertNotIn("[PERSON_NAME_", sanitized)


    def test_generic_preserves_standard_aws_service_endpoint_only_in_endpoint_metadata(self):
        text = '''GENERIC SECURITY TESTING OUTPUT
Endpoint: ec2.eu-west-1.amazonaws.com
Target: app01.internal.example
'''
        sanitized, _, _, _ = sanitize(text, profile="GENERIC")

        self.assertIn("Endpoint: ec2.eu-west-1.amazonaws.com", sanitized)
        self.assertNotIn("app01.internal.example", sanitized)
        self.assertIn("Target: [HOSTNAME_", sanitized)

    def test_generic_does_not_exempt_customer_specific_aws_public_dns_as_service_endpoint(self):
        customer_host = "ec2-18-202-10-55.eu-west-1.compute.amazonaws.com"
        text = f'''GENERIC SECURITY TESTING OUTPUT
Endpoint: {customer_host}
'''
        sanitized, _, _, _ = sanitize(text, profile="GENERIC")

        self.assertNotIn(customer_host, sanitized)
        self.assertIn("Endpoint: [HOSTNAME_", sanitized)


if __name__ == "__main__":
    unittest.main()
