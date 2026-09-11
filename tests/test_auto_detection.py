import subprocess
import sys
import unittest

from vapt_sanitize.context import ContextEngine
from vapt_sanitize.profiles import detect_profile


class AutoDetectionTests(unittest.TestCase):
    def test_profile_detector_matrix(self):
        cases = {
            "NMAP": "Nmap scan report for host.internal.example\nPORT STATE SERVICE\n443/tcp open https\n",
            "BURP": "GET /login HTTP/1.1\nHost: app.internal.example\nAuthorization: Bearer FAKE123456789\n",
            "GOBUSTER": "Gobuster v3.6\n[+] Url: https://app.internal.example\n/admin (Status: 200)\n",
            "NUCLEI": "[INF] Current nuclei version: v3.4.10\n[tech-detect:nginx] [http] [info] https://app.internal.example\n",
            "WINDOWS": "Windows Server 2022\nHost Name: APP-SRV01\n",
            "LINUX": "Operating System: Debian GNU/Linux 12\nsshd\nsystemd\n",
            "AWS": "AWS ENUMERATION\n$ aws sts get-caller-identity\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            "SECRETS": "SECRETS ENUMERATION\nGET /login HTTP/1.1\nHost: app.internal.example\nDB_PASSWORD=FakePassword123!\n",
            "PII": "PII ENUMERATION\nGET /profile HTTP/1.1\nHost: app.internal.example\nFull Name: Mario Rossi\nEmail: mario.rossi@example.internal\n",
            "GENERIC": "GENERIC SECURITY TESTING OUTPUT\nGET /health HTTP/1.1\nHost: app.internal.example\n",
        }

        for expected, text in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(detect_profile(text).name, expected)

    def test_cli_ai_handoff_auto_detection_matrix(self):
        cases = {
            "NMAP": (
                "Nmap enumeration",
                "Nmap scan report for host.internal.example\nPORT STATE SERVICE\n443/tcp open https\n",
            ),
            "BURP": (
                "Burp HTTP data",
                "GET /login HTTP/1.1\nHost: app.internal.example\nAuthorization: Bearer FAKE123456789\n",
            ),
            "GOBUSTER": (
                "Gobuster enumeration",
                "Gobuster v3.6\n[+] Url: https://app.internal.example\n/admin (Status: 200)\n",
            ),
            "NUCLEI": (
                "Nuclei scan",
                "[INF] Current nuclei version: v3.4.10\n[tech-detect:nginx] [http] [info] https://app.internal.example\n",
            ),
            "WINDOWS": (
                "Windows enumeration",
                "WINDOWS ENUMERATION\nWindows Server 2022\nHost Name: APP-SRV01\n",
            ),
            "LINUX": (
                "Linux enumeration",
                "LINUX ENUMERATION\nOperating System: Debian GNU/Linux 12\nStatic hostname: web-prod-01\n",
            ),
            "AWS": (
                "AWS enumeration",
                "AWS ENUMERATION\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=FakeSecretKeyValue1234567890\n",
            ),
            "SECRETS": (
                "Secrets / credentials review",
                "SECRETS ENUMERATION\nGET /login HTTP/1.1\nHost: app.internal.example\nDB_PASSWORD=FakePassword123!\n",
            ),
            "PII": (
                "PII / personal data review",
                "PII ENUMERATION\nGET /profile HTTP/1.1\nHost: app.internal.example\nFull Name: Mario Rossi\nEmail: mario.rossi@example.internal\n",
            ),
            "GENERIC": (
                "Generic security testing input",
                "GENERIC SECURITY TESTING OUTPUT\nGET /health HTTP/1.1\nHost: app.internal.example\n",
            ),
        }

        for expected_profile, (expected_source, text) in cases.items():
            with self.subTest(expected_profile=expected_profile):
                result = subprocess.run(
                    [sys.executable, "-m", "vapt_sanitize", "-", "--ai-prompt"],
                    input=text,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Profile: {expected_profile}", result.stderr)
                self.assertIn(f"Source: {expected_source}", result.stdout)
                self.assertIn("Security Gate: PASS", result.stderr)

    def test_context_engine_recognizes_standardized_headers(self):
        cases = {
            "GOBUSTER ENUMERATION": "GOBUSTER",
            "LINUX ENUMERATION": "LINUX",
            "SECRETS ENUMERATION": "SECRETS",
            "PII ENUMERATION": "PII",
            "GENERIC SECURITY TESTING OUTPUT": "GENERIC",
        }

        engine = ContextEngine()
        for header, expected in cases.items():
            with self.subTest(header=header):
                blocks = engine.analyze(header + "\nexample body\n")
                self.assertEqual(len(blocks), 1)
                self.assertEqual(blocks[0].profile, expected)
                self.assertEqual(blocks[0].confidence, 1.0)

    def test_explicit_semantic_header_beats_embedded_http_signatures(self):
        http = "GET /profile HTTP/1.1\nHost: app.internal.example\nContent-Type: application/json\n"
        self.assertEqual(
            detect_profile("SECRETS ENUMERATION\n" + http + "DB_PASSWORD=FakePass123!\n").name,
            "SECRETS",
        )
        self.assertEqual(
            detect_profile("PII ENUMERATION\n" + http + "Email: user@example.internal\n").name,
            "PII",
        )
        self.assertEqual(
            detect_profile("GENERIC SECURITY TESTING OUTPUT\n" + http).name,
            "GENERIC",
        )

    def test_explicit_document_hint_only_applies_at_document_start(self):
        text = (
            "GET /login HTTP/1.1\n"
            "Host: app.internal.example\n"
            "Content-Type: text/plain\n\n"
            "SECRETS ENUMERATION\n"
        )
        self.assertEqual(detect_profile(text).name, "BURP")


if __name__ == "__main__":
    unittest.main()
