import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from vapt_sanitize.llm.handoff import residual_mandatory_secret
from vapt_sanitize.policy import Policy


class TestCLIAndAIHandoff(unittest.TestCase):

    def test_ai_handoff_residual_scan_uses_selected_profile(self):

        with patch(
            "vapt_sanitize.llm.handoff.detect",
            return_value=[],
        ) as detect_mock:

            result = residual_mandatory_secret(
                "22/tcp open ssh",
                profile="NMAP",
                policy=Policy(),
            )

        self.assertIsNone(
            result
        )

        detect_mock.assert_called_once_with(
            "22/tcp open ssh",
            profile="NMAP",
            policy=detect_mock.call_args.kwargs["policy"],
        )


    def test_cli_nmap_ai_prompt_stdout(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            input_path = Path(temp_dir) / "scan.txt"

            input_path.write_text(
                "Nmap scan report for server.example.com\n"
                "Host is up.\n"
                "PORT   STATE SERVICE VERSION\n"
                "22/tcp open  ssh     OpenSSH 9.2\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vapt_sanitize",
                    str(input_path),
                    "--profile",
                    "nmap",
                    "--ai-prompt",
                    "--task",
                    "analyze-security",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "Source: Nmap enumeration",
            result.stdout,
        )

        self.assertIn(
            "--- SANITIZED DATA ---",
            result.stdout,
        )

        self.assertIn(
            "[HOSTNAME_001]",
            result.stdout,
        )

        self.assertNotIn(
            "server.example.com",
            result.stdout,
        )

        self.assertIn(
            "Security Gate: PASS",
            result.stderr,
        )

        self.assertIn(
            "No network communication was performed.",
            result.stderr,
        )


    def test_cli_nmap_ai_prompt_preserves_official_banner_url(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            input_path = Path(temp_dir) / "scan.txt"

            input_path.write_text(
                "Starting Nmap 7.95 ( https://nmap.org ) at "
                "2026-09-09 16:30 CEST\n"
                "Nmap scan report for server.example.com\n"
                "PORT   STATE SERVICE\n"
                "443/tcp open  https\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vapt_sanitize",
                    str(input_path),
                    "--profile",
                    "nmap",
                    "--ai-prompt",
                    "--task",
                    "analyze-security",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "https://nmap.org",
            result.stdout,
        )

        self.assertNotIn(
            "server.example.com",
            result.stdout,
        )

        self.assertIn(
            "[HOSTNAME_001]",
            result.stdout,
        )


    def test_cli_gobuster_ai_prompt_preserves_paths_and_sanitizes_hosts(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            input_path = Path(temp_dir) / "gobuster.txt"

            input_path.write_text(
                "GOBUSTER ENUMERATION\n"
                "[+] Url: https://portal.interno.local\n"
                "[+] Wordlist: /usr/share/wordlists/dirb/common.txt\n"
                "/admin (Status: 301) [Size: 169] "
                "[--> https://admin.interno.local/login]\n"
                "/robots.txt (Status: 200) [Size: 87]\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vapt_sanitize",
                    str(input_path),
                    "--profile",
                    "gobuster",
                    "--ai-prompt",
                    "--task",
                    "analyze-security",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "Source: Gobuster enumeration",
            result.stdout,
        )

        self.assertIn(
            "/usr/share/wordlists/dirb/common.txt",
            result.stdout,
        )

        self.assertIn(
            "/robots.txt",
            result.stdout,
        )

        self.assertNotIn(
            "portal.interno.local",
            result.stdout,
        )

        self.assertNotIn(
            "admin.interno.local",
            result.stdout,
        )

        self.assertIn(
            "[HOSTNAME_001]",
            result.stdout,
        )

    def test_cli_nmap_ai_prompt_to_clipboard(self):

        import vapt_sanitize.__main__ as cli

        with tempfile.TemporaryDirectory() as temp_dir:

            input_path = Path(temp_dir) / "scan.txt"

            input_path.write_text(
                "Nmap scan report for server.example.com\n"
                "PORT   STATE SERVICE\n"
                "443/tcp open  https\n",
                encoding="utf-8",
            )

            argv = [
                "vapt-sanitize",
                str(input_path),
                "--profile",
                "nmap",
                "--ai-prompt",
                "--ai-clipboard",
            ]

            with (
                patch.object(
                    sys,
                    "argv",
                    argv,
                ),
                patch.object(
                    cli,
                    "write_clipboard",
                ) as write_mock,
                patch.object(
                    cli,
                    "verify_clipboard",
                ) as verify_mock,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):

                cli.main()

        write_mock.assert_called_once()
        verify_mock.assert_called_once()

        prompt = write_mock.call_args.args[0]

        self.assertEqual(
            verify_mock.call_args.args[0],
            prompt,
        )

        self.assertIn(
            "Source: Nmap enumeration",
            prompt,
        )

        self.assertIn(
            "[HOSTNAME_001]",
            prompt,
        )

        self.assertNotIn(
            "server.example.com",
            prompt,
        )


    def test_cli_review_requires_explicit_approval(self):

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "generic",
                "--ai-prompt",
            ],
            input="harmless technical note\n",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            3,
        )

        self.assertEqual(
            result.stdout,
            "",
        )

        self.assertIn(
            "AI handoff requires REVIEW",
            result.stderr,
        )

        self.assertIn(
            "--review-approved",
            result.stderr,
        )


    def test_cli_review_approved_builds_prompt(self):

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "generic",
                "--ai-prompt",
                "--review-approved",
            ],
            input="harmless technical note\n",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "Source: Generic security testing input",
            result.stdout,
        )

        self.assertIn(
            "harmless technical note",
            result.stdout,
        )

        self.assertIn(
            "Security Gate: REVIEW",
            result.stderr,
        )


    def test_cli_strict_no_findings_blocks(self):

        policy_path = (
            Path(__file__).resolve().parents[1]
            / "policies"
            / "strict_llm.yml"
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "generic",
                "--policy",
                str(policy_path),
                "--ai-prompt",
                "--review-approved",
            ],
            input="harmless technical note\n",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            3,
        )

        self.assertEqual(
            result.stdout,
            "",
        )

        self.assertIn(
            "AI handoff BLOCKED",
            result.stderr,
        )


    def test_cli_standard_file_output_still_sanitizes_without_ai_prompt(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            input_path = Path(temp_dir) / "request.txt"
            output_path = Path(temp_dir) / "clean.txt"

            original_token = (
                "eyJhbGciOiJIUzI1NiJ9.test.signature"
            )

            input_path.write_text(
                "GET / HTTP/1.1\n"
                "Host: api.example.com\n"
                f"Authorization: Bearer {original_token}\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vapt_sanitize",
                    str(input_path),
                    "--profile",
                    "burp",
                    "-o",
                    str(output_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            sanitized = output_path.read_text(
                encoding="utf-8"
            )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "[BEARER_TOKEN_REDACTED]",
            sanitized,
        )

        self.assertNotIn(
            original_token,
            sanitized,
        )

        self.assertIn(
            "=== VAPT-SANITIZE REPORT ===",
            result.stdout,
        )



    def test_cli_nuclei_ai_prompt_explicit_profile(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            input_path = Path(temp_dir) / "nuclei.txt"

            input_path.write_text(
                "NUCLEI SCAN OUTPUT\n"
                "[INF] Current nuclei version: v3.4.10\n"
                "[api-docs:swagger-ui] [http] [info] "
                "https://api.interno.local/swagger/index.html\n"
                "[INF] Reference: "
                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773\n"
                "[INF] Template repository: "
                "https://github.com/projectdiscovery/nuclei-templates\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vapt_sanitize",
                    str(input_path),
                    "--profile",
                    "nuclei",
                    "--ai-prompt",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "Source: Nuclei scan",
            result.stdout,
        )

        self.assertIn(
            "https://[HOSTNAME_001]/swagger/index.html",
            result.stdout,
        )

        self.assertIn(
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            result.stdout,
        )

        self.assertIn(
            "https://github.com/projectdiscovery/nuclei-templates",
            result.stdout,
        )

        self.assertNotIn(
            "api.interno.local",
            result.stdout,
        )

        self.assertIn(
            "Profile: NUCLEI",
            result.stderr,
        )


    def test_cli_nuclei_ai_prompt_auto_detect(self):

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--ai-prompt",
            ],
            input=(
                "[INF] Current nuclei version: v3.4.10\n"
                "[tech-detect:nginx] [http] [info] "
                "https://portal.interno.local\n"
                "[INF] Matched-at: "
                "https://portal.interno.local/login\n"
            ),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "Source: Nuclei scan",
            result.stdout,
        )

        self.assertIn(
            "Profile: NUCLEI",
            result.stderr,
        )

        self.assertNotIn(
            "portal.interno.local",
            result.stdout,
        )


    def test_cli_windows_ai_prompt_preserves_files_and_hides_host_sid(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "windows",
                "--ai-prompt",
            ],
            input=r"""WINDOWS ENUMERATION
Host Name: APP-SRV01
Windows Server 2022
Logon Server: \\DC01
IPv4 Address: 10.20.30.45
User SID: S-1-5-21-1111111111-2222222222-3333333333-1105
C:\> dir \\FILE01\Deploy$
05/09/2026  11:03            18,422 web.config.bak
BINARY_PATH_NAME : C:\Program Files\Backup Agent\backup-agent.exe
""",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Source: Windows enumeration", result.stdout)
        self.assertIn("web.config.bak", result.stdout)
        self.assertIn("backup-agent.exe", result.stdout)
        self.assertIn("[WINDOWS_SID_001]", result.stdout)
        self.assertIn("[PRIVATE_IP_001]", result.stdout)
        self.assertNotIn("APP-SRV01", result.stdout)
        self.assertNotIn("DC01", result.stdout)
        self.assertNotIn("FILE01", result.stdout)
        self.assertNotIn(
            "S-1-5-21-1111111111-2222222222-3333333333-1105",
            result.stdout,
        )
        self.assertIn("Profile: WINDOWS", result.stderr)


    def test_windows_ai_prompt_pseudonymizes_netbios_domain_only(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "windows",
                "--ai-prompt",
            ],
            input=r"""WINDOWS ENUMERATION
Current User: CORP\svc_web
SERVICE_START_NAME : CORP\svc_backup
CORP\Domain Users
BUILTIN\Administrators
""",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(r"[WINDOWS_DOMAIN_001]\svc_web", result.stdout)
        self.assertIn(r"[WINDOWS_DOMAIN_001]\svc_backup", result.stdout)
        self.assertIn(r"[WINDOWS_DOMAIN_001]\Domain Users", result.stdout)
        self.assertIn(r"BUILTIN\Administrators", result.stdout)
        self.assertNotIn("CORP\\", result.stdout)
        self.assertIn("Profile: WINDOWS", result.stderr)


    def test_cli_linux_ai_prompt_preserves_technical_metadata_and_hides_environment_identifiers(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "linux",
                "--ai-prompt",
            ],
            input="""LINUX ENUMERATION
$ hostnamectl
 Static hostname: web-prod-01
 Machine ID: 8f1a2b3c4d5e67890123456789abcdef
$ whoami
deploy
$ ip addr show
 link/ether 52:54:00:ab:cd:ef brd ff:ff:ff:ff:ff:ff
 inet6 fe80::5054:ff:feab:cdef/64 scope link
$ cat /etc/resolv.conf
search corp.local
$ ls -la /var/www/app
-rw-r----- 1 deploy deploy 2841 app.conf
-rw-r----- 1 root root 612 web-prod.service
$ cat /etc/ssh/sshd_config
AllowUsers deploy adminops
$ sudo -l
Matching Defaults entries for deploy on web-prod-01:
User deploy may run the following commands on web-prod-01:
    (root) NOPASSWD: /usr/bin/systemctl restart web-prod.service
""",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Source: Linux enumeration", result.stdout)
        self.assertIn("app.conf", result.stdout)
        self.assertIn("web-prod.service", result.stdout)
        self.assertIn("resolv.conf", result.stdout)
        self.assertIn("NOPASSWD:", result.stdout)
        self.assertIn("ff:ff:ff:ff:ff:ff", result.stdout)
        self.assertIn("[LINUX_ID_001]", result.stdout)
        self.assertIn("[PRIVATE_IPV6_001]", result.stdout)
        self.assertIn("[USERNAME_001]", result.stdout)
        self.assertNotIn("web-prod-01", result.stdout)
        self.assertNotIn("adminops", result.stdout)
        self.assertNotIn("8f1a2b3c4d5e67890123456789abcdef", result.stdout)
        self.assertNotIn("fe80::5054:ff:feab:cdef", result.stdout)
        self.assertNotIn("[PASSWORD_REDACTED]", result.stdout)
        self.assertIn("Profile: LINUX", result.stderr)


    def test_cli_aws_ai_prompt_never_contains_raw_credentials(self):
        raw_values = (
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "IQoJb3JpZ2luX2VjEExampleSyntheticSessionTokenForTestingOnly1234567890",
            "ASIAEXAMPLESESSION1234",
            "SyntheticSecretAccessKeyForTestingOnlyEXAMPLE123456",
            "SyntheticTemporarySessionTokenForTestingOnlyEXAMPLE987654321",
        )

        result = subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "-", "--profile", "aws", "--ai-prompt"],
            input='''AWS ENUMERATION
access_key     AKIAIOSFODNN7EXAMPLE shared-credentials-file
secret_key     wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY shared-credentials-file
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEExampleSyntheticSessionTokenForTestingOnly1234567890
"Account": "123456789012",
"InstanceId": "i-0abc123def4567890",
"Handler": "app.handler",
"AccessKeyId": "ASIAEXAMPLESESSION1234",
"SecretAccessKey": "SyntheticSecretAccessKeyForTestingOnlyEXAMPLE123456",
"Token": "SyntheticTemporarySessionTokenForTestingOnlyEXAMPLE987654321"
''',
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Source: AWS enumeration", result.stdout)
        self.assertIn("[AWS_ACCESS_KEY_REDACTED]", result.stdout)
        self.assertIn("[AWS_SECRET_KEY_REDACTED]", result.stdout)
        self.assertIn("[AWS_SESSION_TOKEN_REDACTED]", result.stdout)
        self.assertIn("[AWS_ACCOUNT_ID_001]", result.stdout)
        self.assertIn("[AWS_RESOURCE_ID_001]", result.stdout)
        self.assertIn('"Handler": "app.handler"', result.stdout)
        for raw_value in raw_values:
            self.assertNotIn(raw_value, result.stdout)
        self.assertIn("Security Gate: PASS", result.stderr)


    def test_cli_aws_ai_prompt_pseudonymizes_customer_resource_names(self):
        result = subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "-", "--profile", "aws", "--ai-prompt"],
            input='''AWS ENUMERATION
$ aws iam list-attached-user-policies --user-name redteam-audit
"Arn": "arn:aws:iam::123456789012:user/redteam-audit"
"Buckets": [{"Name": "acme-prod-backups"}]
$ aws s3api get-bucket-location --bucket acme-prod-backups
"FunctionName": "invoice-processor-prod"
"FunctionArn": "arn:aws:lambda:eu-west-1:123456789012:function:invoice-processor-prod"
"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
"Handler": "app.handler"
''',
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("redteam-audit", result.stdout)
        self.assertNotIn("acme-prod-backups", result.stdout)
        self.assertNotIn("invoice-processor-prod", result.stdout)
        self.assertIn("[AWS_IAM_NAME_001]", result.stdout)
        self.assertIn("[AWS_BUCKET_001]", result.stdout)
        self.assertIn("[AWS_FUNCTION_NAME_001]", result.stdout)
        self.assertIn("arn:aws:iam::aws:policy/ReadOnlyAccess", result.stdout)
        self.assertIn('"Handler": "app.handler"', result.stdout)


    def test_cli_secrets_ai_prompt_never_contains_raw_credentials(self):
        raw_values = (
            "SuperSecretPassword123!",
            "AnotherFakePass987!",
            "abcdef1234567890ABCDEF1234567890",
            "clientSecret_FAKE_qwerty987654321",
            "IQoJb3JpZ2luX2VjEFAKESESSIONTOKEN1234567890abcdefghijklmnop",
            "ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz",
            "sess_FAKE_987654321",
            "P@ssw0rd-FAKE-2026",
            "access_FAKE_1234567890",
            "dXNlcjpGQUtFX1BBU1NXT1JE",
            "FakeMongoPassword!",
        )

        result = subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "-", "--profile", "secrets", "--ai-prompt"],
            input='''SECRETS ENUMERATION
DB_PASSWORD=SuperSecretPassword123!
DATABASE_URL=postgresql://appsvc:AnotherFakePass987!@db01.internal.example:5432/appdb
X_API_KEY=abcdef1234567890ABCDEF1234567890
CLIENT_SECRET=clientSecret_FAKE_qwerty987654321
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEFAKESESSIONTOKEN1234567890abcdefghijklmnop
GITHUB_TOKEN=ghp_FAKE1234567890abcdefghijklmnopqrstuvwxyz
Cookie: PHPSESSID=abc123; sessionid=sess_FAKE_987654321
{"password":"P@ssw0rd-FAKE-2026","access_token":"access_FAKE_1234567890"}
Authorization: Basic dXNlcjpGQUtFX1BBU1NXT1JE
mongodb://dbadmin:FakeMongoPassword!@mongo.internal.example:27017/admin
''',
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Source: Secrets / credentials review", result.stdout)
        self.assertIn("[PASSWORD_REDACTED]", result.stdout)
        self.assertIn("[API_KEY_REDACTED]", result.stdout)
        self.assertIn("[GENERIC_SECRET_REDACTED]", result.stdout)
        self.assertIn("[AWS_SESSION_TOKEN_REDACTED]", result.stdout)
        self.assertIn("[SESSION_REDACTED]", result.stdout)
        self.assertIn("[AUTH_CREDENTIAL_REDACTED]", result.stdout)
        self.assertIn("[DATABASE_PASSWORD_REDACTED]", result.stdout)
        for raw in raw_values:
            self.assertNotIn(raw, result.stdout)
        self.assertIn("Security Gate: PASS", result.stderr)
        self.assertIn("Profile: SECRETS", result.stderr)


    def test_pii_ai_prompt_hides_direct_identifiers_and_preserves_public_reference(self):
        content = '''PII ENUMERATION
Username: m.rossi
Full Name: Mario Rossi
Email: mario.rossi@cliente-example.it
Phone: +39 333 123 4567
Date of Birth: 15/04/1986
Fiscal Code: RSSMRA86D15F839X
IBAN: IT60X0542811101000000123456
Target hostname: crm.internal.example
Public reference: https://owasp.org/www-project-top-ten/
'''
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "pii.txt"
            input_path.write_text(content, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vapt_sanitize",
                    str(input_path),
                    "--profile",
                    "pii",
                    "--ai-prompt",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        for raw in (
            "m.rossi",
            "Mario Rossi",
            "mario.rossi@cliente-example.it",
            "+39 333 123 4567",
            "15/04/1986",
            "RSSMRA86D15F839X",
            "IT60X0542811101000000123456",
            "crm.internal.example",
        ):
            self.assertNotIn(raw, result.stdout)
        self.assertIn("https://owasp.org/www-project-top-ten/", result.stdout)
        self.assertIn("[IBAN_REDACTED]", result.stdout)
        self.assertIn("[PERSON_NAME_001]", result.stdout)


    def test_generic_ai_prompt_preserves_public_refs_and_paths_but_sanitizes_context_accounts(self):
        text = r'''GENERIC SECURITY TESTING OUTPUT
Target: app01.internal.example
login user=j.smith email=john.smith@example.internal
DB_USER=appsvc
DB_PASSWORD=GenericDbPassword_FAKE_789!
{"username": "j.smith", "name": "John Smith", "email": "john.smith@example.internal", "phone": "+39 333 765 4321", "employee_id": "EMP-009931"}
/etc/nginx/nginx.conf
/var/www/app/config.yml
/home/j.smith/.ssh/authorized_keys
C:\\Program Files\\Generic Agent\\agent.exe
OWASP: https://owasp.org/www-project-top-ten/
NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
Vendor docs: https://nginx.org/en/docs/
Endpoint: ec2.eu-west-1.amazonaws.com
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "generic.txt"
            input_path.write_text(text, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vapt_sanitize",
                    str(input_path),
                    "--profile",
                    "generic",
                    "--ai-prompt",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        for raw in (
            "app01.internal.example",
            "j.smith",
            "john.smith@example.internal",
            "appsvc",
            "GenericDbPassword_FAKE_789!",
            "John Smith",
            "+39 333 765 4321",
            "EMP-009931",
        ):
            self.assertNotIn(raw, result.stdout)
        self.assertIn("/etc/nginx/nginx.conf", result.stdout)
        self.assertIn("/var/www/app/config.yml", result.stdout)
        self.assertIn(r"C:\\Program Files\\Generic Agent\\agent.exe", result.stdout)
        self.assertIn("https://owasp.org/www-project-top-ten/", result.stdout)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2021-41773", result.stdout)
        self.assertIn("https://nginx.org/en/docs/", result.stdout)
        self.assertIn("Endpoint: ec2.eu-west-1.amazonaws.com", result.stdout)

if __name__ == "__main__":
    unittest.main()
