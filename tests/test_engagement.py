import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vapt_sanitize.engagement import EngagementError, EngagementVault
from vapt_sanitize.engine import sanitize


class EngagementEnvironmentMixin:
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.config_dir = root / "config"
        self.data_dir = root / "data"
        self.env_patch = patch.dict(
            os.environ,
            {
                "VAPT_SANITIZE_CONFIG_DIR": str(self.config_dir),
                "VAPT_SANITIZE_DATA_DIR": str(self.data_dir),
            },
            clear=False,
        )
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.temp_dir.cleanup()


class TestEngagementVault(EngagementEnvironmentMixin, unittest.TestCase):
    def test_create_uses_separate_key_and_encrypted_mapping(self):
        vault = EngagementVault.create("ACME-2026-09")
        text = "Nmap scan report for srv01.acme.local (10.20.30.45)\n"
        sanitize(text, profile="NMAP", mapping_store=vault)

        key_path = self.config_dir / "master.key"
        mapping_path = self.data_dir / "engagements" / "ACME-2026-09" / "mapping.enc"

        self.assertTrue(key_path.is_file())
        self.assertTrue(mapping_path.is_file())
        self.assertNotEqual(key_path.parent, mapping_path.parent)
        self.assertNotIn(b"10.20.30.45", mapping_path.read_bytes())
        self.assertNotIn(b"srv01.acme.local", mapping_path.read_bytes())

        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(mapping_path.stat().st_mode), 0o600)

    def test_same_engagement_reuses_mapping_across_runs_and_profiles(self):
        vault = EngagementVault.create("ACME")
        first, _, _, _ = sanitize(
            "Nmap scan report for srv01.acme.local (10.20.30.45)\n",
            profile="NMAP",
            mapping_store=vault,
        )

        reopened = EngagementVault.open("ACME")
        second, _, _, _ = sanitize(
            "Target: srv01.acme.local\nIP Address: 10.20.30.45\n",
            profile="GENERIC",
            mapping_store=reopened,
        )

        self.assertIn("[HOSTNAME_001]", first)
        self.assertIn("[PRIVATE_IP_001]", first)
        self.assertIn("Target: [HOSTNAME_001]", second)
        self.assertIn("IP Address: [PRIVATE_IP_001]", second)

    def test_new_values_continue_category_counter(self):
        vault = EngagementVault.create("ACME")
        sanitize("Target: host1.acme.local\n", profile="GENERIC", mapping_store=vault)

        reopened = EngagementVault.open("ACME")
        sanitized, _, _, _ = sanitize(
            "Target: host2.acme.local\n",
            profile="GENERIC",
            mapping_store=reopened,
        )

        self.assertIn("[HOSTNAME_002]", sanitized)

    def test_different_engagements_are_isolated(self):
        acme = EngagementVault.create("ACME")
        beta = EngagementVault.create("BETA")

        first, _, _, _ = sanitize(
            "IP Address: 10.20.30.45\n",
            profile="GENERIC",
            mapping_store=acme,
        )
        second, _, _, _ = sanitize(
            "IP Address: 172.16.10.77\n",
            profile="GENERIC",
            mapping_store=beta,
        )

        self.assertIn("[PRIVATE_IP_001]", first)
        self.assertIn("[PRIVATE_IP_001]", second)
        self.assertEqual(EngagementVault.open("ACME").resolve("[PRIVATE_IP_001]"), ["10.20.30.45"])
        self.assertEqual(EngagementVault.open("BETA").resolve("[PRIVATE_IP_001]"), ["172.16.10.77"])

    def test_resolve_returns_phone_aliases_for_same_canonical_value(self):
        vault = EngagementVault.create("ACME")
        sanitize(
            "PII ENUMERATION\nPhone: +39 333 123 4567\nphone=+39-333-123-4567\n",
            profile="PII",
            mapping_store=vault,
        )

        reopened = EngagementVault.open("ACME")
        self.assertEqual(
            reopened.resolve("[PHONE_001]"),
            ["+39 333 123 4567", "+39-333-123-4567"],
        )

    def test_redacted_secrets_are_never_stored(self):
        vault = EngagementVault.create("ACME")
        secret = "DoNotStoreThisPassword123!"
        sanitize(
            f"DB_PASSWORD={secret}\nTarget: app.acme.local\n",
            profile="SECRETS",
            mapping_store=vault,
        )

        reopened = EngagementVault.open("ACME")
        serialized_values = "\n".join(
            value
            for entry in reopened.entries()
            for value in entry["originals"]
        )

        self.assertNotIn(secret, serialized_values)
        self.assertFalse(any(entry["category"] == "PASSWORD" for entry in reopened.entries()))

    def test_missing_master_key_fails_closed(self):
        EngagementVault.create("ACME")
        (self.config_dir / "master.key").unlink()

        with self.assertRaises(EngagementError):
            EngagementVault.open("ACME")

    def test_invalid_engagement_id_is_rejected(self):
        with self.assertRaises(EngagementError):
            EngagementVault.create("../client")


class TestEngagementCLI(EngagementEnvironmentMixin, unittest.TestCase):
    def _env(self):
        env = os.environ.copy()
        env["VAPT_SANITIZE_CONFIG_DIR"] = str(self.config_dir)
        env["VAPT_SANITIZE_DATA_DIR"] = str(self.data_dir)
        return env

    def test_cli_init_sanitize_resolve_and_show(self):
        init_result = subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "engagement", "init", "ACME"],
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(init_result.returncode, 0, init_result.stderr)

        sanitize_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "generic",
                "--engagement",
                "ACME",
            ],
            input="Target: app.acme.local\nIP Address: 10.20.30.45\n",
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(sanitize_result.returncode, 0, sanitize_result.stderr)
        self.assertIn("[HOSTNAME_001]", sanitize_result.stdout)
        self.assertIn("[PRIVATE_IP_001]", sanitize_result.stdout)
        self.assertIn("Engagement: ACME", sanitize_result.stdout)

        resolve_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "engagement",
                "resolve",
                "ACME",
                "[PRIVATE_IP_001]",
                "[HOSTNAME_001]",
            ],
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(resolve_result.returncode, 0, resolve_result.stderr)
        self.assertIn("[PRIVATE_IP_001] -> 10.20.30.45", resolve_result.stdout)
        self.assertIn("[HOSTNAME_001] -> app.acme.local", resolve_result.stdout)

        show_result = subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "engagement", "show", "ACME"],
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(show_result.returncode, 0, show_result.stderr)
        self.assertIn("10.20.30.45", show_result.stdout)
        self.assertIn("app.acme.local", show_result.stdout)

    def test_cli_ai_handoff_reports_engagement_and_reuses_mapping(self):
        subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "engagement", "init", "ACME"],
            text=True,
            capture_output=True,
            env=self._env(),
            check=True,
        )

        first = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "nmap",
                "--engagement",
                "ACME",
                "--ai-prompt",
            ],
            input="Nmap scan report for srv01.acme.local (10.20.30.45)\n22/tcp open ssh\n",
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("[+] Engagement: ACME", first.stderr)
        self.assertNotIn("Engagement: ACME", first.stdout)

        second = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "generic",
                "--engagement",
                "ACME",
                "--ai-prompt",
            ],
            input="Target: srv01.acme.local\nIP Address: 10.20.30.45\n",
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("Target: [HOSTNAME_001]", second.stdout)
        self.assertIn("IP Address: [PRIVATE_IP_001]", second.stdout)

    def test_burp_python_bridge_can_share_engagement_mapping(self):
        subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "engagement", "init", "ACME"],
            text=True,
            capture_output=True,
            env=self._env(),
            check=True,
        )

        first = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.integrations.burp",
                "--profile",
                "BURP",
                "--engagement",
                "ACME",
            ],
            input="GET / HTTP/1.1\nHost: portal.acme.local\n\n",
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("Host: [HOSTNAME_001]", first.stdout)

        second = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize",
                "-",
                "--profile",
                "generic",
                "--engagement",
                "ACME",
            ],
            input="Target: portal.acme.local\n",
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("Target: [HOSTNAME_001]", second.stdout)


    def test_burp_bridge_explicit_roots_override_mismatched_home_and_xdg(self):
        subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "engagement", "init", "ACME"],
            text=True,
            capture_output=True,
            env=self._env(),
            check=True,
        )

        wrong_root = Path(self.temp_dir.name) / "wrong-runtime-home"
        wrong_root.mkdir(parents=True, exist_ok=True)

        env = self._env()
        env["HOME"] = str(wrong_root)
        env["XDG_CONFIG_HOME"] = str(wrong_root / "config")
        env["XDG_DATA_HOME"] = str(wrong_root / "data")
        # VAPT_SANITIZE_* intentionally remain set to the known vault roots,
        # matching what the Burp Java integration now forces on the child.

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.integrations.burp",
                "--profile",
                "BURP",
                "--engagement",
                "ACME",
                "--preview",
            ],
            input="GET / HTTP/1.1\nHost: portal.acme.local\n\n",
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VAPT_SANITIZER_PREVIEW_V1", result.stdout)

    def test_burp_bridge_surfaces_safe_engagement_error_detail(self):
        subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "engagement", "init", "ACME"],
            text=True,
            capture_output=True,
            env=self._env(),
            check=True,
        )

        (self.config_dir / "master.key").unlink()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vapt_sanitize.integrations.burp",
                "--profile",
                "BURP",
                "--engagement",
                "ACME",
                "--preview",
            ],
            input="GET / HTTP/1.1\nHost: portal.acme.local\n\n",
            text=True,
            capture_output=True,
            env=self._env(),
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Sanitization failed: EngagementError: Master key not found:",
            result.stderr,
        )
        self.assertNotIn("portal.acme.local", result.stderr)

    def test_concurrent_cli_runs_do_not_reuse_same_placeholder_for_different_values(self):
        subprocess.run(
            [sys.executable, "-m", "vapt_sanitize", "engagement", "init", "ACME"],
            text=True,
            capture_output=True,
            env=self._env(),
            check=True,
        )

        command = [
            sys.executable,
            "-m",
            "vapt_sanitize",
            "-",
            "--profile",
            "generic",
            "--engagement",
            "ACME",
        ]

        first = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self._env(),
        )
        second = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self._env(),
        )

        out1, err1 = first.communicate("Target: alpha.acme.local\n", timeout=20)
        out2, err2 = second.communicate("Target: beta.acme.local\n", timeout=20)

        self.assertEqual(first.returncode, 0, err1)
        self.assertEqual(second.returncode, 0, err2)

        placeholder1 = re.search(r"\[HOSTNAME_\d{3}\]", out1)
        placeholder2 = re.search(r"\[HOSTNAME_\d{3}\]", out2)
        self.assertIsNotNone(placeholder1)
        self.assertIsNotNone(placeholder2)
        self.assertNotEqual(placeholder1.group(0), placeholder2.group(0))

        vault = EngagementVault.open("ACME")
        resolved = {
            tuple(vault.resolve(placeholder1.group(0))),
            tuple(vault.resolve(placeholder2.group(0))),
        }
        self.assertEqual(
            resolved,
            {("alpha.acme.local",), ("beta.acme.local",)},
        )


if __name__ == "__main__":
    unittest.main()
