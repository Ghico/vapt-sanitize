import re
import unittest
from pathlib import Path

import vapt_sanitize


ROOT = Path(__file__).resolve().parents[1]


class TestReleaseMetadata(unittest.TestCase):

    def test_version_is_1_0_0_everywhere(self):
        self.assertEqual(vapt_sanitize.__version__, "1.0.0")
        self.assertEqual((ROOT / "VERSION").read_text().strip(), "1.0.0")
        self.assertIn('version = "1.0.0"', (ROOT / "pyproject.toml").read_text())

    def test_runtime_dependencies_are_frozen(self):
        requirements = (ROOT / "requirements.txt").read_text().splitlines()
        self.assertEqual(requirements, ["PyYAML==6.0.3", "cryptography==50.0.1"])
        pyproject = (ROOT / "pyproject.toml").read_text()
        for requirement in requirements:
            self.assertIn(f'"{requirement}"', pyproject)

    def test_all_ten_synthetic_fixtures_are_present(self):
        expected = {
            "nmap.txt", "burp.txt", "gobuster.txt", "nuclei.txt",
            "windows.txt", "linux.txt", "aws.txt", "secrets.txt",
            "pii.txt", "generic.txt",
        }
        actual = {p.name for p in (ROOT / "tests/fixtures").glob("*.txt")}
        self.assertEqual(actual, expected)

    def test_release_contains_no_vault_material(self):
        forbidden_names = {"master.key", "mapping.enc"}
        discovered = []
        for path in ROOT.rglob("*"):
            if path.is_file() and (path.name in forbidden_names or path.suffix == ".enc"):
                discovered.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(discovered, [])

    def test_burp_build_is_pinned_to_montoya_2026_7(self):
        build = (ROOT / "burp-extension/build.gradle").read_text()
        self.assertIn("compileOnly 'net.portswigger.burp.extensions:montoya-api:2026.7'", build)
        self.assertIn("JavaVersion.VERSION_17", build)

    def test_gitignore_excludes_sensitive_local_artifacts(self):
        gitignore = (ROOT / ".gitignore").read_text()
        for required in ["master.key", "mapping.enc", "engagements/", ".venv/"]:
            self.assertIn(required, gitignore)


    def test_burp_gradle_bootstrap_is_pinned_and_usable_from_cache(self):
        import os
        import subprocess
        import tempfile

        wrapper = ROOT / "burp-extension/gradlew"
        self.assertTrue(wrapper.exists())
        self.assertTrue(wrapper.stat().st_mode & 0o111)

        text = wrapper.read_text()
        self.assertIn('GRADLE_VERSION="8.14.3"', text)
        self.assertIn(
            'GRADLE_SHA256="bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531"',
            text,
        )
        self.assertNotIn("command -v gradle", (ROOT / "scripts/build-burp.sh").read_text())

        with tempfile.TemporaryDirectory() as tmp:
            fake_gradle = (
                Path(tmp)
                / "vapt-sanitize-bootstrap"
                / "gradle-8.14.3"
                / "bin"
                / "gradle"
            )
            fake_gradle.parent.mkdir(parents=True)
            fake_gradle.write_text('#!/usr/bin/env bash\nprintf "FAKE_GRADLE:%s\\n" "$*"\n')
            fake_gradle.chmod(0o755)

            env = os.environ.copy()
            env["GRADLE_USER_HOME"] = tmp
            proc = subprocess.run(
                [str(wrapper), "clean", "jar"],
                cwd=ROOT / "burp-extension",
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("FAKE_GRADLE:clean jar", proc.stdout)



if __name__ == "__main__":
    unittest.main()
