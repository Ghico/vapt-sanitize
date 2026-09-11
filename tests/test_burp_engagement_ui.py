from pathlib import Path
import unittest


class TestBurpEngagementUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_path = Path("burp-extension/src/main/java/Extension.java")
        cls.source = cls.source_path.read_text(encoding="utf-8")

    def test_engagement_is_session_scoped_not_globally_persisted(self):
        self.assertIn("selectedEngagement", self.source)
        self.assertIn("for this Burp session", self.source)
        self.assertNotIn("vapt_sanitizer.selected_engagement", self.source)

    def test_context_menu_displays_active_engagement(self):
        self.assertIn('"Engagement: "', self.source)
        self.assertIn("engagementIndicator.setEnabled", self.source)

    def test_burp_bridge_receives_selected_engagement(self):
        self.assertIn('command.add(\n                "--engagement"', self.source)
        self.assertIn("engagementSnapshot", self.source)
        self.assertIn(
            "runSanitizerPreview(\n                                input,\n                                policySnapshot,\n                                engagementSnapshot",
            self.source,
        )

    def test_ui_lists_only_valid_existing_encrypted_vaults(self):
        self.assertIn('"mapping.enc"', self.source)
        self.assertIn("file.isDirectory()", self.source)
        self.assertIn("isValidEngagementId", self.source)
        self.assertIn('"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"', self.source)

    def test_engagement_root_matches_python_xdg_rules(self):
        self.assertIn('"VAPT_SANITIZE_DATA_DIR"', self.source)
        self.assertIn('"XDG_DATA_HOME"', self.source)
        self.assertIn('".local/share/vapt-sanitize"', self.source)


    def test_python_subprocess_receives_explicit_vault_roots(self):
        self.assertIn('"VAPT_SANITIZE_DATA_DIR"', self.source)
        self.assertIn('"VAPT_SANITIZE_CONFIG_DIR"', self.source)
        self.assertIn('builder.environment().put(', self.source)
        self.assertIn('sanitizerDataRoot()', self.source)
        self.assertIn('sanitizerConfigRoot()', self.source)

    def test_config_root_matches_python_xdg_rules(self):
        self.assertIn('"XDG_CONFIG_HOME"', self.source)
        self.assertIn('".config/vapt-sanitize"', self.source)

    def test_preview_shows_engagement_without_adding_it_to_ai_source(self):
        self.assertIn('"    Engagement: "', self.source)
        self.assertIn('return "Burp HTTP Request";', self.source)
        self.assertIn('return "Burp HTTP Response";', self.source)
        self.assertNotIn('return "Burp HTTP Request - " + engagementId', self.source)

    def test_stateless_warning_is_explicit(self):
        self.assertIn(
            "Stateless mode: mappings are not shared with CLI or other Burp messages.",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
