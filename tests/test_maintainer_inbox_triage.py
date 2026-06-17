import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from maintainer_inbox_triage_cli import classify_payload, load_payloads, main


class MaintainerInboxTriageTests(unittest.TestCase):
    def test_classifies_security_payload(self):
        payload = {
            "title": "Possible token exposure in logs",
            "body": "The debug output leaks API tokens and should be treated as security sensitive.",
            "html_url": "https://example.test/issues/1",
        }

        result = classify_payload(payload)

        self.assertIn("security", result.labels)
        self.assertIn("security keyword", " ".join(result.reasons))

    def test_bug_without_reproduction_gets_repro_needed(self):
        payload = {"title": "Crash on startup", "body": "The app crashes immediately."}

        result = classify_payload(payload)

        self.assertIn("bug", result.labels)
        self.assertIn("repro-needed", result.labels)

    def test_docs_typo_gets_docs_and_good_first(self):
        payload = {"title": "Typo in README", "body": "Small spelling fix in the documentation."}

        result = classify_payload(payload)

        self.assertEqual(["docs", "good-first"], result.labels)

    def test_question_payload_gets_question(self):
        payload = {"title": "How do I configure cache?", "body": "Question about local setup."}

        result = classify_payload(payload)

        self.assertIn("question", result.labels)

    def test_dependency_update_gets_dependencies_label(self):
        payload = {"title": "Dependabot: update package-lock", "body": "Dependency refresh for npm lockfile."}

        result = classify_payload(payload)

        self.assertIn("dependencies", result.labels)

    def test_ci_failure_gets_ci_and_bug_labels(self):
        payload = {"title": "GitHub Actions test failure", "body": "The workflow fails on Python 3.12."}

        result = classify_payload(payload)

        self.assertIn("ci", result.labels)
        self.assertIn("bug", result.labels)

    def test_cli_dry_run_json_for_multiple_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            issue = Path(tmp) / "issue.json"
            pr = Path(tmp) / "pr.json"
            output = Path(tmp) / "triage.json"
            issue.write_text(json.dumps({"title": "Bug: error after install", "body": "steps to reproduce: run install"}), encoding="utf-8")
            pr.write_text(json.dumps({"title": "Docs: update guide", "body": "README change", "pull_request": {}}), encoding="utf-8")

            code = main(["--json", "--output", str(output), str(issue), str(pr)])

            self.assertEqual(0, code)
            rows = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(2, len(rows))
            self.assertIn("bug", rows[0]["labels"])
            self.assertIn("docs", rows[1]["labels"])
            self.assertTrue(rows[0]["dry_run"])

    def test_load_payloads_accepts_list_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            payloads = Path(tmp) / "payloads.json"
            payloads.write_text(json.dumps([
                {"title": "Crash on startup", "body": "It errors"},
                {"title": "README typo", "body": "Small docs fix"},
            ]), encoding="utf-8")

            rows = load_payloads([str(payloads)])

            self.assertEqual(2, len(rows))
            self.assertEqual("Crash on startup", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
