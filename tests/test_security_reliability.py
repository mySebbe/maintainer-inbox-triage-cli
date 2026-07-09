import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from maintainer_inbox_triage_cli import (
    PayloadInputError,
    classify_payload,
    format_json,
    format_text,
    load_payloads,
    main,
)


class ExplainableTriageTests(unittest.TestCase):
    def test_explanations_are_complete_and_deterministic(self):
        first = classify_payload(
            {
                "title": "Token exposure is a vulnerability and security concern",
                "body": "Private credentials may leak.",
            }
        )
        second = classify_payload(
            {
                "body": "Private credentials may leak.",
                "title": "Token exposure is a vulnerability and security concern",
            }
        )

        self.assertEqual(first, second)
        self.assertEqual(
            ["keyword.security", "priority.security"],
            [explanation.rule_id for explanation in first.explanations],
        )
        self.assertEqual(
            ["security", "vulnerability", "token"],
            first.explanations[0].evidence,
        )
        self.assertEqual("priority:p0", first.explanations[-1].effect)

    def test_json_serialization_is_byte_stable(self):
        result = classify_payload({"title": "README typo", "body": "Small docs fix"})

        self.assertEqual(format_json([result]), format_json([result]))
        decoded = json.loads(format_json([result]))
        self.assertEqual("scope.good-first", decoded[0]["explanations"][1]["rule_id"])


class HostileOutputTests(unittest.TestCase):
    def test_text_output_escapes_terminal_and_bidi_controls(self):
        result = classify_payload(
            {
                "title": "safe\x1b]8;;https://evil.test\x07link\nforged\u202e",
                "body": "Question",
                "html_url": "https://example.test/\x1b[2J",
            }
        )

        rendered = format_text([result])

        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\x1b]8;;https://evil.test\x07link\nforged\u202e", rendered)
        self.assertIn(r"https://example.test/\x1b[2J", rendered)
        self.assertTrue(rendered.splitlines()[0].startswith("issue: safe"))

    def test_json_output_escapes_all_non_ascii_controls(self):
        result = classify_payload({"title": "alert\x1b\u202e", "body": "Question"})

        rendered = format_json([result])

        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"\u001b", rendered)
        self.assertIn(r"\u202e", rendered)
        self.assertEqual("alert\x1b\u202e", json.loads(rendered)[0]["title"])


class BoundedIngestionTests(unittest.TestCase):
    def test_auto_detects_bom_prefixed_jsonl_and_skips_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issues.jsonl"
            first = json.dumps({"title": "First", "body": "Question"}).encode()
            second = json.dumps({"title": "Second", "body": "README typo"}).encode()
            source.write_bytes(b"\xef\xbb\xbf" + first + b"\n\n" + second + b"\n")

            rows = load_payloads([str(source)])

        self.assertEqual(["First", "Second"], [row["title"] for row in rows])

    def test_explicit_jsonl_supports_nonstandard_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "export.txt"
            source.write_text('{"title":"One"}\n{"title":"Two"}\n', encoding="utf-8")

            rows = load_payloads([str(source)], input_format="jsonl")

        self.assertEqual(2, len(rows))

    def test_jsonl_reports_the_exact_bad_line_without_echoing_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issues.jsonl"
            source.write_text(
                '{"title":"valid"}\n{"title":"PRIVATE-SENTINEL",}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PayloadInputError, r"line 2, column") as raised:
                load_payloads([str(source)])

        self.assertNotIn("PRIVATE-SENTINEL", str(raised.exception))

    def test_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "duplicate.json"
            source.write_text(
                '{"title":"first","title":"PRIVATE-SENTINEL"}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PayloadInputError, "duplicate object key") as raised:
                load_payloads([str(source)])

        self.assertNotIn("PRIVATE-SENTINEL", str(raised.exception))

    def test_combined_byte_limit_applies_across_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first.json"
            second = Path(tmp) / "second.json"
            first.write_text('{"title":"first"}', encoding="utf-8")
            second.write_text('{"title":"second"}', encoding="utf-8")
            combined_size = first.stat().st_size + second.stat().st_size

            with self.assertRaisesRegex(PayloadInputError, "combined input exceeds"):
                load_payloads(
                    [str(first), str(second)],
                    max_input_bytes=combined_size - 1,
                )

    def test_payload_limit_applies_to_json_arrays(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issues.json"
            source.write_text(
                json.dumps([{"title": "one"}, {"title": "two"}]),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PayloadInputError, "1-item limit"):
                load_payloads([str(source)], max_payloads=1)

    def test_payload_limit_is_enforced_before_json_array_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issues.json"
            source.write_text("[" + ",".join("{}" for _ in range(100)) + "]", encoding="utf-8")

            with patch("maintainer_inbox_triage_cli.json.loads") as loads:
                with self.assertRaisesRegex(PayloadInputError, "payload count"):
                    load_payloads([str(source)], max_payloads=10)

            loads.assert_not_called()

    def test_invalid_utf8_is_a_bounded_input_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "invalid.json"
            source.write_bytes(b'{"title":"\xff"}')

            with self.assertRaisesRegex(PayloadInputError, "not valid UTF-8"):
                load_payloads([str(source)])

    def test_excessive_json_nesting_is_reported_without_recursion_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "deep.json"
            source.write_text("[" * 1_500 + "0" + "]" * 1_500, encoding="utf-8")

            with self.assertRaisesRegex(PayloadInputError, "nesting limit"):
                load_payloads([str(source)])

    def test_empty_jsonl_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "empty.jsonl"
            source.write_text("\n \t\n", encoding="utf-8")

            with self.assertRaisesRegex(PayloadInputError, "contains no JSONL objects"):
                load_payloads([str(source)])


class SafeOutputTests(unittest.TestCase):
    def test_cli_refuses_to_replace_an_input_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issue.json"
            original = '{"title":"Question"}'
            source.write_text(original, encoding="utf-8")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                code = main(["--output", str(source), str(source)])

            self.assertEqual(2, code)
            self.assertEqual(original, source.read_text(encoding="utf-8"))
            self.assertIn("must not replace input", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_refuses_symlink_output_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issue.json"
            target = Path(tmp) / "target.txt"
            link = Path(tmp) / "output.txt"
            source.write_text('{"title":"Question"}', encoding="utf-8")
            target.write_text("sentinel", encoding="utf-8")
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                code = main(["--output", str(link), str(source)])

            self.assertEqual(2, code)
            self.assertEqual("sentinel", target.read_text(encoding="utf-8"))
            self.assertTrue(link.is_symlink())
            self.assertIn("symlink", stderr.getvalue())

    def test_cli_refuses_linked_output_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issue.json"
            real_parent = Path(tmp) / "real-output"
            linked_parent = Path(tmp) / "linked-output"
            source.write_text('{"title":"Question"}', encoding="utf-8")
            real_parent.mkdir()
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"directory links unavailable: {exc}")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                code = main(["--output", str(linked_parent / "triage.json"), str(source)])

            self.assertEqual(2, code)
            self.assertFalse((real_parent / "triage.json").exists())
            self.assertIn("output parent", stderr.getvalue())

    def test_atomic_output_replaces_regular_file_and_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issue.json"
            output = Path(tmp) / "triage.json"
            source.write_text('{"title":"Question"}', encoding="utf-8")
            output.write_text("old", encoding="utf-8")

            code = main(["--json", "--output", str(output), str(source)])

            self.assertEqual(0, code)
            self.assertEqual("Question", json.loads(output.read_text(encoding="utf-8"))[0]["title"])
            self.assertEqual([], list(Path(tmp).glob(".triage.json.*.tmp")))

    def test_output_error_returns_two_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issue.json"
            output = Path(tmp) / "missing" / "triage.json"
            source.write_text('{"title":"Question"}', encoding="utf-8")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                code = main(["--output", str(output), str(source)])

            self.assertEqual(2, code)
            self.assertIn("error:", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_jsonl_output_emits_one_deterministic_object_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "issues.json"
            output = Path(tmp) / "triage.jsonl"
            source.write_text(
                json.dumps([{"title": "Question"}, {"title": "README typo"}]),
                encoding="utf-8",
            )

            code = main(["--format", "jsonl", "--output", str(output), str(source)])
            lines = output.read_text(encoding="utf-8").splitlines()

        self.assertEqual(0, code)
        self.assertEqual(2, len(lines))
        self.assertEqual(["Question", "README typo"], [json.loads(line)["title"] for line in lines])
        self.assertTrue(all(" " not in line[:20] for line in lines))


if __name__ == "__main__":
    unittest.main()
