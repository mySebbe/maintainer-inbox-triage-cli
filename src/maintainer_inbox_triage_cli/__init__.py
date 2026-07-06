"""Local heuristic triage for GitHub issue and pull request payloads."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from ._version import __version__


@dataclass(frozen=True)
class TriageResult:
    title: str
    labels: list[str]
    reasons: list[str]
    item_type: str
    priority: str
    dry_run: bool = True
    url: str | None = None


KEYWORDS = {
    "security": ["security", "vulnerability", "cve", "token", "secret", "xss", "injection", "auth bypass"],
    "bug": ["bug", "crash", "error", "exception", "traceback", "fails", "broken", "regression"],
    "ci": ["ci", "workflow", "github actions", "action failed", "build failed", "test failure"],
    "dependencies": ["dependabot", "dependency", "dependencies", "lockfile", "package-lock", "requirements.txt"],
    "docs": ["docs", "documentation", "readme", "guide", "typo", "spelling"],
    "question": ["question", "how do i", "help", "usage", "configure", "support"],
}
REPRO_KEYWORDS = ["steps to reproduce", "reproduction", "minimal repro", "expected", "actual", "traceback"]
GOOD_FIRST_KEYWORDS = ["typo", "spelling", "readme", "docs", "documentation", "small", "simple"]


def classify_payload(payload: dict[str, object]) -> TriageResult:
    """Classify a GitHub issue or PR webhook/API payload without network calls."""
    title = _string(payload.get("title")) or _nested_string(payload, "issue", "title") or _nested_string(payload, "pull_request", "title")
    body = _string(payload.get("body")) or _nested_string(payload, "issue", "body") or _nested_string(payload, "pull_request", "body")
    url = _string(payload.get("html_url")) or _nested_string(payload, "issue", "html_url") or _nested_string(payload, "pull_request", "html_url")
    item_type = "pull_request" if "pull_request" in payload or _nested_string(payload, "pull_request", "title") else "issue"
    text = f"{title}\n{body}".lower()

    labels: list[str] = []
    reasons: list[str] = []
    for label in ["security", "bug", "ci", "dependencies", "docs", "question"]:
        matched = _matching_keyword(text, KEYWORDS[label])
        if matched:
            labels.append(label)
            reasons.append(f"{label} keyword: {matched}")

    if "bug" in labels and not _matching_keyword(text, REPRO_KEYWORDS):
        labels.append("repro-needed")
        reasons.append("bug report lacks reproduction keywords")

    if _is_good_first_candidate(text, labels):
        labels.append("good-first")
        reasons.append("small or documentation-scoped change")

    if not labels:
        labels.append("needs-triage")
        reasons.append("no high-confidence local heuristic matched")

    labels = _dedupe(labels)
    return TriageResult(
        title=title or "(untitled)",
        labels=labels,
        reasons=reasons,
        item_type=item_type,
        priority=_priority_for(labels, text),
        url=url,
    )


def format_text(results: Iterable[TriageResult]) -> str:
    lines: list[str] = []
    for result in results:
        lines.append(f"{result.item_type}: {result.title}")
        lines.append(f"  labels: {', '.join(result.labels)}")
        lines.append(f"  priority: {result.priority}")
        for reason in result.reasons:
            lines.append(f"  - {reason}")
        if result.url:
            lines.append(f"  url: {result.url}")
        lines.append("  mode: dry-run")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def load_payloads(paths: Iterable[str]) -> list[dict[str, object]]:
    """Load one or more JSON payload files.

    Each file may contain a single GitHub issue/PR object or a list of objects.
    List support keeps local exports and batched fixture files easy to triage.
    """
    payloads: list[dict[str, object]] = []
    for path in paths:
        decoded = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(decoded, list):
            for item in decoded:
                if not isinstance(item, dict):
                    raise ValueError(f"{path} contains a non-object list item")
                payloads.append(item)
        elif isinstance(decoded, dict):
            payloads.append(decoded)
        else:
            raise ValueError(f"{path} must contain a JSON object or list of objects")
    return payloads


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify GitHub issue/PR JSON payloads locally.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("payloads", nargs="+", help="Path(s) to GitHub issue or pull request JSON payloads")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--output", help="Write output to a file instead of stdout")
    args = parser.parse_args(argv)

    try:
        results = [classify_payload(payload) for payload in load_payloads(args.payloads)]
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = json.dumps([asdict(result) for result in results], indent=2, sort_keys=True) + "\n" if args.json else format_text(results)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


def _matching_keyword(text: str, keywords: Iterable[str]) -> str | None:
    for keyword in keywords:
        pattern = r"\b" + re.escape(keyword) + r"\b" if keyword.replace(" ", "").isalnum() else re.escape(keyword)
        if re.search(pattern, text):
            return keyword
    return None


def _is_good_first_candidate(text: str, labels: list[str]) -> bool:
    if "security" in labels or "bug" in labels:
        return False
    return bool(_matching_keyword(text, GOOD_FIRST_KEYWORDS) and ("docs" in labels or len(text) < 240))


def _dedupe(labels: Iterable[str]) -> list[str]:
    result: list[str] = []
    for label in labels:
        if label not in result:
            result.append(label)
    return result


def _priority_for(labels: list[str], text: str) -> str:
    if "security" in labels or "auth bypass" in text or "vulnerability" in text:
        return "p0"
    if "ci" in labels or "bug" in labels:
        return "p1"
    if "dependencies" in labels:
        return "p2"
    return "p3"


def _nested_string(payload: dict[str, object], key: str, nested_key: str) -> str:
    value = payload.get(key)
    if isinstance(value, dict):
        return _string(value.get(nested_key))
    return ""


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = ["__version__", "TriageResult", "classify_payload", "format_text", "load_payloads", "main"]
