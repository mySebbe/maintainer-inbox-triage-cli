"""Local heuristic triage for GitHub issue and pull request payloads."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from ._version import __version__

DEFAULT_MAX_INPUT_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_PAYLOADS = 10_000
DEFAULT_MAX_JSON_DEPTH = 100
_INPUT_FORMATS = ("auto", "json", "jsonl")
_OUTPUT_FORMATS = ("text", "json", "jsonl")
_JSONL_SUFFIXES = frozenset({".jsonl", ".ndjson"})


@dataclass(frozen=True)
class RuleExplanation:
    """A stable, machine-readable explanation of one triage decision."""

    rule_id: str
    effect: str
    summary: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TriageResult:
    title: str
    labels: list[str]
    reasons: list[str]
    item_type: str
    priority: str
    dry_run: bool = True
    url: str | None = None
    explanations: list[RuleExplanation] = field(default_factory=list)


@dataclass
class _InputBudget:
    max_bytes: int
    max_payloads: int
    bytes_read: int = 0
    payloads_read: int = 0

    @property
    def remaining_bytes(self) -> int:
        return self.max_bytes - self.bytes_read

    def consume_bytes(self, count: int, path: Path) -> None:
        if count > self.remaining_bytes:
            raise PayloadInputError(
                f"combined input exceeds the {self.max_bytes}-byte limit while reading {path}"
            )
        self.bytes_read += count

    def add_payload(self, payloads: list[dict[str, object]], payload: dict[str, object], source: str) -> None:
        if self.payloads_read >= self.max_payloads:
            raise PayloadInputError(
                f"payload count exceeds the {self.max_payloads}-item limit at {source}"
            )
        payloads.append(payload)
        self.payloads_read += 1


class PayloadInputError(ValueError):
    """Raised when payload input is malformed or exceeds a safety limit."""


class _DuplicateKeyError(ValueError):
    pass


class _OutputSafetyError(ValueError):
    pass


KEYWORDS = {
    "security": [
        "security",
        "vulnerability",
        "cve",
        "token",
        "secret",
        "xss",
        "injection",
        "auth bypass",
    ],
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
    title = (
        _string(payload.get("title"))
        or _nested_string(payload, "issue", "title")
        or _nested_string(payload, "pull_request", "title")
    )
    body = (
        _string(payload.get("body"))
        or _nested_string(payload, "issue", "body")
        or _nested_string(payload, "pull_request", "body")
    )
    url = (
        _string(payload.get("html_url"))
        or _nested_string(payload, "issue", "html_url")
        or _nested_string(payload, "pull_request", "html_url")
    )
    item_type = (
        "pull_request"
        if "pull_request" in payload or _nested_string(payload, "pull_request", "title")
        else "issue"
    )
    text = f"{title}\n{body}".lower()

    labels: list[str] = []
    reasons: list[str] = []
    explanations: list[RuleExplanation] = []
    for label in ["security", "bug", "ci", "dependencies", "docs", "question"]:
        matches = _matching_keywords(text, KEYWORDS[label])
        if matches:
            labels.append(label)
            reasons.append(f"{label} keyword: {matches[0]}")
            explanations.append(
                RuleExplanation(
                    rule_id=f"keyword.{label}",
                    effect=f"label:{label}",
                    summary=f"matched {label} keyword rule",
                    evidence=matches,
                )
            )

    if "bug" in labels and not _matching_keywords(text, REPRO_KEYWORDS):
        labels.append("repro-needed")
        reasons.append("bug report lacks reproduction keywords")
        explanations.append(
            RuleExplanation(
                rule_id="quality.reproduction-missing",
                effect="label:repro-needed",
                summary="bug report lacks reproduction keywords",
            )
        )

    good_first_matches = _matching_keywords(text, GOOD_FIRST_KEYWORDS)
    if _is_good_first_candidate(text, labels, good_first_matches):
        labels.append("good-first")
        reasons.append("small or documentation-scoped change")
        explanations.append(
            RuleExplanation(
                rule_id="scope.good-first",
                effect="label:good-first",
                summary="small or documentation-scoped change",
                evidence=good_first_matches,
            )
        )

    if not labels:
        labels.append("needs-triage")
        reasons.append("no high-confidence local heuristic matched")
        explanations.append(
            RuleExplanation(
                rule_id="fallback.needs-triage",
                effect="label:needs-triage",
                summary="no high-confidence local heuristic matched",
            )
        )

    labels = _dedupe(labels)
    priority, priority_explanation = _priority_for(labels)
    explanations.append(priority_explanation)
    return TriageResult(
        title=title or "(untitled)",
        labels=labels,
        reasons=reasons,
        item_type=item_type,
        priority=priority,
        url=url,
        explanations=explanations,
    )


def sanitize_terminal_text(value: str) -> str:
    """Render untrusted text without emitting terminal or bidi control characters."""
    escaped: list[str] = []
    named_escapes = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
    for character in value:
        if character.isprintable():
            escaped.append(character)
            continue
        if character in named_escapes:
            escaped.append(named_escapes[character])
            continue
        codepoint = ord(character)
        if codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(f"\\U{codepoint:08x}")
    return "".join(escaped)


def format_text(results: Iterable[TriageResult]) -> str:
    """Format results for a terminal, escaping all untrusted non-printing text."""
    lines: list[str] = []
    for result in results:
        lines.append(
            f"{sanitize_terminal_text(result.item_type)}: {sanitize_terminal_text(result.title)}"
        )
        lines.append(f"  labels: {', '.join(sanitize_terminal_text(label) for label in result.labels)}")
        lines.append(f"  priority: {sanitize_terminal_text(result.priority)}")
        for reason in result.reasons:
            lines.append(f"  - {sanitize_terminal_text(reason)}")
        for explanation in result.explanations:
            evidence = ""
            if explanation.evidence:
                evidence = "; evidence=" + ", ".join(
                    sanitize_terminal_text(item) for item in explanation.evidence
                )
            lines.append(
                "  rule: "
                f"{sanitize_terminal_text(explanation.rule_id)} -> "
                f"{sanitize_terminal_text(explanation.effect)}; "
                f"{sanitize_terminal_text(explanation.summary)}{evidence}"
            )
        if result.url:
            lines.append(f"  url: {sanitize_terminal_text(result.url)}")
        lines.append("  mode: dry-run")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_json(results: Iterable[TriageResult], *, json_lines: bool = False) -> str:
    """Format deterministic JSON; non-ASCII controls remain JSON escaped."""
    rows = [asdict(result) for result in results]
    if json_lines:
        return "".join(
            json.dumps(row, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
            for row in rows
        )
    return json.dumps(rows, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def load_payloads(
    paths: Iterable[str],
    *,
    input_format: Literal["auto", "json", "jsonl"] = "auto",
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_payloads: int = DEFAULT_MAX_PAYLOADS,
) -> list[dict[str, object]]:
    """Load bounded JSON or JSONL payload files in deterministic file order.

    ``max_input_bytes`` is a combined budget across all files. JSON files may
    contain one object or an array of objects. JSONL requires one object per
    non-empty line. Duplicate object keys are rejected in both formats.
    """
    _validate_positive_limit("max_input_bytes", max_input_bytes)
    _validate_positive_limit("max_payloads", max_payloads)
    if input_format not in _INPUT_FORMATS:
        raise ValueError(f"input_format must be one of: {', '.join(_INPUT_FORMATS)}")

    payloads: list[dict[str, object]] = []
    budget = _InputBudget(max_bytes=max_input_bytes, max_payloads=max_payloads)
    for raw_path in paths:
        path = Path(raw_path)
        selected_format = _detect_input_format(path) if input_format == "auto" else input_format
        if selected_format == "jsonl":
            _load_json_lines(path, payloads, budget)
        else:
            _load_json_document(path, payloads, budget)
    return payloads


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify GitHub issue/PR JSON payloads locally.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("payloads", nargs="+", help="Path(s) to JSON or JSONL issue/PR payloads")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="Emit JSON (compatibility alias)")
    output_group.add_argument(
        "--format",
        choices=_OUTPUT_FORMATS,
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--input-format",
        choices=_INPUT_FORMATS,
        default="auto",
        help="Input format; auto uses .jsonl/.ndjson suffixes (default: auto)",
    )
    parser.add_argument(
        "--max-input-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_INPUT_BYTES,
        help=f"Combined input byte limit (default: {DEFAULT_MAX_INPUT_BYTES})",
    )
    parser.add_argument(
        "--max-payloads",
        type=_positive_int,
        default=DEFAULT_MAX_PAYLOADS,
        help=f"Maximum number of payload objects (default: {DEFAULT_MAX_PAYLOADS})",
    )
    parser.add_argument("--output", help="Atomically write output to a non-symlink file")
    args = parser.parse_args(argv)

    try:
        if args.output:
            _validate_output_destination(Path(args.output), args.payloads)
        payloads = load_payloads(
            args.payloads,
            input_format=args.input_format,
            max_input_bytes=args.max_input_bytes,
            max_payloads=args.max_payloads,
        )
        results = [classify_payload(payload) for payload in payloads]
        output_format = "json" if args.json else args.format
        output = (
            format_text(results)
            if output_format == "text"
            else format_json(results, json_lines=output_format == "jsonl")
        )
        if args.output:
            _write_text_atomic(Path(args.output), output)
        else:
            sys.stdout.write(output)
    except (OSError, PayloadInputError, _OutputSafetyError, UnicodeError) as exc:
        print(f"error: {sanitize_terminal_text(str(exc))}", file=sys.stderr)
        return 2
    return 0


def _load_json_document(
    path: Path, payloads: list[dict[str, object]], budget: _InputBudget
) -> None:
    data = _read_bounded_file(path, budget)
    text = _decode_utf8(data, path)
    _preflight_array_items(text, path, budget.max_payloads - budget.payloads_read)
    decoded = _decode_json(text, path)
    if isinstance(decoded, dict):
        budget.add_payload(payloads, decoded, str(path))
        return
    if isinstance(decoded, list):
        for index, item in enumerate(decoded, start=1):
            if not isinstance(item, dict):
                raise PayloadInputError(f"{path} contains a non-object item at array index {index - 1}")
            budget.add_payload(payloads, item, f"{path} array item {index}")
        return
    raise PayloadInputError(f"{path} must contain a JSON object or array of objects")


def _load_json_lines(
    path: Path, payloads: list[dict[str, object]], budget: _InputBudget
) -> None:
    objects_before = budget.payloads_read
    try:
        with _open_regular_binary(path) as stream:
            line_number = 0
            while True:
                chunk = stream.readline(budget.remaining_bytes + 1)
                if not chunk:
                    break
                line_number += 1
                budget.consume_bytes(len(chunk), path)
                text = _decode_utf8(chunk, path, line_number=line_number)
                if not text.strip():
                    continue
                decoded = _decode_json(text, path, line_number=line_number)
                if not isinstance(decoded, dict):
                    raise PayloadInputError(f"{path} line {line_number} must contain a JSON object")
                budget.add_payload(payloads, decoded, f"{path} line {line_number}")
    except PayloadInputError:
        raise
    except OSError as exc:
        raise PayloadInputError(f"cannot read {path}: {exc}") from exc

    if budget.payloads_read == objects_before:
        raise PayloadInputError(f"{path} contains no JSONL objects")


def _read_bounded_file(path: Path, budget: _InputBudget) -> bytes:
    try:
        with _open_regular_binary(path) as stream:
            data = stream.read(budget.remaining_bytes + 1)
    except PayloadInputError:
        raise
    except OSError as exc:
        raise PayloadInputError(f"cannot read {path}: {exc}") from exc
    budget.consume_bytes(len(data), path)
    return data


def _open_regular_binary(path: Path):
    try:
        before = path.lstat()
    except OSError as exc:
        raise PayloadInputError(f"cannot inspect {path}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode) or _is_reparse_stat(before):
        raise PayloadInputError(f"{path} is not a regular unlinked file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PayloadInputError(f"cannot read {path}: {exc}") from exc
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
        ):
            raise PayloadInputError(f"{path} changed during the regular-file safety check")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _decode_utf8(data: bytes, path: Path, *, line_number: int | None = None) -> str:
    encoding = "utf-8-sig" if line_number in (None, 1) else "utf-8"
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as exc:
        location = f" line {line_number}" if line_number is not None else ""
        raise PayloadInputError(
            f"{path}{location} is not valid UTF-8 at byte offset {exc.start}"
        ) from exc


def _decode_json(text: str, path: Path, *, line_number: int | None = None) -> object:
    _validate_json_nesting(text, path, line_number=line_number)
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKeyError as exc:
        location = f" line {line_number}" if line_number is not None else ""
        raise PayloadInputError(f"{path}{location} contains a duplicate object key") from exc
    except json.JSONDecodeError as exc:
        if line_number is None:
            location = f"line {exc.lineno}, column {exc.colno}"
        else:
            location = f"line {line_number}, column {exc.colno}"
        raise PayloadInputError(f"{path} contains invalid JSON at {location}") from exc
    except RecursionError as exc:
        location = f" line {line_number}" if line_number is not None else ""
        raise PayloadInputError(f"{path}{location} exceeds the JSON nesting limit") from exc


def _preflight_array_items(text: str, path: Path, remaining_payloads: int) -> None:
    stripped = text.lstrip("\ufeff \t\r\n")
    if not stripped.startswith("["):
        return

    depth = 0
    count = 0
    item_started = False
    in_string = False
    escaped = False
    for character in stripped:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            if depth == 1:
                item_started = True
            in_string = True
        elif character in "[{":
            if depth == 1:
                item_started = True
            depth += 1
        elif character in "]}":
            if character == "]" and depth == 1:
                if item_started:
                    count += 1
                if count > remaining_payloads:
                    raise PayloadInputError(
                        f"payload count exceeds the {remaining_payloads}-item limit while reading {path}"
                    )
                return
            depth -= 1
        elif depth == 1 and character == ",":
            if item_started:
                count += 1
                if count > remaining_payloads:
                    raise PayloadInputError(
                        f"payload count exceeds the {remaining_payloads}-item limit while reading {path}"
                    )
                item_started = False
        elif depth == 1 and not character.isspace():
            item_started = True


def _validate_json_nesting(text: str, path: Path, *, line_number: int | None = None) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > DEFAULT_MAX_JSON_DEPTH:
                location = f" line {line_number}" if line_number is not None else ""
                raise PayloadInputError(f"{path}{location} exceeds the JSON nesting limit")
        elif character in "]}":
            depth -= 1


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise _DuplicateKeyError
        decoded[key] = value
    return decoded


def _detect_input_format(path: Path) -> Literal["json", "jsonl"]:
    return "jsonl" if path.suffix.lower() in _JSONL_SUFFIXES else "json"


def _validate_output_destination(destination: Path, input_paths: Iterable[str]) -> None:
    if _is_link_or_reparse(destination):
        raise _OutputSafetyError(f"refusing to write through symlink output path {destination}")
    _safe_output_parent(destination.parent)
    destination_key = _normalized_path(destination)
    for input_path in input_paths:
        if destination_key == _normalized_path(Path(input_path)):
            raise _OutputSafetyError(f"output path must not replace input file {destination}")


def _write_text_atomic(destination: Path, output: str) -> None:
    if _is_link_or_reparse(destination):
        raise _OutputSafetyError(f"refusing to write through symlink output path {destination}")
    parent_identity = _safe_output_parent(destination.parent)

    temporary: Path | None = None
    descriptor = -1
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            stream.write(output.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        if _is_link_or_reparse(destination):
            raise _OutputSafetyError(f"refusing to replace symlink output path {destination}")
        if _safe_output_parent(destination.parent) != parent_identity:
            raise _OutputSafetyError("output parent changed during atomic write")
        os.replace(temporary, destination)
        temporary = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _safe_output_parent(parent: Path) -> tuple[int, int]:
    try:
        info = parent.lstat()
    except OSError as exc:
        raise _OutputSafetyError(f"cannot inspect output parent {parent}: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or _is_reparse_stat(info):
        raise _OutputSafetyError(f"output parent is not a regular directory: {parent}")
    return info.st_dev, info.st_ino


def _is_link_or_reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or _is_reparse_stat(path.lstat())
    except FileNotFoundError:
        return False


def _is_reparse_stat(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _normalized_path(path: Path) -> str:
    return os.path.normcase(str(path.resolve(strict=False)))


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _validate_positive_limit(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _matching_keywords(text: str, keywords: Iterable[str]) -> list[str]:
    matches: list[str] = []
    for keyword in keywords:
        pattern = (
            r"\b" + re.escape(keyword) + r"\b"
            if keyword.replace(" ", "").isalnum()
            else re.escape(keyword)
        )
        if re.search(pattern, text):
            matches.append(keyword)
    return matches


def _is_good_first_candidate(text: str, labels: list[str], matches: list[str]) -> bool:
    if "security" in labels or "bug" in labels:
        return False
    return bool(matches and ("docs" in labels or len(text) < 240))


def _dedupe(labels: Iterable[str]) -> list[str]:
    result: list[str] = []
    for label in labels:
        if label not in result:
            result.append(label)
    return result


def _priority_for(labels: list[str]) -> tuple[str, RuleExplanation]:
    if "security" in labels:
        return "p0", RuleExplanation(
            rule_id="priority.security",
            effect="priority:p0",
            summary="security-sensitive rule matched",
            evidence=["security"],
        )
    urgent_labels = [label for label in ("bug", "ci") if label in labels]
    if urgent_labels:
        return "p1", RuleExplanation(
            rule_id="priority.defect",
            effect="priority:p1",
            summary="bug or CI rule matched",
            evidence=urgent_labels,
        )
    if "dependencies" in labels:
        return "p2", RuleExplanation(
            rule_id="priority.dependencies",
            effect="priority:p2",
            summary="dependency rule matched",
            evidence=["dependencies"],
        )
    return "p3", RuleExplanation(
        rule_id="priority.default",
        effect="priority:p3",
        summary="no higher-priority rule matched",
    )


def _nested_string(payload: dict[str, object], key: str, nested_key: str) -> str:
    value = payload.get(key)
    if isinstance(value, dict):
        return _string(value.get(nested_key))
    return ""


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = [
    "DEFAULT_MAX_INPUT_BYTES",
    "DEFAULT_MAX_JSON_DEPTH",
    "DEFAULT_MAX_PAYLOADS",
    "PayloadInputError",
    "RuleExplanation",
    "TriageResult",
    "__version__",
    "classify_payload",
    "format_json",
    "format_text",
    "load_payloads",
    "main",
    "sanitize_terminal_text",
]
