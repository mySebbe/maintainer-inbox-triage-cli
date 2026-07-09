# maintainer-inbox-triage-cli

`maintainer-inbox-triage-cli` classifies local GitHub issue and pull request JSON payloads with inspectable heuristics. It never calls the GitHub API and defaults to dry-run output.

## 0.1.2 Highlights

- Local triage now assigns `p0` to `p3` priorities alongside labels.
- Text and JSON output include priority so exported inboxes can be sorted without GitHub API calls.

## Labels

The v0.1 classifier can emit:

- `bug`
- `ci`
- `dependencies`
- `docs`
- `question`
- `security`
- `repro-needed`
- `good-first`
- `needs-triage`

## Usage

```bash
python -m maintainer_inbox_triage_cli issue.json pr.json
python -m maintainer_inbox_triage_cli --json --output triage.json issue.json
python -m maintainer_inbox_triage_cli --input-format jsonl --format jsonl issues.ndjson
```

The output includes labels, priority, and structured rule explanations so maintainers can inspect
exactly why a label was suggested. Text output escapes terminal and bidirectional controls.

Input is bounded to 10 MiB, 10,000 payloads, and JSON depth 100 by default. Use
`--max-input-bytes` and `--max-payloads` to set stricter automation limits. JSON and JSONL reject
duplicate keys and malformed records without echoing sensitive input. `--output` writes atomically
and refuses symlink targets or replacement of an input file.

## Development

```bash
python -m unittest discover -s tests
```
