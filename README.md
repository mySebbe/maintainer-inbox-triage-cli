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
```

The output includes labels, priority, and plain-language reasons so maintainers can inspect why a label was suggested.

## Development

```bash
python -m unittest discover -s tests
```
