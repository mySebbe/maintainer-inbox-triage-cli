# Changelog

All notable changes to `maintainer-inbox-triage-cli` will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning.

## [Unreleased]

- Added deterministic structured rule explanations to text, JSON, and JSONL output.
- Added bounded JSON/JSONL ingestion with byte, payload-count, depth, duplicate-key, and UTF-8
  validation.
- Escaped terminal and bidirectional controls in human-readable output.
- Added atomic output and refusal of symlink targets or input-file replacement.

## [0.1.2] - 2026-07-06

- Updated GitHub Actions workflow dependencies to current major versions.
- Modernized package license metadata to avoid current Setuptools deprecation warnings.
- Added local `p0` to `p3` priority assignment to triage results.
- Included priority in text and JSON output for easier sorting of exported inboxes.

## [0.1.1] - 2026-06-17

- Added `ci` and `dependencies` heuristic labels.
- Detected workflow failures, Dependabot updates, lockfile changes, and requirements updates.
- Fixed GitHub Actions workflow pins to supported action versions.

## [0.1.0] - 2026-06-03

- Initial open-source release with CLI, examples, tests, GitHub workflows, security policy, and contributor docs.
