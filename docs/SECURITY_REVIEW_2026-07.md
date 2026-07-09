# Security Review - July 2026

## Scope

The review covered hostile issue/PR payload ingestion, deterministic classification, terminal and
JSON output, and output-file handling.

## Fixed Findings

1. Input files were read without aggregate size, object-count, or nesting limits. JSON and JSONL
   now enforce conservative defaults before classification.
2. Duplicate JSON keys and malformed JSONL records could produce ambiguous results. They are now
   rejected with location-only diagnostics that do not echo private payload text.
3. Titles and URLs could contain terminal escape or bidirectional controls. Human output now
   renders those controls visibly instead of executing or visually reordering them.
4. Output writes could replace an input or follow a symlink. Output is now checked, written through
   a temporary file, synced, and atomically replaced only when the target is a regular file.
5. Special input files and reparse-point output parents could cross or block filesystem boundaries.
   Input now uses pre/post-open regular-file identity checks, and output rejects linked parents.
6. Large JSON arrays were counted only after full decoding. A string-aware structural preflight now
   enforces the payload-count limit before `json.loads` materializes array objects.

## Residual Risk

Classification is heuristic and must not be used as an authorization or disclosure decision. Keep
human review for security labels and avoid feeding public output into an auto-publish workflow.

## Validation

The final PR gate runs unittest, Ruff, Bandit, pip-audit, package build, Trivy, and targeted hostile
terminal/JSONL/output-path regression tests.
