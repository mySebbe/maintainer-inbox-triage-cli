# Publishing

This repo is configured for PyPI Trusted Publishing through GitHub Actions.

## One-Time Setup

1. Create the GitHub repository at `https://github.com/mySebbe/maintainer-inbox-triage-cli`.
2. Create the PyPI project named `maintainer-inbox-triage-cli`.
3. In PyPI, add a Trusted Publisher for:
   - Owner: `mySebbe`
   - Repository: `maintainer-inbox-triage-cli`
   - Workflow: `.github/workflows/release.yml`
   - Environment: leave blank unless you add one to the workflow.

## Release Flow

```bash
git tag v0.1.0
git push origin v0.1.0
```

Then create a GitHub Release for the tag. The `release.yml` workflow builds the package and publishes it to PyPI with OIDC, without storing a PyPI API token.

## Before Each Release

- Run `python verify_projects.py` from the pack root, or `python -m unittest discover -s tests -v` in this repo.
- Update `CHANGELOG.md`.
- Confirm `pyproject.toml` version matches the tag.
