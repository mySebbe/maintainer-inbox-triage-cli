"""Version helpers for maintainer-inbox-triage-cli."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

_DISTRIBUTION_NAME = "maintainer-inbox-triage-cli"

try:
    __version__ = _distribution_version(_DISTRIBUTION_NAME)
except PackageNotFoundError:
    __version__ = "0.1.0"
