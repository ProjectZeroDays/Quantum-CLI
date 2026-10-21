"""quantum.skills — operator skill configuration.

Each module here describes one part of the operator's configuration
and reports the real state of this host: which provider is resolved,
which API key is present, which skills actually import.

Nothing in this package enables a capability on its own — the modules
report, they do not switch things on.

Authorized engagements / lab work only.
"""
from __future__ import annotations

__all__ = [
    "openrouter_config",
]
