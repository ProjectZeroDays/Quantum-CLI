"""quantum.control — operator control surfaces.

Each module here exposes a `*_dashboard_state()` probe that reports what
the host actually has, plus the operator actions that follow from it.
Probes return honest results: when the hardware, tool or file is absent
they say so rather than reporting a capability that was never confirmed.

Submodules are imported lazily by the caller (the CLI and the C2 API
import the specific module they need) so that a missing optional
dependency in one module cannot break the others.
"""
from __future__ import annotations

__all__ = [
    "bluetooth",
    "hid",
    "imsi",
    "sdr",
]
