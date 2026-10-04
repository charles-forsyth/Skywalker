"""Skywalker intel: the library behind the MCP server.

Every function takes a `Gcp` (one caller's credentials) plus explicit
arguments and returns plain JSON-able dicts. Nothing prints, exits or touches
process-wide state, so many callers can run at once in one process.
"""

from .gcp import Gcp, GcpError
from .util import IntelConfig

__all__ = ["Gcp", "GcpError", "IntelConfig"]
