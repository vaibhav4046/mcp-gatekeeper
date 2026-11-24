"""Load the Python reference policy (src/mcp_gatekeeper/policy.py) without importing the package
__init__, which pulls in psycopg and the MCP SDK. Needs only: sqlglot, pydantic, pyyaml."""

from __future__ import annotations

import sys
import types
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "mcp_gatekeeper"

if "mcp_gatekeeper" not in sys.modules:
    _pkg = types.ModuleType("mcp_gatekeeper")
    _pkg.__path__ = [str(SRC)]  # type: ignore[attr-defined]
    sys.modules["mcp_gatekeeper"] = _pkg

from mcp_gatekeeper import config, policy

__all__ = ["config", "policy"]
