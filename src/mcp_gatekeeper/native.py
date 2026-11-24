"""Optional C++20 backend for the static policy check (cpp/, binary `gatekeeper-cpp`).

`NativePolicy.check` returns the same `PolicyResult` fields as `policy.check` (`statement` is always
None: the AST lives in the C++ process). The Python implementation stays the reference; see
cpp/README.md for what is and is not equivalent. Not wired into the proxy by default.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
from collections.abc import Iterable
from pathlib import Path

from .config import Policy
from .policy import PolicyResult

DEFAULT_BINARY = Path(__file__).resolve().parents[2] / "cpp" / "build" / "gatekeeper-cpp"


class NativePolicy:
    """One long-lived `gatekeeper-cpp` process speaking JSON lines over stdin/stdout."""

    def __init__(self, policy: Policy, binary: str | os.PathLike[str] | None = None) -> None:
        exe = Path(binary or os.environ.get("GATEKEEPER_CPP", DEFAULT_BINARY))
        if not exe.exists():
            raise FileNotFoundError(
                f"gatekeeper-cpp not found at {exe}; build it with `cmake -S cpp -B cpp/build && cmake --build cpp/build`"
            )
        self._policy_file = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")  # noqa: SIM115
        json.dump(policy.model_dump(mode="json"), self._policy_file)
        self._policy_file.close()
        self._proc = subprocess.Popen(  # noqa: S603
            [str(exe), "--policy", self._policy_file.name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._lock = threading.Lock()
        self._n = 0

    def check(self, sql: str, role: str, known_tables: Iterable[str] | None = None) -> PolicyResult:
        """`role` is the role *name* in the policy (e.g. "scoped_write"), not the Role object."""
        assert self._proc.stdin is not None and self._proc.stdout is not None
        with self._lock:
            self._n += 1
            req = {"id": self._n, "sql": sql, "role": role, "known": None if known_tables is None else sorted(known_tables)}
            self._proc.stdin.write(json.dumps(req) + "\n")
            self._proc.stdin.flush()
            line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError("gatekeeper-cpp exited unexpectedly")
        res = json.loads(line)
        return PolicyResult(
            allowed=res["allowed"],
            rule_id=res["rule_id"],
            reason=res["reason"],
            statement=None,
            is_write=res["is_write"],
            is_ddl=res["is_ddl"],
            tables=frozenset(res["tables"]),
        )

    def close(self) -> None:
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait(timeout=5)
        Path(self._policy_file.name).unlink(missing_ok=True)

    def __enter__(self) -> NativePolicy:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
