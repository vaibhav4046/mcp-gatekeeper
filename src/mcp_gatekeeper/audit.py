"""Tamper-evident JSONL traces and deterministic redaction.

Each line is a JSON object with `prev_hash` and `entry_hash`, where

    entry_hash = SHA-256( canonical_json(entry without entry_hash/hmac) + prev_hash )

and canonical_json is `json.dumps(sort_keys=True, separators=(",", ":"))`. The first entry's
prev_hash is 64 zeros. With GATEKEEPER_AUDIT_KEY set, each line also carries
`hmac = HMAC-SHA256(key, entry_hash)`, so an attacker who rewrites the file cannot recompute a
valid chain without the key. Redaction is regex-based on purpose: it runs on free text (error
messages, SQL literals), not on SQL structure.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
REDACTED = "[REDACTED]"

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # connection strings with credentials: scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@'\"]+):[^\s@'\"]+@"), r"\1:" + REDACTED + "@"),
    # key=value / key: value credentials
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth)(\s*[=:]\s*)('[^']*'|\"[^\"]*\"|[^\s,;)]+)"
        ),
        r"\1\2" + REDACTED,
    ),
    (re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}"), "Bearer " + REDACTED),
    # well-known token shapes
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{4,}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), REDACTED),  # JWT
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),
    # e-mail addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
)


class Redactor:
    """Replaces credentials, tokens, e-mails and known secret values in text."""

    def __init__(self, secret_values: Iterable[str] = ()) -> None:
        # longest first so a secret that contains another is removed whole
        self._secrets = sorted({s for s in secret_values if s and len(s) >= 4}, key=len, reverse=True)

    def text(self, value: str) -> str:
        for secret in self._secrets:
            value = value.replace(secret, REDACTED)
        for pattern, repl in _PATTERNS:
            value = pattern.sub(repl, value)
        return value

    def obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: self.obj(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.obj(v) for v in value]
        return value


def canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def entry_hash(body: dict[str, Any], prev_hash: str) -> str:
    return hashlib.sha256((canonical(body) + prev_hash).encode("utf-8")).hexdigest()


def sign(digest: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), digest.encode("utf-8"), hashlib.sha256).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL trace for one session."""

    def __init__(self, path: Path, redactor: Redactor, key: str | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._redactor = redactor
        self._key = key
        self._fh = path.open("a", encoding="utf-8")
        self._seq = 0
        self._prev = GENESIS

    def write(self, event: dict[str, Any]) -> None:
        self._seq += 1
        body = {"seq": self._seq, "ts": round(time.time(), 6), **self._redactor.obj(event), "prev_hash": self._prev}
        body = json.loads(canonical(body))  # normalise types exactly as they will be re-read
        digest = entry_hash(body, self._prev)
        record = {**body, "entry_hash": digest}
        if self._key:
            record["hmac"] = sign(digest, self._key)
        self._fh.write(canonical(record) + "\n")
        self._fh.flush()
        self._prev = digest

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    entries: int
    bad_line: int | None = None
    reason: str = ""


def verify_trace(path: str | Path, key: str | None = None) -> VerifyReport:
    """Recompute the chain. Returns the first bad 1-based line number on any tampering."""
    prev = GENESIS
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    if not lines:
        return VerifyReport(False, 0, None, "empty trace")
    for n, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            return VerifyReport(False, n - 1, n, f"line {n} is not valid JSON: {e.msg}")
        if not isinstance(record, dict):
            return VerifyReport(False, n - 1, n, f"line {n} is not a JSON object")
        claimed = record.pop("entry_hash", None)
        mac = record.pop("hmac", None)
        if record.get("prev_hash") != prev:
            return VerifyReport(False, n - 1, n, f"line {n}: prev_hash does not match line {n - 1}")
        if record.get("seq") != n:
            return VerifyReport(False, n - 1, n, f"line {n}: sequence number {record.get('seq')} != {n}")
        digest = entry_hash(record, prev)
        if claimed != digest:
            return VerifyReport(False, n - 1, n, f"line {n}: entry_hash mismatch (content was modified)")
        if key is not None and (mac is None or not hmac.compare_digest(mac, sign(digest, key))):
            return VerifyReport(False, n - 1, n, f"line {n}: HMAC signature invalid or missing")
        prev = digest
    return VerifyReport(True, len(lines))
