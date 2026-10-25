"""Secret redaction.

Applied to everything the LLM sees (tool output) and everything written to disk
(report, trace, logs), so credential values never leave the process.
"""
from __future__ import annotations

import re

_registered: list[str] = []

_TOKEN_PATTERNS = [
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("API_KEY", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("STRIPE_KEY", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("GOOGLE_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]
_URL_CRED = re.compile(r"(://[^/\s:@]+:)([^@\s/]+)(@)")
_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_ASSIGN = re.compile(
    r"""(?ix)
    (?P<key>[\w.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|
        private[_\-]?key|credential|auth[_\-]?key)[\w.\-]*)
    (?P<sep>["']?[ \t]*[:=][ \t]*["']?)
    (?P<val>[^\s"'`,;#)}\]]{6,})
    """
)
_PLACEHOLDER_HINTS = (
    "your", "xxx", "changeme", "change-me", "change_me", "example", "dummy",
    "placeholder", "<", "replace", "redacted", "...", "none", "null", "true", "false",
)
_CODE_REF_HINTS = ("os.", "environ", "getenv", "process.env", "secrets.", "env.", "vars.", "config.", "settings.")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def register_secret(value: str | None) -> None:
    """Register an exact secret (e.g. the LLM API key) to be masked everywhere."""
    if value and len(value) >= 8 and value not in _registered:
        _registered.append(value)


def _assign_sub(m: re.Match) -> str:
    val, sep = m.group("val"), m.group("sep")
    low = val.lower()
    quoted = sep.endswith(("'", '"'))
    if val.startswith(("$", "{{", "<", "%", "@")):
        return m.group(0)
    if any(h in low for h in _PLACEHOLDER_HINTS) or any(h in low for h in _CODE_REF_HINTS):
        return m.group(0)
    if "(" in val or val.endswith("["):
        return m.group(0)
    if not quoted and _IDENT.match(val) and not any(c.isdigit() for c in val) and ("_" in val or "." in val):
        return m.group(0)  # looks like a code reference, not a literal
    return f"{m.group('key')}{sep}[REDACTED]"


def redact(text: str) -> str:
    if not text:
        return text
    for secret in _registered:
        text = text.replace(secret, "[REDACTED:API_KEY]")
    out: list[str] = []
    in_key = False
    for line in text.split("\n"):
        if in_key:
            out.append("[REDACTED]")
            if _KEY_END.search(line):
                in_key = False
            continue
        if _KEY_BEGIN.search(line):
            out.append("-----BEGIN PRIVATE KEY----- [REDACTED]")
            in_key = not _KEY_END.search(line)
            continue
        for label, pat in _TOKEN_PATTERNS:
            line = pat.sub(f"[REDACTED:{label}]", line)
        line = _URL_CRED.sub(r"\1[REDACTED]\3", line)
        line = _ASSIGN.sub(_assign_sub, line)
        out.append(line)
    return "\n".join(out)
