"""Validation, normalisation and writing of the JSON report."""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from prompts import CATEGORIES, SEVERITIES
from redact import redact

REQUIRED_FIELDS = ["rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"]
PREFIX = {"repository_hygiene": "REPO", "dependency_management": "DEP", "code_quality": "QUAL", "testing": "TEST",
          "ci_cd": "CI", "security": "SEC", "configuration": "CFG", "collaboration": "COLLAB", "build_release": "BUILD"}
_CAT_ALIASES = {
    "ci": "ci_cd", "cicd": "ci_cd", "ci_cd": "ci_cd", "github_actions": "ci_cd", "actions": "ci_cd", "workflow": "ci_cd",
    "hygiene": "repository_hygiene", "repository": "repository_hygiene", "repo": "repository_hygiene",
    "dependencies": "dependency_management", "dependency": "dependency_management", "deps": "dependency_management",
    "quality": "code_quality", "lint": "code_quality", "linting": "code_quality",
    "tests": "testing", "test": "testing", "config": "configuration",
    "build": "build_release", "release": "build_release", "deployment": "build_release", "build_and_release": "build_release",
}
log = logging.getLogger("audit")
_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
_OVERLAP = {frozenset({"repository_hygiene", "security"}), frozenset({"configuration", "security"})}
_TOKEN = re.compile(r"[a-z0-9_]+")


def _canon_category(c: Any) -> str | None:
    key = re.sub(r"[\s\-/&]+", "_", str(c or "").strip().lower())
    if key in CATEGORIES:
        return key
    return _CAT_ALIASES.get(key)


def _norm_path(p: Any) -> str | None:
    if p is None:
        return None
    s = str(p).strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    s = s.lstrip("/")
    return s or None


def _count_lines(path: Path) -> int:
    n = 0
    with open(path, "rb") as fh:
        for n, _ in enumerate(fh, 1):
            pass
    return n


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+|[A-Za-z_][A-Za-z0-9_]*(?:[-_][A-Za-z0-9_]+)+|[A-Z][A-Z0-9_]{3,}")


def _snap_line(path: Path, line: int, text: str, window: int = 3) -> int:
    """Fix an off-by-a-few line number. The finding's text names identifiers (continue-on-error, API_KEY,
    github.event.pull_request.title ...). If a nearby line contains a strict superset of the identifiers found on the
    cited line, move there. Never changes the finding itself."""
    toks = {t for t in _IDENT.findall(text) if len(t) >= 5 and t != "REDACTED"}
    if not toks:
        return line
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return line
    if not (1 <= line <= len(lines)):
        return line

    def found(n: int) -> frozenset:
        return frozenset(t for t in toks if t in lines[n - 1])

    here = found(line)
    best, best_set = line, here
    for d in range(1, window + 1):
        for cand in (line - d, line + d):
            if 1 <= cand <= len(lines):
                s = found(cand)
                if s and s > best_set:          # strict superset of what the best line so far matches
                    best, best_set = cand, s
    return best


_SIM_STOP = {"the", "and", "with", "without", "that", "this", "from", "into", "for", "are", "was", "has", "have", "not",
             "its", "can", "any", "all", "use", "uses", "used", "file", "files", "repository", "repo", "found", "present"}


def _sim_tokens(s: str) -> set[str]:
    return {t for t in _TOKEN.findall(s.lower()) if len(t) > 2 and t not in _SIM_STOP}


def _similar(a: str, b: str, threshold: float = 0.6) -> bool:
    ta, tb = _sim_tokens(a), _sim_tokens(b)
    return bool(ta and tb) and len(ta & tb) / len(ta | tb) >= threshold


def normalize_violations(raw: Any, repo_root: str | Path) -> tuple[list[dict], list[str]]:
    """Return (valid violations with rule_ids, human-readable rejection reasons)."""
    root = Path(repo_root).resolve()
    rejected: list[str] = []
    if not isinstance(raw, list):
        return [], ["'violations' must be a list"]
    cleaned: list[dict] = []
    for i, item in enumerate(raw):
        tag = f"violation #{i + 1}"
        if not isinstance(item, dict):
            rejected.append(f"{tag}: not an object")
            continue
        cat = _canon_category(item.get("category"))
        sev = str(item.get("severity") or "").strip().lower()
        if cat is None:
            rejected.append(f"{tag}: invalid category {item.get('category')!r}; use one of {CATEGORIES}")
            continue
        if sev not in SEVERITIES:
            rejected.append(f"{tag}: invalid severity {item.get('severity')!r}; use one of {SEVERITIES}")
            continue
        texts = {}
        for f, limit in (("description", 300), ("evidence", 700), ("recommendation", 700)):
            v = redact(str(item.get(f) or "").strip())
            if not v:
                rejected.append(f"{tag}: '{f}' is empty")
                break
            texts[f] = v[:limit]
        else:
            file = _norm_path(item.get("file"))
            line: int | None = None
            try:
                line = int(item.get("line")) if item.get("line") not in (None, "", 0, "0") else None
            except (TypeError, ValueError):
                line = None
            if line is not None and line < 1:
                line = None
            if file is not None:
                target = (root / file).resolve()
                if root not in target.parents and target != root:
                    rejected.append(f"{tag}: file {file!r} is outside the repository")
                    continue
                if not target.exists():
                    rejected.append(f"{tag}: file {file!r} does not exist in the repository "
                                    "(use an empty file and line 0 for missing-file findings)")
                    continue
                if target.is_file() and line is not None:
                    total = _count_lines(target)
                    if line > total:
                        rejected.append(f"{tag}: line {line} exceeds length of {file} ({total} lines)")
                        continue
                    line = _snap_line(target, line, texts["description"] + " " + texts["evidence"])
                if target.is_dir():
                    line = None
            else:
                line = None
            cleaned.append({"category": cat, "severity": sev, "file": file, "line": line, **texts})

    # de-duplicate (same defect reported twice earns nothing and can hurt precision)
    unique: list[dict] = []
    for v in cleaned:
        dup = False
        for idx, u in enumerate(unique):
            same_loc = u["file"] is not None and u["file"] == v["file"] and u["line"] is not None and u["line"] == v["line"]
            same_cat_file = u["category"] == v["category"] and u["file"] == v["file"]
            ut, vt = u["description"] + " " + u["evidence"], v["description"] + " " + v["evidence"]
            if same_cat_file and _similar(ut, vt, 0.5 if same_loc else 0.6):
                dup = True            # same defect described twice
            elif same_loc and frozenset({u["category"], v["category"]}) in _OVERLAP and _similar(ut, vt, 0.2):
                dup = True            # e.g. a committed secret file reported as both hygiene and security
                if _SEV_ORDER[v["severity"]] < _SEV_ORDER[u["severity"]]:
                    unique[idx] = v
            if dup:
                log.info("merged duplicate finding: %r into %r", v["description"][:60], u["description"][:60])
                break
        if not dup:
            unique.append(v)
    unique.sort(key=lambda v: (_SEV_ORDER[v["severity"]], v["category"], v["file"] or "", v["line"] or 0))
    counters: dict[str, int] = {}
    out = []
    for v in unique:
        p = PREFIX[v["category"]]
        counters[p] = counters.get(p, 0) + 1
        out.append({"rule_id": f"{p}-{counters[p]:03d}", **v})
    return out, rejected


def validate_report(report: Any) -> list[str]:
    """Check a report dict against the assignment's output contract. Returns a list of problems."""
    problems: list[str] = []
    if not isinstance(report, dict) or set(report) != {"repository", "violations"}:
        return ["report must be an object with exactly 'repository' and 'violations'"]
    if not isinstance(report["repository"], str) or not report["repository"]:
        problems.append("'repository' must be a non-empty string")
    if not isinstance(report["violations"], list):
        return problems + ["'violations' must be a list"]
    for i, v in enumerate(report["violations"]):
        if not isinstance(v, dict) or any(f not in v for f in REQUIRED_FIELDS):
            problems.append(f"violation {i}: missing required field(s)")
            continue
        if v["severity"] not in SEVERITIES:
            problems.append(f"violation {i}: bad severity")
        if v["file"] is not None and not isinstance(v["file"], str):
            problems.append(f"violation {i}: file must be string or null")
        if v["line"] is not None and (not isinstance(v["line"], int) or isinstance(v["line"], bool)):
            problems.append(f"violation {i}: line must be integer or null")
        for f in ("rule_id", "category", "description", "evidence", "recommendation"):
            if not isinstance(v[f], str) or not v[f]:
                problems.append(f"violation {i}: {f} must be a non-empty string")
    return problems


def write_report(path: str | Path, repo_url: str, violations: list[dict]) -> None:
    report = {"repository": repo_url, "violations": violations}
    problems = validate_report(report)
    if problems:
        raise ValueError("internal error: invalid report: " + "; ".join(problems))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".report-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
