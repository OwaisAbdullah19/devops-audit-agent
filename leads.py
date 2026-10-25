"""Open leads: signals that the agent's own tool calls surfaced.

After the LLM submits its report, the loop compares these leads with the findings and asks the LLM,
once, to decide on every lead that is not clearly covered (add a finding, or explain why it is fine).
This module never creates findings itself; the LLM stays the judge.
"""
from __future__ import annotations

import json
import re
from typing import Any

_WF_KEEP = re.compile(
    r"pull_request_target|checks out PR head|write permissions|interpolated|pipes remote script|continue-on-error|"
    r"disabled with if|not gated|every push|do not include push|do not match default branch|auto-merge|"
    r"issue_comment|self-hosted|does not parse|not a mapping|no triggers", re.I)
_NOISY_PATH = re.compile(r"(^|/)(examples?|docs?|tests?|test_apps|fixtures?|samples?|testdata)(/|$)", re.I)
_CONFIG_LIKE = re.compile(r"(config|settings|\.env|\.ya?ml$|\.ini$|\.toml$|\.cfg$|\.json$|dockerfile|compose)", re.I)
_CRED_WORDS = re.compile(r"credential|password|passwd|secret|token|api[_ -]?key|\\bkey\\b|private", re.I)
_STOP = {"file", "files", "found", "with", "that", "this", "from", "also", "check", "when", "only", "each", "there",
         "have", "uses", "used", "into", "none", "true", "false"}


def _lead(tool: str, kind: str, text: str, file: str | None = None, line: int | None = None,
          context: str | None = None) -> dict[str, Any]:
    return {"tool": tool, "kind": kind, "file": file, "line": line, "text": text, "context": context}


def extract_leads(tool: str, raw: str) -> list[dict[str, Any]]:
    try:
        d = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(d, dict):
        return []
    out: list[dict[str, Any]] = []
    add = lambda *a, **k: out.append(_lead(tool, *a, **k))  # noqa: E731

    if tool == "inspect_workflows":
        for w in d.get("workflows") or ([d] if "signals" in d else []):
            has_validation = bool(w.get("test_steps") or w.get("lint_steps") or w.get("build_steps"))
            for s in w.get("signals") or []:
                if not _WF_KEEP.search(s):
                    continue
                if "write permissions" in s and "write-all" not in s:
                    continue  # ordinary scoped write grants (id-token, contents) are not leads on their own
                if "do not include push/pull_request" in s and not has_validation:
                    continue  # schedule/dispatch-only maintenance workflows are normal
                add("ci", s, w.get("file"))
    elif tool == "inspect_dockerfiles":
        for df in (d.get("dockerfiles") or []) + (d.get("compose_files") or []):
            for s in df.get("signals") or []:
                add("docker", s["issue"], df.get("file"), s.get("line"))
    elif tool == "inspect_tests_and_quality":
        for p in d.get("test_problems") or []:
            if p.get("issue") not in ("empty body", "constant assert"):
                continue  # 'no assertions'/'skipped' are too often legitimate (helpers, reasoned skips)
            add("tests", f"test {p.get('test')}: {p.get('issue')}", p.get("path"), p.get("line"))
        if d.get("any_lint_or_format_config") is False:
            add("quality", "no linter/formatter configuration found (also check CI lint steps and pre-commit)")
        if (d.get("test_files") or {}).get("count") == 0:
            add("tests", "no test files found")
    elif tool == "inspect_hygiene":
        rd = d.get("readme_files")
        if isinstance(rd, str):
            add("hygiene", "no README file found")
        elif isinstance(rd, list) and rd and all(r.get("looks_like_stub") for r in rd):
            add("hygiene", "README looks like a stub", rd[0].get("path"))
        gi = d.get("gitignore") or {}
        if not gi.get("root_present"):
            add("hygiene", "no root .gitignore")
        for label, v in (d.get("tracked_junk_by_category") or {}).items():
            ex = (v.get("examples") or [None])[0]
            add("hygiene", f"tracked {label}: e.g. {ex}", ex)
        for m in d.get("merge_conflict_markers") or []:
            add("hygiene", "merge-conflict markers committed", m.get("path"), m.get("line"))
    elif tool == "inspect_dependencies":
        for c in d.get("conflicting_specs_across_manifests") or []:
            srcs = list((c.get("specs") or {}))
            add("deps", f"conflicting specs for {c.get('package')}: {c.get('specs')}", srcs[0] if srcs else None)
        manifests = d.get("manifests") or []
        for m in manifests:
            if m.get("type") == "requirements" and m.get("unpinned"):
                add("deps", f"unpinned requirements in {m['file']}: {m['unpinned'][:6]}", m["file"])
        if manifests and not d.get("lockfiles_present") and not d.get("requirements_fully_pinned_with_equals"):
            add("deps", "no lockfile found and requirements not fully pinned (matters for applications, not libraries)")
    elif tool == "scan_secrets":
        sensitive = {f["path"] for f in d.get("sensitive_files") or [] if not f.get("likely_test_or_example")}
        for p in sorted(sensitive):
            kind = next((f.get("kind") for f in d["sensitive_files"] if f["path"] == p), "secret file")
            add("secrets", f"committed {kind}", p)
        for h in d.get("hits") or []:
            if not h.get("likely_test_or_example") and h["path"] not in sensitive:
                add("secrets", f"{h.get('kind')}{' (' + h['name'] + ')' if h.get('name') else ''}", h["path"],
                    h.get("line"), context=h.get("text"))
    elif tool == "scan_config_smells":
        for h in d.get("hits") or []:
            if h.get("likely_placeholder") or h.get("likely_test_or_example"):
                continue
            kind = h.get("kind", "config smell")
            if kind == "Windows absolute path":
                continue  # too often a docstring/regex; user-specific paths are kept
            if kind.startswith(("debug/development", "hardcoded local")) and not _CONFIG_LIKE.search(h["path"]):
                continue  # only meaningful in configuration files, not arbitrary source
            add("config", kind, h["path"], h.get("line"))
        for f in d.get("committed_local_or_ide_files") or []:
            add("config", "committed local/IDE settings file", f)
    elif tool == "analyze_python":
        for e in d.get("syntax_errors") or []:
            add("python", f"syntax error: {e.get('error')} (confirm; parser may be older than the repo's Python)",
                e.get("path"), e.get("line"))
    return [ld for ld in out if not (ld["file"] and _NOISY_PATH.search(ld["file"]) and ld["kind"] in ("deps", "hygiene", "config", "tests"))]


def _words(s: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9_\-.]{4,}", s.lower()) if w not in _STOP}


def is_covered(lead: dict[str, Any], violations: list[dict]) -> bool:
    lw = _words(lead["text"] + " " + (lead.get("context") or ""))
    need = min(2, len(lw))
    if need == 0:
        return True
    for v in violations:
        vtext = " ".join(str(v.get(k) or "") for k in ("file", "description", "evidence", "recommendation"))
        same_file = lead["file"] is not None and v.get("file") == lead["file"]
        if lead["file"]:
            if lead.get("line") is not None:
                if same_file and v.get("line") == lead["line"] and (
                        lead["kind"] != "secrets" or _CRED_WORDS.search(vtext)):
                    return True
            elif lead["kind"] not in ("ci", "docker") and (same_file or lead["file"] in vtext):
                return True  # file-level lead (e.g. a committed .env) is covered by any finding on / naming that file
        if (same_file or lead["file"] is None) and len(lw & _words(vtext)) >= need:
            return True
    return False


def open_leads(leads: list[dict[str, Any]], violations: list[dict], limit: int = 15) -> list[dict[str, Any]]:
    seen, out = set(), []
    for ld in leads:
        key = (ld["text"], ld["file"], ld["line"])
        if key in seen:
            continue
        seen.add(key)
        if not is_covered(ld, violations):
            out.append(ld)
    return out[:limit]


def review_message(leads: list[dict[str, Any]]) -> str:
    lines = []
    for i, ld in enumerate(leads, 1):
        loc = f"{ld['file']}" + (f":{ld['line']}" if ld.get("line") else "") if ld.get("file") else "repo-level"
        lines.append(f"{i}. [{ld['kind']}] {loc} - {ld['text'][:200]}")
    return ("SELF-REVIEW (one time only). These leads came from tools you ran but are not clearly covered by your report:\n"
            + "\n".join(lines) +
            "\n\nFor each lead decide: add it as its own finding (with its own file/line and concrete evidence) if it is a genuine "
            "violation under the evidence rules, or leave it out if it is acceptable, intentional, a placeholder or an equivalent "
            "solution. Also split any finding that bundles several different defects (one finding per defect and line). Then call "
            "submit_report again with the COMPLETE final list AND lead_decisions: one entry per numbered lead (decision add or skip, "
            "plus a one-sentence reason). You will not be asked again. On a healthy repository most leads are "
            "NOT violations, and adding nothing is a perfectly good answer.")
