"""Read-only inspection tools for the audit agent.

Nothing here executes code from the inspected repository. Every tool returns a
string (JSON or numbered text) that is fed back to the LLM, which must interpret it.
Tool output is size-capped and secret values are redacted before it leaves this module.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import yaml

from inspectors import EXTRA_SCHEMAS, Inspectors
from redact import redact

MAX_OUTPUT_CHARS = int(os.environ.get("AGENT_MAX_TOOL_CHARS", "8000"))
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_SEARCH_FILE_BYTES = 1024 * 1024
MAX_LINE_CHARS = 400


class ToolError(Exception):
    """Raised for bad arguments or unavailable data; reported back to the LLM."""


def _trunc(s: str, n: int) -> str:
    s = s if isinstance(s, str) else str(s)
    return s if len(s) <= n else s[:n] + "…"


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


class RepoTools(Inspectors):
    def __init__(self, root: str | Path, max_output: int = MAX_OUTPUT_CHARS):
        self.root = Path(root).resolve()
        if not (self.root / ".git").exists():
            raise ToolError(f"{self.root} is not a git repository")
        self.max_output = max_output
        self._files_cache: list[str] | None = None
        self._registry: dict[str, Callable[..., str]] = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "git_log": self.git_log,
            "git_status": self.git_status,
            "git_tracked_ignored": self.git_tracked_ignored,
            "inspect_workflows": self.inspect_workflows,
            "scan_secrets": self.scan_secrets,
            "inspect_dependencies": self.inspect_dependencies,
            "inspect_dockerfiles": self.inspect_dockerfiles,
            "scan_config_smells": self.scan_config_smells,
            "inspect_hygiene": self.inspect_hygiene,
            "inspect_tests_and_quality": self.inspect_tests_and_quality,
            "analyze_python": self.analyze_python,
        }

    # ------------------------------------------------------------------ helpers
    def _git(self, *args: str, timeout: int = 30) -> str:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
        cmd = ["git", "-C", str(self.root), "-c", "safe.directory=*", "-c", "core.fsmonitor=false", *args]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, errors="replace")
        except subprocess.TimeoutExpired:
            raise ToolError(f"git {args[0]} timed out after {timeout}s")
        except FileNotFoundError:
            raise ToolError("git is not installed")
        if r.returncode != 0:
            raise ToolError(f"git {args[0]} failed: {_trunc(r.stderr.strip(), 300)}")
        return r.stdout

    def _tracked(self) -> list[str]:
        if self._files_cache is None:
            out = self._git("ls-files", "-z")
            self._files_cache = sorted(p for p in out.split("\0") if p)
        return self._files_cache

    def _safe_path(self, rel: str) -> Path:
        if not isinstance(rel, str) or not rel.strip():
            raise ToolError("path must be a non-empty string")
        rel = rel.replace("\\", "/").lstrip("/")
        if ".git" in Path(rel).parts:
            raise ToolError("access to .git internals is not allowed")
        p = (self.root / rel).resolve()
        if p != self.root and self.root not in p.parents:
            raise ToolError("path escapes the repository")
        return p

    @staticmethod
    def _json(obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _match(path: str, pattern: str) -> bool:
        return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern)

    # -------------------------------------------------------------------- tools
    def list_files(self, path: str = "", glob: str = "", max_results: int = 300) -> str:
        """List tracked files (path + size), optionally under a directory or matching a glob."""
        max_results = max(1, min(int(max_results), 1000))
        prefix = (path or "").replace("\\", "/").strip()
        while prefix.startswith("./"):
            prefix = prefix[2:]
        prefix = "" if prefix in (".", "./", "/") else prefix.strip("/")
        files = self._tracked()
        if prefix:
            files = [f for f in files if f == prefix or f.startswith(prefix + "/")]
        if glob:
            files = [f for f in files if self._match(f, glob)]
        top = Counter(f.split("/")[0] if "/" in f else "(root files)" for f in files)
        shown, used = [], 0
        budget = max(500, self.max_output - 1200)
        for f in files[:max_results]:
            try:
                size = (self.root / f).lstat().st_size
            except OSError:
                size = None
            entry = {"path": f, "size": size}
            used += len(f) + 24
            if used > budget:
                break
            shown.append(entry)
        return self._json({
            "total_matching": len(files),
            "shown": len(shown),
            "truncated": len(files) > len(shown),
            "hint": "narrow with path='dir' or glob='*.ext' to see the rest" if len(files) > len(shown) else None,
            "top_level_counts": dict(top.most_common(25)),
            "files": shown,
        })

    def read_file(self, path: str, start_line: int = 1, end_line: int = 0) -> str:
        """Read a text file with line numbers. Default window is 250 lines."""
        p = self._safe_path(path)
        if not p.exists():
            raise ToolError(f"file not found: {path}")
        if p.is_dir():
            raise ToolError(f"{path} is a directory; use list_files")
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ToolError(f"file too large ({size} bytes); read a smaller file or use search_code")
        with open(p, "rb") as fh:
            if _is_binary(fh.read(4096)):
                raise ToolError("binary file; cannot display")
        start = max(1, int(start_line or 1))
        end = int(end_line or 0) or start + 249
        end = min(end, start + 799)
        out, total = [], 0
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for total, line in enumerate(fh, 1):
                if start <= total <= end:
                    out.append(f"{total}: {_trunc(redact(line.rstrip(chr(10)).rstrip(chr(13))), MAX_LINE_CHARS)}")
        header = f"# {path} (lines {start}-{min(end, total)} of {total})"
        if total > end:
            header += f" — more lines available, call again with start_line={end + 1}"
        if not out:
            header += " — requested range is empty"
        return header + "\n" + "\n".join(out)

    def search_code(self, pattern: str, glob: str = "", max_results: int = 40, ignore_case: bool = True) -> str:
        """Regex search across tracked text files. Returns path, line number, redacted line."""
        if not isinstance(pattern, str) or not pattern:
            raise ToolError("pattern must be a non-empty string")
        try:
            rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as e:
            raise ToolError(f"invalid regex: {e}")
        max_results = max(1, min(int(max_results), 200))
        matches, files_hit, scanned = [], set(), 0
        deadline = time.monotonic() + 15
        truncated = False
        for f in self._tracked():
            if glob and not self._match(f, glob):
                continue
            if time.monotonic() > deadline:
                truncated = True
                break
            fp = self.root / f
            try:
                if not fp.is_file() or fp.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
                with open(fp, "rb") as fh:
                    if _is_binary(fh.read(4096)):
                        continue
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    scanned += 1
                    for n, line in enumerate(fh, 1):
                        if rx.search(line[:2000]):
                            matches.append({"path": f, "line": n, "text": _trunc(redact(line.strip()), 200)})
                            files_hit.add(f)
                            if len(matches) >= max_results:
                                truncated = True
                                break
            except OSError:
                continue
            if len(matches) >= max_results:
                break
        return self._json({
            "pattern": pattern, "files_scanned": scanned, "files_with_matches": len(files_hit),
            "match_count": len(matches), "truncated": truncated, "matches": matches,
        })

    def git_log(self, max_count: int = 30, path: str = "") -> str:
        """Recent commit history (hash, date, author, subject)."""
        max_count = max(1, min(int(max_count), 100))
        args = ["log", f"-n{max_count}", "--date=short", "--pretty=format:%h\t%ad\t%an\t%s"]
        if path:
            self._safe_path(path)
            args += ["--", path]
        rows = [ln.split("\t", 3) for ln in self._git(*args).splitlines() if ln]
        commits = [{"hash": r[0], "date": r[1], "author": r[2], "subject": _trunc(redact(r[3]), 160)}
                   for r in rows if len(r) == 4]
        authors = Counter(c["author"] for c in commits)
        shallow = self._git("rev-parse", "--is-shallow-repository").strip() == "true"
        return self._json({
            "commits_shown": len(commits), "history_is_truncated_shallow_clone": shallow,
            "authors_in_shown_commits": dict(authors.most_common(10)), "commits": commits,
        })

    def git_status(self) -> str:
        """HEAD, current branch and working-tree state of the (read-only) clone."""
        try:
            branch = self._git("symbolic-ref", "--short", "-q", "HEAD", timeout=10).strip()
        except ToolError:
            branch = "(detached)"
        head = self._git("rev-parse", "--short", "HEAD").strip()
        dirty = [ln for ln in self._git("status", "--porcelain").splitlines() if ln]
        return self._json({"branch_default_in_clone": branch, "head": head,
                           "working_tree_clean": not dirty, "changes": dirty[:20]})

    def git_tracked_ignored(self, max_results: int = 100) -> str:
        """Files that are committed although the repository's .gitignore rules match them."""
        out = self._git("ls-files", "-z", "-c", "-i", "--exclude-standard")
        files = [p for p in out.split("\0") if p]
        return self._json({"count": len(files), "files": files[:max_results], "truncated": len(files) > max_results})

    # ---------------------------------------------------------- workflow facts
    _TEST_RE = re.compile(r"\b(pytest|py\.test|unittest|tox|nox|npm (?:run )?test|yarn test|pnpm test|go test|cargo test|"
                          r"mvn\S* .*test|gradle\S* .*test|make test|dotnet test|rspec|phpunit|jest|vitest|ctest)\b")
    _LINT_RE = re.compile(r"\b(ruff|flake8|pylint|black|isort|mypy|pyright|eslint|prettier|golangci-lint|cargo clippy|"
                          r"cargo fmt|rubocop|pre-commit|shellcheck|hadolint)\b")
    _BUILD_RE = re.compile(r"\b(docker (?:buildx? )?build|python -m build|poetry build|npm run build|yarn build|pnpm build|"
                           r"cargo build|go build|mvn\S* .*package|gradle\S* .*build|make build)\b")
    _DEPLOY_RE = re.compile(r"\b(twine upload|pypi-publish|docker push|npm publish|kubectl|helm (?:upgrade|install)|"
                            r"terraform apply|gh release|deploy)\b", re.I)
    _CURL_PIPE = re.compile(r"(curl|wget)[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh")
    _INJECT = re.compile(r"\$\{\{\s*(github\.event\.(?:issue|pull_request|comment|review|head_commit|commits|pages)"
                         r"[^}]*|github\.head_ref|inputs\.[\w-]+|github\.event\.inputs\.[\w-]+)\s*\}\}")
    _OTHER_CI = [".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml", ".travis.yml",
                 "bitbucket-pipelines.yml", ".drone.yml", "cloudbuild.yaml", ".buildkite/pipeline.yml"]

    @staticmethod
    def _triggers(on: Any) -> dict[str, Any]:
        if isinstance(on, str):
            return {on: {}}
        if isinstance(on, list):
            return {str(e): {} for e in on}
        if isinstance(on, dict):
            res = {}
            for k, v in on.items():
                if isinstance(v, dict):
                    keep = {kk: vv for kk, vv in v.items()
                            if kk in ("branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore", "types", "workflows")}
                    res[str(k)] = keep
                elif isinstance(v, list):
                    res[str(k)] = {"entries": v[:5]}
                else:
                    res[str(k)] = {}
            return res
        return {}

    @staticmethod
    def _branch_matches(patterns: list[str], branch: str) -> bool:
        for pat in patterns:
            if pat.startswith("!"):
                continue
            if fnmatch.fnmatch(branch, pat.replace("**", "*")):
                return True
        return False

    def _summarize_workflow(self, rel: str, default_branch: str, run_max: int) -> dict[str, Any]:
        text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
        info: dict[str, Any] = {"file": rel}
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            info["parse_error"] = _trunc(str(e).replace("\n", " "), 200)
            info["signals"] = ["workflow YAML does not parse"]
            return info
        if not isinstance(doc, dict):
            info["parse_error"] = "top-level YAML is not a mapping"
            info["signals"] = ["workflow YAML is not a mapping"]
            return info
        on = doc.get("on", doc.get(True))
        trig = self._triggers(on)
        info["name"] = doc.get("name")
        info["triggers"] = trig
        info["permissions"] = doc.get("permissions")
        signals: list[str] = []
        if not trig:
            signals.append("no triggers defined")
        elif not set(trig) & {"push", "pull_request", "pull_request_target", "workflow_call", "merge_group", "release", "workflow_run"}:
            signals.append(f"triggers {sorted(trig)} do not include push/pull_request (not run on code changes)")
        for ev in ("push", "pull_request"):
            br = trig.get(ev, {}).get("branches") if isinstance(trig.get(ev), dict) else None
            if br and isinstance(br, list) and not self._branch_matches([str(b) for b in br], default_branch):
                signals.append(f"{ev} branches {br} do not match default branch '{default_branch}'")
            if isinstance(trig.get(ev), dict) and (trig[ev].get("paths") or trig[ev].get("paths-ignore")):
                signals.append(f"{ev} has path filters (workflow may be skipped for some changes)")
        if "pull_request_target" in trig:
            signals.append("uses pull_request_target (runs with base-repo secrets/write token)")
        if "workflow_run" in trig:
            signals.append("uses workflow_run trigger")
        for ev in ("issue_comment", "pull_request_review_comment", "issues"):
            if ev in trig:
                signals.append(f"triggered by {ev} (untrusted user input; check what it can do)")
        if re.search(r"gh pr merge|enable-automerge|automerge|auto-merge|merge-method", text, re.I):
            signals.append("contains auto-merge/merge automation")
        rel_trig = [e for e in ("release", "workflow_dispatch") if e in trig]
        pushc = trig.get("push") if isinstance(trig.get("push"), dict) else {}
        if pushc.get("tags"):
            rel_trig.append(f"push tags {pushc['tags']}")
        if rel_trig:
            signals.append(f"release-style triggers: {rel_trig}")
        perms = doc.get("permissions")
        jobs_out: dict[str, Any] = {}
        secrets_used = sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text)))
        tests, lints, builds, deploys = [], [], [], []
        unpinned = []
        for jname, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            jperm = job.get("permissions")
            jo: dict[str, Any] = {"runs-on": job.get("runs-on"), "needs": job.get("needs"),
                                  "permissions": jperm, "if": job.get("if"),
                                  "continue-on-error": job.get("continue-on-error"),
                                  "timeout-minutes": job.get("timeout-minutes")}
            if "uses" in job:
                jo["uses"] = job["uses"]
            ro = str(job.get("runs-on"))
            if "self-hosted" in ro:
                signals.append(f"job '{jname}' uses self-hosted runner")
            if perms is None and jperm is None:
                signals.append(f"job '{jname}' has no explicit permissions (workflow has none either)")
            for pv in [perms, jperm]:
                if pv == "write-all" or (isinstance(pv, dict) and any(str(v) == "write" for v in pv.values())):
                    signals.append(f"job '{jname}': write permissions granted ({pv})")
                    break
            if job.get("continue-on-error") is True:
                signals.append(f"job '{jname}' has continue-on-error: true")
            if str(job.get("if")).strip().lower() in ("false", "${{ false }}"):
                signals.append(f"job '{jname}' is disabled with if: false")
            steps_out = []
            for i, st in enumerate(job.get("steps") or [], 1):
                if not isinstance(st, dict):
                    continue
                run = st.get("run")
                so: dict[str, Any] = {"i": i}
                if st.get("name"):
                    so["name"] = _trunc(str(st["name"]), 80)
                if st.get("uses"):
                    so["uses"] = st["uses"]
                    ref = str(st["uses"])
                    if "@" in ref and not ref.startswith(("./", "docker://")):
                        action, _, rv = ref.partition("@")
                        if not re.fullmatch(r"[0-9a-f]{40}", rv) and not action.lower().startswith(("actions/", "github/")):
                            unpinned.append(ref)
                if run:
                    so["run"] = _trunc(redact(str(run).strip()), run_max)
                    r = str(run)
                    label = f"{jname}#{i}"
                    if self._TEST_RE.search(r):
                        tests.append(label)
                    if self._LINT_RE.search(r):
                        lints.append(label)
                    if self._BUILD_RE.search(r):
                        builds.append(label)
                    if self._DEPLOY_RE.search(r):
                        deploys.append(label)
                    if self._CURL_PIPE.search(r):
                        signals.append(f"{label}: pipes remote script into shell")
                    if self._INJECT.search(r):
                        signals.append(f"{label}: untrusted github.event/head_ref expression interpolated in run script")
                if st.get("if"):
                    so["if"] = _trunc(str(st["if"]), 100)
                    if str(st["if"]).strip().lower() in ("false", "${{ false }}"):
                        signals.append(f"{jname}#{i} step disabled with if: false")
                if st.get("continue-on-error") is True:
                    so["continue-on-error"] = True
                    if run and (self._TEST_RE.search(str(run)) or self._LINT_RE.search(str(run))):
                        signals.append(f"{jname}#{i}: test/lint step has continue-on-error: true (failures ignored)")
                if isinstance(st.get("with"), dict):
                    so["with"] = {k: _trunc(redact(f"{k}: {v}").split(": ", 1)[-1], 80) for k, v in st["with"].items()}
                    ref = str(st["with"].get("ref", ""))
                    if "pull_request_target" in trig and "head" in ref and "pull_request" in ref:
                        signals.append(f"{jname}#{i}: checks out PR head code under pull_request_target")
                steps_out.append(so)
            jo["steps"] = steps_out
            jobs_out[str(jname)] = {k: v for k, v in jo.items() if v not in (None, [], {})}
        gated = bool(tests)
        for jname, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            dep = [f"{jname}#{i}" for i, st in enumerate(job.get("steps") or [], 1)
                   if isinstance(st, dict) and (self._DEPLOY_RE.search(str(st.get("run", "")))
                       or re.search(r"pypi-publish|action-gh-release|build-push-action|deploy|publish", str(st.get("uses", "")), re.I))]
            tag_or_release = bool(pushc.get("tags")) or "release" in trig
            if dep and not job.get("needs") and not gated and not tag_or_release:
                signals.append(f"deploy/publish steps {dep[:3]} in job '{jname}' are not gated by needs or any test step in this workflow")
            if dep and isinstance(trig.get("push"), dict) and not trig["push"].get("tags") and not trig["push"].get("branches") \
                    and "release" not in trig:
                signals.append(f"deploy/publish job '{jname}' runs on every push (no branch/tag filter)")
        if unpinned:
            signals.append(f"third-party actions not pinned to a commit SHA: {sorted(set(unpinned))[:10]}")
        info["jobs"] = jobs_out
        info["test_steps"], info["lint_steps"] = tests, lints
        info["build_steps"], info["deploy_or_publish_steps"] = builds, deploys
        info["secrets_referenced"] = secrets_used
        info["uses_build_or_publish_actions"] = sorted({str(st.get("uses")).split("@")[0]
            for j in (doc.get("jobs") or {}).values() if isinstance(j, dict)
            for st in (j.get("steps") or []) if isinstance(st, dict) and st.get("uses") and re.search(
                r"build-push|pypi-publish|gh-release|setup-buildx|docker/", str(st.get("uses")), re.I)})
        info["signals"] = list(dict.fromkeys(signals))
        return info

    @staticmethod
    def _compact_workflow(w: dict[str, Any]) -> dict[str, Any]:
        c = dict(w)
        if "jobs" in c:
            c["jobs"] = {j: {k: v for k, v in jd.items() if k != "steps"} | {"step_count": len(jd.get("steps", []))}
                         for j, jd in c["jobs"].items()}
        return c

    def inspect_workflows(self, file: str = "") -> str:
        """Structured facts about GitHub Actions workflows (triggers, permissions, steps, signals).
        Overview of all workflows by default; pass file=<path> for full step-level detail of one."""
        tracked = self._tracked()
        wf = [f for f in tracked if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", f)]
        others = [f for f in tracked if f in self._OTHER_CI or f.startswith(".circleci/") or f.startswith(".buildkite/")]
        try:
            default_branch = self._git("symbolic-ref", "--short", "-q", "HEAD", timeout=10).strip() or "main"
        except ToolError:
            default_branch = "main"
        extras = {"dependabot_or_renovate": [f for f in tracked if f in (
            ".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".github/renovate.json")],
            "codeowners": [f for f in tracked if f.endswith("CODEOWNERS")],
            "pr_templates": [f for f in tracked if "pull_request_template" in f.lower()],
            "contributing_or_security_docs": [f for f in tracked if re.search(
                r"(^|/)(contributing|security|code_of_conduct)(\.\w+)?$", f, re.I)],
            "issue_templates": [f for f in tracked if f.startswith(".github/ISSUE_TEMPLATE")][:5]}
        if not wf:
            return self._json({"workflow_files": [], "default_branch": default_branch,
                               "note": "no .github/workflows/*.yml files found",
                               "other_ci_configs_present": others, **extras})
        if file:
            norm = file.replace("\\", "/")
            while norm.startswith("./"):
                norm = norm[2:]
            norm = norm.lstrip("/")
            if norm not in wf:
                raise ToolError(f"{file!r} is not a workflow file. Available: {wf}")
            for run_max in (500, 200, 80, 0):
                s = self._json({"default_branch": default_branch, **self._summarize_workflow(norm, default_branch, run_max)})
                if len(s) <= self.max_output:
                    break
            return s
        all_wf = [self._summarize_workflow(f, default_branch, 500) for f in wf]
        summary = {
            "any_test_steps": any(w.get("test_steps") for w in all_wf),
            "any_lint_steps": any(w.get("lint_steps") for w in all_wf),
            "any_build_steps": any(w.get("build_steps") or w.get("uses_build_or_publish_actions") for w in all_wf),
            "any_deploy_or_publish": any(w.get("deploy_or_publish_steps") for w in all_wf)}
        head = {"default_branch": default_branch, "workflow_files": wf, "other_ci_configs_present": others,
                **extras, "summary": summary}
        for run_max in (500, 200, 80, 0):
            ws = all_wf if run_max == 500 else [self._summarize_workflow(f, default_branch, run_max) for f in wf]
            s = self._json({**head, "workflows": ws})
            if len(s) <= self.max_output:
                return s
        s = self._json({**head, "note": "overview only (step detail omitted for size); call inspect_workflows(file=...) "
                        "for one workflow's steps", "workflows": [self._compact_workflow(w) for w in all_wf]})
        if len(s) > self.max_output:
            slim = [{k: w.get(k) for k in ("file", "name", "triggers", "permissions", "test_steps", "lint_steps",
                                           "build_steps", "deploy_or_publish_steps", "signals") if w.get(k) not in (None, [], {})}
                    for w in all_wf]
            s = self._json({**head, "note": "slim overview; call inspect_workflows(file=...) for details", "workflows": slim})
        if len(s) > self.max_output:
            mini = [{"file": w["file"], "name": w.get("name"), "triggers": sorted(w.get("triggers", {})),
                     "test": bool(w.get("test_steps")), "lint": bool(w.get("lint_steps")),
                     "n_signals": len(w.get("signals", []))} for w in all_wf]
            s = self._json({"default_branch": default_branch, "summary": summary, "other_ci_configs_present": others,
                            "note": "minimal overview (many workflows); call inspect_workflows(file=...) for each workflow's "
                                    "signals and steps", "workflows": mini})
        return s

    # ---------------------------------------------------------------- dispatch
    def dispatch(self, name: str, arguments: dict[str, Any] | None) -> str:
        fn = self._registry.get(name)
        if fn is None:
            return f"ERROR: unknown tool '{name}'. Available: {sorted(self._registry)}"
        args = arguments or {}
        if not isinstance(args, dict):
            return "ERROR: tool arguments must be a JSON object"
        if "__parse_error" in args:
            return "ERROR: your tool arguments were not valid JSON; resend them as a JSON object"
        try:
            result = fn(**args)
        except ToolError as e:
            return f"ERROR: {e}"
        except TypeError as e:
            return f"ERROR: bad arguments for {name}: {e}"
        except (ValueError, OSError) as e:
            return f"ERROR: {name} failed: {e}"
        if len(result) > self.max_output:
            result = result[: self.max_output] + f"\n…[output truncated at {self.max_output} chars; narrow the query]"
        return result


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {"name": "list_files",
     "description": "List files tracked in the repository with sizes. Use path (directory prefix) or glob (e.g. '*.yml') to narrow. Start here.",
     "parameters": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Directory prefix to list, e.g. '.github'. Empty = whole repo."},
         "glob": {"type": "string", "description": "Filename glob, e.g. '*.toml' or 'requirements*.txt'."},
         "max_results": {"type": "integer", "description": "Max files to return (default 300)."}}}},
    {"name": "read_file",
     "description": "Read a text file with line numbers (default first 250 lines). Use this to get exact line numbers for evidence. Literal credentials appear as [REDACTED].",
     "parameters": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Repo-relative file path."},
         "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, "required": ["path"]}},
    {"name": "search_code",
     "description": "Case-insensitive regex search over tracked text files; returns path, line, matching line. Use for credentials, absolute paths, risky patterns, usages.",
     "parameters": {"type": "object", "properties": {
         "pattern": {"type": "string", "description": "Python regex."},
         "glob": {"type": "string", "description": "Optional filename glob to restrict the search."},
         "max_results": {"type": "integer"}, "ignore_case": {"type": "boolean"}}, "required": ["pattern"]}},
    {"name": "git_log",
     "description": "Recent commits (hash, date, author, subject). Optional path filter. Shows whether history is a truncated shallow clone.",
     "parameters": {"type": "object", "properties": {
         "max_count": {"type": "integer"}, "path": {"type": "string"}}}},
    {"name": "git_status",
     "description": "Branch, HEAD and working-tree state of the read-only clone.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "git_tracked_ignored",
     "description": "Files committed to git that the repo's own .gitignore rules say should be ignored (tracked generated/temporary/local files).",
     "parameters": {"type": "object", "properties": {"max_results": {"type": "integer"}}}},
    {"name": "inspect_workflows",
     "description": "Parse GitHub Actions workflows into structured facts: triggers, permissions, jobs, steps, test/lint/build/deploy steps, secrets used, plus neutral 'signals' to verify. Also lists other CI configs, dependabot, CODEOWNERS, PR templates. Read the workflow with read_file to confirm line numbers. Pass file='.github/workflows/x.yml' for step-level detail of one workflow when the overview is condensed.",
     "parameters": {"type": "object", "properties": {"file": {"type": "string", "description": "Optional workflow path for full detail."}}}},
]

TOOL_SCHEMAS.extend(EXTRA_SCHEMAS)
