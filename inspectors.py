"""Additional fact-gathering inspectors, mixed into RepoTools.

Each tool reports FACTS (with file/line where possible) and the equivalents it found, never a verdict.
The LLM decides what is a genuine violation. Nothing here executes code from the inspected repository
(Python files are only parsed with `ast`).
"""
from __future__ import annotations

import ast
import configparser
import json
import os
import re
import subprocess
import sys
import warnings
from collections import Counter
from typing import Any, Iterator

from redact import _ASSIGN, _KEY_BEGIN, _KEY_END, _TOKEN_PATTERNS, _URL_CRED, _assign_sub, redact

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

_GENERATED = re.compile(r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|uv\.lock|"
                        r"Pipfile\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock|pdm\.lock)$|\.lock$|-lock\.(json|ya?ml)$|"
                        r"\.min\.(js|css)$|\.map$|\.svg$")
_VERSION_LIKE = re.compile(r"[\^~<>=v]*\d+\.\d+(\.[\w*-]+)*")
_TEST_OR_EXAMPLE = re.compile(r"(^|/)(docs?|examples?|samples?|tests?|fixtures?|__tests__|testdata|spec|mocks?)(/|$)|"
                              r"\.(md|rst|example|sample|template|dist)$|(^|/)test_[^/]*$|_test\.[a-z]+$", re.I)
_CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs", ".c", ".cpp",
             ".h", ".swift", ".scala"}
_CAP = 12


def _t(s: Any, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def _more(items: list, n: int = _CAP) -> dict[str, Any]:
    return {"items": items[:n], "total": len(items), **({"truncated": True} if len(items) > n else {})}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def classify_spec(spec: str) -> str:
    s = re.sub(r"--hash=\S+", "", spec.split(";")[0].split(" #")[0]).strip().strip("()")
    if not s:
        return "unpinned"
    if s.startswith("@") or "://" in s:
        return "url"
    if "===" in s or re.search(r"(?<![<>=!~])==", s):
        return "wildcard" if "*" in s else "pinned"
    if "~=" in s or re.match(r"^[\^~]\s*\d", s):
        return "compatible"
    if re.fullmatch(r"\d[\w.]*", s):
        return "pinned"
    lower, upper = bool(re.search(r"(>=|>)", s)), "<" in s
    if lower and upper:
        return "bounded"
    if lower:
        return "lower_bound_only"
    return "upper_only" if upper else "other"


class Inspectors:
    # these attributes/methods are provided by RepoTools
    root: Any

    # ------------------------------------------------------------- shared utils
    def _text(self, rel: str, max_bytes: int = 1_000_000) -> str | None:
        p = self.root / rel
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > max_bytes:
                return None
            data = p.read_bytes()
        except OSError:
            return None
        if b"\x00" in data[:4096]:
            return None
        return data.decode("utf-8", errors="replace")

    def _iter_text(self, skip_generated: bool = True, max_files: int = 3000) -> Iterator[tuple[str, str]]:
        n = 0
        for rel in self._tracked():
            if skip_generated and _GENERATED.search(rel):
                continue
            txt = self._text(rel)
            if txt is None:
                continue
            n += 1
            if n > max_files:
                return
            yield rel, txt

    def _git_ok(self, *args: str) -> bool:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
        try:
            r = subprocess.run(["git", "-C", str(self.root), "-c", "safe.directory=*", *args],
                               capture_output=True, timeout=15, env=env)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return r.returncode == 0

    def _toml(self, rel: str) -> dict | None:
        txt = self._text(rel)
        if txt is None or tomllib is None:
            return None
        try:
            return tomllib.loads(txt)
        except Exception:  # noqa: BLE001 - any parse failure just means "unparsed"
            return None

    # ------------------------------------------------------------ scan_secrets
    _SENSITIVE_FILES = [
        (re.compile(r"(^|/)\.env(\.(?!example|sample|template|dist|defaults?)[\w.-]+)?$", re.I), "dotenv file"),
        (re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$", re.I), "key/certificate file"),
        (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), "ssh private key file"),
        (re.compile(r"(^|/)(credentials?|secrets?)\.(json|ya?ml|toml|ini|txt)$", re.I), "credentials file"),
        (re.compile(r"(^|/)\.(npmrc|pypirc|netrc|htpasswd|git-credentials)$"), "credential config file"),
        (re.compile(r"\.tfstate(\.backup)?$|\.tfvars$"), "terraform state/vars"),
        (re.compile(r"(^|/)(kubeconfig|\.kube/config)$"), "kubeconfig"),
    ]

    def scan_secrets(self, max_results: int = 40) -> str:
        """Locate likely hardcoded credentials, private keys and committed secret files. Values are never shown."""
        max_results = max(1, min(int(max_results), 100))
        sensitive = []
        for rel in self._tracked():
            for rx, kind in self._SENSITIVE_FILES:
                if rx.search(rel):
                    txt = self._text(rel) or ""
                    rec: dict[str, Any] = {"path": rel, "kind": kind,
                                           "likely_test_or_example": bool(_TEST_OR_EXAMPLE.search(rel))}
                    if _KEY_BEGIN.search(txt):
                        rec["contains_private_key_block"] = True
                    if kind == "dotenv file":
                        rec["literal_secret_like_lines"] = sum(
                            1 for ln in txt.splitlines() if redact(ln) != ln)
                    sensitive.append(rec)
                    break
        hits: list[dict[str, Any]] = []
        for rel, txt in self._iter_text():
            ext = os.path.splitext(rel)[1].lower()
            code_file = ext in _CODE_EXT
            in_key = False
            for n, line in enumerate(txt.split("\n"), 1):
                if len(line) > 2000:
                    continue
                kind = name = None
                if in_key:
                    in_key = not _KEY_END.search(line)
                    continue
                if _KEY_BEGIN.search(line):
                    kind, in_key = "private key block", not _KEY_END.search(line)
                if kind is None:
                    for label, pat in _TOKEN_PATTERNS:
                        if pat.search(line):
                            kind = f"known token format ({label})"
                            break
                if kind is None:
                    m = _URL_CRED.search(line)
                    if m and not m.group(2).startswith(("$", "{", "<", "%")):
                        kind = "credentials embedded in URL"
                if kind is None:
                    for m in _ASSIGN.finditer(line):
                        quoted = m.group("sep").endswith(("'", '"'))
                        if code_file and not quoted:
                            continue
                        if "/" in m.group("key") or _VERSION_LIKE.fullmatch(m.group("val")):
                            continue  # package names like js-tokens / version specs are not credentials
                        if _assign_sub(m) != m.group(0):
                            kind, name = "literal value assigned to credential-like name", m.group("key")
                            break
                if kind:
                    hits.append({"path": rel, "line": n, "kind": kind, **({"name": name} if name else {}),
                                 "likely_test_or_example": bool(_TEST_OR_EXAMPLE.search(rel)),
                                 "text": _t(redact(line.strip()), 120)})
        hits.sort(key=lambda h: (h["likely_test_or_example"], h["path"], h["line"]))
        return self._json({
            "note": "Values are masked. Judge placeholders/test fixtures from path and context; env-var reads are not hits.",
            "sensitive_files": sensitive[:30], "hit_count": len(hits),
            "files_with_hits": len({h["path"] for h in hits}), "truncated": len(hits) > max_results,
            "hits": hits[:max_results]})

    # ---------------------------------------------------- inspect_dependencies
    _LOCKFILES = ["poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "requirements.lock", "package-lock.json",
                  "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "go.sum", "Cargo.lock",
                  "Gemfile.lock", "composer.lock", "gradle.lockfile", "packages.lock.json"]
    _OTHER_MANIFESTS = ["go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile",
                        "composer.json", "environment.yml", "conda.yml", "packages.config"]

    @staticmethod
    def _summ(entries: dict[str, str]) -> dict[str, Any]:
        kinds = {n: classify_spec(s) for n, s in entries.items()}
        c = Counter(kinds.values())
        weak = [n for n, k in kinds.items() if k in ("unpinned", "wildcard", "lower_bound_only", "other", "upper_only")]
        return {"count": len(entries), "by_kind": dict(c), "weak_or_unpinned": weak[:25],
                "unpinned": [n for n, k in kinds.items() if k == "unpinned"][:25]}

    @staticmethod
    def _pep508(items: list) -> dict[str, str]:
        out = {}
        for it in items or []:
            if isinstance(it, str):
                m = _REQ.match(it)
                if m:
                    out[_norm(m.group(1))] = m.group(2).strip()
        return out

    def _parse_requirements(self, rel: str) -> dict[str, Any]:
        txt = self._text(rel) or ""
        entries: dict[str, str] = {}
        includes, vcs, hashes = [], 0, "--hash=" in txt
        for raw in re.sub(r"\\\n", " ", txt).splitlines():
            line = raw.split(" #")[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "-c", "--requirement", "--constraint")):
                includes.append(line.split(None, 1)[-1][:60])
                continue
            if line.startswith("-e") or "://" in line.split(";")[0].split("@")[0] or line.startswith(("git+", "http")):
                vcs += 1
                continue
            if line.startswith("-"):
                continue
            m = _REQ.match(line)
            if m:
                entries[_norm(m.group(1))] = m.group(2).strip()
        return {"entries": entries, "includes": includes, "vcs_or_editable": vcs, "uses_hashes": hashes}

    def inspect_dependencies(self) -> str:
        """Dependency manifests, version-constraint quality, lockfiles and cross-manifest conflicts."""
        tracked = self._tracked()
        sources: dict[str, dict[str, str]] = {}
        manifests: list[dict[str, Any]] = []
        for rel in tracked:
            base = os.path.basename(rel)
            if re.fullmatch(r"(requirements|constraints)[\w.-]*\.(txt|in)|[\w.-]*requirements[\w.-]*\.(txt|in)", base):
                p = self._parse_requirements(rel)
                sources[rel] = p["entries"]
                manifests.append({"file": rel, "type": "requirements", **self._summ(p["entries"]),
                                  "includes": p["includes"], "vcs_or_editable": p["vcs_or_editable"],
                                  "uses_hashes": p["uses_hashes"]})
            elif base == "pyproject.toml":
                d = self._toml(rel)
                if d is None:
                    manifests.append({"file": rel, "type": "pyproject", "parse_error_or_unsupported": True})
                    continue
                proj, tool = d.get("project", {}), d.get("tool", {})
                entries = self._pep508(proj.get("dependencies", []))
                optional = {g: self._pep508(v) for g, v in (proj.get("optional-dependencies") or {}).items()}
                groups = {g: self._pep508([x for x in v if isinstance(x, str)])
                          for g, v in (d.get("dependency-groups") or {}).items()}
                poetry = tool.get("poetry", {})
                pd = {n: (v if isinstance(v, str) else (v.get("version", "") if isinstance(v, dict) else ""))
                      for n, v in (poetry.get("dependencies") or {}).items() if n.lower() != "python"}
                for gname, g in (poetry.get("group") or {}).items():
                    for n, v in (g.get("dependencies") or {}).items():
                        pd[n] = v if isinstance(v, str) else (v.get("version", "") if isinstance(v, dict) else "")
                pd = {_norm(k): ("" if v == "*" else v) for k, v in pd.items()}
                allm = {**entries, **pd}
                sources[rel] = allm
                rec = {"file": rel, "type": "pyproject", "name": proj.get("name") or poetry.get("name"),
                       "build_backend": (d.get("build-system") or {}).get("build-backend"),
                       "requires_python": proj.get("requires-python") or (poetry.get("dependencies") or {}).get("python"),
                       "has_project_table": bool(proj), "uses_poetry": bool(poetry),
                       "runtime": self._summ(entries) if entries else None,
                       "poetry": self._summ(pd) if pd else None,
                       "optional_groups": {g: self._summ(v) for g, v in {**optional, **groups}.items()} or None}
                manifests.append({k: v for k, v in rec.items() if v not in (None, {})})
            elif base == "Pipfile":
                d = self._toml(rel) or {}
                ent = {_norm(n): ("" if (v == "*") else (v if isinstance(v, str) else v.get("version", "")
                                                          if isinstance(v, dict) else ""))
                       for n, v in {**(d.get("packages") or {}), **(d.get("dev-packages") or {})}.items()}
                sources[rel] = ent
                manifests.append({"file": rel, "type": "Pipfile", **self._summ(ent)})
            elif base == "setup.py":
                txt = self._text(rel) or ""
                m = re.search(r"install_requires\s*=\s*\[(.*?)\]", txt, re.S)
                items = re.findall(r"""["']([^"']+)["']""", m.group(1)) if m else []
                ent = self._pep508(items)
                sources[rel] = ent
                manifests.append({"file": rel, "type": "setup.py", **self._summ(ent), "install_requires_found": bool(m)})
            elif base == "setup.cfg":
                cp = configparser.ConfigParser(interpolation=None)
                try:
                    cp.read_string(self._text(rel) or "")
                    items = [x.strip() for x in cp.get("options", "install_requires", fallback="").splitlines() if x.strip()]
                except configparser.Error:
                    items = []
                if items:
                    ent = self._pep508(items)
                    sources[rel] = ent
                    manifests.append({"file": rel, "type": "setup.cfg", **self._summ(ent)})
            elif base == "package.json":
                try:
                    d = json.loads(self._text(rel) or "{}")
                except ValueError:
                    manifests.append({"file": rel, "type": "package.json", "parse_error": True})
                    continue
                if not isinstance(d, dict):
                    continue
                deps = {**(d.get("dependencies") or {}), **(d.get("devDependencies") or {})}
                weak = [n for n, v in deps.items() if str(v).strip() in ("", "*", "latest", "x") or "://" in str(v)
                        or str(v).startswith(("git", "github:"))]
                manifests.append({"file": rel, "type": "package.json", "dependencies": len(d.get("dependencies") or {}),
                                  "devDependencies": len(d.get("devDependencies") or {}),
                                  "weak_constraints": weak[:25], "scripts": sorted((d.get("scripts") or {}))[:20],
                                  "private": d.get("private"), "has_main_or_bin": bool(d.get("main") or d.get("bin")),
                                  "packageManager": d.get("packageManager"), "engines": d.get("engines")})
        # cross-manifest consistency (python)
        names: dict[str, dict[str, str]] = {}
        for src, ent in sources.items():
            for n, s in ent.items():
                names.setdefault(n, {})[src] = re.sub(r"\s+", "", s)
        def _is_conflict(specs: dict[str, str]) -> bool:
            vals = set(specs.values())
            if len(vals) < 2:
                return False
            # an unconstrained dependency next to an exact pin elsewhere is the normal "manifest + pinned file" pattern
            if "" in vals and all(v == "" or v.startswith("==") for v in vals):
                return False
            return True

        conflicts = [{"package": n, "specs": v} for n, v in names.items() if _is_conflict(v)][:20]
        lockfiles = [f for f in tracked if os.path.basename(f) in self._LOCKFILES]
        other = [f for f in tracked if os.path.basename(f) in self._OTHER_MANIFESTS]
        req_all = [m for m in manifests if m["type"] == "requirements"]
        fully_pinned = bool(req_all) and all(m["count"] and m["by_kind"].get("pinned", 0) == m["count"] for m in req_all)
        pyfiles = sum(1 for f in tracked if f.endswith(".py"))
        out = {
            "manifests": manifests, "lockfiles_present": lockfiles, "other_ecosystem_manifests": other,
            "python_files_tracked": pyfiles,
            "requirements_fully_pinned_with_equals": fully_pinned,
            "conflicting_specs_across_manifests": conflicts,
            "has_dockerfile": any(re.search(r"(^|/)(Dockerfile|Containerfile)", f) for f in tracked),
            "note": ("Lockfile equivalents: poetry.lock/uv.lock/Pipfile.lock/pdm.lock, fully '=='-pinned requirements "
                     "(optionally with hashes), package-lock/yarn/pnpm locks. Libraries often legitimately omit lockfiles."),
        }
        if not manifests and not other:
            out["note"] = "no dependency manifests found. " + out["note"]
        return self._json(out)

    # ---------------------------------------------------- inspect_dockerfiles
    _DOCKERFILE = re.compile(r"(^|/)(Dockerfile|Containerfile)([._-][\w.-]+)?$|\.Dockerfile$")
    _COMPOSE = re.compile(r"(^|/)(docker-)?compose([.-][\w.-]*)?\.ya?ml$")

    def _dockerfile_facts(self, rel: str) -> dict[str, Any]:
        raw = (self._text(rel) or "").split("\n")
        instrs: list[tuple[int, str, str]] = []
        buf, start = "", 0
        for i, line in enumerate(raw, 1):
            s = line.strip()
            if not buf and (not s or s.startswith("#")):
                continue
            if not buf:
                start = i
            if s.endswith("\\"):
                buf += s[:-1] + " "
                continue
            full = (buf + s).strip()
            buf = ""
            m = re.match(r"^([A-Za-z]+)\s+(.*)$", full)
            if m:
                instrs.append((start, m.group(1).upper(), m.group(2)))
            elif full:
                instrs.append((start, full.upper(), ""))
        bases, stages, signals = [], 0, []
        user_in_stage, healthcheck, stage_names = None, False, set()
        for ln, ins, arg in instrs:
            if ins == "FROM":
                stages += 1
                user_in_stage = None
                parts = [p for p in arg.split() if not p.startswith("--")]
                img = parts[0] if parts else ""
                if len(parts) >= 3 and parts[1].lower() == "as":
                    stage_names.add(parts[2].lower())
                if img.lower() in stage_names or img.lower() == "scratch":
                    continue
                if "@sha256:" in img:
                    kind = "digest-pinned"
                elif "$" in img:
                    kind = "build-arg"
                elif ":" not in img.rsplit("/", 1)[-1]:
                    kind = "no tag (implicit latest)"
                    signals.append({"line": ln, "issue": f"base image '{img}' has no tag (implicit latest)"})
                elif img.endswith(":latest"):
                    kind = "latest"
                    signals.append({"line": ln, "issue": f"base image '{img}' uses the latest tag"})
                else:
                    kind = "tagged"
                bases.append({"line": ln, "image": img, "pin": kind})
            elif ins == "USER":
                user_in_stage = arg.split()[0] if arg.split() else None
            elif ins == "HEALTHCHECK":
                healthcheck = True
            elif ins == "ADD" and any(re.match(r"https?://", t) for t in arg.split()):
                signals.append({"line": ln, "issue": "ADD from a remote URL (unverified download)"})
            elif ins in ("ENV", "ARG", "LABEL") and redact(arg) != arg:
                signals.append({"line": ln, "issue": f"{ins} sets a secret-like literal value (value masked)"})
            elif ins == "COPY" and re.search(r"(^|\s)(\S*\.env\S*|\S*\.pem|\S*id_rsa\S*)(\s|$)", arg):
                signals.append({"line": ln, "issue": f"COPY of a likely secret file: {_t(arg, 80)}"})
            if ins == "RUN":
                if re.search(r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh", arg):
                    signals.append({"line": ln, "issue": "RUN pipes a remote script into a shell"})
                if re.search(r"chmod\s+(-R\s+)?777", arg):
                    signals.append({"line": ln, "issue": "RUN chmod 777"})
                if re.search(r"\bsudo\b", arg):
                    signals.append({"line": ln, "issue": "RUN uses sudo"})
                if re.search(r"pip3? install", arg) and not re.search(r"==|-r\s|requirements|\.\s*$|-e\s|--no-deps|\.\[", arg):
                    signals.append({"line": ln, "issue": f"pip install without pinned versions: {_t(arg, 90)}"})
        if instrs and not user_in_stage or (user_in_stage or "").lower() in ("root", "0", "0:0"):
            signals.append({"line": None, "issue": "final stage never switches to a non-root USER"})
        return {"file": rel, "stages": stages, "base_images": bases, "final_user": user_in_stage,
                "has_healthcheck": healthcheck, "signals": signals[:25]}

    def inspect_dockerfiles(self) -> str:
        """Dockerfile and docker-compose facts: base image pinning, USER, remote ADD, secrets, privileged services."""
        tracked = self._tracked()
        dfs = [f for f in tracked if self._DOCKERFILE.search(f)]
        comps = [f for f in tracked if self._COMPOSE.search(f)]
        ci_text = " ".join(self._text(f) or "" for f in tracked if re.match(r"\.github/workflows/[^/]+\.ya?ml$", f))
        ci_build = bool(re.search(r"docker(\s+buildx)?\s+build|docker/build-push-action|buildah|kaniko", ci_text))
        if not dfs and not comps:
            return self._json({"dockerfiles": [], "note": "no Dockerfile/Containerfile or compose file tracked"})
        comp_out = []
        for rel in comps:
            sig = []
            for n, line in enumerate((self._text(rel) or "").split("\n"), 1):
                s = line.strip()
                if re.match(r"image:\s*\S+", s):
                    img = s.split(":", 1)[1].strip().strip("\"'")
                    if img.endswith(":latest") or (":" not in img.rsplit("/", 1)[-1] and "$" not in img):
                        sig.append({"line": n, "issue": f"image '{img}' has no tag or uses latest"})
                if re.match(r"privileged:\s*true", s):
                    sig.append({"line": n, "issue": "privileged: true"})
                if re.match(r"network_mode:\s*[\"']?host", s):
                    sig.append({"line": n, "issue": "network_mode: host"})
                if "docker.sock" in s:
                    sig.append({"line": n, "issue": "mounts the Docker socket"})
                if re.match(r"-?\s*[\w.-]*(password|secret|token|key)[\w.-]*\s*[:=]", s, re.I) and redact(s) != s:
                    sig.append({"line": n, "issue": "secret-like literal in compose environment (value masked)"})
            comp_out.append({"file": rel, "signals": sig[:20]})
        return self._json({
            "dockerfiles": [self._dockerfile_facts(f) for f in dfs[:8]], "compose_files": comp_out[:5],
            "dockerignore_present": any(os.path.basename(f) == ".dockerignore" for f in tracked),
            "ci_mentions_image_build": ci_build})

    # ------------------------------------------------------ scan_config_smells
    _MACHINE_PATHS = [
        (re.compile(r"/home/([A-Za-z0-9_.\-]+)/"), "unix home path"),
        (re.compile(r"/Users/([A-Za-z0-9_.\- ]+)/"), "macOS home path"),
        (re.compile(r"[A-Za-z]:\\{1,2}Users\\{1,2}([^\\/\s\"']+)", re.I), "Windows user path"),
        (re.compile(r"(?<![\w/])[A-Za-z]:\\{1,2}(?!Users)[\w$ .\-]+\\{1,2}[\w$ .\-\\]+"), "Windows absolute path"),
        (re.compile(r"(?<![\w])/mnt/[a-z]/"), "WSL drive path"),
    ]
    _PLACEHOLDER_USERS = {"user", "username", "you", "name", "yourname", "example", "runner", "circleci", "vscode",
                          "node", "app", "appuser", "ubuntu", "vsts", "me", "<user>", "your-username", "jenkins"}
    _HOSTS = re.compile(r"""(?ix)(database_url|db_url|db_host|redis_url|redis_host|mongo\w*|broker_url|sqlalchemy_database_uri|
        \bhost\b|server|endpoint|api_url|base_url)["']?\s*[:=]\s*["']?(\w+://)?(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)""")
    _URLHOST = re.compile(r"""["'](?:postgres(?:ql)?|mysql|mongodb|redis|amqp|https?)://(?:[^/@"'\s]+@)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)""", re.I)
    _DEBUG = re.compile(r"(?i)(\bDEBUG\s*[:=]\s*[\"']?(true|1)\b|app\.run\([^)]*debug\s*=\s*True|FLASK_ENV\s*[:=]\s*[\"']?development|"
                        r"NODE_ENV\s*[:=]\s*[\"']?development)")
    _LOCAL_FILES = re.compile(r"(^|/)(\.idea/|\.vscode/(?!extensions\.json)|[^/]+\.iml$|local_settings\.py$|settings_local\.py$|"
                              r"config\.local\.[\w.]+$|\.env\.local$|\.DS_Store$|Thumbs\.db$|\.python-version$|\.nvmrc$)")

    def scan_config_smells(self, max_results: int = 50) -> str:
        """Machine-specific paths, hardcoded hosts, debug flags, committed local settings, env-config layout."""
        tracked = self._tracked()
        hits: list[dict[str, Any]] = []
        for rel, txt in self._iter_text():
            if rel.endswith((".md", ".rst")):
                continue
            for n, line in enumerate(txt.split("\n"), 1):
                if len(line) > 1500:
                    continue
                for rx, kind in self._MACHINE_PATHS:
                    m = rx.search(line)
                    if m:
                        user = (m.group(1) if m.groups() else "").lower()
                        hits.append({"path": rel, "line": n, "kind": kind,
                                     "likely_placeholder": user in self._PLACEHOLDER_USERS,
                                     "likely_test_or_example": bool(_TEST_OR_EXAMPLE.search(rel)),
                                     "text": _t(redact(line.strip()), 140)})
                        break
                else:
                    kind = None
                    if self._HOSTS.search(line) or self._URLHOST.search(line):
                        kind = "hardcoded local/private host"
                    elif self._DEBUG.search(line):
                        kind = "debug/development flag set in committed file"
                    if kind:
                        hits.append({"path": rel, "line": n, "kind": kind, "likely_placeholder": False,
                                     "likely_test_or_example": bool(_TEST_OR_EXAMPLE.search(rel)),
                                     "text": _t(redact(line.strip()), 140)})
        hits.sort(key=lambda h: (h["likely_placeholder"], h["likely_test_or_example"], h["path"], h["line"]))
        local = [f for f in tracked if self._LOCAL_FILES.search(f)]
        env_variants = [f for f in tracked if re.search(
            r"(^|/)(\.env[\w.-]*|[\w.-]*(dev|development|staging|stage|prod|production|test|local)[\w.-]*\.(ya?ml|json|toml|ini|cfg|env|py))$", f)
            and not f.startswith(("tests/", "test/"))]
        env_example = [f for f in tracked if re.search(r"\.env\.(example|sample|template|dist)$|^\.env\.example$", f)]
        return self._json({
            "hit_count": len(hits), "truncated": len(hits) > max_results, "hits": hits[:max_results],
            "committed_local_or_ide_files": local[:25],
            "env_specific_config_files": env_variants[:25], "env_example_files": env_example,
            "note": "Docs/tests/examples and placeholder users (user, runner, ...) are usually not defects."})

    # ----------------------------------------------------------- inspect_hygiene
    _JUNK = [
        ("python bytecode/caches", re.compile(r"(^|/)__pycache__/|\.py[co]$")),
        ("node_modules", re.compile(r"(^|/)node_modules/")),
        ("virtualenv", re.compile(r"^(\.venv|venv)/|(^|/)site-packages/")),
        ("build/dist output", re.compile(r"^(dist|build|target)/|\.egg-info/")),
        ("test/coverage/tool caches", re.compile(r"(^|/)(\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|htmlcov|\.ipynb_checkpoints|\.nox)/|(^|/)\.coverage$|(^|/)coverage\.xml$")),
        ("logs/temp/backup files", re.compile(r"\.(log|tmp|bak|orig|rej|swp|swo)$|~$|(^|/)\.DS_Store$|(^|/)Thumbs\.db$")),
        ("local databases", re.compile(r"\.(sqlite3?|db)$")),
        ("IDE settings", re.compile(r"(^|/)(\.idea|\.vscode)/")),
        ("compiled binaries/archives", re.compile(r"\.(class|jar|war|o|so|dll|exe|pyd|zip|tar|tgz|gz|7z)$")),
        ("terraform local state", re.compile(r"(^|/)\.terraform/")),
        ("env file", re.compile(r"(^|/)\.env$")),
    ]
    _BACKUP_NAME = re.compile(r"(?i)(^|/)[^/]*(_old|_backup|_copy|-copy|-old|\.old| copy|\(\d+\))(\.\w+)?$")
    _KNOWN_BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".otf", ".eot",
                         ".pdf", ".webp", ".mp4", ".mp3", ".wav", ".bmp", ".icns"}
    _STACK_PROBES = {
        "general": [(".env", [[".env"]])],
        "python": [("__pycache__", [["__pycache__/a.pyc"]]), ("virtualenv dir", [[".venv/a", "venv/a", "env/a"]]),
                   ("dist/ and build/", [["dist/a"], ["build/a"]]), (".pytest_cache", [[".pytest_cache/a"]])],
        "node": [("node_modules", [["node_modules/a"]]), ("dist/build", [["dist/a", "build/a"]])],
        "java": [("target/", [["target/a.class"]])],
        "rust": [("target/", [["target/a"]])],
        "dotnet": [("bin/obj", [["bin/a"], ["obj/a"]])],
    }

    def _stacks(self) -> list[str]:
        t = self._tracked()
        base = {os.path.basename(f) for f in t}
        s = []
        if any(f.endswith(".py") for f in t) or base & {"pyproject.toml", "setup.py", "requirements.txt", "Pipfile"}:
            s.append("python")
        if "package.json" in base:
            s.append("node")
        if base & {"pom.xml", "build.gradle", "build.gradle.kts"}:
            s.append("java")
        if "Cargo.toml" in base:
            s.append("rust")
        if any(f.endswith((".csproj", ".sln")) for f in t):
            s.append("dotnet")
        return s

    def inspect_hygiene(self) -> str:
        """README/.gitignore quality, tracked junk by category, large/binary files, conflict markers, stray files."""
        tracked = self._tracked()
        root_files = [f for f in tracked if "/" not in f]
        readmes = [f for f in tracked if re.search(r"(^|/)readme(\.\w+)?$", f, re.I)]
        rd = []
        for f in readmes[:5]:
            txt = self._text(f) or ""
            lines = [ln for ln in txt.splitlines() if ln.strip()]
            rd.append({"path": f, "bytes": len(txt.encode()), "non_empty_lines": len(lines),
                       "headings": sum(1 for ln in lines if ln.lstrip().startswith("#")),
                       "looks_like_stub": len(lines) <= 3 or len(txt) < 80})
        gi_root = ".gitignore" in root_files
        gi_txt = self._text(".gitignore") if gi_root else None
        stacks = self._stacks()
        probes = []
        for stack in ["general", *stacks]:
            for label, groups in self._STACK_PROBES.get(stack, []):
                missing = [g for g in groups if not any(self._git_ok("check-ignore", "-q", "--no-index", "--", p) for p in g)]
                if missing:
                    probes.append({"stack": stack, "expected_ignored": label, "not_ignored_examples": [g[0] for g in missing]})
        junk: dict[str, list[str]] = {}
        for f in tracked:
            for label, rx in self._JUNK:
                if rx.search(f):
                    junk.setdefault(label, []).append(f)
        junk_out = {k: {"count": len(v), "examples": v[:5]} for k, v in junk.items()}
        sizes = []
        for f in tracked:
            try:
                sizes.append((f, (self.root / f).lstat().st_size))
            except OSError:
                continue
        large = sorted([(f, s) for f, s in sizes if s > 1_000_000], key=lambda x: -x[1])[:10]
        binaries, empties = [], []
        for f, s in sizes[:4000]:
            ext = os.path.splitext(f)[1].lower()
            if s == 0 and os.path.basename(f) not in ("__init__.py", ".gitkeep", "py.typed", ".keep", ".nojekyll"):
                empties.append(f)
            elif ext not in self._KNOWN_BINARY_EXT and ext not in (".py", ".js", ".md", ".txt", ".json", ".yml", ".yaml") and s:
                try:
                    with open(self.root / f, "rb") as fh:
                        if b"\x00" in fh.read(2048):
                            binaries.append(f)
                except OSError:
                    pass
        markers = []
        for rel, txt in self._iter_text():
            if rel.endswith((".md", ".rst", ".txt")):
                continue
            if re.search(r"^<{7}( |$)", txt, re.M) and re.search(r"^>{7}( |$)", txt, re.M):
                markers.append({"path": rel, "line": txt[:txt.index("<<<<<<<")].count("\n") + 1})
        stray = [f for f in tracked if self._BACKUP_NAME.search(f)]
        return self._json({
            "stacks_detected": stacks, "readme_files": rd or "none found at any path",
            "root_files": root_files[:40],
            "gitignore": {"root_present": gi_root, "root_lines": len((gi_txt or "").splitlines()) if gi_root else 0,
                          "nested": [f for f in tracked if f.endswith("/.gitignore")][:10]},
            "weak_signal_gitignore_gaps": probes,
            "tracked_junk_by_category": junk_out,
            "large_files_over_1MB": [{"path": f, "bytes": s} for f, s in large],
            "unexpected_binary_files": binaries[:15], "empty_files": empties[:15],
            "merge_conflict_markers": markers[:10], "backup_or_copy_named_files": stray[:15],
            "note": ("tracked_junk may be intentional (vendored/committed dist, fixtures). weak_signal_gitignore_gaps alone is NOT enough: "
                     "many healthy repos omit some patterns. Treat .gitignore as unsuitable only if it is missing/near-empty/clearly "
                     "wrong for the stack, or if junk it should have ignored is actually tracked.")})

    # ------------------------------------------------ python parsing utilities
    def _py_files(self, limit: int = 400) -> list[str]:
        return [f for f in self._tracked() if f.endswith(".py")
                and not re.search(r"(^|/)(site-packages|node_modules|\.venv|venv)/", f)][:limit]

    @staticmethod
    def _parse_py(txt: str) -> tuple[ast.AST | None, tuple[int | None, str] | None]:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                return ast.parse(txt), None
        except SyntaxError as e:
            return None, (e.lineno, e.msg)
        except (RecursionError, ValueError, MemoryError) as e:
            return None, (None, f"unparseable: {type(e).__name__}")

    # ---------------------------------------------- inspect_tests_and_quality
    def inspect_tests_and_quality(self) -> str:
        """Test files/health (empty, skipped, assert-less tests), test runners and lint/format configuration."""
        tracked = self._tracked()
        base = {os.path.basename(f): f for f in tracked}
        test_files = [f for f in tracked if re.search(
            r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]*\.py$|_test\.(py|go)$|\.(test|spec)\.(js|jsx|ts|tsx)$|(^|/)src/test/", f)
            and not f.endswith((".md", ".rst", ".json", ".txt", ".yml", ".yaml"))]
        py_tests = [f for f in test_files if f.endswith(".py")]
        total = skipped = empty = no_assert = trivial = 0
        problems, syntax = [], []
        for f in py_tests[:200]:
            tree, err = self._parse_py(self._text(f) or "")
            if err:
                syntax.append({"path": f, "line": err[0], "error": err[1]})
                continue
            top_level = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
                top_level += [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for node in top_level:
                if node.name.startswith("test"):
                    total += 1
                    decos = " ".join(ast.unparse(d) for d in node.decorator_list)
                    body = [b for b in node.body if not (isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None), ast.Constant))]
                    is_empty = all(isinstance(b, ast.Pass) for b in body) or not body
                    has_assert = any(isinstance(n, ast.Assert) for n in ast.walk(node)) or any(
                        isinstance(n, ast.Call) and (getattr(n.func, "attr", "") .startswith(("assert", "raises", "fail", "approx"))
                                                      or getattr(n.func, "id", "") in ("fail", "raises")) for n in ast.walk(node))
                    triv = any(isinstance(n, ast.Assert) and isinstance(n.test, ast.Constant) for n in ast.walk(node))
                    sk = bool(re.search(r"skip(?!if)", decos))
                    skipped += sk
                    empty += is_empty
                    trivial += triv
                    no_assert += (not has_assert and not is_empty)
                    if sk or is_empty or triv or (not has_assert):
                        problems.append({"path": f, "line": node.lineno, "test": node.name,
                                         "issue": "skipped" if sk else "empty body" if is_empty else
                                         "constant assert" if triv else "no assertions"})
        cfg = {}
        pp = self._toml("pyproject.toml") if "pyproject.toml" in base else None
        tool = (pp or {}).get("tool", {})
        cfg_text = {n: (self._text(base[n]) or "") for n in ("setup.cfg", "tox.ini") if n in base}
        runners = [n for n in ("pytest.ini", "tox.ini", "noxfile.py", "conftest.py", ".coveragerc", "jest.config.js", "jest.config.ts",
                               "vitest.config.ts", "vitest.config.js", "karma.conf.js") if n in base]
        if "pytest" in tool:
            runners.append("pyproject [tool.pytest]")
        if "[tool:pytest]" in cfg_text.get("setup.cfg", ""):
            runners.append("setup.cfg [tool:pytest]")
        targets = []
        if "Makefile" in base:
            targets = sorted(set(re.findall(r"^([A-Za-z_][\w.-]*):(?!=)", self._text(base["Makefile"]) or "", re.M)))[:30]
        pkg = {}
        if "package.json" in base:
            try:
                pkg = json.loads(self._text(base["package.json"]) or "{}").get("scripts") or {}
            except ValueError:
                pkg = {}
        quality = {
            "ruff": bool({"ruff.toml", ".ruff.toml"} & set(base)) or "ruff" in tool,
            "flake8": ".flake8" in base or "[flake8]" in cfg_text.get("setup.cfg", "") + cfg_text.get("tox.ini", ""),
            "pylint": ".pylintrc" in base or "pylint" in tool or "pylintrc" in base,
            "black": "black" in tool, "isort": "isort" in tool or ".isort.cfg" in base,
            "mypy": "mypy.ini" in base or "mypy" in tool or "pyright" in tool or "pyrightconfig.json" in base,
            "pre_commit": ".pre-commit-config.yaml" in base,
            "eslint": any(re.match(r"(\.eslintrc|eslint\.config)", n) for n in base),
            "prettier": any(n.startswith((".prettierrc", "prettier.config")) for n in base),
            "editorconfig": ".editorconfig" in base,
            "golangci": any(n.startswith(".golangci") for n in base), "rubocop": ".rubocop.yml" in base,
            "biome": "biome.json" in base,
        }
        hooks = []
        if ".pre-commit-config.yaml" in base:
            hooks = sorted(set(re.findall(r"^\s*-\s*id:\s*([\w.-]+)", self._text(base[".pre-commit-config.yaml"]) or "", re.M)))[:20]
        lintish = [k for k in targets if re.search(r"lint|format|fmt|check|style", k)]
        testish = [k for k in targets if re.search(r"test|check", k)]
        scripts_q = {k: v for k, v in pkg.items() if re.search(r"lint|format|test|build", k)}
        return self._json({
            "test_files": {"count": len(test_files), "python_test_files": len(py_tests), "examples": test_files[:8]},
            "python_test_stats": {"test_functions": total, "skipped": skipped, "empty_body": empty,
                                  "no_assertions": no_assert, "constant_assert": trivial},
            "test_problems": problems[:15], "test_files_with_syntax_errors": syntax[:10],
            "parser_python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "test_runner_config": runners, "makefile_targets": targets, "makefile_test_targets": testish,
            "package_json_scripts": scripts_q,
            "lint_format_config_present": {k: v for k, v in quality.items() if v},
            "any_lint_or_format_config": any(quality.values()), "pre_commit_hooks": hooks,
            "makefile_lint_targets": lintish,
            "note": ("Linting may also run only in CI (see inspect_workflows lint_steps) or via tox/nox/Makefile/pre-commit. "
                     "Absence of config is only a finding if none of these exist.")})

    # --------------------------------------------------------- analyze_python
    def analyze_python(self) -> str:
        """Parse Python files (never executed): syntax errors and visible maintainability/safety problems."""
        files = self._py_files()
        syntax, bare, swallowed, star, evals, shell, longf, mut, debug, big = [], [], [], [], [], [], [], [], [], []
        parsed = 0
        for f in files:
            txt = self._text(f)
            if txt is None:
                continue
            tree, err = self._parse_py(txt)
            if err:
                syntax.append({"path": f, "line": err[0], "error": err[1]})
                continue
            parsed += 1
            nlines = txt.count("\n") + 1
            if nlines > 1000:
                big.append({"path": f, "lines": nlines})
            test = bool(re.search(r"(^|/)(tests?|test_[^/]*)", f))
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        bare.append({"path": f, "line": node.lineno})
                    elif all(isinstance(b, ast.Pass) for b in node.body) and ast.unparse(node.type) in ("Exception", "BaseException"):
                        swallowed.append({"path": f, "line": node.lineno})
                elif isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
                    star.append({"path": f, "line": node.lineno, "module": node.module})
                elif isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name) and fn.id in ("eval", "exec") and not test:
                        evals.append({"path": f, "line": node.lineno, "call": fn.id})
                    if isinstance(fn, ast.Name) and fn.id == "breakpoint":
                        debug.append({"path": f, "line": node.lineno, "what": "breakpoint()"})
                    if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                        shell.append({"path": f, "line": node.lineno})
                elif isinstance(node, ast.Import) and any(a.name in ("pdb", "ipdb") for a in node.names) and not test:
                    debug.append({"path": f, "line": node.lineno, "what": "import pdb"})
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if (getattr(node, "end_lineno", node.lineno) - node.lineno) > 100 and not test:
                        longf.append({"path": f, "line": node.lineno, "function": node.name,
                                      "lines": node.end_lineno - node.lineno + 1})
                    if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in node.args.defaults + [x for x in node.args.kw_defaults if x]):
                        mut.append({"path": f, "line": node.lineno, "function": node.name})
        return self._json({
            "python_files_parsed": parsed, "python_files_total": len(files),
            "parser_python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "syntax_errors": syntax[:15],
            "syntax_error_caveat": ("Parsed with the Python version above. Errors may come from NEWER syntax (match, except*, "
                                    "'except A, B:' in 3.14, type statements). Confirm with read_file and the repo's requires-python "
                                    "before reporting." if syntax else None), "bare_except": _more(bare), "except_Exception_pass": _more(swallowed),
            "wildcard_imports": _more(star), "eval_exec_calls": _more(evals),
            "subprocess_shell_true": _more(shell), "very_long_functions_over_100_lines": _more(longf),
            "files_over_1000_lines": _more(big), "mutable_default_args": _more(mut), "leftover_debugger": _more(debug),
            "note": "Facts from static parsing only. Report a maintainability finding only if clearly significant."})


EXTRA_SCHEMAS: list[dict[str, Any]] = [
    {"name": "scan_secrets",
     "description": "Find likely hardcoded credentials (known token formats, private keys, literal values assigned to password/token/secret-like names, credentials in URLs) and committed secret files (.env, *.pem, credentials.json...). Values are masked. Returns path/line/kind; judge test fixtures and placeholders from context, then read_file to confirm.",
     "parameters": {"type": "object", "properties": {"max_results": {"type": "integer"}}}},
    {"name": "inspect_dependencies",
     "description": "Dependency facts: all manifests (requirements*, pyproject incl. poetry, Pipfile, setup.py/cfg, package.json), constraint quality (pinned/bounded/unpinned), lockfiles present, fully-pinned requirements, and conflicting specs across manifests.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "inspect_dockerfiles",
     "description": "Dockerfile/compose facts with line numbers: base image pinning (latest/no tag), non-root USER, remote ADD, curl|sh, secrets in ENV/ARG, privileged/host-network services, .dockerignore, and whether CI builds the image.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "scan_config_smells",
     "description": "Machine-specific absolute paths (/home/x, C:\\Users\\x), hardcoded localhost/private hosts, debug flags, committed IDE/local settings files, and per-environment config layout (.env.example, dev/prod files).",
     "parameters": {"type": "object", "properties": {"max_results": {"type": "integer"}}}},
    {"name": "inspect_hygiene",
     "description": "Repository hygiene facts: README presence/stub, .gitignore presence and whether stack-appropriate paths are actually ignored, tracked junk by category (pycache, node_modules, dist, logs, db, IDE, .env), large/binary/empty files, merge-conflict markers, backup-named files.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "inspect_tests_and_quality",
     "description": "Testing and lint/format facts: test file counts, empty/skipped/assert-less/constant-assert tests, test runner config, Makefile/package.json scripts, and which linters/formatters/pre-commit hooks are configured.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "analyze_python",
     "description": "Parse all Python files with ast (no execution): syntax errors, bare except, swallowed exceptions, wildcard imports, eval/exec, subprocess shell=True, very long functions, huge files, mutable default args, leftover debuggers.",
     "parameters": {"type": "object", "properties": {}}},
]
