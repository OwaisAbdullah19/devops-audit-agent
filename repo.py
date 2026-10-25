"""Safe acquisition of the target repository (read-only, never executed)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

_GITHUB_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?(?:/.*)?$"
)
CLONE_DEPTH = 300


class RepoError(Exception):
    pass


def parse_github_url(url: str) -> tuple[str, str]:
    m = _GITHUB_RE.match((url or "").strip())
    if not m:
        raise RepoError(
            f"Invalid repository URL: {url!r}. Expected https://github.com/<owner>/<repo>"
        )
    return m.group(1), m.group(2)


def clone_repo(url: str, timeout: int = 180) -> Path:
    """Shallow-clone a public GitHub repo into a fresh temp dir. Nothing is executed."""
    owner, name = parse_github_url(url)
    if shutil.which("git") is None:
        raise RepoError("git is not installed or not on PATH")
    base = Path(tempfile.mkdtemp(prefix="audit-"))
    dest = base / name
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo", "GCM_INTERACTIVE": "never"}
    cmd = [
        "git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never",
        "-c", "protocol.file.allow=never", "-c", "core.fsmonitor=false",
        "clone", "--depth", str(CLONE_DEPTH), "--single-branch", "--no-tags",
        "--no-recurse-submodules", "--quiet", f"https://github.com/{owner}/{name}.git", str(dest),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, errors="replace")
    except subprocess.TimeoutExpired:
        cleanup(base)
        raise RepoError(f"Timed out cloning {url} after {timeout}s")
    if r.returncode != 0:
        cleanup(base)
        msg = (r.stderr or "").strip().splitlines()[-1:] or ["unknown error"]
        raise RepoError(f"Could not clone {url} (is it a public repository?): {msg[0]}")
    return dest


def cleanup(path: Path) -> None:
    root = path if path.parent == Path(tempfile.gettempdir()) else path.parent
    if root.name.startswith("audit-"):
        shutil.rmtree(root, ignore_errors=True)
