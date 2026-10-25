import json
import subprocess

import pytest

from tools import RepoTools


def _commit(root):
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-f", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)


def _w(root, rel, text, mode="w"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    (p.write_bytes if mode == "wb" else p.write_text)(text)


@pytest.fixture
def bad(tmp_path):
    r = tmp_path / "bad"
    _w(r, ".gitignore", "*.pyc\n")
    _w(r, "__pycache__/x.cpython-312.pyc", b"\x00\x01", "wb")
    _w(r, ".env", "DB_PASSWORD=hunter2hunter2\nDEBUG=true\n")
    _w(r, ".idea/workspace.xml", "<x/>")
    _w(r, "big.dat", b"\x00" * 1_200_000, "wb")
    _w(r, "merge.py", "<<<<<<< HEAD\na = 1\n=======\na = 2\n>>>>>>> branch\n")
    _w(r, "broken.py", "def f(:\n    pass\n")
    _w(r, "config_old.py", "X = 1\n")
    _w(r, "empty.txt", "")
    _w(r, "requirements.txt", "requests\nflask==2.0.1\nnumpy>=1.20\n")
    _w(r, "pyproject.toml", '[project]\nname="p"\nversion="1"\ndependencies=["requests>=2.31","flask==3.0.0"]\n')
    _w(r, "Dockerfile", "FROM python:latest\nADD https://x.com/a.tgz /tmp/\nRUN curl http://x.sh | sh\n"
                        "ENV API_TOKEN=abcd1234efgh5678\nRUN pip install flask\nCMD [\"python\"]\n")
    _w(r, "docker-compose.yml", "services:\n  a:\n    image: redis\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/s\n")
    _w(r, "tests/test_a.py", "import pytest\n\ndef test_empty():\n    pass\n\n@pytest.mark.skip\ndef test_skip():\n    assert 1 == 1\n\n"
                             "def test_noassert():\n    x = 1\n\ndef test_const():\n    assert True\n")
    _w(r, "config.py", 'DB = "postgres://localhost/db"\nPATH = "/home/alice/app"\nWIN = "C:\\\\Users\\\\bob\\\\data"\n'
                       'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n')
    _w(r, "src/app.py", "from os import *\n\ndef f():\n    try:\n        eval('1')\n    except:\n        pass\n\n"
                        "def g(x=[]):\n    import subprocess\n    subprocess.run('ls', shell=True)\n")
    _commit(r)
    return RepoTools(r)


@pytest.fixture
def good(tmp_path):
    r = tmp_path / "good"
    _w(r, "README.md", "# Project\n\nA well documented project.\n\n## Install\n\npip install .\n\n## Usage\n\nRun it.\n")
    _w(r, ".gitignore", "__pycache__/\n*.pyc\n.venv/\n.env\ndist/\nbuild/\n.pytest_cache/\n")
    _w(r, "pyproject.toml", '[project]\nname="p"\nversion="1"\ndependencies=["requests==2.31.0"]\n[tool.ruff]\nline-length=100\n')
    _w(r, "uv.lock", "version = 1\n")
    _w(r, "src/app.py", "import os\n\n\ndef f():\n    return os.environ['HOME']\n")
    _w(r, "tests/test_app.py", "from src.app import f\n\n\ndef test_f():\n    assert f()\n")
    _w(r, ".github/workflows/ci.yml", "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\npermissions:\n  contents: read\n"
                                      "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
                                      "      - run: ruff check .\n      - run: pytest\n")
    _w(r, "Dockerfile", "FROM python:3.12-slim\nUSER app\nCMD [\"python\"]\n")
    _commit(r)
    subprocess.run(["git", "-C", str(r), "branch", "-M", "main"], check=True)
    return RepoTools(r)


def j(t, name, **kw):
    out = t.dispatch(name, kw)
    assert not out.startswith("ERROR"), out
    return json.loads(out)


def test_scan_secrets_finds_and_masks(bad):
    raw = bad.dispatch("scan_secrets", {})
    assert "hunter2" not in raw and "sk-abcdef" not in raw
    d = json.loads(raw)
    assert any(f["path"] == ".env" and f["kind"] == "dotenv file" for f in d["sensitive_files"])
    kinds = {(h["path"], h["line"]) for h in d["hits"]}
    assert (".env", 1) in kinds and ("config.py", 4) in kinds and ("Dockerfile", 4) in kinds


def test_inspect_dependencies(bad):
    d = j(bad, "inspect_dependencies")
    req = next(m for m in d["manifests"] if m["type"] == "requirements")
    assert "requests" in req["unpinned"] and req["by_kind"]["pinned"] == 1
    assert d["lockfiles_present"] == [] and d["requirements_fully_pinned_with_equals"] is False
    assert any(c["package"] == "flask" for c in d["conflicting_specs_across_manifests"])


def test_inspect_dependencies_poetry_and_node(tmp_path):
    r = tmp_path / "p"
    _w(r, "pyproject.toml", '[tool.poetry]\nname="x"\n[tool.poetry.dependencies]\npython="^3.10"\nrequests="*"\nflask="^3.0"\n')
    _w(r, "package.json", '{"dependencies":{"left-pad":"*","ok":"^1.0.0"},"scripts":{"test":"jest"}}')
    _w(r, "poetry.lock", "")
    _commit(r)
    d = j(RepoTools(r), "inspect_dependencies")
    poetry = next(m for m in d["manifests"] if m["type"] == "pyproject")["poetry"]
    assert poetry["unpinned"] == ["requests"] and poetry["by_kind"]["compatible"] == 1
    node = next(m for m in d["manifests"] if m["type"] == "package.json")
    assert node["weak_constraints"] == ["left-pad"] and "poetry.lock" in d["lockfiles_present"]


def test_inspect_dockerfiles(bad):
    d = j(bad, "inspect_dockerfiles")
    issues = " | ".join(s["issue"] for s in d["dockerfiles"][0]["signals"])
    assert "latest" in issues and "remote URL" in issues and "pipes a remote script" in issues
    assert "secret-like literal" in issues and "non-root" in issues and "pip install" in issues
    lines = {s["line"] for s in d["dockerfiles"][0]["signals"]}
    assert {1, 2, 3, 4} <= lines
    comp = " | ".join(s["issue"] for s in d["compose_files"][0]["signals"])
    assert "privileged" in comp and "Docker socket" in comp and "no tag" in comp
    assert "API_TOKEN" not in bad.dispatch("inspect_dockerfiles", {}) or "abcd1234" not in bad.dispatch("inspect_dockerfiles", {})


def test_scan_config_smells(bad):
    d = j(bad, "scan_config_smells")
    kinds = {(h["path"], h["kind"]) for h in d["hits"]}
    assert ("config.py", "unix home path") in kinds and ("config.py", "Windows user path") in kinds
    assert ("config.py", "hardcoded local/private host") in kinds and (".env", "debug/development flag set in committed file") in kinds
    assert ".idea/workspace.xml" in d["committed_local_or_ide_files"]


def test_inspect_hygiene(bad):
    d = j(bad, "inspect_hygiene")
    assert d["readme_files"] == "none found at any path"
    assert "python bytecode/caches" in d["tracked_junk_by_category"] and "IDE settings" in d["tracked_junk_by_category"]
    assert d["large_files_over_1MB"][0]["path"] == "big.dat"
    assert d["merge_conflict_markers"][0] == {"path": "merge.py", "line": 1}
    assert "config_old.py" in d["backup_or_copy_named_files"] and "empty.txt" in d["empty_files"]
    assert any(p["expected_ignored"] == "virtualenv dir" for p in d["weak_signal_gitignore_gaps"])


def test_inspect_tests_and_quality(bad):
    d = j(bad, "inspect_tests_and_quality")
    s = d["python_test_stats"]
    assert s["test_functions"] == 4 and s["empty_body"] == 1 and s["skipped"] == 1
    assert s["no_assertions"] == 1 and s["constant_assert"] == 1
    assert d["any_lint_or_format_config"] is False
    assert {p["issue"] for p in d["test_problems"]} >= {"empty body", "skipped", "no assertions", "constant assert"}


def test_analyze_python(bad):
    d = j(bad, "analyze_python")
    assert {e["path"] for e in d["syntax_errors"]} >= {"broken.py", "merge.py"}
    assert d["syntax_error_caveat"]
    assert d["bare_except"]["items"] == [{"path": "src/app.py", "line": 6}]
    assert d["wildcard_imports"]["total"] == 1 and d["eval_exec_calls"]["total"] == 1
    assert d["subprocess_shell_true"]["total"] == 1 and d["mutable_default_args"]["total"] == 1


def test_healthy_repo_produces_no_findings(good):
    assert j(good, "scan_secrets")["hit_count"] == 0 and j(good, "scan_secrets")["sensitive_files"] == []
    h = j(good, "inspect_hygiene")
    assert h["tracked_junk_by_category"] == {} and h["gitignore"]["root_present"] and h["weak_signal_gitignore_gaps"] == []
    assert h["readme_files"][0]["looks_like_stub"] is False and h["merge_conflict_markers"] == []
    d = j(good, "inspect_dependencies")
    assert d["lockfiles_present"] == ["uv.lock"] and d["conflicting_specs_across_manifests"] == []
    q = j(good, "inspect_tests_and_quality")
    assert q["any_lint_or_format_config"] and q["test_problems"] == []
    a = j(good, "analyze_python")
    assert a["syntax_errors"] == [] and a["bare_except"]["total"] == 0
    assert j(good, "scan_config_smells")["hit_count"] == 0
    df = j(good, "inspect_dockerfiles")["dockerfiles"][0]
    assert df["signals"] == [] and df["final_user"] == "app"
    wf = j(good, "inspect_workflows")
    assert wf["summary"]["any_test_steps"] and wf["summary"]["any_lint_steps"] and wf["workflows"][0]["signals"] == []


def test_workflow_file_drilldown_and_new_signals(tmp_path):
    r = tmp_path / "w"
    _w(r, ".github/workflows/rel.yml", "name: rel\non:\n  push:\n  issue_comment:\n  workflow_dispatch:\n    inputs: {x: {}}\n"
                                      "jobs:\n  pub:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
                                      "      - run: echo ${{ inputs.x }}\n      - run: twine upload dist/*\n      - run: gh pr merge --auto\n")
    _commit(r)
    t = RepoTools(r)
    sig = " | ".join(j(t, "inspect_workflows", file="./.github/workflows/rel.yml")["signals"])
    assert "issue_comment" in sig and "interpolated" in sig and "not gated" in sig
    assert "every push" in sig and "auto-merge" in sig
    assert t.dispatch("inspect_workflows", {"file": "x.yml"}).startswith("ERROR")
