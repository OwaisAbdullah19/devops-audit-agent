import json

import pytest

from tools import RepoTools, TOOL_SCHEMAS


@pytest.fixture
def t(repo):
    return RepoTools(repo)


def test_list_files(t):
    d = json.loads(t.list_files())
    paths = {f["path"] for f in d["files"]}
    assert {"README.md", "config.py", ".github/workflows/ci.yml"} <= paths
    assert json.loads(t.list_files(path="src"))["total_matching"] == 1
    assert json.loads(t.list_files(glob="*.py"))["total_matching"] == 2


def test_read_file_numbers_and_redacts(t):
    out = t.read_file("config.py")
    assert "3: API_KEY" in out and "sk-abcdef" not in out and "hunter2" not in out
    assert "lines 2-3" in t.read_file("config.py", start_line=2, end_line=3)


def test_read_file_rejects_escape_binary_missing(t):
    assert t.dispatch("read_file", {"path": "../../etc/passwd"}).startswith("ERROR")
    assert t.dispatch("read_file", {"path": ".git/config"}).startswith("ERROR")
    assert "binary" in t.dispatch("read_file", {"path": "image.bin"})
    assert "not found" in t.dispatch("read_file", {"path": "nope.txt"})


def test_symlink_escape_blocked(t, repo, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("top secret")
    (repo / "link.txt").symlink_to(outside)
    assert t.dispatch("read_file", {"path": "link.txt"}).startswith("ERROR")


def test_search_code(t):
    d = json.loads(t.search_code(r"/home/\w+"))
    assert d["match_count"] == 1 and d["matches"][0]["path"] == "config.py"
    assert d["matches"][0]["line"] == 5
    assert t.dispatch("search_code", {"pattern": "("}).startswith("ERROR: invalid regex")
    dump = t.search_code("password|api_key")
    assert "hunter2" not in dump and "sk-abcdef" not in dump


def test_git_log_redacts_and_reports_authors(t):
    d = json.loads(t.git_log())
    assert d["commits_shown"] == 1 and "ghp_a" not in json.dumps(d)


def test_git_status_and_tracked_ignored(t):
    assert json.loads(t.git_status())["working_tree_clean"] is True
    assert json.loads(t.git_tracked_ignored())["files"] == ["debug.log"]


def test_inspect_workflows_signals(t):
    d = json.loads(t.inspect_workflows())
    sig = " | ".join(d["workflows"][0]["signals"])
    assert "pull_request_target" in sig
    assert "checks out PR head" in sig
    assert "write permissions" in sig
    assert "do not match default branch" in sig
    assert "continue-on-error" in sig
    assert "not pinned" in sig and "someone/custom-action@main" in sig
    assert "interpolated" in sig


def test_inspect_workflows_none(tmp_path):
    import subprocess
    r = tmp_path / "x"
    r.mkdir()
    (r / ".gitlab-ci.yml").write_text("test:\n  script: pytest\n")
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    subprocess.run(["git", "-C", str(r), "add", "."], check=True)
    d = json.loads(RepoTools(r).inspect_workflows())
    assert d["workflow_files"] == [] and ".gitlab-ci.yml" in d["other_ci_configs_present"]


def test_dispatch_unknown_and_bad_args(t):
    assert t.dispatch("rm_rf", {}).startswith("ERROR: unknown tool")
    assert t.dispatch("list_files", {"bogus": 1}).startswith("ERROR: bad arguments")


def test_output_truncated(repo):
    small = RepoTools(repo, max_output=200)
    assert "truncated" in small.dispatch("list_files", {})


def test_schemas_match_registry(t):
    assert {s["name"] for s in TOOL_SCHEMAS} == set(t._registry)


def test_list_files_accepts_dot_and_dot_slash_paths(t):
    whole = json.loads(t.list_files())["total_matching"]
    assert whole > 3
    for p in (".", "./", "/", "./."[:2], " . "):
        assert json.loads(t.list_files(path=p))["total_matching"] == whole, p
    assert json.loads(t.list_files(path="./src"))["total_matching"] == 1
    assert json.loads(t.list_files(path="src/"))["total_matching"] == 1
