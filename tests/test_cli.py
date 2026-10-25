import json

import pytest

import agent as cli
from repo import RepoError, parse_github_url


def test_url_parsing():
    assert parse_github_url("https://github.com/a/b") == ("a", "b")
    assert parse_github_url("https://github.com/a/b.git") == ("a", "b")
    assert parse_github_url("https://github.com/a/b/tree/main/x") == ("a", "b")
    for bad in ["", "ftp://github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a", "not a url",
                "https://github.com/a/b;rm -rf"]:
        with pytest.raises(RepoError):
            parse_github_url(bad)


def test_cli_invalid_url_exits_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("LLM_API_KEY", "x" * 12)
    assert cli.main(["--repo", "https://example.com/x", "--output", str(tmp_path / "r.json")]) == 2
    assert "Invalid repository URL" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()


def test_cli_missing_key_exits_nonzero(tmp_path, monkeypatch, capsys):
    for k in ("LLM_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **k: None)
    assert cli.main(["--repo", "https://github.com/a/b", "--output", str(tmp_path / "r.json")]) == 2
    assert "No API key" in capsys.readouterr().err


def test_cli_end_to_end_with_fake_llm(tmp_path, repo, monkeypatch):
    from llm import LLMResponse, ToolCall

    class Fake:
        model = "fake"
        step = 0

        def chat(self, system, messages, tools, force_tool=None):
            Fake.step += 1
            plan = [("list_files", {}), ("read_file", {"path": "README.md"}), ("git_log", {}), ("inspect_workflows", {})]
            if Fake.step <= len(plan):
                n, a = plan[Fake.step - 1]
                return LLMResponse(tool_calls=[ToolCall(id=f"c{Fake.step}", name=n, arguments=a)])
            return LLMResponse(tool_calls=[ToolCall(id="s", name="submit_report", arguments={"violations": [
                {"category": "ci_cd", "severity": "high", "file": ".github/workflows/ci.yml", "line": 3,
                 "description": "pull_request_target used", "evidence": "Trigger on line 3",
                 "recommendation": "Use pull_request"}]})])

    monkeypatch.setattr(cli, "make_client", lambda **k: Fake())
    monkeypatch.setattr(cli, "clone_repo", lambda url: repo)
    monkeypatch.setattr(cli, "cleanup", lambda p: None)
    out = tmp_path / "out" / "report.json"
    assert cli.main(["--repo", "https://github.com/o/demo", "--output", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["repository"] == "https://github.com/o/demo"
    assert data["violations"][0]["rule_id"] == "CI-001"
    assert (tmp_path / "out" / "report.json.trace.jsonl").exists()


def test_cli_llm_failure_nonzero(tmp_path, repo, monkeypatch, capsys):
    from llm import LLMError

    class Boom:
        model = "b"

        def chat(self, *a, **k):
            raise LLMError("provider down")

    monkeypatch.setattr(cli, "make_client", lambda **k: Boom())
    monkeypatch.setattr(cli, "clone_repo", lambda url: repo)
    monkeypatch.setattr(cli, "cleanup", lambda p: None)
    out = tmp_path / "r.json"
    assert cli.main(["--repo", "https://github.com/o/demo", "--output", str(out)]) == 4
    assert "provider down" in capsys.readouterr().err and not out.exists()
