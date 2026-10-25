import json
import subprocess

import pytest

from leads import extract_leads, is_covered, open_leads, review_message
from llm import LLMResponse, ToolCall
from loop import AuditAgent
from tools import RepoTools


def _w(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


@pytest.fixture
def proj(tmp_path):
    r = tmp_path / "p"
    _w(r, "README.md", "# P\n\nSome project with enough text to not be a stub.\n\n## Use\n\nRun it.\n")
    _w(r, ".gitignore", "__pycache__/\n*.pyc\n.venv/\n.env\n")
    _w(r, "app.py", "def f():\n    return 1\n")
    _w(r, "requirements.txt", "requests\n")
    _w(r, "Dockerfile", "FROM python:3.12\nCOPY . .\nCMD [\"python\", \"app.py\"]\n")
    _w(r, ".github/workflows/release.yml", "name: R\non:\n  push:\n    branches: [main]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                                          "    steps:\n      - uses: actions/checkout@v4\n      - run: twine upload dist/*\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    subprocess.run(["git", "-C", str(r), "add", "."], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)
    return RepoTools(r)


def _leads(t):
    out = []
    for n in ("inspect_workflows", "inspect_dockerfiles", "inspect_hygiene", "inspect_tests_and_quality", "inspect_dependencies"):
        out += extract_leads(n, t.dispatch(n, {}))
    return out


def test_leads_extracted_from_tool_output(proj):
    texts = " | ".join(l["text"] for l in _leads(proj))
    assert "not gated" in texts and "non-root USER" in texts and "no linter/formatter" in texts


def test_covered_and_uncovered_leads(proj):
    leads = _leads(proj)
    viol = [{"category": "build_release", "file": ".github/workflows/release.yml", "line": 9,
             "description": "Release job publishes with twine and is not gated by any test step",
             "evidence": "publish job runs twine upload and is not gated", "recommendation": "gate it"}]
    open_ = open_leads(leads, viol)
    kinds = {(l["kind"], l["text"][:20]) for l in open_}
    assert not any("not gated" in l["text"] for l in open_)          # covered by the finding
    assert any("non-root USER" in l["text"] for l in open_)          # still open
    assert any(l["kind"] == "quality" for l in open_)


def test_file_level_lead_covered_by_any_finding_on_that_file():
    lead = {"tool": "scan_secrets", "kind": "secrets", "file": ".env", "line": None, "text": "committed dotenv file", "context": None}
    v = [{"file": ".env", "line": 1, "description": "x", "evidence": "y", "recommendation": "z", "category": "security"}]
    assert is_covered(lead, v) and not is_covered(lead, [])


def test_review_message_lists_leads(proj):
    msg = review_message(open_leads(_leads(proj), []))
    assert msg.startswith("SELF-REVIEW") and "COMPLETE final list" in msg and "adding nothing" in msg


class Scripted:
    model = "s"

    def __init__(self, submits, auto_decisions=True):
        self.submits, self.i, self.seen, self.auto = submits, 0, [], auto_decisions

    def chat(self, system, messages, tools, force_tool=None):
        import re
        self.i += 1
        self.seen.append(messages)
        if self.i == 1:
            names = ["inspect_workflows", "inspect_dockerfiles", "inspect_tests_and_quality", "inspect_dependencies"]
            return LLMResponse(tool_calls=[ToolCall(id=f"c{k}", name=n, arguments={}) for k, n in enumerate(names)])
        item = self.submits[min(self.i - 2, len(self.submits) - 1)]
        args = dict(item) if isinstance(item, dict) else {"violations": item}
        review = [m["content"] for m in messages if m["role"] == "tool" and m["content"].startswith("SELF-REVIEW")]
        if review and self.auto and "lead_decisions" not in args:
            n = len(re.findall(r"^\d+\. \[", review[-1], re.M))
            args["lead_decisions"] = [{"lead": k, "decision": "skip", "reason": "acceptable"} for k in range(1, n + 1)]
        return LLMResponse(tool_calls=[ToolCall(id=f"s{self.i}", name="submit_report", arguments=args)])


RELEASE = {"category": "build_release", "severity": "high", "file": ".github/workflows/release.yml", "line": 9,
           "description": "Publishes to PyPI on every push to main without any test gate",
           "evidence": "twine upload step in job publish, not gated by any test step", "recommendation": "Gate on tags/tests"}
ROOT = {"category": "build_release", "severity": "medium", "file": "Dockerfile", "line": 0,
        "description": "Container never switches to a non-root USER", "evidence": "Dockerfile has no USER instruction",
        "recommendation": "Add a non-root USER"}


def test_review_round_happens_once_and_second_submission_wins(proj):
    llm = Scripted([[RELEASE], [RELEASE, ROOT]])
    agent = AuditAgent(llm, proj, "u", min_inspections=1)
    out = agent.run()
    assert {v["file"] for v in out} == {".github/workflows/release.yml", "Dockerfile"}
    reviews = [m["content"] for m in agent.messages if m["role"] == "tool" and m["content"].startswith("SELF-REVIEW")]
    assert len(reviews) == 1 and "non-root USER" in reviews[0]


def test_review_not_repeated_if_second_submission_is_still_incomplete(proj):
    llm = Scripted([[RELEASE], [RELEASE]])
    out = AuditAgent(llm, proj, "u", min_inspections=1).run()
    assert len(out) == 1 and llm.i == 3          # tools, first submit (-> review), second submit accepted: no third round


def test_review_can_be_disabled(proj):
    llm = Scripted([[RELEASE]])
    out = AuditAgent(llm, proj, "u", min_inspections=1, review=False).run()
    assert len(out) == 1 and llm.i == 2


def test_empty_report_on_leadless_repo_needs_no_review(tmp_path):
    r = tmp_path / "h"
    _w(r, "README.md", "# H\n\nA healthy project with enough text in it.\n\n## Use\n\nRun.\n")
    _w(r, "pyproject.toml", '[project]\nname="h"\nversion="1"\ndependencies=["requests==2.31.0"]\n[tool.ruff]\nline-length=100\n')
    _w(r, "uv.lock", "x")
    _w(r, "tests/test_h.py", "def test_ok():\n    assert 1 + 1 == 2\n")
    _w(r, ".gitignore", "__pycache__/\n.env\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    subprocess.run(["git", "-C", str(r), "add", "."], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)
    llm = Scripted([[]])
    assert AuditAgent(llm, RepoTools(r), "u", min_inspections=1).run() == [] and llm.i == 2


def test_same_line_finding_about_something_else_does_not_cover_a_secrets_lead():
    lead = {"tool": "scan_secrets", "kind": "secrets", "file": "app/config.py", "line": 6,
            "text": "credentials embedded in URL", "context": 'DATABASE_URL = "postgresql://admin:[REDACTED]@localhost/demo"'}
    host = [{"file": "app/config.py", "line": 6, "category": "configuration", "description": "Hardcodes local development database host",
             "evidence": "line 6 sets the host to localhost", "recommendation": "Load from environment"}]
    cred = [{"file": "app/config.py", "line": 6, "category": "security", "description": "Password embedded in the database URL",
             "evidence": "credentials in DATABASE_URL", "recommendation": "Use a secret store"}]
    assert not is_covered(lead, host)
    assert is_covered(lead, cred)


def test_missing_lead_decisions_are_requested_once_then_accepted(proj):
    llm = Scripted([[RELEASE], [RELEASE, ROOT]], auto_decisions=False)
    agent = AuditAgent(llm, proj, "u", min_inspections=1)
    out = agent.run()
    msgs = [m["content"] for m in agent.messages if m["role"] == "tool"]
    assert sum("Missing lead_decisions" in m for m in msgs) == 1
    assert len(out) == 2 and llm.i == 4      # tools, submit (-> review), submit w/o decisions (-> reminder), submit (accepted)


def test_lead_decisions_are_traced(proj, tmp_path):
    llm = Scripted([[RELEASE], {"violations": [RELEASE, ROOT], "lead_decisions": [
        {"lead": k, "decision": "add" if k == 1 else "skip", "reason": "because"} for k in range(1, 12)]}])
    agent = AuditAgent(llm, proj, "u", min_inspections=1, trace_path=tmp_path / "t.jsonl")
    agent.run()
    agent.close()
    events = [json.loads(x) for x in (tmp_path / "t.jsonl").read_text().splitlines()]
    dec = [e for e in events if e["type"] == "lead_decisions"]
    assert dec and dec[0]["decisions"][0]["decision"] == "add" and dec[0]["decisions"][1]["reason"] == "because"
