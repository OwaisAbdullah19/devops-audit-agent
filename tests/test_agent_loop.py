import json

import pytest

from llm import LLMResponse, ToolCall
from loop import AgentError, AuditAgent
from tools import RepoTools


class ScriptedLLM:
    """Fake provider: decides its next tool call from what the previous tool returned (like a real LLM)."""
    model = "scripted"

    def __init__(self, policy):
        self.policy, self.calls = policy, []

    def chat(self, system, messages, tools, force_tool=None):
        self.calls.append({"n_msgs": len(messages), "tools": [t["name"] for t in tools], "force": force_tool})
        return self.policy(messages, tools)


def _last_tool_result(messages):
    for m in reversed(messages):
        if m["role"] == "tool":
            return m["content"]
    return ""


def call(name, **args):
    return LLMResponse(text=f"calling {name}", tool_calls=[ToolCall(id=f"id{abs(hash((name, json.dumps(args))))}", name=name, arguments=args)])


def test_agent_follows_observations_and_reports(repo):
    submitted = {}

    def policy(messages, tools):
        n = sum(1 for m in messages if m["role"] == "tool")
        if n == 0:
            return call("list_files")
        if n == 1:
            assert "config.py" in _last_tool_result(messages)
            return call("search_code", pattern=r"/home/\w+")        # chosen because config.py was listed
        if n == 2:
            return call("inspect_workflows")
        if n == 3:
            return call("git_tracked_ignored")
        if n == 4:
            return call("read_file", path="config.py", start_line=1, end_line=6)
        viol = [
            {"category": "configuration", "severity": "medium", "file": "config.py", "line": 5,
             "description": "Machine-specific absolute path", "evidence": "Line 5 hardcodes /home/alice/data",
             "recommendation": "Use a relative or configurable path"},
            {"category": "security", "severity": "critical", "file": "config.py", "line": 3,
             "description": "Hardcoded credential", "evidence": "Literal API key assigned (value withheld)",
             "recommendation": "Use env vars"},
            {"category": "repository_hygiene", "severity": "low", "file": "ghost.py", "line": 1,
             "description": "hallucinated", "evidence": "none", "recommendation": "none"},
        ]
        submitted["n"] = submitted.get("n", 0) + 1
        return LLMResponse(tool_calls=[ToolCall(id="s", name="submit_report", arguments={"violations": viol})])

    llm = ScriptedLLM(policy)
    agent = AuditAgent(llm, RepoTools(repo), "https://github.com/o/demo", trace_path=repo.parent / "t.jsonl")
    out = agent.run()
    agent.close()
    # hallucinated finding rejected first, LLM resubmits (same list here), then accepted & dropped
    assert [v["rule_id"] for v in out] == ["SEC-001", "CFG-001"]
    assert out[0]["severity"] == "critical"
    trace = [json.loads(l) for l in (repo.parent / "t.jsonl").read_text().splitlines()]
    assert [e["tool"] for e in trace if e["type"] == "tool_call"] == [
        "list_files", "search_code", "inspect_workflows", "git_tracked_ignored", "read_file"]
    assert "sk-abcdef" not in json.dumps(out)


def test_submit_too_early_is_rejected(repo):
    state = {"i": 0}

    def policy(messages, tools):
        state["i"] += 1
        if state["i"] == 1:
            return LLMResponse(tool_calls=[ToolCall(id="s1", name="submit_report", arguments={"violations": []})])
        if state["i"] <= 5:
            return call("list_files", path="src") if state["i"] == 2 else call("read_file", path="README.md") \
                if state["i"] == 3 else call("git_log") if state["i"] == 4 else call("search_code", pattern="todo")
        return LLMResponse(tool_calls=[ToolCall(id="s2", name="submit_report", arguments={"violations": []})])

    agent = AuditAgent(ScriptedLLM(policy), RepoTools(repo), "u")
    assert agent.run() == []
    assert any("only 0 inspection calls" in m["content"] for m in agent.messages if m["role"] == "tool")


def test_unknown_tool_and_repeat_handled(repo):
    seq = iter([call("delete_everything"), call("list_files"), call("list_files"), call("list_files"),
                call("git_log"), call("read_file", path="README.md")])

    def policy(messages, tools):
        try:
            return next(seq)
        except StopIteration:
            return LLMResponse(tool_calls=[ToolCall(id="s", name="submit_report", arguments={"violations": []})])

    agent = AuditAgent(ScriptedLLM(policy), RepoTools(repo), "u", min_inspections=3)
    agent.run()
    results = [m["content"] for m in agent.messages if m["role"] == "tool"]
    assert any("unknown tool" in r for r in results) and any("exact call twice" in r for r in results)


def test_step_budget_forces_final_report(repo):
    def policy(messages, tools):
        if [t["name"] for t in tools] == ["submit_report"]:
            return LLMResponse(tool_calls=[ToolCall(id="s", name="submit_report", arguments={"violations": []})])
        return call("git_log", max_count=len(messages))

    llm = ScriptedLLM(policy)
    out = AuditAgent(llm, RepoTools(repo), "u", max_steps=6, min_inspections=2).run()
    assert out == [] and llm.calls[-1]["force"] == "submit_report"


def test_no_tool_support_is_fatal(repo):
    llm = ScriptedLLM(lambda m, t: LLMResponse(text="I would look at the files."))
    with pytest.raises(AgentError, match="tool calling"):
        AuditAgent(llm, RepoTools(repo), "u").run()


def test_old_tool_outputs_are_compacted(repo):
    agent = AuditAgent(ScriptedLLM(lambda m, t: None), RepoTools(repo), "u", keep_full=2)
    for k in range(5):
        agent.messages.append({"role": "assistant", "content": None, "tool_calls": []})
        agent.messages.append({"role": "tool", "tool_call_id": str(k), "name": "x", "content": f"R{k}" + "x" * 2000})
    tool = [m["content"] for m in agent._compact() if m["role"] == "tool"]
    assert all("elided" in c for c in tool[:3]) and all("elided" not in c for c in tool[3:])
    assert len(tool[0]) < 500 and len(tool[-1]) > 2000


def test_every_tool_is_described_in_the_prompt():
    from prompts import SYSTEM_PROMPT
    from tools import TOOL_SCHEMAS
    missing = [t["name"] for t in TOOL_SCHEMAS if t["name"] not in SYSTEM_PROMPT and t["name"] not in
               ("read_file", "search_code", "git_log", "git_status")]
    assert missing == []


def test_prompt_separates_core_extras_and_never_report():
    from prompts import SYSTEM_PROMPT
    for token in ("CORE", "EXTRAS", "NEVER report", "at most 3"):
        assert token in SYSTEM_PROMPT


def test_thought_signature_is_echoed_back_to_the_provider(repo):
    sig = {"google": {"thought_signature": "opaque-base64=="}}
    seen = []

    def policy(messages, tools):
        seen.append(messages)
        n = len(seen)
        if n == 1:
            return LLMResponse(tool_calls=[ToolCall(id="c1", name="list_files", arguments={}, extra=sig)])
        return LLMResponse(tool_calls=[ToolCall(id="s", name="submit_report", arguments={"violations": []})])

    AuditAgent(ScriptedLLM(policy), RepoTools(repo), "u", min_inspections=1).run()
    assistant = [m for m in seen[1] if m["role"] == "assistant"][0]
    assert assistant["tool_calls"][0]["extra_content"] == sig
