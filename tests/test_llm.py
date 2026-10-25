import pytest

import llm
from llm import AnthropicClient, LLMError, OpenAICompatClient, make_client


def test_provider_resolution_and_aliases():
    c = make_client(env={"LLM_PROVIDER": "grok", "LLM_API_KEY": "k" * 10})
    assert isinstance(c, OpenAICompatClient) and "x.ai" in c.base_url
    c = make_client(env={"LLM_PROVIDER": "claude", "ANTHROPIC_API_KEY": "k" * 10})
    assert isinstance(c, AnthropicClient)
    c = make_client(env={"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "k" * 10, "LLM_MODEL": "m"})
    assert c.model == "m"
    assert make_client(env={"LLM_PROVIDER": "ollama"}).api_key == ""


def test_config_errors():
    with pytest.raises(LLMError, match="No API key"):
        make_client(env={"LLM_PROVIDER": "groq"})
    with pytest.raises(LLMError, match="Unknown"):
        make_client(env={"LLM_PROVIDER": "nope", "LLM_API_KEY": "x" * 10})
    with pytest.raises(LLMError, match="LLM_BASE_URL"):
        make_client(env={"LLM_PROVIDER": "custom", "LLM_API_KEY": "x" * 10, "LLM_MODEL": "m"})


class FakeResp:
    def __init__(self, status=200, data=None, text="", headers=None):
        self.status_code, self._d, self.text, self.headers = status, data, text, headers or {}

    def json(self):
        return self._d


def _client(responses, monkeypatch, cls=OpenAICompatClient):
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    c = cls(api_key="secretkey123", model="m", base_url="http://x", max_retries=3)
    seq = iter(responses)
    c.session.post = lambda *a, **k: next(seq)
    return c


def test_openai_parse_tool_call(monkeypatch):
    data = {"choices": [{"message": {"content": "hi", "tool_calls": [
        {"id": "c1", "function": {"name": "list_files", "arguments": '{"path": "src"}'}}]}}]}
    r = _client([FakeResp(data=data)], monkeypatch).chat("sys", [], [])
    assert r.text == "hi" and r.tool_calls[0].arguments == {"path": "src"}


def test_bad_json_arguments_flagged(monkeypatch):
    data = {"choices": [{"message": {"tool_calls": [{"id": "c", "function": {"name": "x", "arguments": "{oops"}}]}}]}
    r = _client([FakeResp(data=data)], monkeypatch).chat("s", [], [])
    assert "__parse_error" in r.tool_calls[0].arguments


def test_retry_on_429_then_success(monkeypatch):
    ok = {"choices": [{"message": {"content": "ok"}}]}
    c = _client([FakeResp(429, text="slow down"), FakeResp(503, text="x"), FakeResp(data=ok)], monkeypatch)
    assert c.chat("s", [], []).text == "ok"


def test_auth_error_fatal_and_key_never_leaked(monkeypatch):
    c = _client([FakeResp(401, text="bad key secretkey123")], monkeypatch)
    with pytest.raises(LLMError) as e:
        c.chat("s", [], [])
    assert "Authentication" in str(e.value) and "secretkey123" not in str(e.value)


def test_retries_exhausted(monkeypatch):
    c = _client([FakeResp(500, text="boom")] * 4, monkeypatch)
    with pytest.raises(LLMError, match="after 4 attempts"):
        c.chat("s", [], [])


def test_forced_tool_choice_falls_back(monkeypatch):
    ok = {"choices": [{"message": {"content": "fine"}}]}
    c = _client([FakeResp(400, text="tool_choice unsupported"), FakeResp(data=ok)], monkeypatch)
    assert c.chat("s", [], [{"name": "t", "description": "d", "parameters": {}}], force_tool="t").text == "fine"


def test_anthropic_message_conversion_and_parse(monkeypatch):
    msgs = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "thinking", "tool_calls": [
            {"id": "a", "type": "function", "function": {"name": "list_files", "arguments": "{}"}},
            {"id": "b", "type": "function", "function": {"name": "git_log", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "a", "name": "list_files", "content": "r1"},
        {"role": "tool", "tool_call_id": "b", "name": "git_log", "content": "r2"},
        {"role": "user", "content": "continue"},
    ]
    out = AnthropicClient.convert_messages(msgs)
    assert [m["role"] for m in out] == ["user", "assistant", "user"]
    assert [b["type"] for b in out[2]["content"]] == ["tool_result", "tool_result", "text"]
    assert [b["type"] for b in out[1]["content"]] == ["text", "tool_use", "tool_use"]
    data = {"content": [{"type": "text", "text": "t"}, {"type": "tool_use", "id": "z", "name": "git_log", "input": {"max_count": 3}}]}
    r = _client([FakeResp(data=data)], monkeypatch, AnthropicClient).chat("s", msgs, [{"name": "git_log", "description": "d", "parameters": {}}])
    assert r.tool_calls[0].arguments == {"max_count": 3}


def test_gemini_thought_signature_is_captured(monkeypatch):
    sig = {"google": {"thought_signature": "opaque-base64=="}}
    data = {"choices": [{"message": {"tool_calls": [
        {"id": "c1", "function": {"name": "list_files", "arguments": "{}"}, "extra_content": sig},
        {"id": "c2", "function": {"name": "git_log", "arguments": "{}"}}]}}]}
    r = _client([FakeResp(data=data)], monkeypatch).chat("s", [], [])
    assert r.tool_calls[0].extra == sig and r.tool_calls[1].extra is None


def test_reasoning_effort_sent_and_falls_back_on_400(monkeypatch):
    monkeypatch.setenv("LLM_REASONING_EFFORT", "medium")
    sent = []
    ok = {"choices": [{"message": {"content": "ok"}}]}
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    c = OpenAICompatClient(api_key="k" * 10, model="m", base_url="http://x", max_retries=1)
    seq = iter([FakeResp(400, text="unknown field reasoning_effort"), FakeResp(data=ok)])

    def post(url, headers, json, timeout):
        sent.append(json)
        return next(seq)

    c.session.post = post
    assert c.chat("s", [], [{"name": "t", "description": "d", "parameters": {}}]).text == "ok"
    assert sent[0]["reasoning_effort"] == "medium" and "reasoning_effort" not in sent[1]


def test_no_reasoning_effort_by_default(monkeypatch):
    monkeypatch.delenv("LLM_REASONING_EFFORT", raising=False)
    c = OpenAICompatClient(api_key="k" * 10, model="m", base_url="http://x")
    assert "reasoning_effort" not in c._payload("s", [], [], None)
    assert c._payload("s", [], [], None, "high")["reasoning_effort"] == "high"
