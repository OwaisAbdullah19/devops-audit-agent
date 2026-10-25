"""Provider-agnostic LLM layer.

The agent loop speaks one internal format (OpenAI-style chat messages + tool calls).
Two adapters cover essentially every provider:

* OpenAICompatClient - Gemini, Groq, xAI Grok, OpenAI, OpenRouter, Mistral, DeepSeek, Ollama, any custom endpoint
* AnthropicClient    - Claude

Plain HTTPS via `requests`; no provider SDK and no agent framework.
"""
from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from redact import redact, register_secret


class LLMError(Exception):
    """Fatal LLM problem (bad key, bad model, retries exhausted)."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    # Provider-specific extras that must be echoed back unchanged (e.g. Gemini 3 thought signatures)
    extra: dict[str, Any] | None = None


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


# name -> (adapter, base_url, default_model, [api key env vars])
PROVIDERS: dict[str, dict[str, Any]] = {
    "gemini": {"adapter": "openai", "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
               "model": "gemini-3.5-flash-lite", "keys": ["GEMINI_API_KEY", "GOOGLE_API_KEY"]},
    "groq": {"adapter": "openai", "base_url": "https://api.groq.com/openai/v1",
             "model": "openai/gpt-oss-120b", "keys": ["GROQ_API_KEY"]},
    "xai": {"adapter": "openai", "base_url": "https://api.x.ai/v1",
            "model": "grok-4", "keys": ["XAI_API_KEY", "GROK_API_KEY"]},
    "openai": {"adapter": "openai", "base_url": "https://api.openai.com/v1",
               "model": "gpt-4.1-mini", "keys": ["OPENAI_API_KEY"]},
    "openrouter": {"adapter": "openai", "base_url": "https://openrouter.ai/api/v1",
                   "model": "openai/gpt-oss-120b:free", "keys": ["OPENROUTER_API_KEY"]},
    "mistral": {"adapter": "openai", "base_url": "https://api.mistral.ai/v1",
                "model": "mistral-large-latest", "keys": ["MISTRAL_API_KEY"]},
    "deepseek": {"adapter": "openai", "base_url": "https://api.deepseek.com/v1",
                 "model": "deepseek-chat", "keys": ["DEEPSEEK_API_KEY"]},
    "ollama": {"adapter": "openai", "base_url": "http://localhost:11434/v1",
               "model": "llama3.1", "keys": [], "keyless": True},
    "anthropic": {"adapter": "anthropic", "base_url": "https://api.anthropic.com",
                  "model": "claude-sonnet-5-5", "keys": ["ANTHROPIC_API_KEY"]},
    "custom": {"adapter": "openai", "base_url": "", "model": "", "keys": []},
}
ALIASES = {"claude": "anthropic", "grok": "xai", "google": "gemini", "x.ai": "xai", "local": "ollama"}

RETRYABLE = {408, 409, 425, 429, 500, 502, 503, 504, 529}


class BaseClient:
    def __init__(self, api_key: str, model: str, base_url: str, timeout: int = 120, max_retries: int = 6):
        self.api_key, self.model, self.base_url = api_key, model, base_url.rstrip("/")
        self.timeout, self.max_retries = timeout, max_retries
        self.session = requests.Session()
        register_secret(api_key)

    # --- subclass hooks
    def _url(self) -> str: raise NotImplementedError
    def _headers(self) -> dict[str, str]: raise NotImplementedError
    def _payload(self, system: str, messages: list[dict], tools: list[dict], force_tool: str | None,
                 effort: str | None = None) -> dict: raise NotImplementedError
    def _parse(self, data: dict) -> LLMResponse: raise NotImplementedError

    def chat(self, system: str, messages: list[dict], tools: list[dict], force_tool: str | None = None) -> LLMResponse:
        effort = (os.environ.get("LLM_REASONING_EFFORT") or "").strip().lower() or None
        # Try the richest request first; if the provider rejects optional extras (HTTP 400), fall back.
        attempts: list[tuple[str | None, str | None]] = [(force_tool, effort)]
        if effort:
            attempts.append((force_tool, None))
        if force_tool or effort:
            attempts.append((None, None))
        attempts = list(dict.fromkeys(attempts))
        data = None
        for i, (ft, ef) in enumerate(attempts):
            try:
                data = self._post(self._payload(system, messages, tools, ft, ef))
                break
            except LLMError as e:
                if getattr(e, "status", None) == 400 and i < len(attempts) - 1:
                    continue
                raise
        try:
            return self._parse(data)
        except (KeyError, IndexError, TypeError, ValueError) as e:
            raise LLMError(f"Unexpected response format from LLM provider: {e}") from e

    def _post(self, payload: dict) -> dict:
        delay, last = 2.0, "unknown error"
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.post(self._url(), headers=self._headers(), json=payload, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as e:
                last = f"network error: {type(e).__name__}"
                resp = None
            if resp is not None:
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError:
                        last = "provider returned non-JSON body"
                else:
                    body = redact(resp.text[:400].replace("\n", " "))
                    last = f"HTTP {resp.status_code}: {body}"
                    if resp.status_code in (401, 403):
                        raise self._fatal(f"Authentication failed ({last}). Check LLM_API_KEY and provider.", resp.status_code)
                    if resp.status_code == 404:
                        raise self._fatal(f"Endpoint or model not found ({last}). Check LLM_MODEL / LLM_BASE_URL.", 404)
                    if resp.status_code not in RETRYABLE:
                        raise self._fatal(f"LLM request rejected ({last})", resp.status_code)
            if attempt == self.max_retries:
                break
            wait = delay
            if resp is not None and resp.headers.get("retry-after", "").replace(".", "", 1).isdigit():
                wait = max(wait, float(resp.headers["retry-after"]))
            wait = min(wait, 60) + random.uniform(0, 1)
            time.sleep(wait)
            delay = min(delay * 2, 30)
        raise LLMError(f"LLM request failed after {self.max_retries + 1} attempts: {last}")

    @staticmethod
    def _fatal(msg: str, status: int) -> LLMError:
        e = LLMError(msg)
        e.status = status  # type: ignore[attr-defined]
        return e


def _loads(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else {"__parse_error": str(raw)[:200]}
    except (ValueError, TypeError):
        return {"__parse_error": str(raw)[:200]}


class OpenAICompatClient(BaseClient):
    def _url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _payload(self, system, messages, tools, force_tool, effort=None):
        p: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "tools": [{"type": "function", "function": t} for t in tools],
        }
        temp = os.environ.get("LLM_TEMPERATURE")
        if temp:
            p["temperature"] = float(temp)
        if effort:
            p["reasoning_effort"] = effort
        if force_tool:
            p["tool_choice"] = {"type": "function", "function": {"name": force_tool}}
        return p

    def _parse(self, data):
        msg = data["choices"][0]["message"]
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc["function"]
            calls.append(ToolCall(id=tc.get("id") or f"call_{int(time.time()*1000)}_{i}",
                                  name=fn["name"], arguments=_loads(fn.get("arguments")),
                                  extra=tc.get("extra_content") or None))
        return LLMResponse(text=msg.get("content") or "", tool_calls=calls)


class AnthropicClient(BaseClient):
    def _url(self) -> str:
        return f"{self.base_url}/v1/messages"

    def _headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json", "x-api-key": self.api_key, "anthropic-version": "2023-06-01"}

    @staticmethod
    def convert_messages(messages: list[dict]) -> list[dict]:
        """OpenAI-style history -> Anthropic messages (tool results merged into one user turn)."""
        out: list[dict] = []
        for m in messages:
            role = m["role"]
            if role == "assistant":
                blocks: list[dict] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    args = tc["function"]["arguments"]
                    blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["function"]["name"],
                                   "input": _loads(args)})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no content)"}]})
            elif role == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"] or "(empty)"}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) \
                        and out[-1]["content"] and out[-1]["content"][0].get("type") == "tool_result":
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
            else:
                if out and out[-1]["role"] == "user":
                    prev = out[-1]["content"]
                    if isinstance(prev, str):
                        out[-1]["content"] = [{"type": "text", "text": prev}]
                    out[-1]["content"].append({"type": "text", "text": m["content"]})
                else:
                    out.append({"role": "user", "content": m["content"]})
        return out

    def _payload(self, system, messages, tools, force_tool, effort=None):
        p: dict[str, Any] = {
            "model": self.model, "max_tokens": 4096, "system": system,
            "messages": self.convert_messages(messages),
            "tools": [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools],
        }
        temp = os.environ.get("LLM_TEMPERATURE")
        if temp:
            p["temperature"] = float(temp)
        if force_tool:
            p["tool_choice"] = {"type": "tool", "name": force_tool}
        return p

    def _parse(self, data):
        text, calls = [], []
        for b in data["content"]:
            if b["type"] == "text":
                text.append(b["text"])
            elif b["type"] == "tool_use":
                calls.append(ToolCall(id=b["id"], name=b["name"], arguments=b.get("input") or {}))
        return LLMResponse(text="\n".join(text), tool_calls=calls)


def make_client(provider: str | None = None, model: str | None = None, env: dict[str, str] | None = None) -> BaseClient:
    """Build a client from LLM_PROVIDER / LLM_API_KEY / LLM_MODEL / LLM_BASE_URL (or CLI overrides)."""
    env = env if env is not None else dict(os.environ)
    name = (provider or env.get("LLM_PROVIDER") or "gemini").strip().lower()
    name = ALIASES.get(name, name)
    if name not in PROVIDERS:
        raise LLMError(f"Unknown LLM provider '{name}'. Choose one of: {', '.join(sorted(PROVIDERS))} "
                       f"(aliases: {', '.join(sorted(ALIASES))}), or use 'custom' with LLM_BASE_URL.")
    spec = PROVIDERS[name]
    base_url = (env.get("LLM_BASE_URL") or spec["base_url"]).strip()
    mdl = (model or env.get("LLM_MODEL") or spec["model"]).strip()
    key = (env.get("LLM_API_KEY") or "").strip()
    for k in spec["keys"]:
        key = key or (env.get(k) or "").strip()
    if not key and not spec.get("keyless") and not (name == "custom" and env.get("LLM_ALLOW_NO_KEY")):
        raise LLMError(f"No API key found for provider '{name}'. Set LLM_API_KEY in .env "
                       f"(or {' / '.join(spec['keys']) or 'LLM_API_KEY'}).")
    if not base_url:
        raise LLMError("Provider 'custom' needs LLM_BASE_URL (an OpenAI-compatible endpoint, e.g. https://host/v1).")
    if not mdl:
        raise LLMError("Provider 'custom' needs LLM_MODEL.")
    cls = AnthropicClient if spec["adapter"] == "anthropic" else OpenAICompatClient
    timeout = int(env.get("LLM_TIMEOUT", "120"))
    return cls(api_key=key, model=mdl, base_url=base_url, timeout=timeout)
