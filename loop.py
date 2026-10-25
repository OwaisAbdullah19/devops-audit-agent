"""The explicit agent loop (no orchestration framework).

Observe -> Reason (LLM) -> Select tool (LLM) -> Execute tool (tools.py) -> Interpret (LLM) -> Report.
The LLM alone decides which tool to call next; this module only enforces safety rails
(step/time budgets, context size, argument handling, report validation).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from leads import extract_leads, open_leads, review_message
from llm import BaseClient, LLMError, LLMResponse, ToolCall
from prompts import SUBMIT_TOOL, SYSTEM_PROMPT, initial_user_message
from redact import redact
from report import normalize_violations
from tools import TOOL_SCHEMAS, RepoTools

log = logging.getLogger("audit")


class AgentError(Exception):
    """The agent could not complete an inspection."""


class AuditAgent:
    def __init__(self, client: BaseClient, tools: RepoTools, repo_url: str, max_steps: int = 40,
                 min_inspections: int = 4, deadline_seconds: int = 900, trace_path: str | Path | None = None,
                 keep_full: int | None = None, review: bool | None = None):
        self.client, self.tools, self.repo_url = client, tools, repo_url
        self.max_steps, self.min_inspections = max_steps, min_inspections
        self.deadline = time.monotonic() + deadline_seconds
        self.keep_full = keep_full if keep_full is not None else int(os.environ.get("AGENT_KEEP_FULL", "6"))
        self.messages: list[dict[str, Any]] = [{"role": "user", "content": initial_user_message(repo_url)}]
        self.inspections = 0
        self.submit_attempts = 0
        self._seen: dict[str, int] = {}
        self.review = review if review is not None else os.environ.get("AGENT_REVIEW", "1") != "0"
        self.leads: list[dict[str, Any]] = []
        self._reviewed = False
        self._review_leads: list[dict[str, Any]] = []
        self._decision_retries = 0
        self._pending: list[dict] | None = None
        self._trace = open(trace_path, "w", encoding="utf-8") if trace_path else None
        self.tool_names = {t["name"] for t in TOOL_SCHEMAS}

    # ------------------------------------------------------------------ tracing
    def _log_trace(self, **entry: Any) -> None:
        if self._trace:
            entry["ts"] = round(time.time(), 2)
            self._trace.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            self._trace.flush()

    def close(self) -> None:
        if self._trace:
            self._trace.close()
            self._trace = None

    # ------------------------------------------------------------- context mgmt
    def _compact(self) -> list[dict[str, Any]]:
        """Elide old tool outputs (the LLM keeps running notes in its own text)."""
        idx = [i for i, m in enumerate(self.messages) if m["role"] == "tool"]
        old = set(idx[:-self.keep_full]) if self.keep_full >= 0 and len(idx) > self.keep_full else set()
        out = []
        for i, m in enumerate(self.messages):
            if i in old and len(m["content"]) > 400:
                m = {**m, "content": m["content"][:300] + "\n…[older output elided to save context; re-run the tool if needed]"}
            out.append(m)
        return out

    # ----------------------------------------------------------------- the loop
    def run(self) -> list[dict]:
        final_step = False
        nudges = 0
        for step in range(1, self.max_steps + 1):
            if not final_step and (step == self.max_steps or time.monotonic() > self.deadline):
                final_step = True
                reason = "step budget" if step == self.max_steps else "time budget"
                self.messages.append({"role": "user", "content": (
                    f"The {reason} is exhausted. Call submit_report NOW with the findings you have confirmed so far.")})
                log.warning("%s exhausted; forcing final report", reason)
            tools = [SUBMIT_TOOL] if final_step else [*TOOL_SCHEMAS, SUBMIT_TOOL]
            try:
                resp: LLMResponse = self.client.chat(SYSTEM_PROMPT, self._compact(), tools,
                                                     force_tool="submit_report" if final_step else None)
            except LLMError:
                raise
            self._append_assistant(resp)
            if resp.text.strip():
                self._log_trace(step=step, type="reasoning", text=redact(resp.text)[:2000])
                log.info("[step %d] LLM: %s", step, redact(resp.text.strip().replace("\n", " "))[:160])

            if not resp.tool_calls:
                nudges += 1
                parsed = self._json_from_text(resp.text) if nudges >= 2 or final_step else None
                if parsed is not None and (self.inspections >= self.min_inspections or final_step):
                    return self._finalize(parsed.get("violations", []))
                if nudges > 4:
                    if self._pending is not None:
                        return self._pending
                    raise AgentError("LLM repeatedly replied without calling any tool; it may not support tool calling")
                self.messages.append({"role": "user", "content": (
                    "Reply with a tool call. Continue investigating with the inspection tools, "
                    "or call submit_report if you are done.")})
                continue
            nudges = 0

            submit = [c for c in resp.tool_calls if c.name == "submit_report"]
            others = [c for c in resp.tool_calls if c.name != "submit_report"]
            for call in others:
                self._execute(step, call)
            for call in submit:
                done = self._handle_submit(step, call, alongside_others=bool(others), final_step=final_step)
                if done is not None:
                    return done
            if final_step:
                if self._pending is not None:
                    return self._pending
                raise AgentError("LLM did not produce a valid final report after the budget was exhausted")
        if self._pending is not None:
            return self._pending
        raise AgentError("agent loop ended without a report")

    # ------------------------------------------------------------------ helpers
    def _append_assistant(self, resp: LLMResponse) -> None:
        msg: dict[str, Any] = {"role": "assistant", "content": resp.text or None}
        if resp.tool_calls:
            calls = []
            for c in resp.tool_calls:
                d: dict[str, Any] = {"id": c.id, "type": "function",
                                     "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                if c.extra:  # e.g. Gemini 3 thought_signature: must be sent back exactly as received
                    d["extra_content"] = c.extra
                calls.append(d)
            msg["tool_calls"] = calls
        self.messages.append(msg)

    def _tool_message(self, call: ToolCall, content: str) -> None:
        self.messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name, "content": content})

    def _execute(self, step: int, call: ToolCall) -> None:
        args = call.arguments if isinstance(call.arguments, dict) else {}
        key = f"{call.name}:{json.dumps(args, sort_keys=True)}"
        self._seen[key] = self._seen.get(key, 0) + 1
        log.info("[step %d] tool %s %s", step, call.name, redact(json.dumps(args))[:150])
        if call.name not in self.tool_names:
            result = f"ERROR: unknown tool '{call.name}'. Available: {sorted(self.tool_names | {'submit_report'})}"
        elif self._seen[key] > 2:
            result = "NOTE: you already made this exact call twice; the result will not change. Try a different query or submit_report."
        else:
            self.inspections += 1
            result = self.tools.dispatch(call.name, args)
            if not result.startswith("ERROR"):
                self.leads.extend(extract_leads(call.name, result))
        self._log_trace(step=step, type="tool_call", tool=call.name, args=json.loads(redact(json.dumps(args))),
                        result_chars=len(result), result_preview=result[:300], is_error=result.startswith("ERROR"))
        self._tool_message(call, result)

    def _handle_submit(self, step: int, call: ToolCall, alongside_others: bool, final_step: bool) -> list[dict] | None:
        self._log_trace(step=step, type="submit_report", n_raw=len((call.arguments or {}).get("violations", []) or []))
        if alongside_others:
            self._tool_message(call, "ERROR: submit_report must be called alone, after you have seen the results of your other tool calls. Call it again.")
            return None
        if self.inspections < self.min_inspections and not final_step:
            self._tool_message(call, f"ERROR: you have made only {self.inspections} inspection calls. Investigate the repository "
                                     "(files, manifests, CI workflows, security patterns) before submitting.")
            return None
        if "__parse_error" in (call.arguments or {}):
            self._tool_message(call, "ERROR: submit_report arguments were not valid JSON. Resend as a JSON object with a 'violations' array.")
            return None
        raw = (call.arguments or {}).get("violations")
        self.submit_attempts += 1
        valid, rejected = normalize_violations(raw, self.tools.root)
        if rejected and self.submit_attempts < 3 and not final_step:
            self._tool_message(call, "REJECTED some findings; fix them and call submit_report again with the full corrected list:\n- "
                               + "\n- ".join(rejected))
            return None
        for r in rejected:
            log.warning("dropping finding: %s", r)
        if self._reviewed and self._review_leads and not final_step:
            dec = (call.arguments or {}).get("lead_decisions")
            given = {d.get("lead") for d in dec if isinstance(d, dict)} if isinstance(dec, list) else set()
            missing = [i for i in range(1, len(self._review_leads) + 1) if i not in given]
            if missing and self._decision_retries < 1:
                self._decision_retries += 1
                self._tool_message(call, f"Missing lead_decisions for lead(s) {missing}. Call submit_report again with the complete "
                                         "report and one lead_decisions entry (add or skip + short reason) for every numbered lead.")
                return None
            if isinstance(dec, list):
                self._log_trace(step=step, type="lead_decisions", decisions=[
                    {"lead": d.get("lead"), "decision": d.get("decision"),
                     "reason": redact(str(d.get("reason", "")))[:300]} for d in dec if isinstance(d, dict)])
        if self.review and not self._reviewed and not final_step:
            pending = open_leads(self.leads, valid)
            if pending:
                self._reviewed, self._pending, self._review_leads = True, valid, pending
                log.info("self-review: %d lead(s) not covered by the report", len(pending))
                self._log_trace(step=step, type="review", n_leads=len(pending),
                                leads=[f"{p['kind']}:{p['file']}:{p['line']}:{p['text'][:80]}" for p in pending])
                self._tool_message(call, review_message(pending))
                return None
        self._tool_message(call, "Report accepted.")
        return valid

    def _finalize(self, raw: Any) -> list[dict]:
        valid, rejected = normalize_violations(raw, self.tools.root)
        for r in rejected:
            log.warning("dropping finding: %s", r)
        return valid

    @staticmethod
    def _json_from_text(text: str) -> dict | None:
        """Fallback for models that print the report instead of calling submit_report."""
        m = re.search(r"\{.*\}", text or "", re.S)
        if not m:
            return None
        try:
            val = json.loads(m.group(0))
        except ValueError:
            return None
        return val if isinstance(val, dict) and "violations" in val else None
