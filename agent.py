#!/usr/bin/env python3
"""DevOps repository auditing agent - CLI entry point.

    python agent.py --repo https://github.com/<owner>/<repo> --output report.json

Exit codes: 0 ok | 2 invalid input/config | 3 clone failed | 4 LLM failure | 5 agent failure | 1 unexpected
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

from llm import LLMError, make_client
from loop import AgentError, AuditAgent
from redact import redact
from repo import RepoError, cleanup, clone_repo, parse_github_url
from report import write_report
from tools import RepoTools, ToolError

log = logging.getLogger("audit")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LLM-driven DevOps auditing agent for public GitHub repositories.")
    p.add_argument("--repo", required=True, help="Public GitHub repository URL, e.g. https://github.com/owner/repo")
    p.add_argument("--output", required=True, help="Path of the JSON report to write")
    p.add_argument("--provider", help="Override LLM_PROVIDER (gemini, groq, xai/grok, openai, anthropic/claude, openrouter, mistral, deepseek, ollama, custom)")
    p.add_argument("--model", help="Override LLM_MODEL")
    p.add_argument("--max-steps", type=int, default=40, help="Maximum LLM turns (default 40)")
    p.add_argument("--timeout", type=int, default=900, help="Overall time budget in seconds (default 900)")
    p.add_argument("--trace", help="Tool-call trace file (JSONL). Default: <output>.trace.jsonl")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    load_dotenv(Path.cwd() / ".env")
    load_dotenv(Path(__file__).resolve().parent / ".env")

    try:
        parse_github_url(args.repo)
        client = make_client(provider=args.provider, model=args.model)
    except (RepoError, LLMError) as e:
        print(f"error: {redact(str(e))}", file=sys.stderr)
        return 2

    trace_path = args.trace or f"{args.output}.trace.jsonl"
    try:
        Path(trace_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"error: cannot create output directory: {e}", file=sys.stderr)
        return 2

    repo_dir = None
    agent = None
    try:
        log.info("cloning %s", args.repo)
        repo_dir = clone_repo(args.repo)
        tools = RepoTools(repo_dir)
        log.info("auditing with %s (%s)", type(client).__name__, client.model)
        agent = AuditAgent(client, tools, args.repo.strip().rstrip("/"), max_steps=args.max_steps,
                           deadline_seconds=args.timeout, trace_path=trace_path)
        violations = agent.run()
        try:
            dirty = json.loads(tools.git_status())
            if not dirty.get("working_tree_clean", True):
                log.warning("inspected clone has modifications (unexpected)")
        except ToolError:
            pass
        write_report(args.output, args.repo.strip().rstrip("/"), violations)
        log.info("done: %d violation(s) -> %s (trace: %s)", len(violations), args.output, trace_path)
        return 0
    except RepoError as e:
        print(f"error: {redact(str(e))}", file=sys.stderr)
        return 3
    except LLMError as e:
        print(f"error: LLM failure: {redact(str(e))}", file=sys.stderr)
        return 4
    except (AgentError, ToolError) as e:
        print(f"error: audit failed: {redact(str(e))}", file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001 - last-resort guard so we always exit nonzero with a message
        print(f"error: unexpected failure: {type(e).__name__}: {redact(str(e))}", file=sys.stderr)
        return 1
    finally:
        if agent:
            agent.close()
        if repo_dir:
            cleanup(repo_dir)


if __name__ == "__main__":
    sys.exit(main())
