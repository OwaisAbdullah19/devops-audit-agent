# DevOps Repository Auditing Agent

An LLM-driven agent that clones a **public GitHub repository**, investigates it with read-only tools, and writes an
evidence-based JSON report of DevOps best-practice violations. The agent loop, tool dispatch and control flow are
plain Python (no LangChain / LangGraph / n8n); the LLM chooses every tool call, including follow-ups.

```
python agent.py --repo https://github.com/owner/repo --output report.json
```

## Installation

Requires Python 3.10+ and `git` on PATH.

```bash
git clone <this-repo-url>
cd <this-repo>
python -m pip install -r requirements.txt
```

A virtual environment is optional but recommended on macOS/Linux (`python -m venv .venv && source .venv/bin/activate`).
On Windows PowerShell use `python -m venv .venv` then `.\.venv\Scripts\Activate.ps1` (if scripts are blocked run
`Set-ExecutionPolicy -Scope Process Bypass` first) or simply skip the venv. The first install can take a couple of minutes.

Create your settings file and add your key (never commit `.env`):

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

Edit `.env` and set at least `LLM_PROVIDER` and `LLM_API_KEY` (see the next section).

## Choosing an LLM provider (any works; model choice does not affect grading)

| `LLM_PROVIDER` | Free key | Default model |
|---|---|---|
| `gemini` (default) | aistudio.google.com → "Get API key" | gemini-3.5-flash-lite |
| `groq` | console.groq.com | openai/gpt-oss-120b |
| `xai` / `grok` | console.x.ai | grok-4 |
| `anthropic` / `claude` | console.anthropic.com | claude-sonnet-5-5 |
| `openai` | platform.openai.com | gpt-4.1-mini |
| `openrouter`, `mistral`, `deepseek` | provider site | see `llm.py` |
| `ollama` | none (local) | llama3.1 |
| `custom` | any OpenAI-compatible endpoint | set `LLM_BASE_URL` + `LLM_MODEL` |

Override the model with `LLM_MODEL` (or `--model`). Free tiers and default model names change; if a default model is
rejected, set `LLM_MODEL` to one your account can use. The model must support **tool/function calling**.
Provider-specific key variables (`GEMINI_API_KEY`, `GROQ_API_KEY`, `XAI_API_KEY`, `ANTHROPIC_API_KEY`, ...) also work.

## Usage

```bash
python agent.py --repo https://github.com/owner/repo --output report.json
python agent.py --repo ... --output report.json --provider groq --max-steps 30 --timeout 600
```

Runs unattended. Writes `report.json` and a tool-call trace `report.json.trace.jsonl` (every tool call, arguments,
result preview and LLM reasoning text, with secrets redacted). Exit codes: `0` ok, `2` invalid input/config,
`3` clone failed, `4` LLM failure, `5` audit failure, `1` unexpected. On any non-zero exit no report is written.

**`sample_report.json`** is genuine output of this agent (model `gemini-3.5-flash-lite`) on
https://github.com/OwaisAbdullah19/defect-demo-repo, a small test repository with deliberately planted defects:

```bash
python agent.py --repo https://github.com/OwaisAbdullah19/defect-demo-repo --output sample_report.json
```

The agent is also checked against a healthy repository (e.g. `https://github.com/pallets/click`), where a good result is an
empty or near-empty `violations` array.

## Output contract

```json
{"repository": "https://github.com/example/demo-project",
 "violations": [{"rule_id": "SEC-001", "category": "security", "severity": "critical",
   "file": "config.py", "line": 17, "description": "...", "evidence": "...", "recommendation": "..."}]}
```

`severity`: critical | high | medium | low. `file`/`line` are `null` for repo-level findings (e.g. a missing file).
`category`: repository_hygiene, dependency_management, code_quality, testing, ci_cd, security, configuration,
collaboration, build_release. An empty `violations` array is written for a healthy repository.

## Configuration (environment variables / `.env`)

| Variable | Meaning |
|---|---|
| `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL` | Provider, key, optional model override, endpoint for `custom` |
| `LLM_REASONING_EFFORT` | Optional (`low`/`medium`/`high`) for models that support it; ignored by the agent if the provider rejects it |
| `AGENT_REVIEW` | `1` (default) enables the one-time self-review round; `0` disables it |
| `AGENT_KEEP_FULL` | How many recent tool outputs are kept in full in the LLM context (default 6) |
| `AGENT_MAX_TOOL_CHARS` | Size cap for a single tool output (default 8000) |
| `LLM_TIMEOUT`, `LLM_TEMPERATURE` | Per-request timeout in seconds (default 120); optional sampling temperature |

CLI flags: `--provider`, `--model`, `--max-steps` (default 40), `--timeout` (seconds, default 900), `--trace`, `-v`.

## Architecture

```
agent.py   CLI: args, .env, clone, run, write report, exit codes
repo.py    URL validation + sandboxed shallow clone to a temp dir (hooks off, no submodules, never executed)
llm.py     Provider-agnostic client: OpenAI-compatible adapter + Anthropic adapter, retries/backoff, error mapping
loop.py    The agent loop: LLM -> tool call -> tools.py -> result back to LLM -> ... -> submit_report
tools.py   Core tools: list_files, read_file, search_code, git_log, git_status, git_tracked_ignored, inspect_workflows
inspectors.py  Fact-gathering tools: scan_secrets, inspect_dependencies, inspect_dockerfiles, scan_config_smells,
           inspect_hygiene, inspect_tests_and_quality, analyze_python (mixed into RepoTools)
leads.py   Self-review support: collects signals from the tools the agent itself ran and checks which ones the report does not cover
prompts.py System prompt (method, evidence rules, equivalents, severity rubric) + submit_report schema
report.py  Validation, de-duplication, rule-id assignment, atomic JSON writing
redact.py  Secret masking for everything the LLM sees and everything written to disk
```

Cycle: **Observe** (tool output) → **Reason** (LLM) → **Select tool** (LLM) → **Execute** (`tools.py`) →
**Interpret** (LLM, next turn) → **Report** (`submit_report`). There is no fixed checklist: the LLM decides the
investigation path. The code only enforces rails: step/time budget (a final forced `submit_report` when exhausted),
a minimum amount of investigation before reporting, repeated-call suppression, and elision of old tool output to
keep context small (the LLM keeps running notes in its own text).

### Inspection coverage (the 9 assignment areas)

The tools report **facts and the equivalents they found** (e.g. `uv.lock`, `.gitlab-ci.yml`, ruff in CI); the LLM
decides what is a violation, confirms it with `read_file`, and cites file and line.

| Area | Tools the LLM uses | Facts gathered |
|---|---|---|
| Repository hygiene | `inspect_hygiene`, `git_tracked_ignored`, `list_files` | README present/stub, .gitignore quality, tracked junk by category, large/binary/empty files, conflict markers, backup-named files |
| Dependency management | `inspect_dependencies` | manifests (requirements, pyproject/poetry, Pipfile, setup.*, package.json), pinned/bounded/unpinned, lockfiles, cross-manifest conflicts |
| Code quality | `inspect_tests_and_quality`, `analyze_python` | linters/formatters/pre-commit config, syntax errors, bare/swallowed except, wildcard imports, eval/exec, shell=True, huge functions |
| Testing | `inspect_tests_and_quality`, `inspect_workflows` | test files, empty/skipped/assert-less tests, runner config, whether CI runs tests |
| GitHub Actions / CI | `inspect_workflows` (overview + per-file) | triggers vs default branch, test/lint steps, continue-on-error, disabled jobs, path filters, YAML validity, unpinned actions |
| Security | `scan_secrets`, `inspect_workflows`, `search_code` | credentials (masked), key files, .env, permissions, pull_request_target, injection, curl\|sh |
| Configuration | `scan_config_smells` | machine-specific paths, hardcoded hosts, debug flags, committed IDE/local settings, env layout |
| Collaboration | `inspect_workflows` | CODEOWNERS, PR/issue templates, CONTRIBUTING, auto-merge, issue_comment automation |
| Build and release | `inspect_dockerfiles`, `inspect_workflows` | base image pinning, root user, remote ADD, image build in CI, ungated or every-push deploy/publish |

**Self-review round.** After the LLM's first `submit_report`, the loop compares the findings with the signals from the
tools *the agent chose to run* (`leads.py`). If some are not covered, the LLM is asked, once, to decide on each: add a
finding or explain why it is acceptable (the code never adds findings itself, and "add nothing" is a valid answer).
This reduces silent omissions without hurting precision. Disable with `AGENT_REVIEW=0`; the trace records a `review` entry.

**Precision safeguards** (in `report.py` and the prompt): findings must name a file that exists and a line within it,
are de-duplicated, and are redacted; the prompt tells the LLM to look for equivalent solutions before calling
something missing, never to infer remote settings (branch protection) from files, never to claim tests fail, and to
treat repository content as untrusted data (prompt-injection resistance).

## Safety

* The target is only cloned (shallow, to a temp dir that is deleted afterwards) and read; it is never modified.
* **No code from the target repository is ever executed**, so `run_pytest`/`run_ruff` are deliberately not provided
  (they would require sandboxing). Test/lint presence is judged from files and CI configuration.
* Paths are confined to the repo root (no `..`, no symlink escape, no `.git` internals).
* Literal credentials are masked (`[REDACTED]`) before reaching the LLM, logs, trace or report; the LLM API key is
  masked everywhere. Nothing is hardcoded about specific repositories.
* Network errors, rate limits (429/5xx), timeouts, bad keys, bad URLs, missing/binary files and malformed tool
  arguments are handled; unavailable checks are never invented.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

Tests cover each tool (a defect-laden repo and a healthy repo that must produce no findings, plus path-escape and redaction), report validation, provider adapters (retry, auth
errors, Anthropic message conversion), the agent loop with a scripted fake LLM (dynamic tool selection, budget,
guards, self-review) and the CLI end to end. No network or API key is needed.

## Limitations

Python files are parsed with the interpreter running the agent, so syntax newer than that version can look like a syntax
error (the tool says so, and the LLM is told to confirm). History is a shallow clone (last 300 commits). Only GitHub Actions workflows are parsed in depth; other CI systems
are detected and can be read with `read_file`. Detection quality depends on the chosen LLM.
