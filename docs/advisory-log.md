# Security Audit 2026 — Python (pip) Advisory Log

**Scope:** GitHub-reviewed advisories for the `pip` ecosystem at **high** or **critical** severity — the ten most recent as of the audit date (2026-10-17).

**Method:** Enumerated from the GitHub Advisory Database (global advisories, `type=reviewed`, `ecosystem=pip`, severity `high`/`critical`), ordered by publish date, newest first. Records were pulled individually for verification where the bulk listing truncated.

**Prepared for:** @HeziLiu — security review week.

---

## Advisories (most recent first)

### 1. GHSA-w5f2-9q9c-ff4h — `lmcache` — Critical

Unauthenticated remote code execution via pickle deserialization on the multiprocess-mode ZeroMQ transport (default port 5555); routable/multi-node deployments run as root and are fully exposed.

- CVSS 9.8 · CVE-2026-105192 · Published 2026-10-16
- Affected: `>= 0.3.9, < 0.5.6` — fixed in **0.5.6**
- Advisory: https://github.com/advisories/GHSA-w5f2-9q9c-ff4h

### 2. GHSA-h4mw-j7qp-8mwm — `claude-agent-sdk` — Critical

Argument injection through the `resume` option: an attacker-controlled value beginning with `-` is interpreted as a CLI flag, allowing an injected `--mcp-config` to define a stdio MCP server and execute arbitrary commands at CLI startup.

- CVE-2026-96620 · Published 2026-10-16
- Affected: `< 0.2.121` — fixed in **0.2.121**
- Advisory: https://github.com/advisories/GHSA-h4mw-j7qp-8mwm

### 3. GHSA-68w4-83fh-f2w8 — `pyload-ng` — High

`getUserData`/`get_userdata` are exposed with `Perms.ANY`, a no-op permission gate, giving any authenticated account a binary oracle to brute-force the administrator password (no lockout; rate limit bypassable via `X-Forwarded-For` rotation).

- CVSS 8.1 · Published 2026-10-09
- Affected range: not fully retrievable from the advisory API response (truncated); the advisory's triage notes confirm the `0.5.0b3.dev*` line is vulnerable and that maintainers were asked to confirm `0.5.0b2.*` and `0.4.x`
- Advisory: https://github.com/advisories/GHSA-68w4-83fh-f2w8

### 4. GHSA-cv3g-hj65-pcfh — `praisonai` — High

Shell command allowlist bypass via `find`'s built-in `-exec`/`-execdir` actions — the `+` batch terminator replaces the blocked `;`, executing arbitrary binaries without shell metacharacters.

- CVSS 8.8 · CVE-2026-61434 · Published 2026-10-08
- Affected: bypasses the hardening introduced in PraisonAI 4.6.58; sibling advisories in this series are fixed in **4.6.78**
- Advisory: https://github.com/advisories/GHSA-cv3g-hj65-pcfh

### 5. GHSA-9mp3-24cc-77mg — `praisonai` — Critical

The AICoder UI component exposes `write_to_file` and `execute_command` tools to the LLM with no path validation and no command sanitization, enabling arbitrary file write and command execution through prompt injection in the chat interface.

- CVSS 9.9 · CVE-2026-61445 · Published 2026-10-08
- Affected: `<= 4.6.77` — fixed in **4.6.78**
- Advisory: https://github.com/advisories/GHSA-9mp3-24cc-77mg

### 6. GHSA-hc5v-gxvj-58wh — `praisonai` — High

The MCP HTTP-stream transport is unauthenticated by default (`--api-key` defaults to `None`), exposing tool enumeration (~50 tools) and an unvalidated tool-call surface; the dispatcher forwards arguments without checking the advertised `inputSchema`.

- CVSS 7.3 · CVE-2026-61427 · Published 2026-10-08
- Affected: `<= 4.6.77` — fixed in **4.6.78**
- Advisory: https://github.com/advisories/GHSA-hc5v-gxvj-58wh

### 7. GHSA-qg25-6gc4-48mg — `praisonaiagents` — High

DNS-rebinding bypass of the `web_crawl` SSRF protection: the URL string is validated at check time but re-resolved at connect time, so a rebinding domain returns an internal/private HTTP response body to the caller.

- CVSS 8.5 · Published 2026-10-08
- Affected: reported against PraisonAI 4.6.63 (`praisonaiagents`); fix version not stated in the retrieved record
- Advisory: https://github.com/advisories/GHSA-qg25-6gc4-48mg

### 8. GHSA-m6wp-h223-4c8g — `praisonaiagents` — High

Plugin auto-discovery executes arbitrary `.py` files from `.praisonai/plugins/` (project and user home) via `exec_module()` with no code signing, integrity verification, or sandboxing — persistence executes at framework initialization.

- CVSS 8.4 · CVE-2026-61446 · Published 2026-10-08
- Affected: `<= 1.6.77` — fixed in **1.6.78**
- Advisory: https://github.com/advisories/GHSA-m6wp-h223-4c8g

### 9. GHSA-2xv2-w8cq-5gxw — `praisonaiagents` — Critical

`CodeAgent._execute_python()` runs LLM-generated code in a subprocess with the complete parent environment (`os.environ.copy()`), zero AST validation, and no import restrictions — leaking every environment secret and enabling arbitrary code execution via prompt injection.

- CVSS 10.0 · CVE-2026-61447 · Published 2026-10-08
- Affected: `<= 1.6.77` — fixed in **1.6.78**
- Advisory: https://github.com/advisories/GHSA-2xv2-w8cq-5gxw

### 10. GHSA-w794-rj3p-xv45 — `langflow` — Critical

OS command injection (RCE) via an arbitrary command in an MCP stdio server configuration; before 1.10.3 the command was wrapped in `bash -c "exec ..."` with no allowlist, and with the default `LANGFLOW_AUTO_LOGIN=true` this is reachable without an account.

- CVSS 9.9 · CVE-2026-105697 · Published 2026-10-07
- Affected: `langflow >= 1.1.2, < 1.10.3` — fixed in **1.10.3** (see focus record below)
- Advisory: https://github.com/advisories/GHSA-w794-rj3p-xv45

---

## Focus record: most relevant to a typical Python web project

**GHSA-w794-rj3p-xv45 — Langflow** was selected as the most relevant of the ten to a typical Python web project: it is a self-hosted web application with an HTTP API surface, commonly internet-facing, and its default configuration (auto-login) hands out tokens without credentials — matching the standard exposure profile of a deployed Python web service.

**Affected version ranges (full record):**

| Package (PyPI) | Vulnerable range | First patched |
|---|---|---|
| `langflow` | `>= 1.1.2, < 1.10.3` | `1.10.3` |
| `langflow-base` | `>= 0.1.2, < 0.10.3` | `0.10.3` |
| `lfx` | `< 1.10.3` | `1.10.3` |

The fix landed in two steps: 1.9.0 added a command allowlist and argument/env validation on the REST model (`MCPServerConfig`), and 1.10.3 enforced the same policy at the execution sink (including configs embedded in flows/tweaks and the pre-spawn boundary) and removed the `bash -c` wrapper. Workarounds if upgrading is not immediately possible: set `LANGFLOW_AUTO_LOGIN=false` and do not expose Langflow directly to untrusted networks.

---

## My repositories — exposure check

Each repository owned by @HeziLiu was checked for a Python dependency manifest (`requirements.txt`, `pyproject.toml`, `setup.py`, or `Pipfile`), at the repository root, in subdirectories via GitHub code search, and by language inspection.

| Repository | Python manifest? | Exposure verdict |
|---|---|---|
| `HeziLiu/Little-rookie` | **None** — Java/C++ undergraduate coursework, no `requirements.txt`/`pyproject.toml`/`setup.py`/`Pipfile` anywhere in the tree | **Not exposed** — no pinned Python packages, so nothing can match any advisory above |
| `HeziLiu/Big-Buzzard` | **None** — contains only a `.gitattributes` file and an empty directory | **Not exposed** — no code or dependencies at all |
| `HeziLiu/CodingInterviewChinese2` (fork) | **None** — C++ source code only | **Not exposed** — no pinned Python packages |
| `HeziLiu/awesome-chatgpt-prompts-zh` (fork) | **None** — Markdown/JSON prompt content only | **Not exposed** — no pinned Python packages |

**Overall verdict: zero exposure.** None of the four repositories declares Python dependencies, so none of the ten advisories (lmcache, claude-agent-sdk, pyload-ng, praisonai, praisonaiagents, langflow) applies to any of them.

*Caveats:* the manifest check is based on the repository trees as currently indexed on GitHub (code search can lag recent pushes), and forks were checked at their current state rather than upstream.
