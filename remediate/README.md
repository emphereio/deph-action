# remediate

Turns a deph scan into a remediation plan and an investigation surface. It reads
deph's report JSON and answers "what do I actually do?" — ranked by what's
*reachable*, split by base-OS vs application, with verified upgrade targets.

Two layers, on purpose:

- **Deterministic floor** (`plan.py`, `tools.py`) — version math and rollups with
  no model in the loop. Reproducible, unit-tested. This is the source of truth.
- **Model-agnostic agent** (`agent.py`) — narration, target selection, freshness.
  It *proposes*; the deterministic `cves_cleared` tool *verifies* what a target
  actually clears. The model is never trusted for version math.

## Bring your own model

The agent speaks the OpenAI-compatible `/chat/completions` tool-calling protocol,
which OpenAI, Anthropic (compat endpoint), Google, Mistral, OpenRouter, Groq,
Together, and local runtimes (Ollama, vLLM, llama.cpp) all implement.

```
DEPH_LLM_BASE_URL   default https://api.openai.com/v1   (point anywhere)
DEPH_LLM_MODEL      required; any model the endpoint serves
DEPH_LLM_API_KEY    or OPENAI_API_KEY; omit for keyless local servers
```

With no model configured, the agent emits the deterministic plan and exits 0 — it
never blocks a scan.

## Usage

```sh
# deterministic plan (no model)
python3 plan.py report.json

# agent plan (PR-comment form); --show-trace prints each propose->verify call
python3 agent.py report.json --mode plan --show-trace

# investigate
python3 agent.py report.json --mode ask --ask "smallest set of bumps that kills the most reachable risk?"

# MCP server: drive the same tools from any client/model
python3 mcp_server.py report.json
```

## Tools

`graph_query`, `cves_cleared` (verifier), `package_remediation`, `plan_remediation`,
`explain_reachability` are deterministic over the report. `latest_releases` is the
only network call (PyPI/npm), advisory and point-in-time.

## Security

Package names and versions come from an **untrusted scanned image**. They are:

- validated against a conservative charset before reaching a registry URL
  (rejects traversal, newlines, injection); registry reads are size-bounded;
- escaped for markdown, and never emitted as a runnable command unless they
  validate — an unusual string is surfaced as a signal, not pasted into a shell;
- passed to the model as data, with the system prompt instructing that scan
  output is never instructions (prompt-injection guard).

## Tests

```sh
python3 -m unittest -q
```

No network, no on-disk fixtures.
