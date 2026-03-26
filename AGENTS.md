# Frieza (APKit) — Codex Agent Instructions

## Environment bootstrap

Run this once at the start of every session before using any tool or command:

```bash
pip install -e ".[dev]" -q
```

This installs all four packages (`apk_intercept`, `apk_static_lief`, `apk_intercept_mcp`,
`trust_e2e`) and the `apkit` CLI entry point. The install is editable so source changes
take effect immediately without reinstalling.

## MCP server

Start the server with:

```bash
apkit mcp-server
```

The server speaks JSON-RPC 2.0 over stdio. It is safe to restart between tasks.

## Repeatable per-APK workflow

Every APK analysis run must start by creating an isolated workspace session.
Call the `bootstrap_analysis_session` MCP tool first, then run scans against it:

1. `bootstrap_analysis_session` — creates an isolated session, copies the APK into
   `input/`, activates it, returns all artifact paths.
2. `scan_static_apk` or `chat_analyze_apk` — runs LIEF static analysis; report lands
   in the active session `static/` directory automatically.
3. `recommend_dynamic_plan` — builds a dynamic execution plan from the report.
4. `list_apks` — lists all APKs in the active session.

Always pass the `apk_path` returned from `bootstrap_analysis_session` (the path inside
`input/`) to subsequent scan tools so the report is written into the correct session.

## Workspace layout

Artifacts are written outside the repo to keep the source tree clean:

| Path | Contents |
|------|----------|
| `$APKIT_HOME/sessions/<engagement>/<target>/<session>/input/` | APK inputs |
| `.../static/` | JSON analysis reports |
| `.../generated-hooks/` | Frida hook bundles |
| `.../repacked/` | Rebuilt APKs |
| `.../trust/events.jsonl` | Trust evidence log |

Override the root with `APKIT_HOME` or `--workspace`. Override the active session
with `APKIT_SESSION` or `--session`.

## Platform notes

- Static analysis (`scan_static_apk`, `chat_analyze_apk`, `scan_decompiled_tree`,
  `recommend_dynamic_plan`, `bootstrap_analysis_session`, `list_apks`,
  `summarize_findings`) — works on Linux, macOS, Windows.
- Dynamic analysis, repack, trust server/bridge — require Windows + PowerShell + ADB +
  Frida. These tools will error on Linux; skip them in cloud/Codex runs.

## Running tests

```bash
pytest
```

## Linting

```bash
ruff check .
```
