# Frieza (APKit) — Codex Agent Instructions

## One-time setup (run once after cloning)

From the repo root in PowerShell:

```powershell
pip install -e ".[dev]"
```

This installs all four packages (`apk_intercept`, `apk_static_lief`, `apk_intercept_mcp`,
`trust_e2e`) and the `apkit` CLI entry point. Editable install — source changes take
effect immediately.

Verify with:

```powershell
apkit --version
apkit healthcheck
```

## Repeatable per-APK workflow

Every APK analysis run must start by creating an isolated workspace session.
Call `bootstrap_analysis_session` first, then scan:

1. `bootstrap_analysis_session` — creates a session, copies the APK into `input/`,
   activates it, returns artifact paths.
2. `scan_static_apk` or `chat_analyze_apk` — LIEF static analysis; report goes to
   the active session `static/` directory.
3. `recommend_dynamic_plan` — builds a dynamic execution plan from the static report.
4. `start_hardened_session` or `start_native_intercept_session` — attach Frida
   (requires device connected via ADB).
5. `list_apks` — list everything in the active session.

Always use the `seed_apk` path returned by `bootstrap_analysis_session` (the copy
inside `input/`) when calling scan tools, so reports land in the right session.

## Workspace layout

Artifacts stay outside the repo:

| Directory | Contents |
|-----------|----------|
| `%LOCALAPPDATA%\apk-intercept-kit\sessions\<engagement>\<target>\<session>\input\` | APK inputs |
| `...\static\` | JSON analysis reports |
| `...\generated-hooks\` | Frida hook bundles |
| `...\repacked\` | Rebuilt APKs |
| `...\trust\events.jsonl` | Trust evidence log |

Override root with `APKIT_HOME` env var or `--workspace`. Override active session
with `APKIT_SESSION` or `--session`.

## Tool availability

All tools work on Windows. The following require a connected ADB device and
frida-server running on the device:

- `start_hardened_session`
- `start_native_intercept_session`
- `start_trust_server` / `start_trust_adb_bridge`
- `patch_nsc_and_repack` (also needs apktool, zipalign, apksigner in PATH)

Static analysis tools (`scan_static_apk`, `chat_analyze_apk`, `scan_decompiled_tree`,
`recommend_dynamic_plan`, `summarize_findings`, `bootstrap_analysis_session`,
`list_apks`) work without a device.

## Tests and linting

```powershell
pytest
ruff check .
```
