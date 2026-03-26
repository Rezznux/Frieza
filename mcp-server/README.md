# MCP Server

This MCP server exposes the toolkit's static and dynamic workflows so Codex can orchestrate them against the active workspace session.

## Included Tools

- `scan_static_apk`
- `scan_decompiled_tree`
- `recommend_dynamic_plan`
- `generate_native_hook_plan`
- `build_hook_bundle`
- `patch_nsc_and_repack`
- `start_hardened_session`
- `start_native_intercept_session`
- `classify_runtime_block`
- `decode_play_integrity_token`
- `start_trust_server`
- `start_trust_adb_bridge`
- `run_trust_demo`
- `list_apks`
- `summarize_findings`
- `chat_analyze_apk`

## Included Resources

Resources are session-scoped now:
- JSON reports from the active session `static/` directory
- trust verifier event log from the active session `trust/` directory
- the active session `manifest.json`

## Run

```powershell
apkit mcp-server
```

## Expected Flow

1. `scan_static_apk` or `scan_decompiled_tree`
2. `recommend_dynamic_plan`
3. `generate_native_hook_plan` or `start_hardened_session`
4. `patch_nsc_and_repack` when APK modification is allowed
5. `start_trust_server` and `start_trust_adb_bridge`
