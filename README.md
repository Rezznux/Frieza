# Frieza (APKit)

![86gzqmd9ulbe1](https://github.com/user-attachments/assets/7269d78d-f35b-4749-b172-552dade72653)

Android APK analysis toolkit built around a source-only repository plus an external per-engagement workspace.

## Source-Only Layout

The repository now keeps only:
- maintained code
- generic hook profiles
- documentation
- tests
- static policy/config data

Runtime artifacts are no longer meant to live in the repo.

Those artifacts are written to an external workspace session:
- APK inputs
- static reports
- generated hook bundles
- repacked APKs
- trust logs
- target-specific casework

Default workspace root:
- Windows: `%LOCALAPPDATA%\apk-intercept-kit`
- Linux/macOS: `$XDG_DATA_HOME/apk-intercept-kit` or `~/.local/share/apk-intercept-kit`

You can override it with `--workspace` or `APKIT_HOME`.

## Quick Start

Create a session and make it active:

```powershell
apkit session new --engagement bugbounty --target target-app
```

For repeatable per-APK workflows, bootstrap a dedicated analysis session (auto-targeted from APK name and copied into `input/`):

```powershell
apkit session analyze --apk E:\analysis\target.apk --engagement bugbounty
```

Then run static/dynamic steps against the active session:

```powershell
apkit static --apk E:\analysis\target.apk --plan
apkit dynamic --package com.target.app --profile observe
```

### Cloud workspace flow (Codex / remote Linux runners)

If you're running in a cloud workspace, use this exact sequence per APK:

```bash
# 1) install deps once in the workspace
python -m pip install -r requirements.txt

# 2) create/activate an isolated session for this APK
python -m apk_intercept.cli --workspace "$HOME/apkit-workspace" \
  session analyze --apk /workspace/uploads/app.apk --engagement cloud

# 3) run static analysis
python -m apk_intercept.cli --workspace "$HOME/apkit-workspace" \
  static --apk /workspace/uploads/app.apk --plan

# 4) inspect active session paths/results
python -m apk_intercept.cli --workspace "$HOME/apkit-workspace" session show
```

Notes for cloud workspaces:
- Static analysis works cross-platform.
- Dynamic instrumentation (`dynamic`, `native-session`, `repack`, trust tools, MCP server) requires Windows + PowerShell + ADB/Frida.
- To keep uploads outside the repo, always pass `--workspace` to an external path (for example `$HOME/apkit-workspace`).

Inspect the active session:

```powershell
apkit session show
```

If you are converting an older polluted checkout, move repo-local artifacts and target-specific casework into the active session:

```powershell
apkit session migrate
```

After that, new scans and runtime outputs will default into the active session instead of the repo.

## Static Analysis

Analyze an APK:

```powershell
apkit static --apk E:\analysis\target.apk --plan
```

Analyze a decompiled tree:

```powershell
apkit static --source-dir E:\analysis\apktool_out --plan
```

The JSON report is written into the active session `static/` directory unless `--output` is provided.

## Dynamic Analysis

Low-noise observation:

```powershell
apkit dynamic --package com.target.app --profile observe
```

Network-focused session:

```powershell
apkit dynamic --package com.target.app --profile network --mitm
```

Late attach for hardened apps:

```powershell
apkit dynamic --package com.target.app --profile attest --launch-then-attach --delay 10
```

Native-focused runtime plan:

```powershell
apkit native-session --package com.target.app --report C:\path\to\report.json --launch-then-attach --delay 10
```

Generated hook bundles go to the active session `generated-hooks/` directory by default.

## Repackaging

Patch network security config and rebuild into the active session `repacked/` directory:

```powershell
apkit repack --apk E:\analysis\target.apk --nsc
```

Optional gadget embedding:

```powershell
apkit repack --apk E:\analysis\target.apk --nsc --gadget E:\tools\frida-gadget
```

## Trust Verifier

Start the verifier:

```powershell
apkit trust-server --detach
```

Start the ADB bridge:

```powershell
apkit trust-bridge --detach
```

Run the local simulator:

```powershell
apkit trust-demo
```

Evidence logs go to the active session `trust/events.jsonl` path.

## MCP Server

Start the MCP server:

```powershell
apkit mcp-server
```

The MCP server now exposes resources from the active session only:
- static reports
- trust evidence log
- session manifest

## Legacy Script Entry Points

The PowerShell scripts still exist under `scripts/` for direct use, but the preferred interface is `apkit`.

Direct scripts now honor the active workspace session where relevant.

## Notes

- This toolkit is for authorized testing only.
- Hardware-backed attestation forgery is not in scope and is not solved by this project.
- The workspace model is operational hygiene, not just a `.gitignore` change.
