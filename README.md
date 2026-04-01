# Frieza

![86gzqmd9ulbe1](https://github.com/user-attachments/assets/7269d78d-f35b-4749-b172-552dade72653)

Android APK reverse engineering toolkit. Covers the full analysis pipeline from first-pass static scan through dynamic instrumentation, traffic interception, gadget injection, and trust/attestation testing.



---

## What it does

| Stage | What Frieza adds |
|---|---|
| **Static analysis** | LIEF binary scan of ELF/DEX/OAT; manifest + permission extraction; signing cert inspection; obfuscation scoring; endpoint extraction |
| **Decompilation** | JADX integration — decompile APK to Java and merge findings into the static report |
| **Vulnerability scan** | Semgrep against decompiled Java (`p/android`, `p/java` rulesets) |
| **Dynamic plan** | Auto-selects a Frida hook profile and attach strategy from the static report |
| **Frida hooks** | Five graduated profiles: `observe` → `attest` → `network` → `native` → `hardened` |
| **Pinning bypass** | SSLContext, OkHttp3, TrustManagerImpl, Retrofit, Volley, Apache HTTP, Conscrypt |
| **Anti-detection** | Build property spoofing, root artifact hiding, TracerPid/proc masking, Xposed suppression, process list filtering |
| **Gadget injection** | Automated smali patching to embed Frida Gadget for jailed/non-debuggable targets |
| **Repackaging** | NSC injection + gadget embedding + apktool rebuild + zipalign + sign |
| **Trust verifier** | Server-side policy engine: nonce binding, replay prevention, velocity controls, attestation freshness |
| **MCP server** | Full toolkit exposed as an AI agent interface (Claude/Codex) |

---

## Install

```bash
pip install -e ".[dev]"
```

Verify:

```bash
frieza --version
frieza healthcheck
```

`frieza healthcheck` lists every optional tool with install hints. Static analysis works on any platform. Dynamic analysis, repackaging, and trust tools require Windows + PowerShell + ADB + Frida.

---

## Quick start

```bash
# Create an isolated workspace session for one APK
frieza session analyze --apk target.apk --engagement bugbounty

# Full analysis pipeline: binary scan + JADX decompile + semgrep vuln scan
frieza static --apk target.apk --decompile --vulnscan --plan
```

---

## Static Analysis

### Binary scan (all platforms)

```bash
frieza static --apk target.apk
```

Produces a JSON report in the active session `static/` directory containing:
- APK inventory (file counts, extension breakdown)
- AndroidManifest permissions — dangerous and high-risk classified
- Signing certificate (subject, issuer, SHA-256 fingerprint, debug-signed flag)
- Obfuscation score (ProGuard/R8 class name analysis)
- Native library analysis: ELF imports, JNI exports, TLS stack hints, anti-debug candidates
- DEX/OAT/VDEX/ART summaries (class/method counts)
- Pattern matches: attestation, pinning, crypto, JNI, anti-instrumentation, root/emulator
- Extracted HTTP/S endpoints
- Recommended Frida profile + attach strategy

### Full pipeline (JADX + semgrep)

```bash
frieza static --apk target.apk --decompile --vulnscan
```

Requires `jadx` and `semgrep` in PATH (see `frieza healthcheck`). Decompiles to Java, merges source findings into the binary report, and runs semgrep vulnerability scan against the Java output.

### Scan a decompiled tree

```bash
frieza static --source-dir path/to/apktool_out
```

### Generate a dynamic execution plan

```bash
frieza static --apk target.apk --plan
```

---

## Dynamic Analysis

Requires Windows + ADB + `frida-server` running on the target device.

### Hook profiles

| Profile | What it hooks |
|---|---|
| `observe` | OkHttp3 URLs, MAC/hash algorithm names, Play Integrity calls |
| `attest` | Attestation API calls + cadence measurement |
| `network` | `observe` + full certificate pinning bypass |
| `native` | Native `dlopen`, `ptrace`, `prctl`, `syscall` baseline |
| `hardened` | `network` + anti-instrumentation cloaking + environment spoofing |

```bash
# Low-noise baseline
frieza dynamic --package com.target.app --profile observe

# Network interception with MITM proxy
frieza dynamic --package com.target.app --profile network --mitm

# Late attach for hardened apps
frieza dynamic --package com.target.app --profile hardened --launch-then-attach --delay 10
```

### Native session (from static report)

```bash
frieza native-session --package com.target.app --report path/to/report.json --launch-then-attach --delay 10
```

### Build a hook bundle manually

```bash
frieza hooks --profile hardened --output bundle.js
```

---

## Gadget Injection

For apps that block Frida attach entirely (non-debuggable, integrity-checked).

**Step 1 — Decode the APK:**

```bash
apktool d -f -o decoded/ target.apk
```

**Step 2 — Copy Frida Gadget .so files into the decoded tree:**

```
decoded/lib/arm64-v8a/libgadget.so
decoded/lib/armeabi-v7a/libgadget.so
```

**Step 3 — Patch smali to load the gadget at startup:**

```bash
frieza gadget-patch --decoded-dir decoded/
```

Automatically finds `Application.onCreate` (preferred) or the launcher `Activity.onCreate` and inserts `System.loadLibrary("gadget")`. Reports the injection point and mode (`patched-existing-method` or `appended-method`).

**Step 4 — Rebuild and sign:**

```bash
frieza repack --apk target.apk --nsc --gadget path/to/gadget-root/
```

**Step 5 — Attach Frida to the embedded gadget:**

```powershell
.\scripts\start_gadget_capture.ps1 -HookScript bundle.js -PackageName com.target.app -LaunchPackage
```

---

## Repackaging

Inject a permissive Network Security Config and rebuild (trusts user-installed CAs for MITM):

```bash
frieza repack --apk target.apk --nsc
```

With gadget embedding:

```bash
frieza repack --apk target.apk --nsc --gadget E:\tools\frida-gadget
```

Repacked APK is written to the active session `repacked/` directory.

---

## Trust Verifier

Server-side policy engine for testing attestation, request signing, and transaction controls.

```bash
# Start the verifier (localhost:8787)
frieza trust-server --detach

# Bridge ADB logcat TRUST_E2E events to the verifier
frieza trust-bridge --detach

# Run the end-to-end demo
frieza trust-demo
```

Evidence logs are written to the active session `trust/events.jsonl`.

The verifier enforces:
- Attestation freshness and nonce binding
- Nonce and counter replay prevention
- Request signature verification (HMAC-SHA256)
- Transaction velocity limits
- Owner/IDOR checks
- Graceful degradation during vendor outages

---

## MCP Server

Exposes the full toolkit as an MCP server for Claude/Codex agent workflows.

```bash
frieza mcp-server
```

### Available tools

| Tool | What it does |
|---|---|
| `scan_full_apk` | Full pipeline: binary scan + JADX + semgrep in one call |
| `scan_static_apk` | LIEF binary scan only |
| `scan_decompiled_tree` | Scan an already-decompiled source tree |
| `chat_analyze_apk` | Scan + return markdown summary in one step |
| `summarize_findings` | Render a saved report as markdown |
| `recommend_dynamic_plan` | Build a ready-to-run execution plan from a report |
| `generate_native_hook_plan` | Generate a native interceptor script from a report |
| `build_hook_bundle` | Assemble a Frida hook bundle from a profile |
| `patch_gadget_smali` | Patch a decoded tree to load the Frida Gadget |
| `patch_nsc_and_repack` | Decode, patch NSC, embed gadget, rebuild, sign |
| `start_hardened_session` | Start a Frida dynamic session |
| `start_native_intercept_session` | Start a native-focused Frida session |
| `start_trust_server` | Start the trust verifier |
| `start_trust_adb_bridge` | Start the ADB→verifier bridge |
| `run_trust_demo` | Run the trust simulator demo |
| `decode_play_integrity_token` | Call Google's Play Integrity decode API |
| `bootstrap_analysis_session` | Create an isolated per-APK workspace session |
| `list_apks` | List APKs in the active session |

---

## Workspace

All runtime artifacts are written outside the repository to an external workspace session.

| Path | Contents |
|---|---|
| `<workspace>/sessions/<engagement>/<target>/<session>/input/` | APK inputs |
| `.../static/` | JSON analysis reports |
| `.../generated-hooks/` | Frida hook bundles |
| `.../repacked/` | Rebuilt APKs |
| `.../trust/events.jsonl` | Trust evidence log |

Default workspace root:
- Windows: `%LOCALAPPDATA%\frieza`
- Linux/macOS: `$XDG_DATA_HOME/frieza` or `~/.local/share/frieza`

Override with `--workspace` or `FRIEZA_HOME`. Override active session with `FRIEZA_SESSION`.

---

## Required tools

| Tool | Purpose | Install |
|---|---|---|
| `lief` | Core binary analysis | `pip install lief` |
| `jadx` | APK decompilation | [github.com/skylot/jadx](https://github.com/skylot/jadx/releases) |
| `semgrep` | Vulnerability scanning | `pip install semgrep` |
| `aapt2` / `aapt` | Manifest parsing | Android SDK build-tools |
| `keytool` | Certificate inspection | JDK |
| `adb` | Device communication | Android SDK platform-tools |
| `frida` / `frida-server` | Dynamic instrumentation | `pip install frida-tools` |
| `mitmproxy` | Traffic interception | `pip install mitmproxy` |
| `apktool` | Decode/rebuild APKs | [apktool.org](https://apktool.org) |
| `zipalign` / `apksigner` | Align and sign repacked APKs | Android SDK build-tools |

All tools except `lief` are optional — missing tools are gracefully skipped with a message.
