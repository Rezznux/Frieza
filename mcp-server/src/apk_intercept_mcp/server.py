import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from apk_intercept.workspace import describe_session, trust_log_path
from apk_static_lief.scanner import (
    analyze_apk,
    analyze_apk_full,
    analyze_source_tree,
    build_execution_plan,
    load_report,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


def _json_result(payload: Any, request_id: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _json_error(code: int, message: str, request_id: Any = None) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _write_message(payload: Dict[str, Any]) -> None:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sys.stdout.write(f"Content-Length: {len(raw)}\r\n\r\n")
    sys.stdout.flush()
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def _read_message() -> Dict[str, Any] | None:
    headers: Dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line == b"\r\n":
            break
        decoded = line.decode("utf-8").strip()
        if ":" in decoded:
            key, value = decoded.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = sys.stdin.buffer.read(length)
    return json.loads(body.decode("utf-8"))


def _tool_text(data: Any) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, indent=2, sort_keys=True)}], "isError": False}


def _tool_markdown(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _format_report_as_markdown(report: Dict[str, Any]) -> str:
    target = Path(report.get("target", "unknown")).name
    scanned_at = report.get("scanned_at", "unknown")
    kind = report.get("kind", "apk")
    dynamic = report.get("dynamic_plan", {})
    profile = dynamic.get("profile", "observe")
    findings = report.get("findings", {})
    endpoints = report.get("endpoints", [])
    native_libs = report.get("native_libraries", [])
    dex_files = report.get("dex_files", [])
    inventory = report.get("inventory", {})

    risk_label = {
        "attest": "HIGH - attestation/integrity checks detected",
        "native": "HIGH - native TLS verification detected",
        "network": "MEDIUM - certificate pinning detected",
        "observe": "LOW - no strong hardening indicators",
    }.get(profile, profile)

    lines = [
        f"## Static Analysis: `{target}`",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Scanned | {scanned_at} |",
        f"| Kind | {kind} |",
        f"| Recommended profile | `{profile}` |",
        f"| Risk | {risk_label} |",
        "",
    ]

    rationale = dynamic.get("rationale", [])
    if rationale:
        lines += ["### Why this profile?", ""]
        lines += [f"- {item}" for item in rationale]
        lines.append("")

    active = {key: value for key, value in findings.items() if value}
    if active:
        lines += ["### Security Findings", ""]
        for category, hits in active.items():
            label = category.replace("_", " ").title()
            lines.append(f"**{label}** - {len(hits)} match{'es' if len(hits) != 1 else ''}")
            for hit in hits[:4]:
                lines.append(f"  - `{hit.get('source', '')}`")
            if len(hits) > 4:
                lines.append(f"  - ...and {len(hits) - 4} more")
            lines.append("")
    else:
        lines += ["### Security Findings", "", "_No pattern matches found._", ""]

    if inventory:
        lines += ["### Package Inventory", ""]
        for key, value in inventory.items():
            if isinstance(value, dict):
                continue
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
        lines.append("")

    if native_libs:
        lines += ["### Native Libraries", ""]
        for lib in native_libs[:8]:
            name = Path(lib.get("archive_path") or lib.get("path", "?")).name
            tls = lib.get("tls_stack_hints", [])
            candidates = lib.get("native_candidates", {})
            summary = ", ".join(f"{key}({len(value)})" for key, value in candidates.items() if value)
            parts = [f"`{name}`", f"JNI exports: {len(lib.get('jni_symbols', []))}"]
            if tls:
                parts.append(f"TLS stack: `{', '.join(tls)}`")
            if summary:
                parts.append(f"candidates: {summary}")
            lines.append("- " + "  |  ".join(parts))
        if len(native_libs) > 8:
            lines.append(f"- ...and {len(native_libs) - 8} more")
        lines.append("")

    if dex_files:
        total_classes = sum(item.get("class_count", 0) for item in dex_files)
        total_methods = sum(item.get("method_count", 0) for item in dex_files)
        lines += [
            "### DEX Summary",
            "",
            f"- Files: **{len(dex_files)}**  |  Classes: **{total_classes:,}**  |  Methods: **{total_methods:,}**",
            "",
        ]

    manifest = report.get("manifest", {})
    if manifest and not manifest.get("error"):
        lines += ["### Manifest", ""]
        if manifest.get("package_name"):
            lines.append(f"- **Package:** `{manifest['package_name']}`")
        if manifest.get("version_name"):
            lines.append(f"- **Version:** {manifest['version_name']} (code {manifest.get('version_code', '?')})")
        if manifest.get("min_sdk") is not None:
            lines.append(f"- **SDK:** min={manifest['min_sdk']}  target={manifest.get('target_sdk', '?')}")
        lines.append(f"- **Permissions:** {manifest.get('permission_count', 0)} total")
        dangerous = manifest.get("dangerous_permissions", [])
        if dangerous:
            lines.append(f"- **Dangerous ({len(dangerous)}):** " + ", ".join(f"`{p.split('.')[-1]}`" for p in dangerous[:8]))
            if len(dangerous) > 8:
                lines.append(f"  - ...and {len(dangerous) - 8} more")
        high_risk = manifest.get("high_risk_permissions", [])
        if high_risk:
            lines.append(f"- **High-risk ({len(high_risk)}):** " + ", ".join(f"`{p.split('.')[-1]}`" for p in high_risk))
        lines.append("")

    certs = report.get("certificates", {})
    if certs and not certs.get("error"):
        lines += ["### Signing Certificate", ""]
        if certs.get("is_debug_signed"):
            lines.append("- **WARNING: debug-signed APK** (not suitable for production release)")
        for cert in certs.get("certificates", [])[:2]:
            if cert.get("subject"):
                lines.append(f"- **Subject:** `{cert['subject']}`")
            if cert.get("issuer") and cert.get("issuer") != cert.get("subject"):
                lines.append(f"- **Issuer:** `{cert['issuer']}`")
            if cert.get("sha256_fingerprint"):
                lines.append(f"- **SHA-256:** `{cert['sha256_fingerprint']}`")
            if cert.get("validity"):
                lines.append(f"- **Validity:** {cert['validity']}")
            if cert.get("signature_algorithm"):
                lines.append(f"- **Algorithm:** {cert['signature_algorithm']}")
        lines.append("")

    obfuscation = report.get("obfuscation", {})
    if obfuscation and not obfuscation.get("error"):
        score = obfuscation.get("score", 0)
        label = "likely obfuscated" if obfuscation.get("likely_obfuscated") else "minimal obfuscation"
        lines += ["### Obfuscation", ""]
        lines.append(f"- **Score:** {score}/100 — {label}")
        for indicator in obfuscation.get("indicators", []):
            lines.append(f"  - {indicator}")
        lines.append("")

    vulns = report.get("vulnerabilities", {})
    if vulns:
        lines += ["### Vulnerability Scan (semgrep)", ""]
        if not vulns.get("ok"):
            lines.append(f"- _Scan not available: {vulns.get('error', 'unknown error')}_")
        else:
            count = vulns.get("finding_count", 0)
            lines.append(f"- **{count} finding{'s' if count != 1 else ''}** from semgrep")
            by_severity: Dict[str, List[Any]] = {}
            for f in vulns.get("findings", []):
                by_severity.setdefault(f["severity"], []).append(f)
            for sev in ("ERROR", "WARNING", "INFO"):
                grp = by_severity.get(sev, [])
                if not grp:
                    continue
                lines.append(f"\n**{sev}** ({len(grp)})")
                for finding in grp[:5]:
                    lines.append(f"  - `{finding['rule_id']}` — {finding['file']}:{finding['line']}")
                    if finding.get("message"):
                        lines.append(f"    {finding['message'][:120]}")
                if len(grp) > 5:
                    lines.append(f"  - ...and {len(grp) - 5} more")
        lines.append("")

    decompilation = report.get("decompilation", {})
    if decompilation:
        status = "succeeded" if decompilation.get("ok") else f"failed ({decompilation.get('error', '?')})"
        lines += [f"_Decompilation ({decompilation.get('tool', 'jadx')}): {status}_", ""]

    if endpoints:
        lines += ["### Discovered Endpoints", ""]
        for endpoint in endpoints[:20]:
            lines.append(f"- `{endpoint}`")
        if len(endpoints) > 20:
            lines.append(f"- ...and {len(endpoints) - 20} more (full list in report)")
        lines.append("")

    launch_flag = dynamic.get("launch_then_attach", False)
    delay = dynamic.get("delay_seconds", 0)
    lines += [
        "### Recommended Next Steps",
        "",
        f"1. Run **`recommend_dynamic_plan`** with `report_path: \"{report.get('report_path', '')}\"` for a full execution plan.",
    ]
    if launch_flag:
        lines.append(f"2. Use **late-attach** (delay: {delay}s) - anti-instrumentation indicators detected.")
    if active.get("pinning"):
        lines.append("3. Enable MITM proxy before starting the session - pinning is present.")
    if active.get("attestation"):
        lines.append("4. Review attestation hooks before intercepting traffic - integrity checks will likely fire.")
    lines.append("")
    lines.append(f"_Full report saved to:_ `{report.get('report_path', 'N/A')}`")
    return "\n".join(lines)


def _run_powershell(script_name: str, arguments: List[str], detached: bool = False) -> Dict[str, Any]:
    script_path = REPO_ROOT / "scripts" / script_name
    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)] + arguments
    if detached:
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        process = subprocess.Popen(cmd, cwd=REPO_ROOT, creationflags=creationflags)
        return {"started": True, "pid": process.pid, "command": cmd}
    completed = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return {
        "started": False,
        "command": cmd,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _session_context() -> Dict[str, Any]:
    return describe_session(create_if_missing=True)


def _list_resources() -> List[Dict[str, Any]]:
    session = _session_context()
    static_dir = Path(session["paths"]["static"])
    items: List[Dict[str, Any]] = []
    for path in sorted(static_dir.glob("*.json")):
        items.append({"uri": f"file://{path.as_posix()}", "name": path.name, "mimeType": "application/json"})
    manifest_path = Path(session["manifest_path"])
    if manifest_path.exists():
        items.append({"uri": f"file://{manifest_path.as_posix()}", "name": manifest_path.name, "mimeType": "application/json"})
    trust_log = trust_log_path()
    if trust_log.exists():
        items.append({"uri": f"file://{trust_log.as_posix()}", "name": trust_log.name, "mimeType": "application/jsonl"})
    return items


def _read_resource(uri: str) -> Dict[str, Any]:
    if not uri.startswith("file://"):
        raise ValueError("Only file:// URIs are supported")
    path = Path(uri.removeprefix("file://"))
    data = path.read_text(encoding="utf-8")
    return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": data}]}


TOOLS = [
    {
        "name": "scan_static_apk",
        "description": "Run LIEF-backed static analysis on an APK and emit a JSON report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "output_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "scan_decompiled_tree",
        "description": "Run static analysis on a decompiled tree or extracted artifact directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_dir": {"type": "string"},
                "output_path": {"type": "string"},
            },
            "required": ["source_dir"],
        },
    },
    {
        "name": "build_hook_bundle",
        "description": "Build a Frida hook bundle from the named profile.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string"},
                "output_path": {"type": "string"},
            },
            "required": ["profile"],
        },
    },
    {
        "name": "recommend_dynamic_plan",
        "description": "Build a ready-to-run dynamic execution plan from a static report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_path": {"type": "string"},
                "package_name": {"type": "string"},
                "device_id": {"type": "string"},
            },
            "required": ["report_path"],
        },
    },
    {
        "name": "generate_native_hook_plan",
        "description": "Generate a native interception hook script from a static report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_path": {"type": "string"},
                "output_script_path": {"type": "string"},
            },
            "required": ["report_path"],
        },
    },
    {
        "name": "patch_gadget_smali",
        "description": (
            "Patch a decoded apktool tree to inject a System.loadLibrary('gadget') call at startup. "
            "Finds Application.onCreate (preferred) or launcher Activity.onCreate and inserts the "
            "minimal smali snippet. Run this after decoding with apktool and before rebuilding."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "decoded_dir": {
                    "type": "string",
                    "description": "Path to the apktool decoded directory.",
                },
                "library_name": {
                    "type": "string",
                    "description": "Library name for System.loadLibrary (default: gadget).",
                },
            },
            "required": ["decoded_dir"],
        },
    },
    {
        "name": "patch_nsc_and_repack",
        "description": "Decode, optionally patch NSC, optionally embed gadget libs, rebuild, align, and sign an APK.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "output_dir": {"type": "string"},
                "inject_network_security_config": {"type": "boolean"},
                "embed_gadget": {"type": "boolean"},
                "gadget_root": {"type": "string"},
                "keystore_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "start_native_intercept_session",
        "description": "Generate native interceptor hooks and start a native-focused Frida session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {"type": "string"},
                "report_path": {"type": "string"},
                "device_id": {"type": "string"},
                "launch_then_attach": {"type": "boolean"},
                "delay_seconds": {"type": "integer"},
            },
            "required": ["package_name", "report_path"],
        },
    },
    {
        "name": "classify_runtime_block",
        "description": "Classify likely runtime block surface and enforcement mode from log text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_path": {"type": "string"},
                "input_text": {"type": "string"},
            },
        },
    },
    {
        "name": "decode_play_integrity_token",
        "description": "Call the Play Integrity decode endpoint with a supplied or environment bearer token.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {"type": "string"},
                "integrity_token": {"type": "string"},
                "bearer_token": {"type": "string"},
            },
            "required": ["package_name", "integrity_token"],
        },
    },
    {
        "name": "start_hardened_session",
        "description": "Start a dynamic session with the existing hardened session script.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {"type": "string"},
                "profile": {"type": "string"},
                "device_id": {"type": "string"},
                "launch_then_attach": {"type": "boolean"},
                "delay_seconds": {"type": "integer"},
                "enable_mitm_proxy": {"type": "boolean"},
            },
            "required": ["package_name"],
        },
    },
    {
        "name": "start_trust_server",
        "description": "Start the trust-e2e verifier server in a detached process.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
            },
        },
    },
    {
        "name": "start_trust_adb_bridge",
        "description": "Start the adb-to-trust bridge in a detached process.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "server_base_url": {"type": "string"},
            },
        },
    },
    {
        "name": "run_trust_demo",
        "description": "Run the end-to-end trust simulator demo.",
        "inputSchema": {
            "type": "object",
            "properties": {"port": {"type": "integer"}},
        },
    },
    {
        "name": "bootstrap_analysis_session",
        "description": (
            "Create an isolated per-APK workspace session and make it active. "
            "Call this once per APK before running any scan or analysis tool. "
            "Returns session paths so subsequent tools write artifacts to the right place."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Absolute path to the APK file. The APK is copied into the session input/ folder.",
                },
                "engagement": {
                    "type": "string",
                    "description": "Engagement label used to organise sessions (default: 'analysis').",
                },
                "workspace": {
                    "type": "string",
                    "description": "Override workspace root. Defaults to FRIEZA_HOME or the platform data directory.",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "list_apks",
        "description": (
            "List all APK files available in the active workspace session input folder, grouped by app. "
            "Returns each file's name, full path, size, and whether a static report already exists."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "summarize_findings",
        "description": (
            "Load a saved static analysis report and return a human-readable markdown summary "
            "suitable for reading in a chat conversation. Covers risk profile, security findings, "
            "native libraries, DEX stats, discovered endpoints, and recommended next steps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_path": {
                    "type": "string",
                    "description": "Path to a JSON report produced by scan_static_apk or scan_decompiled_tree.",
                },
            },
            "required": ["report_path"],
        },
    },
    {
        "name": "chat_analyze_apk",
        "description": (
            "Run a full LIEF static analysis on an APK and immediately return a human-readable "
            "markdown summary of all findings in one step. Best for getting a quick conversational overview."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Absolute path to the APK file to analyse.",
                },
                "output_path": {
                    "type": "string",
                    "description": "Optional path for the JSON report. Defaults to the active workspace session static dir.",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "scan_full_apk",
        "description": (
            "Run the complete analysis pipeline on an APK: LIEF binary scan, manifest/permission analysis, "
            "certificate inspection, obfuscation scoring, optional JADX decompilation, and optional semgrep "
            "vulnerability scan. Returns a rich JSON report and human-readable markdown summary. "
            "Requires jadx in PATH for decompilation; requires semgrep for vulnerability scan."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Absolute path to the APK file.",
                },
                "output_path": {
                    "type": "string",
                    "description": "Optional path for the JSON report.",
                },
                "decompile": {
                    "type": "boolean",
                    "description": "Decompile with JADX and merge Java source findings (default: true).",
                },
                "vulnscan": {
                    "type": "boolean",
                    "description": "Run semgrep vulnerability scan on decompiled source (default: true).",
                },
            },
            "required": ["apk_path"],
        },
    },
]


def _handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "bootstrap_analysis_session":
        from apk_intercept.workspace import bootstrap_analysis_session

        result = bootstrap_analysis_session(
            apk_path=arguments["apk_path"],
            workspace_root=arguments.get("workspace"),
            engagement=arguments.get("engagement", "analysis"),
        )
        return _tool_text(result)
    if name == "scan_static_apk":
        return _tool_text(analyze_apk(arguments["apk_path"], arguments.get("output_path")))
    if name == "scan_decompiled_tree":
        return _tool_text(analyze_source_tree(arguments["source_dir"], arguments.get("output_path")))
    if name == "build_hook_bundle":
        args = ["-Profile", arguments["profile"]]
        if arguments.get("output_path"):
            args += ["-OutputPath", arguments["output_path"]]
        return _tool_text(_run_powershell("build_hook_bundle.ps1", args))
    if name == "recommend_dynamic_plan":
        report = load_report(arguments["report_path"])
        plan = build_execution_plan(
            report,
            package_name=arguments.get("package_name"),
            device_id=arguments.get("device_id"),
        )
        return _tool_text(plan)
    if name == "generate_native_hook_plan":
        args = ["-ReportPath", arguments["report_path"]]
        if arguments.get("output_script_path"):
            args += ["-OutputScriptPath", arguments["output_script_path"]]
        return _tool_text(_run_powershell("generate_native_hook_plan.ps1", args))
    if name == "patch_gadget_smali":
        from apk_intercept.gadget_repack import patch_decoded_tree_for_gadget
        result = patch_decoded_tree_for_gadget(
            arguments["decoded_dir"],
            library_name=arguments.get("library_name", "gadget"),
        )
        return _tool_text(result)
    if name == "patch_nsc_and_repack":
        args = ["-ApkPath", arguments["apk_path"]]
        if arguments.get("output_dir"):
            args += ["-OutputDir", arguments["output_dir"]]
        if arguments.get("inject_network_security_config"):
            args += ["-InjectNetworkSecurityConfig"]
        if arguments.get("embed_gadget"):
            args += ["-EmbedGadget"]
        if arguments.get("gadget_root"):
            args += ["-GadgetRoot", arguments["gadget_root"]]
        if arguments.get("keystore_path"):
            args += ["-KeystorePath", arguments["keystore_path"]]
        return _tool_text(_run_powershell("patch_nsc_and_repack.ps1", args))
    if name == "start_native_intercept_session":
        args = ["-PackageName", arguments["package_name"], "-ReportPath", arguments["report_path"]]
        if arguments.get("device_id"):
            args += ["-DeviceId", arguments["device_id"]]
        if arguments.get("launch_then_attach"):
            args += ["-LaunchThenAttach"]
        if arguments.get("delay_seconds") is not None:
            args += ["-DelaySeconds", str(arguments["delay_seconds"])]
        return _tool_text(_run_powershell("start_native_intercept_session.ps1", args, detached=True))
    if name == "classify_runtime_block":
        args: List[str] = []
        if arguments.get("log_path"):
            args += ["-LogPath", arguments["log_path"]]
        if arguments.get("input_text"):
            args += ["-InputText", arguments["input_text"]]
        return _tool_text(_run_powershell("classify_runtime_block.ps1", args))
    if name == "decode_play_integrity_token":
        args = ["-PackageName", arguments["package_name"], "-IntegrityToken", arguments["integrity_token"]]
        if arguments.get("bearer_token"):
            args += ["-BearerToken", arguments["bearer_token"]]
        return _tool_text(_run_powershell("decode_play_integrity_token.ps1", args))
    if name == "start_hardened_session":
        args = ["-PackageName", arguments["package_name"]]
        if arguments.get("profile"):
            args += ["-Profile", arguments["profile"]]
        if arguments.get("device_id"):
            args += ["-DeviceId", arguments["device_id"]]
        if arguments.get("launch_then_attach"):
            args += ["-LaunchThenAttach"]
        if arguments.get("delay_seconds") is not None:
            args += ["-DelaySeconds", str(arguments["delay_seconds"])]
        if arguments.get("enable_mitm_proxy"):
            args += ["-EnableMitmProxy"]
        return _tool_text(_run_powershell("start_hardened_session.ps1", args, detached=True))
    if name == "start_trust_server":
        args: List[str] = []
        if arguments.get("host"):
            args += ["-Host", arguments["host"]]
        if arguments.get("port") is not None:
            args += ["-Port", str(arguments["port"])]
        return _tool_text(_run_powershell("start_trust_server.ps1", args, detached=True))
    if name == "start_trust_adb_bridge":
        args: List[str] = []
        if arguments.get("device_id"):
            args += ["-DeviceId", arguments["device_id"]]
        if arguments.get("server_base_url"):
            args += ["-ServerBaseUrl", arguments["server_base_url"]]
        return _tool_text(_run_powershell("start_trust_adb_bridge.ps1", args, detached=True))
    if name == "run_trust_demo":
        args: List[str] = []
        if arguments.get("port") is not None:
            args += ["-Port", str(arguments["port"])]
        return _tool_text(_run_powershell("run_trust_demo.ps1", args))
    if name == "list_apks":
        session = _session_context()
        input_dir = Path(session["paths"]["input"])
        static_dir = Path(session["paths"]["static"])
        apks: List[Dict[str, Any]] = []
        for apk_path in sorted(input_dir.rglob("*.apk")):
            report_path = static_dir / f"{apk_path.stem}-static.json"
            apks.append(
                {
                    "name": apk_path.name,
                    "path": str(apk_path),
                    "app": apk_path.parent.name,
                    "size_mb": round(apk_path.stat().st_size / 1_048_576, 2),
                    "has_report": report_path.exists(),
                    "report_path": str(report_path) if report_path.exists() else None,
                }
            )
        lines = ["## Available APKs", "", f"Workspace session: `{session['session_path']}`", ""]
        if not apks:
            lines.append("_No APK files found in the active workspace session input folder._")
        else:
            current_app = None
            for item in apks:
                if item["app"] != current_app:
                    current_app = item["app"]
                    lines.append(f"### {current_app}")
                report_note = " [report exists]" if item["has_report"] else ""
                lines.append(f"- `{item['name']}` ({item['size_mb']} MB){report_note}")
                lines.append(f"  - path: `{item['path']}`")
                if item["report_path"]:
                    lines.append(f"  - report: `{item['report_path']}`")
            lines.append("")
            lines.append("_Pass the `path` value to `chat_analyze_apk` or `scan_static_apk`._")
        return _tool_markdown("\n".join(lines))
    if name == "summarize_findings":
        report = load_report(arguments["report_path"])
        return _tool_markdown(_format_report_as_markdown(report))
    if name == "chat_analyze_apk":
        report = analyze_apk(arguments["apk_path"], arguments.get("output_path"))
        return _tool_markdown(_format_report_as_markdown(report))
    if name == "scan_full_apk":
        report = analyze_apk_full(
            arguments["apk_path"],
            arguments.get("output_path"),
            decompile=arguments.get("decompile", True),
            vulnscan=arguments.get("vulnscan", True),
        )
        return _tool_markdown(_format_report_as_markdown(report))
    raise ValueError(f"Unknown tool: {name}")


def main() -> int:
    while True:
        request = _read_message()
        if request is None:
            return 0
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        try:
            if method == "initialize":
                response = {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "frieza-mcp", "version": "0.2.0"},
                    "capabilities": {"tools": {}, "resources": {}},
                }
                _write_message(_json_result(response, request_id))
                continue
            if method == "notifications/initialized":
                continue
            if method == "tools/list":
                _write_message(_json_result({"tools": TOOLS}, request_id))
                continue
            if method == "tools/call":
                result = _handle_tool_call(params["name"], params.get("arguments", {}))
                _write_message(_json_result(result, request_id))
                continue
            if method == "resources/list":
                _write_message(_json_result({"resources": _list_resources()}, request_id))
                continue
            if method == "resources/read":
                _write_message(_json_result(_read_resource(params["uri"]), request_id))
                continue
            _write_message(_json_error(-32601, f"Method not found: {method}", request_id))
        except Exception as exc:  # noqa: BLE001
            _write_message(_json_error(-32000, str(exc), request_id))


if __name__ == "__main__":
    raise SystemExit(main())
