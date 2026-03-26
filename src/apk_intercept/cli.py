"""apkit - unified CLI for APK Intercept Kit.

Static analysis commands work on any platform (Linux, macOS, Windows).
Dynamic analysis, repack, and hook-bundle commands require Windows with
adb, frida, and (for repack) apktool / apksigner in PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
PROFILES_FILE = REPO_ROOT / "profiles" / "hook_profiles.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_windows(command: str) -> None:
    if sys.platform != "win32":
        print(
            f"ERROR: '{command}' requires Windows (PowerShell + ADB + Frida).\n"
            "Static analysis commands work on all platforms.",
            file=sys.stderr,
        )
        sys.exit(1)


def _run_ps(script: str, args: list[str], *, detached: bool = False) -> int:
    script_path = SCRIPTS_DIR / script
    if not script_path.exists():
        print(f"ERROR: script not found: {script_path}", file=sys.stderr)
        return 1
    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)] + args
    if detached:
        subprocess.Popen(cmd, cwd=REPO_ROOT, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        return 0
    return subprocess.run(cmd, cwd=REPO_ROOT).returncode


def _require_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _configure_workspace_environment(args: argparse.Namespace) -> None:
    from apk_intercept.workspace import SESSION_ENV, WORKSPACE_ENV

    if getattr(args, "workspace", None):
        os.environ[WORKSPACE_ENV] = str(Path(args.workspace).expanduser().resolve())
    if getattr(args, "session", None):
        os.environ[SESSION_ENV] = str(Path(args.session).expanduser().resolve())


# ---------------------------------------------------------------------------
# static
# ---------------------------------------------------------------------------

def cmd_static(args: argparse.Namespace) -> int:
    from apk_static_lief.scanner import analyze_apk, analyze_source_tree, build_execution_plan

    if args.apk:
        result = analyze_apk(args.apk, args.output)
    else:
        result = analyze_source_tree(args.source_dir, args.output)

    summary = {
        "kind": result["kind"],
        "target": result["target"],
        "report_path": result["report_path"],
        "dynamic_plan": result["dynamic_plan"],
        "inventory": result["inventory"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    if args.plan:
        plan = build_execution_plan(result, package_name=args.package, device_id=args.device)
        print("\n--- Execution Plan ---")
        print(json.dumps(plan, indent=2, sort_keys=True))

    return 0


# ---------------------------------------------------------------------------
# dynamic
# ---------------------------------------------------------------------------

def cmd_dynamic(args: argparse.Namespace) -> int:
    _require_windows("dynamic")

    ps_args: list[str] = []

    if args.select:
        ps_args += ["-SelectFromDevice"]
        if args.device:
            ps_args += ["-DeviceId", args.device]
    else:
        ps_args += ["-PackageName", args.package]
        if args.device:
            ps_args += ["-DeviceId", args.device]

    ps_args += ["-Profile", args.profile]

    if args.mitm:
        ps_args += ["-EnableMitmProxy", "-ProxyHost", args.proxy_host, "-ProxyPort", str(args.proxy_port)]

    if args.launch_then_attach:
        ps_args += ["-LaunchThenAttach", "-DelaySeconds", str(args.delay)]
    elif args.attach_only:
        ps_args += ["-AttachOnly"]

    if args.app_filter:
        ps_args += ["-AppFilter", args.app_filter]

    if args.include_system:
        ps_args += ["-IncludeSystemApps"]

    return _run_ps("start_hardened_session.ps1", ps_args)


# ---------------------------------------------------------------------------
# native-session
# ---------------------------------------------------------------------------

def cmd_native(args: argparse.Namespace) -> int:
    _require_windows("native-session")

    ps_args = ["-PackageName", args.package, "-ReportPath", args.report]
    if args.device:
        ps_args += ["-DeviceId", args.device]
    if args.launch_then_attach:
        ps_args += ["-LaunchThenAttach", "-DelaySeconds", str(args.delay)]

    return _run_ps("start_native_intercept_session.ps1", ps_args)


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

def cmd_plan(args: argparse.Namespace) -> int:
    from apk_static_lief.scanner import build_execution_plan, load_report

    report = load_report(args.report)
    plan = build_execution_plan(report, package_name=args.package, device_id=args.device)
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# hooks
# ---------------------------------------------------------------------------

def cmd_hooks(args: argparse.Namespace) -> int:
    from apk_intercept.workspace import artifact_path

    if not PROFILES_FILE.exists():
        print(f"ERROR: profiles file not found: {PROFILES_FILE}", file=sys.stderr)
        return 1

    profiles = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
    selected = next((p for p in profiles if p["name"] == args.profile), None)
    if not selected:
        print(f"ERROR: profile '{args.profile}' not found in {PROFILES_FILE}", file=sys.stderr)
        return 1

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = artifact_path("generated_hooks", f"apk-intercept-{args.profile}-bundle.js")

    parts = [
        f"// generated bundle profile={args.profile}",
        "// generated by apkit hooks",
    ]
    for hook_rel in selected["hooks"]:
        hook_path = REPO_ROOT / hook_rel
        if not hook_path.exists():
            print(f"ERROR: hook file not found: {hook_path}", file=sys.stderr)
            return 1
        parts += ["", f"// BEGIN {hook_rel}", hook_path.read_text(encoding="utf-8"), f"// END {hook_rel}"]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(str(out_path))
    return 0


# ---------------------------------------------------------------------------
# repack
# ---------------------------------------------------------------------------

def cmd_repack(args: argparse.Namespace) -> int:
    _require_windows("repack")

    ps_args = ["-ApkPath", args.apk]
    if args.output_dir:
        ps_args += ["-OutputDir", args.output_dir]
    if args.nsc:
        ps_args += ["-InjectNetworkSecurityConfig"]
    if args.gadget:
        ps_args += ["-EmbedGadget", "-GadgetRoot", args.gadget]
    if args.keystore:
        ps_args += ["-KeystorePath", args.keystore]

    return _run_ps("patch_nsc_and_repack.ps1", ps_args)


# ---------------------------------------------------------------------------
# trust-server / trust-bridge / trust-demo
# ---------------------------------------------------------------------------

def cmd_trust_server(args: argparse.Namespace) -> int:
    _require_windows("trust-server")
    ps_args: list[str] = []
    if args.host:
        ps_args += ["-Host", args.host]
    if args.port:
        ps_args += ["-Port", str(args.port)]
    return _run_ps("start_trust_server.ps1", ps_args, detached=args.detach)


def cmd_trust_bridge(args: argparse.Namespace) -> int:
    _require_windows("trust-bridge")
    ps_args: list[str] = []
    if args.device:
        ps_args += ["-DeviceId", args.device]
    if args.server_url:
        ps_args += ["-ServerBaseUrl", args.server_url]
    return _run_ps("start_trust_adb_bridge.ps1", ps_args, detached=args.detach)


def cmd_trust_demo(args: argparse.Namespace) -> int:
    _require_windows("trust-demo")
    ps_args: list[str] = []
    if args.port:
        ps_args += ["-Port", str(args.port)]
    return _run_ps("run_trust_demo.ps1", ps_args)


# ---------------------------------------------------------------------------
# healthcheck
# ---------------------------------------------------------------------------

def cmd_healthcheck(_args: argparse.Namespace) -> int:
    required = ["adb", "frida", "mitmproxy"]
    optional = ["apktool", "zipalign", "apksigner", "keytool", "frida-ps"]

    ok = True
    print("[*] Required tools:")
    for tool in required:
        found = _require_tool(tool)
        status = "[+]" if found else "[-]"
        print(f"  {status} {tool}")
        if not found:
            ok = False

    print("[*] Optional tools (repack / frida-ps):")
    for tool in optional:
        found = _require_tool(tool)
        status = "[+]" if found else "[ ]"
        print(f"  {status} {tool}")

    if sys.platform == "win32":
        print("[*] Platform: Windows - all modes available")
    else:
        print(f"[*] Platform: {sys.platform} - static analysis only (dynamic/repack require Windows)")

    return 0 if ok else 1


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

def cmd_mcp(_args: argparse.Namespace) -> int:
    _require_windows("mcp-server")
    return _run_ps("start_mcp_server.ps1", [])


# ---------------------------------------------------------------------------
# session
# ---------------------------------------------------------------------------

def cmd_session(args: argparse.Namespace) -> int:
    from apk_intercept.workspace import (
        bootstrap_analysis_session,
        create_session,
        describe_session,
        migrate_repo_artifacts,
        set_active_session,
    )

    if args.session_command == "new":
        result = create_session(
            args.workspace,
            session_path=args.path,
            engagement=args.engagement,
            target=args.target,
            name=args.name,
            activate=args.activate,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.session_command == "analyze":
        try:
            result = bootstrap_analysis_session(
                apk_path=args.apk,
                workspace_root=args.workspace,
                session_path=args.path,
                engagement=args.engagement,
                target=args.target,
                name=args.name,
                copy_apk=not args.reference_only,
                activate=args.activate,
            )
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.session_command == "show":
        try:
            result = describe_session(args.workspace, args.path, create_if_missing=False)
        except FileNotFoundError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.session_command == "activate":
        session_path = set_active_session(args.path, args.workspace)
        print(json.dumps({"session_path": str(session_path)}, indent=2, sort_keys=True))
        return 0

    if args.session_command == "migrate":
        result = migrate_repo_artifacts(
            REPO_ROOT,
            workspace_root=args.workspace,
            session_path=args.path,
            include_target_hooks=not args.skip_target_hooks,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    print("ERROR: missing session command", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apkit",
        description=(
            "APK Intercept Kit - static analysis (all platforms) and "
            "dynamic instrumentation (Windows + ADB + Frida)."
        ),
    )
    parser.add_argument("--version", action="version", version="apkit 0.3.0")
    parser.add_argument(
        "--workspace",
        metavar="DIR",
        help="Workspace root for reports, repacks, logs, and session state (default: APKIT_HOME or platform data dir).",
    )
    parser.add_argument(
        "--session",
        metavar="DIR",
        help="Explicit session path. If omitted, the active session is used or an ad-hoc one is created on first write.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("static", help="Static analysis of an APK or decompiled source tree")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--apk", metavar="PATH", help="Path to APK file")
    g.add_argument("--source-dir", metavar="DIR", help="Path to decompiled source tree or artifact directory")
    p.add_argument("--output", metavar="PATH", help="JSON report output path (default: active workspace session static dir)")
    p.add_argument("--plan", action="store_true", help="Print full execution plan after scan")
    p.add_argument("--package", metavar="NAME", help="Package name, used in plan output")
    p.add_argument("--device", metavar="SERIAL", help="Device serial, used in plan output")

    p = sub.add_parser(
        "dynamic",
        help="Start a dynamic Frida session [Windows only]",
        description="Requires Windows with adb and frida-server running on the device.",
    )
    pg = p.add_mutually_exclusive_group(required=True)
    pg.add_argument("--package", metavar="NAME", help="Package name to instrument")
    pg.add_argument("--select", action="store_true", help="Interactively select device and package")
    p.add_argument("--profile", choices=["attest", "observe", "network", "native", "hardened"], default="observe")
    p.add_argument("--device", metavar="SERIAL", help="ADB device serial")
    p.add_argument("--app-filter", metavar="STR", help="Pre-filter package list (used with --select)")
    p.add_argument("--include-system", action="store_true", help="Include system apps in picker")
    p.add_argument("--mitm", action="store_true", help="Configure MITM proxy on device before attaching")
    p.add_argument("--proxy-host", default="127.0.0.1", metavar="HOST")
    p.add_argument("--proxy-port", type=int, default=8080, metavar="PORT")
    p.add_argument("--launch-then-attach", action="store_true", help="Launch app first, then attach after delay")
    p.add_argument("--delay", type=int, default=8, metavar="SECONDS", help="Delay before attach (default: 8)")
    p.add_argument("--attach-only", action="store_true", help="Attach to already-running process")

    p = sub.add_parser(
        "native-session",
        help="Generate native interceptor hooks and start a native-focused session [Windows only]",
    )
    p.add_argument("--package", required=True, metavar="NAME")
    p.add_argument("--report", required=True, metavar="PATH", help="Static report JSON from 'apkit static'")
    p.add_argument("--device", metavar="SERIAL")
    p.add_argument("--launch-then-attach", action="store_true")
    p.add_argument("--delay", type=int, default=10, metavar="SECONDS")

    p = sub.add_parser("plan", help="Build a dynamic execution plan from a static report")
    p.add_argument("--report", required=True, metavar="PATH", help="Static report JSON")
    p.add_argument("--package", metavar="NAME", help="Package name for script args in plan")
    p.add_argument("--device", metavar="SERIAL", help="Device serial for script args in plan")

    p = sub.add_parser("hooks", help="Assemble a Frida hook bundle from a named profile")
    p.add_argument("--profile", required=True, choices=["attest", "observe", "network", "native", "hardened"])
    p.add_argument("--output", metavar="PATH", help="Output .js path (default: active workspace session generated-hooks dir)")

    p = sub.add_parser(
        "repack",
        help="Patch NSC and/or embed Frida gadget, then rebuild and resign APK [Windows only]",
        description=(
            "Requires apktool, zipalign, apksigner (and optionally keytool) in PATH. "
            "A debug keystore is auto-generated if --keystore is not supplied."
        ),
    )
    p.add_argument("--apk", required=True, metavar="PATH", help="Path to the original APK")
    p.add_argument("--output-dir", metavar="DIR", help="Output directory (default: active workspace session repacked dir)")
    p.add_argument("--nsc", action="store_true", help="Inject permissive NetworkSecurityConfig (trusts user CAs)")
    p.add_argument("--gadget", metavar="DIR", help="Path containing per-ABI frida-gadget dirs")
    p.add_argument("--keystore", metavar="PATH", help="Keystore for signing (auto-generated if omitted)")

    p = sub.add_parser("trust-server", help="Start the trust-e2e verifier server [Windows only]")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--detach", action="store_true", help="Start in a detached process")

    p = sub.add_parser("trust-bridge", help="Bridge adb logcat TRUST_E2E events to the verifier [Windows only]")
    p.add_argument("--device", metavar="SERIAL")
    p.add_argument("--server-url", metavar="URL", default="http://127.0.0.1:8787")
    p.add_argument("--detach", action="store_true")

    p = sub.add_parser("trust-demo", help="Run the end-to-end trust simulator demo [Windows only]")
    p.add_argument("--port", type=int, default=8787)

    sub.add_parser("healthcheck", help="Verify required tools are available in PATH")
    sub.add_parser("mcp-server", help="Start the MCP orchestration server [Windows only]")

    p = sub.add_parser("session", help="Manage the external workspace session used for runtime artifacts")
    session_sub = p.add_subparsers(dest="session_command", metavar="<session-command>")

    ps = session_sub.add_parser("new", help="Create a new workspace session and make it active")
    ps.add_argument("--engagement", default="default", metavar="NAME")
    ps.add_argument("--target", default="general", metavar="NAME")
    ps.add_argument("--name", metavar="NAME", help="Optional session directory name")
    ps.add_argument("--path", metavar="DIR", help="Use an explicit session directory path")
    ps.add_argument("--activate", action=argparse.BooleanOptionalAction, default=True)

    ps = session_sub.add_parser(
        "analyze",
        help="Create a fresh per-APK analysis session, optionally seeding the APK into input/",
    )
    ps.add_argument("--apk", required=True, metavar="PATH", help="Target APK to seed into the new session")
    ps.add_argument("--engagement", default="analysis", metavar="NAME")
    ps.add_argument("--target", metavar="NAME", help="Target slug (defaults to --apk file stem)")
    ps.add_argument("--name", metavar="NAME", help="Optional session directory name")
    ps.add_argument("--path", metavar="DIR", help="Use an explicit session directory path")
    ps.add_argument(
        "--reference-only",
        action="store_true",
        help="Do not copy --apk into input/; keep only a reference in manifest metadata",
    )
    ps.add_argument("--activate", action=argparse.BooleanOptionalAction, default=True)

    ps = session_sub.add_parser("show", help="Show the active or specified workspace session")
    ps.add_argument("--path", metavar="DIR", help="Specific session directory to inspect")

    ps = session_sub.add_parser("activate", help="Mark an existing workspace session as active")
    ps.add_argument("--path", required=True, metavar="DIR", help="Existing session directory")

    ps = session_sub.add_parser("migrate", help="Move repo-local artifacts and target-specific hooks into the workspace session")
    ps.add_argument("--path", metavar="DIR", help="Specific session directory to receive migrated data")
    ps.add_argument("--skip-target-hooks", action="store_true", help="Do not move target-specific hooks from hooks/")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    _configure_workspace_environment(args)

    dispatch = {
        "static": cmd_static,
        "dynamic": cmd_dynamic,
        "native-session": cmd_native,
        "plan": cmd_plan,
        "hooks": cmd_hooks,
        "repack": cmd_repack,
        "trust-server": cmd_trust_server,
        "trust-bridge": cmd_trust_bridge,
        "trust-demo": cmd_trust_demo,
        "healthcheck": cmd_healthcheck,
        "mcp-server": cmd_mcp,
        "session": cmd_session,
    }

    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        return 1

    try:
        return fn(args) or 0
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
