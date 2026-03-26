import json
import re
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import lief
from apk_intercept.workspace import artifact_path

TEXT_EXTENSIONS = {
    ".xml",
    ".txt",
    ".json",
    ".properties",
    ".cfg",
    ".conf",
    ".js",
    ".kt",
    ".java",
    ".smali",
    ".yml",
    ".yaml",
}
MAX_TEXT_BYTES = 512 * 1024
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
PATTERNS = {
    "attestation": re.compile(r"IntegrityManager|SafetyNet|attest|attestation|device_integrity", re.I),
    "pinning": re.compile(r"CertificatePinner|TrustManager|HostnameVerifier|X509TrustManager|pinning", re.I),
    "crypto": re.compile(r"HmacSHA|MessageDigest|Signature|Cipher|Mac|getInstance|SecretKeySpec", re.I),
    "jni_native": re.compile(r"System\.loadLibrary|JNI_OnLoad|native\s", re.I),
    "anti_instrumentation": re.compile(r"TracerPid|ptrace|frida|xposed|lsposed|isDebuggerConnected|/proc/self/maps", re.I),
    "root_emu": re.compile(r"magisk|/system/xbin/su|ro\.secure|ro\.debuggable|goldfish|qemu|test-keys", re.I),
}
NATIVE_SYMBOL_PATTERNS = {
    "tls_verify": [
        "SSL_CTX_set_custom_verify",
        "SSL_set_custom_verify",
        "SSL_CTX_set_verify",
        "X509_verify_cert",
        "mbedtls_ssl_conf_verify",
        "SSL_get_peer_certificate",
    ],
    "crypto_signing": [
        "HMAC_",
        "EVP_",
        "SHA256_",
        "ECDSA_",
    ],
    "anti_debug": [
        "ptrace",
        "syscall",
        "prctl",
        "kill",
        "tgkill",
        "raise",
    ],
    "anti_instrumentation": [
        "/proc/self/maps",
        "/proc/net/tcp",
        "frida",
        "gum-js-loop",
        "linjector",
        "JVMTI",
        "TracerPid",
        "readlink",
        "open",
        "fopen",
    ],
}
TLS_STACK_HINTS = {
    "cronet": ["cronet", "Cronet"],
    "conscrypt": ["conscrypt", "TrustManagerImpl"],
    "boringssl": ["boringssl", "libssl.so", "SSL_CTX_"],
    "mbedtls": ["mbedtls"],
    "okhttp_java": ["okhttp3", "CertificatePinner"],
    "webview": ["WebViewClient", "android.webkit"],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_iter(value: Any) -> List[Any]:
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return []


def _ensure_report_path(target_name: str, output_path: str | None) -> Path:
    if output_path:
        path = Path(output_path)
    else:
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", target_name)
        path = artifact_path("static", f"{safe_name}-static.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _decode_blob(blob: bytes) -> str:
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        return blob.decode("latin-1", errors="ignore")


def _scan_text_blob(name: str, blob: bytes, findings: Dict[str, List[Dict[str, Any]]], endpoints: set[str]) -> None:
    text = _decode_blob(blob)
    for category, pattern in PATTERNS.items():
        if pattern.search(text):
            findings[category].append({"source": name, "preview": text[:240]})
    for match in URL_RE.findall(blob):
        endpoints.add(match.decode("utf-8", errors="ignore"))


def _elf_summary(elf_path: Path) -> Dict[str, Any]:
    binary = lief.ELF.parse(str(elf_path))
    if binary is None:
        return {"path": str(elf_path), "parsed": False}

    imported_libs = sorted(set(_safe_iter(getattr(binary, "libraries", []))))
    imported_functions = _safe_iter(getattr(binary, "imported_functions", []))
    exported_functions = _safe_iter(getattr(binary, "exported_functions", []))
    symbols = _safe_iter(getattr(binary, "symbols", []))
    jni_symbols = []
    matched_symbols = {key: [] for key in NATIVE_SYMBOL_PATTERNS}
    for symbol in symbols:
        name = getattr(symbol, "name", "")
        if name == "JNI_OnLoad" or name.startswith("Java_"):
            jni_symbols.append(name)
        for category, needles in NATIVE_SYMBOL_PATTERNS.items():
            for needle in needles:
                if needle.endswith("_"):
                    if needle in name:
                        matched_symbols[category].append(name)
                elif needle == name or needle in name:
                    matched_symbols[category].append(name)

    strings = _safe_iter(getattr(binary, "strings", []))
    tls_hints: List[str] = []
    for stack_name, needles in TLS_STACK_HINTS.items():
        if any(any(needle in candidate for needle in needles) for candidate in imported_libs + jni_symbols + strings[:300]):
            tls_hints.append(stack_name)

    return {
        "path": str(elf_path),
        "parsed": True,
        "machine_type": str(getattr(getattr(binary, "header", None), "machine_type", "")),
        "is_pie": bool(getattr(binary, "is_pie", False)),
        "is_android": bool(getattr(binary, "is_targeting_android", False)),
        "imported_libraries": imported_libs,
        "imported_function_count": len(imported_functions),
        "exported_function_count": len(exported_functions),
        "jni_symbols": jni_symbols[:60],
        "native_candidates": {key: sorted(set(value))[:80] for key, value in matched_symbols.items() if value},
        "tls_stack_hints": sorted(set(tls_hints)),
    }


def _dex_summary(path: Path) -> Dict[str, Any]:
    dex = lief.DEX.parse(str(path))
    if dex is None:
        return {"path": str(path), "parsed": False}

    classes = _safe_iter(getattr(dex, "classes", []))
    methods = _safe_iter(getattr(dex, "methods", []))
    class_names = []
    for cls in classes[:60]:
        class_names.append(getattr(cls, "fullname", getattr(cls, "name", "")))

    return {
        "path": str(path),
        "parsed": True,
        "version": str(getattr(dex, "version", "")),
        "class_count": len(classes),
        "method_count": len(methods),
        "sample_classes": class_names,
    }


def _vdex_summary(path: Path) -> Dict[str, Any]:
    vdex = lief.VDEX.parse(str(path))
    if vdex is None:
        return {"path": str(path), "parsed": False}
    dex_files = _safe_iter(getattr(vdex, "dex_files", []))
    return {
        "path": str(path),
        "parsed": True,
        "dex_file_count": len(dex_files),
        "version": str(getattr(getattr(vdex, "header", None), "version", "")),
    }


def _art_summary(path: Path) -> Dict[str, Any]:
    art = lief.ART.parse(str(path))
    if art is None:
        return {"path": str(path), "parsed": False}
    return {
        "path": str(path),
        "parsed": True,
        "version": str(getattr(getattr(art, "header", None), "version", "")),
        "image_roots": len(_safe_iter(getattr(getattr(art, "header", None), "image_roots", []))),
    }


def _oat_summary(path: Path) -> Dict[str, Any]:
    oat = lief.OAT.parse(str(path))
    if oat is None:
        return {"path": str(path), "parsed": False}
    dex_files = _safe_iter(getattr(oat, "dex_files", []))
    classes = _safe_iter(getattr(oat, "classes", []))
    methods = _safe_iter(getattr(oat, "methods", []))
    return {
        "path": str(path),
        "parsed": True,
        "dex_file_count": len(dex_files),
        "class_count": len(classes),
        "method_count": len(methods),
        "android_version": str(getattr(lief.OAT, "android_version", lambda _: "")(oat)),
    }


def _summarize_embedded_file(temp_path: Path, archive_name: str) -> Tuple[str, Dict[str, Any] | None]:
    suffix = temp_path.suffix.lower()
    try:
        if suffix == ".so":
            return "elf", _elf_summary(temp_path)
        if suffix == ".dex":
            return "dex", _dex_summary(temp_path)
        if suffix == ".vdex":
            return "vdex", _vdex_summary(temp_path)
        if suffix == ".art":
            return "art", _art_summary(temp_path)
        if suffix == ".oat":
            return "oat", _oat_summary(temp_path)
    except Exception as exc:  # noqa: BLE001
        return suffix.lstrip("."), {"path": archive_name, "parsed": False, "error": str(exc)}
    return "", None


def _recommend_dynamic_plan(summary: Dict[str, Any]) -> Dict[str, Any]:
    findings = summary["findings"]
    native = summary["native_libraries"]
    has_attest = bool(findings["attestation"])
    has_anti = bool(findings["anti_instrumentation"]) or any(lib["jni_symbols"] for lib in native if lib.get("parsed"))
    has_pinning = bool(findings["pinning"])
    has_native_tls = any(lib.get("native_candidates", {}).get("tls_verify") for lib in native if lib.get("parsed"))

    profile = "observe"
    launch_then_attach = False
    delay_seconds = 0
    rationale = []

    if has_attest:
        profile = "attest"
        rationale.append("attestation indicators found during static analysis")
    if has_pinning and profile == "observe":
        profile = "network"
        rationale.append("pinning indicators suggest network hooks will be needed")
    if has_anti:
        launch_then_attach = True
        delay_seconds = 10
        rationale.append("anti-instrumentation or JNI-heavy behavior suggests late attach")
    if has_attest and has_pinning and not has_anti:
        profile = "network"
        rationale.append("attestation and pinning both present, but anti-instrumentation appears light")
    if has_native_tls:
        profile = "native"
        rationale.append("native TLS verification candidates found; prefer native interception plan")
        launch_then_attach = True
        if delay_seconds < 10:
            delay_seconds = 10

    if not rationale:
        rationale.append("no strong hardening indicators found; start with low-noise observation")

    return {
        "profile": profile,
        "launch_then_attach": launch_then_attach,
        "delay_seconds": delay_seconds,
        "rationale": rationale,
    }


def build_execution_plan(summary: Dict[str, Any], package_name: str | None = None, device_id: str | None = None) -> Dict[str, Any]:
    dynamic = summary["dynamic_plan"]
    profile = dynamic["profile"]
    steps: List[Dict[str, Any]] = []

    if summary["kind"] == "apk":
        steps.append(
            {
                "phase": "static",
                "action": "review_static_report",
                "details": "Review findings, endpoints, native libraries, and artifact summaries before touching the runtime.",
                "artifacts": [summary.get("report_path", "")],
            }
        )
    else:
        steps.append(
            {
                "phase": "static",
                "action": "review_tree_findings",
                "details": "Use the decompiled-tree indicators to narrow attestation, pinning, JNI, and anti-instrumentation targets.",
                "artifacts": [summary.get("report_path", "")],
            }
        )

    runtime_args: List[str] = []
    if package_name:
        runtime_args += ["-PackageName", package_name]
    if device_id:
        runtime_args += ["-DeviceId", device_id]
    runtime_args += ["-Profile", profile]
    if dynamic["launch_then_attach"]:
        runtime_args += ["-LaunchThenAttach", "-DelaySeconds", str(dynamic["delay_seconds"])]

    needs_mitm = profile == "network"
    if needs_mitm:
        runtime_args += ["-EnableMitmProxy"]
    if profile == "native":
        runtime_args = []
        if package_name:
            runtime_args += ["-PackageName", package_name]
        if summary.get("report_path"):
            runtime_args += ["-ReportPath", summary["report_path"]]
        if device_id:
            runtime_args += ["-DeviceId", device_id]
        if dynamic["launch_then_attach"]:
            runtime_args += ["-LaunchThenAttach", "-DelaySeconds", str(dynamic["delay_seconds"])]

    steps.append(
        {
            "phase": "dynamic",
            "action": "start_native_intercept_session" if profile == "native" else "start_hardened_session",
            "details": "Start the lowest-risk runtime profile recommended by static analysis.",
            "script": ".\\scripts\\start_native_intercept_session.ps1" if profile == "native" else ".\\scripts\\start_hardened_session.ps1",
            "arguments": runtime_args,
        }
    )

    trust_steps = [
        {
            "phase": "backend",
            "action": "start_trust_server",
            "details": "Start the trust-e2e verifier for attestation, request integrity, and transaction checks.",
            "script": ".\\scripts\\start_trust_server.ps1",
            "arguments": [],
        },
        {
            "phase": "backend",
            "action": "start_trust_adb_bridge",
            "details": "Forward TRUST_E2E logcat events into the verifier.",
            "script": ".\\scripts\\start_trust_adb_bridge.ps1",
            "arguments": ["-DeviceId", device_id] if device_id else [],
        },
    ]
    steps.extend(trust_steps)

    escalation = []
    if profile == "attest":
        escalation.append("If attestation-only hooks are insufficient, escalate to `observe` with late attach before enabling network hooks.")
    if profile in {"attest", "observe"} and summary["findings"]["pinning"]:
        escalation.append("If traffic remains opaque, escalate to `network` only after confirming pinning indicators are relevant.")
    if summary["findings"]["anti_instrumentation"]:
        escalation.append("Avoid spawn-time Frida. Keep hook surface narrow and prefer late attach throughout.")
    if not escalation:
        escalation.append("Escalate one profile at a time and preserve raw evidence after each change.")

    return {
        "summary_target": summary["target"],
        "report_path": summary.get("report_path"),
        "recommended_profile": profile,
        "launch_then_attach": dynamic["launch_then_attach"],
        "delay_seconds": dynamic["delay_seconds"],
        "package_name": package_name,
        "device_id": device_id,
        "steps": steps,
        "escalation_notes": escalation,
        "rationale": dynamic["rationale"],
    }


def load_report(report_path: str) -> Dict[str, Any]:
    path = Path(report_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def build_native_hook_plan(summary: Dict[str, Any]) -> Dict[str, Any]:
    libraries: List[Dict[str, Any]] = []
    for lib in summary.get("native_libraries", []):
        if not lib.get("parsed"):
            continue
        candidates = lib.get("native_candidates", {})
        if not candidates:
            continue
        libraries.append(
            {
                "library_path": lib.get("archive_path") or lib.get("path"),
                "tls_stack_hints": lib.get("tls_stack_hints", []),
                "jni_symbols": lib.get("jni_symbols", []),
                "candidates": candidates,
            }
        )

    return {
        "target": summary.get("target"),
        "report_path": summary.get("report_path"),
        "libraries": libraries,
        "recommended_profile": "native" if libraries else summary.get("dynamic_plan", {}).get("profile", "observe"),
    }


def render_native_hook_script(plan: Dict[str, Any], output_path: str | None = None) -> Dict[str, Any]:
    if output_path:
        path = Path(output_path)
    else:
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(plan.get("target", "native")).stem or "native")
        path = artifact_path("generated_hooks", f"{safe_name}-native-hooks.js")
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "function log(msg) { console.log('[native] ' + msg); }",
        "function attachIfPresent(symbol) {",
        "    var matches = Module.findExportByName(null, symbol);",
        "    if (!matches) { log('missing export ' + symbol); return; }",
        "    Interceptor.attach(matches, {",
        "        onEnter: function(args) { log('enter ' + symbol); },",
        "        onLeave: function(retval) { log('leave ' + symbol); }",
        "    });",
        "}",
        "",
    ]

    seen: set[str] = set()
    for lib in plan.get("libraries", []):
        for symbols in lib.get("candidates", {}).values():
            for symbol in symbols:
                if symbol in seen:
                    continue
                seen.add(symbol)
                lines.append(f"attachIfPresent('{symbol}');")

    if not seen:
        lines.append("log('no native interceptor candidates found in plan');")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"script_path": str(path), "symbol_count": len(seen), "target": plan.get("target")}


def _new_summary(kind: str, target: str) -> Dict[str, Any]:
    return {
        "scanned_at": _now_iso(),
        "kind": kind,
        "target": target,
        "tooling": {"lief_version": getattr(lief, "__version__", "unknown")},
        "inventory": {},
        "findings": {key: [] for key in PATTERNS},
        "endpoints": [],
        "native_libraries": [],
        "dex_files": [],
        "oat_files": [],
        "vdex_files": [],
        "art_files": [],
        "dynamic_plan": {},
    }


def analyze_apk(apk_path: str, output_path: str | None = None) -> Dict[str, Any]:
    apk = Path(apk_path).expanduser().resolve()
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk}")

    summary = _new_summary("apk", str(apk))
    endpoints: set[str] = set()

    with zipfile.ZipFile(apk, "r") as archive:
        names = archive.namelist()
        counter = Counter(Path(name).suffix.lower() or "<no_ext>" for name in names)
        summary["inventory"] = {
            "entry_count": len(names),
            "top_extensions": dict(counter.most_common(20)),
            "has_android_manifest": "AndroidManifest.xml" in names,
            "native_library_count": len([n for n in names if n.endswith(".so")]),
            "dex_count": len([n for n in names if n.endswith(".dex")]),
            "oat_count": len([n for n in names if n.endswith(".oat")]),
            "vdex_count": len([n for n in names if n.endswith(".vdex")]),
            "art_count": len([n for n in names if n.endswith(".art")]),
        }

        with tempfile.TemporaryDirectory(prefix="apk-static-lief-") as temp_dir:
            temp_root = Path(temp_dir)
            for name in names:
                try:
                    info = archive.getinfo(name)
                except KeyError:
                    continue
                suffix = Path(name).suffix.lower()

                if suffix in TEXT_EXTENSIONS and info.file_size <= MAX_TEXT_BYTES:
                    blob = archive.read(name)
                    _scan_text_blob(name, blob, summary["findings"], endpoints)

                if suffix in {".so", ".dex", ".oat", ".vdex", ".art"}:
                    destination = temp_root / Path(name).name
                    destination.write_bytes(archive.read(name))
                    artifact_type, artifact_summary = _summarize_embedded_file(destination, name)
                    if artifact_summary is None:
                        continue
                    artifact_summary["archive_path"] = name
                    if artifact_type == "elf":
                        summary["native_libraries"].append(artifact_summary)
                    elif artifact_type == "dex":
                        summary["dex_files"].append(artifact_summary)
                    elif artifact_type == "oat":
                        summary["oat_files"].append(artifact_summary)
                    elif artifact_type == "vdex":
                        summary["vdex_files"].append(artifact_summary)
                    elif artifact_type == "art":
                        summary["art_files"].append(artifact_summary)

    summary["endpoints"] = sorted(endpoints)
    summary["dynamic_plan"] = _recommend_dynamic_plan(summary)
    report_path = _ensure_report_path(apk.stem, output_path)
    summary["report_path"] = str(report_path)
    report_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def _scan_source_file(path: Path, findings: Dict[str, List[Dict[str, Any]]], endpoints: set[str]) -> None:
    try:
        blob = path.read_bytes()
    except OSError:
        return
    if path.suffix.lower() in TEXT_EXTENSIONS and len(blob) <= MAX_TEXT_BYTES:
        _scan_text_blob(str(path), blob, findings, endpoints)


def analyze_source_tree(source_dir: str, output_path: str | None = None) -> Dict[str, Any]:
    root = Path(source_dir).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Source directory not found: {root}")

    summary = _new_summary("source_tree", str(root))
    endpoints: set[str] = set()
    files = [path for path in root.rglob("*") if path.is_file()]
    counter = Counter(path.suffix.lower() or "<no_ext>" for path in files)
    summary["inventory"] = {
        "file_count": len(files),
        "top_extensions": dict(counter.most_common(20)),
    }

    for path in files:
        _scan_source_file(path, summary["findings"], endpoints)
        suffix = path.suffix.lower()
        try:
            if suffix == ".so":
                summary["native_libraries"].append(_elf_summary(path))
            elif suffix == ".dex":
                summary["dex_files"].append(_dex_summary(path))
            elif suffix == ".oat":
                summary["oat_files"].append(_oat_summary(path))
            elif suffix == ".vdex":
                summary["vdex_files"].append(_vdex_summary(path))
            elif suffix == ".art":
                summary["art_files"].append(_art_summary(path))
        except Exception as exc:  # noqa: BLE001
            bucket = {
                ".so": "native_libraries",
                ".dex": "dex_files",
                ".oat": "oat_files",
                ".vdex": "vdex_files",
                ".art": "art_files",
            }.get(suffix)
            if bucket:
                summary[bucket].append({"path": str(path), "parsed": False, "error": str(exc)})

    summary["endpoints"] = sorted(endpoints)
    summary["dynamic_plan"] = _recommend_dynamic_plan(summary)
    report_path = _ensure_report_path(root.name, output_path)
    summary["report_path"] = str(report_path)
    report_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary
