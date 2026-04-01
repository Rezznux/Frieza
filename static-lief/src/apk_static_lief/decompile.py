import os
import shutil
import subprocess
from typing import Any, Dict


def _resolve_cmd(name: str) -> str | None:
    """Resolve a command to its full path, handling Windows .cmd shims."""
    path = shutil.which(name)
    if path is None and shutil.which(f"{name}.cmd"):
        path = shutil.which(f"{name}.cmd")
    return path


def jadx_available() -> bool:
    return _resolve_cmd("jadx") is not None


def apktool_available() -> bool:
    return _resolve_cmd("apktool") is not None


def run_jadx(apk_path: str, output_dir: str, timeout: int = 180) -> Dict[str, Any]:
    """Decompile APK to Java source using JADX."""
    result: Dict[str, Any] = {"tool": "jadx", "ok": False, "output_dir": output_dir, "error": None}
    jadx_cmd = _resolve_cmd("jadx")
    if not jadx_cmd:
        result["error"] = "jadx not found in PATH — install from https://github.com/skylot/jadx/releases"
        return result
    try:
        proc = subprocess.run(
            [jadx_cmd, "--output-dir", output_dir, apk_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # Accept partial success: jadx exits non-zero when it encounters decompile
        # errors in individual classes but still produces usable output for the rest.
        output_has_content = os.path.isdir(output_dir) and any(os.scandir(output_dir))
        result["ok"] = proc.returncode == 0 or output_has_content
        if not result["ok"]:
            result["error"] = (proc.stderr or proc.stdout)[:500]
        elif proc.returncode != 0:
            result["warnings"] = f"jadx finished with errors (exit {proc.returncode}); output may be partial"
    except subprocess.TimeoutExpired:
        result["error"] = f"jadx timed out after {timeout}s"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def run_apktool_decode(apk_path: str, output_dir: str, timeout: int = 120) -> Dict[str, Any]:
    """Decode APK to smali/resources using apktool."""
    result: Dict[str, Any] = {"tool": "apktool", "ok": False, "output_dir": output_dir, "error": None}
    apktool_cmd = _resolve_cmd("apktool")
    if not apktool_cmd:
        result["error"] = "apktool not found in PATH — install from https://apktool.org"
        return result
    try:
        proc = subprocess.run(
            [apktool_cmd, "d", "--force", "--output", output_dir, apk_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result["ok"] = proc.returncode == 0
        if not result["ok"]:
            result["error"] = (proc.stderr or proc.stdout)[:500]
    except subprocess.TimeoutExpired:
        result["error"] = f"apktool timed out after {timeout}s"
    except Exception as exc:
        result["error"] = str(exc)
    return result
