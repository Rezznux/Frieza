import re
import shutil
import subprocess
import zipfile
from typing import Any, Dict, List, Set

DANGEROUS_PERMISSIONS: Set[str] = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BODY_SENSORS",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.USE_SIP",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

HIGH_RISK_PERMISSIONS: Set[str] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.DELETE_PACKAGES",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.INTERNET",
    "android.permission.READ_LOGS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.WRITE_SETTINGS",
}

_PERM_RE = re.compile(rb"android\.permission\.[A-Z_]{3,60}")
_PKG_RE = re.compile(r"name='([^']+)'")
_VER_NAME_RE = re.compile(r"versionName='([^']+)'")
_VER_CODE_RE = re.compile(r"versionCode='(\d+)'")
_SDK_RE = re.compile(r"'(\d+)'")


def _aapt_tool() -> str | None:
    for tool in ("aapt2", "aapt"):
        if shutil.which(tool):
            return tool
    return None


def _parse_with_aapt(apk_path: str, tool: str) -> Dict[str, Any] | None:
    try:
        proc = subprocess.run(
            [tool, "dump", "badging", apk_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None
        result: Dict[str, Any] = {
            "permissions": [],
            "package_name": None,
            "version_name": None,
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
        }
        for line in proc.stdout.splitlines():
            if line.startswith("package:"):
                m = _PKG_RE.search(line)
                if m:
                    result["package_name"] = m.group(1)
                m = _VER_NAME_RE.search(line)
                if m:
                    result["version_name"] = m.group(1)
                m = _VER_CODE_RE.search(line)
                if m:
                    result["version_code"] = m.group(1)
            elif line.startswith("sdkVersion:"):
                m = _SDK_RE.search(line)
                if m:
                    result["min_sdk"] = int(m.group(1))
            elif line.startswith("targetSdkVersion:"):
                m = _SDK_RE.search(line)
                if m:
                    result["target_sdk"] = int(m.group(1))
            elif line.startswith("uses-permission:"):
                m = _PKG_RE.search(line)
                if m and m.group(1) not in result["permissions"]:
                    result["permissions"].append(m.group(1))
        return result
    except Exception:
        return None


def _parse_binary_manifest(apk_path: str) -> Dict[str, Any]:
    """Fallback: extract permissions from raw binary AXML via byte-level regex."""
    result: Dict[str, Any] = {
        "permissions": [],
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
    }
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return result
            raw = zf.read("AndroidManifest.xml")
        for match in _PERM_RE.finditer(raw):
            perm = match.group(0).decode("ascii", errors="ignore")
            if perm not in result["permissions"]:
                result["permissions"].append(perm)
        # Package names appear in the binary as short ASCII token sequences
        for candidate in re.findall(rb"[a-z][a-z0-9]{2,}\.[a-z][a-z0-9.]{4,60}", raw):
            decoded = candidate.decode("ascii", errors="ignore")
            if decoded.count(".") >= 2 and not decoded.startswith("android."):
                result["package_name"] = decoded
                break
    except Exception:
        pass
    return result


def analyze_manifest(apk_path: str) -> Dict[str, Any]:
    """Extract permissions and metadata from AndroidManifest.xml."""
    tool = _aapt_tool()
    parsed = _parse_with_aapt(apk_path, tool) if tool else None
    parse_method = tool if parsed else "binary_extraction"
    if parsed is None:
        parsed = _parse_binary_manifest(apk_path)

    permissions: List[str] = sorted(set(parsed.get("permissions", [])))
    dangerous = sorted(p for p in permissions if p in DANGEROUS_PERMISSIONS)
    high_risk = sorted(p for p in permissions if p in HIGH_RISK_PERMISSIONS)

    return {
        "package_name": parsed.get("package_name"),
        "version_name": parsed.get("version_name"),
        "version_code": parsed.get("version_code"),
        "min_sdk": parsed.get("min_sdk"),
        "target_sdk": parsed.get("target_sdk"),
        "permissions": permissions,
        "permission_count": len(permissions),
        "dangerous_permissions": dangerous,
        "high_risk_permissions": high_risk,
        "parse_method": parse_method,
    }
