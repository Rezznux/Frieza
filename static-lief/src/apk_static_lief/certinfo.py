import hashlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

_CERT_RE = re.compile(r"META-INF/[^/]+\.(RSA|DSA|EC)$", re.I)


def _keytool_available() -> bool:
    return shutil.which("keytool") is not None


def _parse_keytool_output(output: str) -> Dict[str, Any]:
    cert: Dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Owner:"):
            cert["subject"] = line[len("Owner:"):].strip()
        elif line.startswith("Issuer:"):
            cert["issuer"] = line[len("Issuer:"):].strip()
        elif line.startswith("Serial number:"):
            cert["serial"] = line[len("Serial number:"):].strip()
        elif line.startswith("Valid from:"):
            cert["validity"] = line[len("Valid from:"):].strip()
        elif "SHA256" in line and ":" in line and "Fingerprint" in line:
            cert["sha256_fingerprint"] = line.split(":", 1)[1].strip()
        elif "SHA1" in line and ":" in line and "Fingerprint" in line:
            cert["sha1_fingerprint"] = line.split(":", 1)[1].strip()
        elif line.startswith("Signature algorithm name:"):
            cert["signature_algorithm"] = line.split(":", 1)[1].strip()
        elif line.startswith("Subject Public Key Algorithm:"):
            cert["public_key_algorithm"] = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            try:
                cert["version"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
    return cert


def _raw_sha256(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return ":".join(f"{b:02X}" for b in digest)


def analyze_certificates(apk_path: str) -> Dict[str, Any]:
    """Extract and analyse signing certificate(s) from APK META-INF."""
    result: Dict[str, Any] = {
        "certificates": [],
        "is_debug_signed": False,
        "parse_method": None,
        "error": None,
    }
    cert_entries: List[tuple[str, bytes]] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            cert_names = [n for n in zf.namelist() if _CERT_RE.match(n)]
            if not cert_names:
                result["error"] = "No signing certificate found in META-INF"
                return result
            cert_entries = [(n, zf.read(n)) for n in cert_names]
    except Exception as exc:
        result["error"] = f"Failed to open APK: {exc}"
        return result

    if _keytool_available():
        with tempfile.TemporaryDirectory(prefix="apk-cert-") as tmp:
            for cert_name, cert_data in cert_entries:
                tmp_cert = Path(tmp) / Path(cert_name).name
                tmp_cert.write_bytes(cert_data)
                try:
                    proc = subprocess.run(
                        ["keytool", "-printcert", "-file", str(tmp_cert)],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    if proc.returncode == 0:
                        parsed = _parse_keytool_output(proc.stdout)
                        parsed["archive_path"] = cert_name
                        parsed["size_bytes"] = len(cert_data)
                        result["certificates"].append(parsed)
                except Exception:
                    pass
        if result["certificates"]:
            result["parse_method"] = "keytool"

    if not result["certificates"]:
        # Fallback: SHA-256 fingerprint of the raw DER blob only
        result["parse_method"] = "raw_fingerprint"
        for cert_name, cert_data in cert_entries:
            result["certificates"].append(
                {
                    "archive_path": cert_name,
                    "size_bytes": len(cert_data),
                    "sha256_fingerprint": _raw_sha256(cert_data),
                    "note": "Install keytool for full certificate details",
                }
            )

    # Heuristic: debug-signed if subject/issuer contains standard debug key markers
    for cert in result["certificates"]:
        combined = (cert.get("subject", "") + cert.get("issuer", "")).lower()
        if "android debug" in combined or "androiddebugkey" in combined:
            result["is_debug_signed"] = True
            break

    return result
