import json
import shutil
import subprocess
from typing import Any, Dict, List

DEFAULT_RULESETS = ["p/android", "p/java"]
_SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(
    source_dir: str,
    rulesets: List[str] | None = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Run semgrep vulnerability scan on a decompiled source directory."""
    rulesets = rulesets or DEFAULT_RULESETS
    result: Dict[str, Any] = {
        "tool": "semgrep",
        "ok": False,
        "findings": [],
        "finding_count": 0,
        "error": None,
    }
    if not semgrep_available():
        result["error"] = "semgrep not found in PATH — install with: pip install semgrep"
        return result
    config_args = [arg for r in rulesets for arg in ("--config", r)]
    try:
        proc = subprocess.run(
            ["semgrep", *config_args, "--json", "--quiet", source_dir],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # semgrep exits 0 (clean), 1 (findings present), or 2+ (error)
        if proc.returncode in (0, 1):
            data = json.loads(proc.stdout)
            findings = [
                {
                    "rule_id": r["check_id"],
                    "severity": r["extra"].get("severity", "INFO"),
                    "message": r["extra"].get("message", ""),
                    "file": r["path"],
                    "line": r["start"]["line"],
                    "code": r["extra"].get("lines", "").strip(),
                }
                for r in data.get("results", [])
            ]
            findings.sort(
                key=lambda x: (_SEVERITY_ORDER.get(x["severity"], 99), x["file"], x["line"])
            )
            result["ok"] = True
            result["findings"] = findings
            result["finding_count"] = len(findings)
        else:
            result["error"] = (proc.stderr or proc.stdout)[:500]
    except subprocess.TimeoutExpired:
        result["error"] = f"semgrep timed out after {timeout}s"
    except (json.JSONDecodeError, KeyError) as exc:
        result["error"] = f"Failed to parse semgrep output: {exc}"
    except Exception as exc:
        result["error"] = str(exc)
    return result
