import json
from pathlib import Path
from typing import Any, Dict

from apk_intercept.workspace import trust_log_path

BASE_DIR = Path(__file__).resolve().parents[2]
POLICY_PATH = BASE_DIR / "policy" / "policy.json"
DEVICE_REGISTRY_PATH = BASE_DIR / "data" / "device_registry.json"
OVERRIDES_PATH = BASE_DIR / "data" / "overrides.json"
LOG_PATH = trust_log_path()


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_policy() -> Dict[str, Any]:
    return _load_json(POLICY_PATH)


def load_device_registry() -> Dict[str, Any]:
    return _load_json(DEVICE_REGISTRY_PATH)


def load_overrides() -> Dict[str, Any]:
    return _load_json(OVERRIDES_PATH)
