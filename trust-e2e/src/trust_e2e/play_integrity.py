import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict


DEFAULT_ENDPOINT = "https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken"


def decode_integrity_token(
    package_name: str,
    integrity_token: str,
    bearer_token: str | None = None,
    endpoint_template: str = DEFAULT_ENDPOINT,
) -> Dict[str, Any]:
    token = bearer_token or os.environ.get("PLAY_INTEGRITY_BEARER_TOKEN", "")
    if not token:
        raise ValueError("Provide bearer_token or set PLAY_INTEGRITY_BEARER_TOKEN.")

    url = endpoint_template.format(package_name=package_name)
    payload = json.dumps({"integrityToken": integrity_token}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "status": exc.code, "error": body}

