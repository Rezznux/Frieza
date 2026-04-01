import json
import os
import time
import urllib.request
from typing import Any, Dict

from .crypto import canonical_request, mint_attestation_token, sha256_hex, sign_request


BASE_URL = os.environ.get("TRUST_E2E_BASE_URL", "http://127.0.0.1:8787")
DEVICE_ID = "device-01"
SESSION_ID = "sess-001"
ACTOR = "acct-A"
RESOURCE = "acct-A"
DEVICE_SECRET = "dev_secret_01"           # demo value — matches device_registry.example.json
ATTEST_KEY = "attest_signing_shared_secret"  # demo value — matches device_registry.example.json
PACKAGE = "com.target.app"
APP_CERT = "sha256:deadbeefcafe01"


def _post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    req = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _attest(nonce: str, ts: int, vendor_outage: bool = False, strong: bool = True) -> Dict[str, Any]:
    payload = {
        "vendor": "play_integrity",
        "ts": ts,
        "nonce": nonce,
        "device_id": DEVICE_ID,
        "package_name": PACKAGE,
        "app_cert_digest": APP_CERT,
        "vendor_outage": vendor_outage,
        "integrity": {"device": True, "app": True, "strong": strong},
    }
    token = mint_attestation_token(payload, ATTEST_KEY)
    return _post("/v1/attest/verify", {"session_id": SESSION_ID, "expected_nonce": nonce, "attestation_token": token})


def _sign_and_verify_request(counter: int, body: str, path: str = "/v1/transfer") -> Dict[str, Any]:
    ts = int(time.time())
    body_hash = sha256_hex(body.encode("utf-8"))
    canonical = canonical_request("POST", path, body_hash, ts, counter, SESSION_ID, DEVICE_ID)
    signature = sign_request(DEVICE_SECRET, canonical)
    return _post(
        "/v1/request/verify",
        {
            "method": "POST",
            "path": path,
            "body": body,
            "body_hash": body_hash,
            "timestamp": ts,
            "counter": counter,
            "session_id": SESSION_ID,
            "device_id": DEVICE_ID,
            "signature": signature,
        },
    )


def _tx(action: str, amount: float, actor: str = ACTOR, resource: str = RESOURCE) -> Dict[str, Any]:
    return _post(
        "/v1/transaction/evaluate",
        {
            "action": action,
            "amount": amount,
            "session_id": SESSION_ID,
            "device_id": DEVICE_ID,
            "actor_account_id": actor,
            "resource_account_id": resource,
        },
    )


def run() -> None:
    print("== Scenario 1: valid attestation + integrity + transfer")
    print(_attest("nonce-1", int(time.time())))
    print(_sign_and_verify_request(1, '{"to":"acct-B","amount":50}'))
    print(_tx("transfer", 50))

    print("\n== Scenario 2: request replay by counter reuse")
    print(_sign_and_verify_request(1, '{"to":"acct-B","amount":50}'))

    print("\n== Scenario 3: IDOR / owner mismatch")
    print(_tx("transfer", 20, actor="acct-A", resource="acct-Z"))

    print("\n== Scenario 4: stale attestation")
    stale = int(time.time()) - 1000
    print(_attest("nonce-2", stale))

    print("\n== Scenario 5: vendor outage graceful mode")
    print(_attest("nonce-3", int(time.time()), vendor_outage=True))
    print(_tx("transfer", 50))
    print(_tx("transfer", 500))


if __name__ == "__main__":
    run()
