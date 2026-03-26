import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Tuple


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_request(
    method: str,
    path: str,
    body_hash: str,
    timestamp: int,
    counter: int,
    session_id: str,
    device_id: str,
) -> str:
    return "\n".join(
        [
            method.upper(),
            path,
            body_hash,
            str(timestamp),
            str(counter),
            session_id,
            device_id,
        ]
    )


def sign_request(secret: str, canonical: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_request_signature(secret: str, canonical: str, signature: str) -> bool:
    expected = sign_request(secret, canonical)
    return hmac.compare_digest(expected, signature)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def mint_attestation_token(payload: Dict[str, Any], signing_key: str) -> str:
    body = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = hmac.new(signing_key.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def decode_and_verify_attestation_token(token: str, signing_key: str) -> Tuple[bool, Dict[str, Any], str]:
    if "." not in token:
        return False, {}, "bad_token_format"
    body, sig = token.rsplit(".", 1)
    expected = hmac.new(signing_key.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False, {}, "bad_attestation_signature"
    try:
        payload = json.loads(b64url_decode(body).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return False, {}, "bad_token_payload"
    return True, payload, ""
