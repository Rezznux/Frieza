import time
from typing import Any, Dict, Tuple

from .crypto import (
    canonical_request,
    decode_and_verify_attestation_token,
    sha256_hex,
    verify_request_signature,
)
from .store import InMemoryStore


class TrustEngine:
    def __init__(
        self,
        policy: Dict[str, Any],
        device_registry: Dict[str, Any],
        overrides: Dict[str, Any],
        store: InMemoryStore,
    ) -> None:
        self.policy = policy
        self.devices = device_registry.get("devices", {})
        self.attestation_signing_key = device_registry.get("attestation_signing_key", "")
        self.overrides = overrides.get("overrides", [])
        self.store = store

    def _now(self) -> int:
        return int(time.time())

    def _find_override(self, session_id: str, device_id: str, now: int) -> Dict[str, Any]:
        for item in self.overrides:
            if item.get("session_id") != session_id:
                continue
            if item.get("device_id") != device_id:
                continue
            if now <= int(item.get("expires_at_epoch", 0)):
                return item
        return {}

    def verify_attestation(self, req: Dict[str, Any]) -> Dict[str, Any]:
        now = self._now()
        session_id = req.get("session_id", "")
        token = req.get("attestation_token", "")
        expected_nonce = req.get("expected_nonce", "")

        ok, payload, err = decode_and_verify_attestation_token(token, self.attestation_signing_key)
        if not ok:
            result = {"ok": False, "decision": "deny", "reason": err}
            self.store.log_event({"type": "attestation", "session_id": session_id, "result": result})
            return result

        device_id = payload.get("device_id", "")
        dev = self.devices.get(device_id, {})
        if not dev:
            return {"ok": False, "decision": "deny", "reason": "unknown_device"}

        max_age = int(self.policy["attestation"]["max_age_seconds"])
        age = now - int(payload.get("ts", 0))
        if age < 0 or age > max_age:
            return {"ok": False, "decision": "challenge", "reason": "stale_attestation", "age_seconds": age}

        nonce = payload.get("nonce", "")
        if expected_nonce and nonce != expected_nonce:
            return {"ok": False, "decision": "deny", "reason": "nonce_mismatch"}

        nonce_ttl = int(self.policy["attestation"]["nonce_ttl_seconds"])
        if self.store.nonce_seen(nonce, now, nonce_ttl):
            return {"ok": False, "decision": "deny", "reason": "nonce_replay"}

        if payload.get("package_name") != dev.get("package_name"):
            return {"ok": False, "decision": "deny", "reason": "package_name_mismatch"}

        if payload.get("app_cert_digest") != dev.get("app_cert_digest"):
            return {"ok": False, "decision": "deny", "reason": "app_cert_mismatch"}

        integrity = payload.get("integrity", {})
        strong = bool(integrity.get("strong"))
        device_ok = bool(integrity.get("device"))
        app_ok = bool(integrity.get("app"))

        decision = "allow"
        confidence = "high"
        reason = "attestation_ok"
        if not app_ok or not device_ok:
            decision = "deny"
            reason = "integrity_failed"
            confidence = "low"
        elif not strong:
            decision = "challenge"
            reason = "strong_integrity_missing"
            confidence = "medium"

        trust = {
            "last_attestation_epoch": int(payload.get("ts", 0)),
            "device_id": device_id,
            "decision": decision,
            "confidence": confidence,
            "vendor": payload.get("vendor", "unknown"),
            "vendor_outage": bool(payload.get("vendor_outage", False)),
            "nonce": nonce,
        }
        self.store.update_session_trust(session_id, trust)
        result = {"ok": decision != "deny", "decision": decision, "reason": reason, "trust": trust}
        self.store.log_event({"type": "attestation", "session_id": session_id, "result": result})
        return result

    def verify_request_integrity(self, req: Dict[str, Any]) -> Dict[str, Any]:
        now = self._now()
        method = req.get("method", "POST")
        path = req.get("path", "/")
        body = req.get("body", "")
        timestamp = int(req.get("timestamp", 0))
        counter = int(req.get("counter", 0))
        session_id = req.get("session_id", "")
        device_id = req.get("device_id", "")
        signature = req.get("signature", "")
        body_hash = req.get("body_hash", "")

        dev = self.devices.get(device_id, {})
        if not dev:
            return {"ok": False, "decision": "deny", "reason": "unknown_device"}

        expected_body_hash = sha256_hex(body.encode("utf-8"))
        if body_hash != expected_body_hash:
            return {"ok": False, "decision": "deny", "reason": "body_hash_mismatch"}

        max_skew = int(self.policy["crypto"]["max_clock_skew_seconds"])
        if abs(now - timestamp) > max_skew:
            return {"ok": False, "decision": "challenge", "reason": "clock_skew_too_large"}

        if not self.store.check_and_store_counter(session_id, device_id, counter):
            return {"ok": False, "decision": "deny", "reason": "counter_replay"}

        canonical = canonical_request(method, path, body_hash, timestamp, counter, session_id, device_id)
        if not verify_request_signature(dev["device_secret"], canonical, signature):
            return {"ok": False, "decision": "deny", "reason": "bad_request_signature"}

        result = {"ok": True, "decision": "allow", "reason": "request_integrity_ok"}
        self.store.log_event({"type": "request_integrity", "session_id": session_id, "result": result})
        return result

    def _evaluate_authorization(self, req: Dict[str, Any]) -> Tuple[bool, str]:
        if not self.policy["authorization"]["enforce_owner_match"]:
            return True, "owner_check_disabled"
        actor = req.get("actor_account_id", "")
        resource = req.get("resource_account_id", "")
        if actor != resource:
            return False, "owner_mismatch_idor_candidate"
        return True, "owner_match"

    def evaluate_transaction(self, req: Dict[str, Any]) -> Dict[str, Any]:
        now = self._now()
        action = req.get("action", "")
        session_id = req.get("session_id", "")
        device_id = req.get("device_id", "")
        account_id = req.get("actor_account_id", "")
        amount = float(req.get("amount", 0))

        authz_ok, authz_reason = self._evaluate_authorization(req)
        if not authz_ok:
            return {"ok": False, "decision": "deny", "reason": authz_reason}

        trust = self.store.get_session_trust(session_id)
        high_risk = action in self.policy["risk"]["high_risk_actions"]
        if high_risk:
            last = int(trust.get("last_attestation_epoch", 0))
            max_age = int(self.policy["attestation"]["max_age_seconds"])
            if (now - last) > max_age:
                return {"ok": False, "decision": "challenge", "reason": "revalidate_attestation_required"}

        velocity_window = int(self.policy["risk"]["velocity"]["window_seconds"])
        velocity_max = int(self.policy["risk"]["velocity"]["max_actions"])
        velocity_count = self.store.track_velocity(account_id, action, now, velocity_window)
        if velocity_count > velocity_max:
            return {"ok": False, "decision": "challenge", "reason": "velocity_exceeded", "velocity_count": velocity_count}

        override = self._find_override(session_id, device_id, now)
        if override:
            result = {"ok": True, "decision": "allow", "reason": "temporary_support_override", "override": override}
            self.store.log_event({"type": "transaction", "session_id": session_id, "result": result})
            return result

        if trust.get("vendor_outage", False):
            gd = self.policy["graceful_degradation"]
            max_amount = float(gd["max_amount"])
            if amount > max_amount:
                return {"ok": False, "decision": "deny", "reason": "vendor_outage_amount_limit"}
            return {"ok": True, "decision": "allow_limited", "reason": "vendor_outage_grace_mode"}

        if trust.get("decision") == "challenge":
            return {"ok": False, "decision": "challenge", "reason": "attestation_needs_step_up"}
        if trust.get("decision") == "deny":
            return {"ok": False, "decision": "deny", "reason": "attestation_failed"}

        result = {"ok": True, "decision": "allow", "reason": "transaction_ok"}
        self.store.log_event({"type": "transaction", "session_id": session_id, "result": result})
        return result
