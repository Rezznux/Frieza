import json
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Tuple


class InMemoryStore:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.lock = Lock()
        self.seen_nonces: Dict[str, int] = {}
        self.last_counter: Dict[Tuple[str, str], int] = {}
        self.session_trust: Dict[str, Dict[str, Any]] = {}
        self.velocity: Dict[Tuple[str, str], List[int]] = {}
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _purge_nonce(self, now: int) -> None:
        dead = [nonce for nonce, expiry in self.seen_nonces.items() if expiry < now]
        for nonce in dead:
            self.seen_nonces.pop(nonce, None)

    def nonce_seen(self, nonce: str, now: int, ttl_seconds: int) -> bool:
        with self.lock:
            self._purge_nonce(now)
            if nonce in self.seen_nonces:
                return True
            self.seen_nonces[nonce] = now + ttl_seconds
            return False

    def check_and_store_counter(self, session_id: str, device_id: str, counter: int) -> bool:
        key = (session_id, device_id)
        with self.lock:
            prev = self.last_counter.get(key, 0)
            if counter <= prev:
                return False
            self.last_counter[key] = counter
            return True

    def update_session_trust(self, session_id: str, trust: Dict[str, Any]) -> None:
        with self.lock:
            self.session_trust[session_id] = trust

    def get_session_trust(self, session_id: str) -> Dict[str, Any]:
        with self.lock:
            return dict(self.session_trust.get(session_id, {}))

    def track_velocity(self, account_id: str, action: str, now: int, window_seconds: int) -> int:
        key = (account_id, action)
        cutoff = now - window_seconds
        with self.lock:
            events = self.velocity.get(key, [])
            events = [ts for ts in events if ts >= cutoff]
            events.append(now)
            self.velocity[key] = events
            return len(events)

    def log_event(self, event: Dict[str, Any]) -> None:
        row = dict(event)
        row.setdefault("logged_at", int(time.time()))
        with self.lock:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
