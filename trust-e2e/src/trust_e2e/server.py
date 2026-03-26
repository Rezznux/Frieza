import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from apk_intercept.workspace import trust_log_path

from .config import load_device_registry, load_overrides, load_policy
from .engine import TrustEngine
from .store import InMemoryStore


def build_engine() -> TrustEngine:
    policy = load_policy()
    devices = load_device_registry()
    overrides = load_overrides()
    store = InMemoryStore(log_path=trust_log_path())
    return TrustEngine(policy=policy, device_registry=devices, overrides=overrides, store=store)


ENGINE = build_engine()


class Handler(BaseHTTPRequestHandler):
    server_version = "TrustE2E/1.0"

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8"))

    def _write_json(self, status: int, body: Dict[str, Any]) -> None:
        payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._write_json(200, {"ok": True, "service": "trust-e2e"})
            return
        self._write_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = self._read_json()
        except json.JSONDecodeError:
            self._write_json(400, {"ok": False, "error": "bad_json"})
            return

        if self.path == "/v1/attest/verify":
            result = ENGINE.verify_attestation(body)
            self._write_json(200, result)
            return
        if self.path == "/v1/request/verify":
            result = ENGINE.verify_request_integrity(body)
            self._write_json(200, result)
            return
        if self.path == "/v1/transaction/evaluate":
            result = ENGINE.evaluate_transaction(body)
            self._write_json(200, result)
            return

        self._write_json(404, {"ok": False, "error": "not_found"})

    def log_message(self, format: str, *args: Any) -> None:
        return


def run(host: str = "127.0.0.1", port: int = 8787) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"trust-e2e listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
