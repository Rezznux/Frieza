# Trust E2E Verifier

This module adds a runnable backend trust verifier to the intercept kit.

It is designed to validate and stress-test:
- attestation freshness and nonce binding
- request signing and replay resistance
- transaction authorization guardrails
- velocity controls
- vendor outage graceful degradation
- temporary support override handling

## End-To-End Flow

1. Client side emits attestation and signed request metadata.
2. Verifier API validates attestation and cryptographic request integrity.
3. Policy engine returns allow, challenge, or deny decisions.
4. Events are persisted as evidence in the active workspace session `trust/events.jsonl` path.

## Layout

- `src/trust_e2e/server.py`: HTTP verifier service
- `src/trust_e2e/engine.py`: policy-driven trust engine
- `src/trust_e2e/simulator.py`: end-to-end scenario runner
- `policy/policy.json`: tunable trust policy
- `data/device_registry.example.json`: demo device/secret registry (copy to `device_registry.json` to customize; the copy is gitignored)
- `data/overrides.json`: time-limited support exceptions

## Run

```powershell
frieza trust-server
frieza trust-bridge
frieza trust-demo
```

The legacy PowerShell entrypoints in `scripts/` still work and now write evidence into the active workspace session.

## Notes

- This is an authorized testing harness, not a production verifier.
- The demo attestation format is simplified so the flow is runnable without vendor SDK dependencies.
- Replace the token verifier with official Play Integrity or vendor verification logic for production-like validation.
