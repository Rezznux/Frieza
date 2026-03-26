# Hardened APK Attack Strategy (Authorized Scope)

Use this flow when protections are stacked and direct interception is unstable.

## 1) Find Trust Boundary First

Do not start with bypasses. Start with:

- where requests are built
- where auth/signature headers are computed
- where device or attestation claims are collected
- where server acceptance appears to depend on client-side logic

Use:

```powershell
.\scripts\profile_apk.ps1 -SourceDir <decompiled_source_dir>
```

## 2) Choose Runtime Profile

- `attest`: smallest hook surface, attestation-use visibility only
- `observe`: no bypass, only data-flow visibility
- `network`: trust-flow visibility + TLS unpinning hooks
- `hardened`: basic env cloaking + anti-instrumentation noise reduction + visibility + unpinning

Use:

```powershell
.\scripts\start_hardened_session.ps1 -PackageName com.target.app -Profile attest -LaunchThenAttach -DelaySeconds 10
.\scripts\start_hardened_session.ps1 -PackageName com.target.app -Profile observe
.\scripts\start_hardened_session.ps1 -PackageName com.target.app -Profile network -EnableMitmProxy
.\scripts\start_hardened_session.ps1 -PackageName com.target.app -Profile hardened -EnableMitmProxy
```

For apps that run integrity checks during cold start, prefer `-LaunchThenAttach` so Frida is not present at process start.

## 3) Layer-to-Action Mapping

- Early attestation blocks: use `attest` with `-LaunchThenAttach` first, then escalate only if you need deeper visibility later in the session.
- Environment trust failures: move from `observe` to `hardened`.
- Instrumentation detection: stay targeted; avoid broad hooks if one function gives the needed signal.
- Integrity/tamper controls: avoid repackaging unless runtime path is blocked.
- Network trust controls: use `network` or `hardened`; if native TLS dominates, pivot to endpoint-level tracing.
- Obfuscation/hardening: follow data flow, not symbol names.
- Native escalation: map JNI entry/exit and only reverse critical boundaries.
- Runtime attestation/server-side checks: prioritize request/response behavior and trust assumptions.

## 4) Stop Conditions

Pause and pivot if you spend long cycles fighting anti-debug layers without new trust-path insight.

The objective is defensible impact evidence, not maximum bypass depth.
