# Static LIEF Module

This module performs first-pass static analysis of APKs, extracted Android artifacts, and decompiled trees using LIEF by default.

It feeds higher-signal targets into the dynamic modules and now writes reports into the active workspace session instead of the repository.

## Output

Each scan produces:
- APK inventory and extension breakdown
- native library inventory
- ELF imported library and JNI symbol mapping
- DEX, OAT, VDEX, and ART summaries
- text-based indicators for attestation, pinning, crypto/signing, anti-instrumentation, and root/emulator checks
- endpoint extraction
- recommended dynamic profile and attach strategy
- native interceptor candidate plan

## Run

```powershell
apkit static --apk E:\analysis\target.apk
apkit static --source-dir E:\analysis\apktool_out
```

By default, reports are written to the active session `static/` directory.
Use `--output` to override that path.
