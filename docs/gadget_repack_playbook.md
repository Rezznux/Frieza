# Frida Gadget Repack Playbook (Escalation Path)

Use this only when MITM + runtime Frida attach cannot intercept traffic.

## Preconditions

- Target APK is in-scope and authorized for modification.
- You can resign and reinstall the package on a test device.
- You have architecture-matching `libfrida-gadget.so` files.

## Suggested Flow

1. Decompile APK (`apktool d`).
2. Add gadget libs under `lib/<abi>/libfrida-gadget.so`.
3. Ensure app loads gadget at startup:
   - preferred: patch target native loader path or app init path
   - fallback: smali patch to call `System.loadLibrary("frida-gadget")`
4. Rebuild APK (`apktool b`).
5. Align and sign APK (`zipalign`, `apksigner`).
6. Install and run with `frida` client attached.

## Stability Notes

- Repacking changes signature and can break app-side integrity checks.
- Treat this as higher-risk than runtime attach.
- Keep original APK, patched APK, and signing details for reproducibility.

## Evidence To Capture

- Original and patched APK SHA256
- Injection point changed (class/function)
- Device + OS version
- Hook script used
- Captured request/response proving security impact
