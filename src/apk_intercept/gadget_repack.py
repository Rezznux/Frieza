"""Automated smali patching to inject a System.loadLibrary("gadget") call.

This module locates the best injection point in a decoded apktool tree
(Application.onCreate preferred, launcher Activity.onCreate fallback) and
inserts a minimal smali snippet so the Frida Gadget .so is loaded at startup.

Typical workflow:
    1. Decode APK:   apktool d -f -o decoded/ target.apk
    2. Copy gadget:  cp frida-gadget-<arch>.so decoded/lib/<abi>/libgadget.so
    3. Patch smali:  frieza gadget-patch --decoded-dir decoded/
    4. Rebuild:      frieza repack --apk target.apk --nsc --gadget <gadget-root>
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_NAME = f"{{{ANDROID_NS}}}name"
ANDROID_TARGET_ACTIVITY = f"{{{ANDROID_NS}}}targetActivity"


@dataclass(frozen=True)
class InjectionTarget:
    component: str        # "application" or "activity"
    class_name: str
    smali_path: Path
    method_signature: str


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def _qualify(raw_name: str | None, package: str) -> str | None:
    if not raw_name:
        return None
    if raw_name.startswith("."):
        return f"{package}{raw_name}"
    if "." not in raw_name:
        return f"{package}.{raw_name}"
    return raw_name


def _load_manifest(decoded_dir: Path) -> tuple[ET.Element, str]:
    path = decoded_dir / "AndroidManifest.xml"
    root = ET.parse(path).getroot()
    package = root.get("package")
    if not package:
        raise ValueError(f"AndroidManifest.xml missing package attribute: {path}")
    return root, package


def _find_smali(decoded_dir: Path, class_name: str) -> Path | None:
    rel = Path(*class_name.split(".")).with_suffix(".smali")
    for candidate in [decoded_dir / "smali" / rel, *decoded_dir.glob(f"smali*/{rel.as_posix()}")]:
        if candidate.exists():
            return candidate
    return None


def choose_injection_target(decoded_dir: str | Path) -> InjectionTarget:
    """Find the best smali file to inject the gadget load call into."""
    root_dir = Path(decoded_dir)
    manifest_root, package = _load_manifest(root_dir)
    app_node = manifest_root.find("application")
    if app_node is None:
        raise ValueError("AndroidManifest.xml missing <application> element.")

    # Prefer Application.onCreate — only one class, cleaner injection point.
    app_class = _qualify(app_node.get(ANDROID_NAME), package)
    if app_class:
        smali = _find_smali(root_dir, app_class)
        if smali:
            return InjectionTarget("application", app_class, smali, "onCreate()V")

    # Fall back to launcher Activity.
    for tag in ("activity", "activity-alias"):
        for activity in app_node.findall(tag):
            has_main = any(
                a.get(ANDROID_NAME) == "android.intent.action.MAIN"
                for a in activity.findall("intent-filter/action")
            )
            has_launcher = any(
                c.get(ANDROID_NAME) == "android.intent.category.LAUNCHER"
                for c in activity.findall("intent-filter/category")
            )
            if not (has_main and has_launcher):
                continue
            raw = (activity.get(ANDROID_TARGET_ACTIVITY) if tag == "activity-alias" else None) or activity.get(ANDROID_NAME)
            cls = _qualify(raw, package)
            if cls:
                smali = _find_smali(root_dir, cls)
                if smali:
                    return InjectionTarget("activity", cls, smali, "onCreate(Landroid/os/Bundle;)V")

    raise ValueError(
        "No patchable Application or launcher Activity smali found in the decoded tree.\n"
        "Ensure apktool decoded successfully and the manifest declares a launcher."
    )


# ---------------------------------------------------------------------------
# Smali patching
# ---------------------------------------------------------------------------

def _super_descriptor(lines: list[str], path: Path) -> str:
    for line in lines:
        s = line.strip()
        if s.startswith(".super "):
            return s.split(None, 1)[1]
    raise ValueError(f"Missing .super declaration in {path}")


def _already_patched(method_lines: list[str], lib: str) -> bool:
    return any("loadLibrary(Ljava/lang/String;)V" in l for l in method_lines) and any(f'"{lib}"' in l for l in method_lines)


def _patch_existing_method(lines: list[str], start: int, end: int, lib: str) -> tuple[bool, str]:
    if _already_patched(lines[start:end], lib):
        return False, "already-present"

    for i in range(start + 1, end):
        s = lines[i].strip()
        indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
        if s.startswith(".locals "):
            n = int(s.split()[1])
            lines[i] = f"{indent}.locals {n + 1}"
            reg = f"v{n}"
            lines[i + 1:i + 1] = [f'{indent}const-string {reg}, "{lib}"', f"{indent}invoke-static {{{reg}}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V", ""]
            return True, "patched-existing-method"
        if s.startswith(".registers "):
            n = int(s.split()[1])
            lines[i] = f"{indent}.registers {n + 1}"
            lines[i + 1:i + 1] = [f'{indent}const-string v0, "{lib}"', f"{indent}invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V", ""]
            return True, "patched-existing-method"

    raise ValueError("Could not find .locals or .registers inside the target method.")


def _append_method(lines: list[str], *, component: str, lib: str, super_desc: str) -> str:
    if component == "application":
        header = ".method public onCreate()V"
        sup = f"    invoke-super {{p0}}, {super_desc}->onCreate()V"
    else:
        header = ".method protected onCreate(Landroid/os/Bundle;)V"
        sup = f"    invoke-super {{p0, p1}}, {super_desc}->onCreate(Landroid/os/Bundle;)V"

    block = ["", header, "    .locals 1", "", sup, "", f'    const-string v0, "{lib}"', "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V", "", "    return-void", ".end method"]

    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == ".end class":
            lines[i:i] = block
            return "appended-method"

    raise ValueError("Missing .end class marker; cannot append onCreate method.")


def patch_smali_for_gadget(
    smali_path: str | Path,
    *,
    component: str,
    method_signature: str,
    library_name: str = "gadget",
) -> Dict[str, Any]:
    """Patch a single smali file to call System.loadLibrary at startup."""
    path = Path(smali_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    super_desc = _super_descriptor(lines, path)

    start = end = None
    needle = f" {method_signature}"
    for i, line in enumerate(lines):
        if line.strip().startswith(".method") and needle in line:
            start = i
            break

    if start is not None:
        for i in range(start + 1, len(lines)):
            if lines[i].strip() == ".end method":
                end = i
                break
        if end is None:
            raise ValueError(f"Unclosed method {method_signature} in {path}")
        changed, mode = _patch_existing_method(lines, start, end, library_name)
    else:
        mode = _append_method(lines, component=component, lib=library_name, super_desc=super_desc)
        changed = True

    if changed:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {"changed": changed, "mode": mode, "smali_path": str(path.resolve())}


def patch_decoded_tree_for_gadget(
    decoded_dir: str | Path,
    *,
    library_name: str = "gadget",
) -> Dict[str, Any]:
    """Find the best injection point and patch the smali tree in-place."""
    target = choose_injection_target(decoded_dir)
    result = patch_smali_for_gadget(
        target.smali_path,
        component=target.component,
        method_signature=target.method_signature,
        library_name=library_name,
    )
    return {
        **result,
        "decoded_dir": str(Path(decoded_dir).resolve()),
        "component": target.component,
        "class_name": target.class_name,
        "method_signature": target.method_signature,
    }
