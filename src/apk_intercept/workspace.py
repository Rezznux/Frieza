"""Workspace and session management for source-only operation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


WORKSPACE_ENV = "APKIT_HOME"
SESSION_ENV = "APKIT_SESSION"
TRUST_LOG_ENV = "APKIT_TRUST_LOG"
ACTIVE_SESSION_FILE = Path("state") / "active_session.txt"
SESSION_DIR_NAMES = {
    "input": "input",
    "static": "static",
    "generated_hooks": "generated-hooks",
    "runtime": "runtime",
    "repacked": "repacked",
    "logs": "logs",
    "trust": "trust",
    "targets": "targets",
}
KNOWN_TARGET_HOOK_GLOBS = ("bitstamp_*.js",)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize_component(value: str | None, fallback: str) -> str:
    raw = (value or "").strip()
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in raw).strip(".-")
    return safe or fallback


def default_workspace_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "apk-intercept-kit"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "apk-intercept-kit"
    return Path.home() / ".local" / "share" / "apk-intercept-kit"


def resolve_workspace_root(override: str | Path | None = None) -> Path:
    candidate = override or os.environ.get(WORKSPACE_ENV) or default_workspace_root()
    path = Path(candidate).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    (path / "sessions").mkdir(parents=True, exist_ok=True)
    (path / "state").mkdir(parents=True, exist_ok=True)
    return path


def active_session_file(workspace_root: str | Path | None = None) -> Path:
    return resolve_workspace_root(workspace_root) / ACTIVE_SESSION_FILE


def session_directories(session_root: str | Path) -> Dict[str, Path]:
    base = Path(session_root).expanduser().resolve()
    return {key: base / name for key, name in SESSION_DIR_NAMES.items()}


def ensure_session_dirs(session_root: str | Path) -> Dict[str, Path]:
    root = Path(session_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    dirs = session_directories(root)
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def load_manifest(session_root: str | Path) -> Dict[str, Any]:
    manifest_path = Path(session_root).expanduser().resolve() / "manifest.json"
    if not manifest_path.exists():
        return {}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def write_manifest(session_root: str | Path, payload: Dict[str, Any]) -> Path:
    session_path = Path(session_root).expanduser().resolve()
    ensure_session_dirs(session_path)
    manifest_path = session_path / "manifest.json"
    current = load_manifest(session_path)
    merged = {**current, **payload}
    merged["session_path"] = str(session_path)
    merged["updated_at"] = _now_iso()
    manifest_path.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


def set_active_session(session_root: str | Path, workspace_root: str | Path | None = None) -> Path:
    session_path = Path(session_root).expanduser().resolve()
    ensure_session_dirs(session_path)
    marker = active_session_file(workspace_root)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(session_path), encoding="utf-8")
    return session_path


def get_active_session(workspace_root: str | Path | None = None) -> Path | None:
    marker = active_session_file(workspace_root)
    if not marker.exists():
        return None
    value = marker.read_text(encoding="utf-8").strip()
    if not value:
        return None
    path = Path(value).expanduser().resolve()
    return path if path.exists() else None


def create_session(
    workspace_root: str | Path | None = None,
    *,
    session_path: str | Path | None = None,
    engagement: str = "default",
    target: str = "general",
    name: str | None = None,
    activate: bool = True,
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    root = resolve_workspace_root(workspace_root)
    if session_path:
        resolved = Path(session_path).expanduser().resolve()
    else:
        session_name = sanitize_component(name, datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
        resolved = root / "sessions" / sanitize_component(engagement, "default") / sanitize_component(target, "general") / session_name

    dirs = ensure_session_dirs(resolved)
    manifest = {
        "created_at": _now_iso(),
        "engagement": sanitize_component(engagement, "default"),
        "target": sanitize_component(target, "general"),
        "name": resolved.name,
        "workspace_root": str(root),
        "paths": {key: str(value) for key, value in dirs.items()},
    }
    if metadata:
        manifest.update(metadata)
    manifest_path = write_manifest(resolved, manifest)
    if activate:
        set_active_session(resolved, root)
    return {
        "workspace_root": str(root),
        "session_path": str(resolved),
        "manifest_path": str(manifest_path),
        "active": activate,
        "paths": {key: str(value) for key, value in dirs.items()},
    }


def resolve_session(
    workspace_root: str | Path | None = None,
    session_path: str | Path | None = None,
    *,
    create_if_missing: bool = True,
) -> Path:
    root = resolve_workspace_root(workspace_root)
    explicit = session_path or os.environ.get(SESSION_ENV)
    if explicit:
        resolved = Path(explicit).expanduser().resolve()
        ensure_session_dirs(resolved)
        return resolved

    active = get_active_session(root)
    if active:
        ensure_session_dirs(active)
        return active

    if not create_if_missing:
        raise FileNotFoundError("No active APK Intercept Kit session is configured.")

    created = create_session(root, engagement="adhoc", target="default", activate=True)
    return Path(created["session_path"])


def describe_session(
    workspace_root: str | Path | None = None,
    session_path: str | Path | None = None,
    *,
    create_if_missing: bool = True,
) -> Dict[str, Any]:
    root = resolve_workspace_root(workspace_root)
    session = resolve_session(root, session_path, create_if_missing=create_if_missing)
    dirs = ensure_session_dirs(session)
    manifest = load_manifest(session)
    return {
        "workspace_root": str(root),
        "session_path": str(session),
        "active_session": str(get_active_session(root)) if get_active_session(root) else None,
        "paths": {key: str(value) for key, value in dirs.items()},
        "manifest_path": str(session / "manifest.json"),
        "manifest": manifest,
    }


def artifact_dir(
    kind: str,
    *,
    workspace_root: str | Path | None = None,
    session_path: str | Path | None = None,
) -> Path:
    dirs = ensure_session_dirs(resolve_session(workspace_root, session_path))
    try:
        return dirs[kind]
    except KeyError as exc:
        raise KeyError(f"Unknown workspace artifact kind: {kind}") from exc


def artifact_path(
    kind: str,
    filename: str,
    *,
    workspace_root: str | Path | None = None,
    session_path: str | Path | None = None,
) -> Path:
    path = artifact_dir(kind, workspace_root=workspace_root, session_path=session_path) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def trust_log_path(
    *,
    workspace_root: str | Path | None = None,
    session_path: str | Path | None = None,
) -> Path:
    if os.environ.get(TRUST_LOG_ENV):
        return Path(os.environ[TRUST_LOG_ENV]).expanduser().resolve()
    return artifact_path("trust", "events.jsonl", workspace_root=workspace_root, session_path=session_path)


def _disambiguate_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    counter = 1
    while True:
        candidate = path.with_name(f"{stem}-{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def _robocopy_move(src: Path, dst: Path) -> Path:
    dst.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            "robocopy",
            str(src),
            str(dst),
            "/E",
            "/MOVE",
            "/R:1",
            "/W:1",
            "/NFL",
            "/NDL",
            "/NJH",
            "/NJS",
            "/NC",
            "/NS",
            "/NP",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode >= 8:
        raise RuntimeError(
            f"robocopy failed moving '{src}' to '{dst}' (exit {completed.returncode}): {completed.stderr or completed.stdout}"
        )
    if src.exists():
        try:
            src.rmdir()
        except OSError:
            pass
    return dst


def _move_item(src: Path, dst: Path) -> Path:
    if src.is_dir():
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            shutil.move(str(src), str(dst))
            return dst
        if os.name == "nt" and shutil.which("robocopy"):
            return _robocopy_move(src, dst)
        dst.mkdir(parents=True, exist_ok=True)
        for child in sorted(src.iterdir()):
            _move_item(child, dst / child.name)
        if src.exists():
            try:
                src.rmdir()
            except OSError:
                pass
        return dst

    dst.parent.mkdir(parents=True, exist_ok=True)
    final_dst = _disambiguate_path(dst)
    shutil.move(str(src), str(final_dst))
    return final_dst


def _move_tree_contents(src: Path, dst: Path) -> list[dict[str, str]]:
    moved: list[dict[str, str]] = []
    if not src.exists():
        return moved
    dst.mkdir(parents=True, exist_ok=True)
    for child in sorted(src.iterdir()):
        final_dst = _move_item(child, dst / child.name)
        moved.append({"from": str(child), "to": str(final_dst)})
    if src.exists():
        try:
            src.rmdir()
        except OSError:
            pass
    return moved


def _remove_empty_parents(path: Path, stop_at: Path) -> None:
    current = path
    while current != stop_at and current.exists():
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def migrate_repo_artifacts(
    repo_root: str | Path,
    *,
    workspace_root: str | Path | None = None,
    session_path: str | Path | None = None,
    include_target_hooks: bool = True,
) -> Dict[str, Any]:
    repo = Path(repo_root).expanduser().resolve()
    session = resolve_session(workspace_root, session_path)
    dirs = ensure_session_dirs(session)
    moved: list[dict[str, str]] = []

    mappings = [
        (repo / "APK", dirs["input"]),
        (repo / "repacked", dirs["repacked"]),
        (repo / "tmp-cacerts", dirs["runtime"] / "tmp-cacerts"),
        (repo / "static-lief" / "reports", dirs["static"]),
        (repo / "static-lief" / "generated-hooks", dirs["generated_hooks"]),
        (repo / "trust-e2e" / "logs", dirs["trust"]),
    ]

    for src, dst in mappings:
        moved.extend(_move_tree_contents(src, dst))
        if src.parent.exists():
            _remove_empty_parents(src, repo)

    generated_files = [
        (repo / "project-files.txt", dirs["logs"] / "project-files.txt"),
    ]
    for src, dst in generated_files:
        if src.exists():
            final_dst = _move_item(src, dst)
            moved.append({"from": str(src), "to": str(final_dst)})

    target_hooks: list[dict[str, str]] = []
    if include_target_hooks:
        hooks_root = repo / "hooks"
        for pattern in KNOWN_TARGET_HOOK_GLOBS:
            for src in sorted(hooks_root.glob(pattern)):
                prefix = src.name.split("_", 1)[0]
                dst = dirs["targets"] / sanitize_component(prefix, "target") / "hooks" / src.name
                final_dst = _move_item(src, dst)
                target_hooks.append({"from": str(src), "to": str(final_dst)})
        moved.extend(target_hooks)

    write_manifest(
        session,
        {
            "migrated_from_repo": str(repo),
            "last_migration_at": _now_iso(),
            "migrated_items": moved,
        },
    )

    return {
        "workspace_root": str(resolve_workspace_root(workspace_root)),
        "session_path": str(session),
        "moved_count": len(moved),
        "moved_items": moved,
        "target_hooks_moved": target_hooks,
    }
