"""Smoke tests — verify all packages import cleanly and key APIs exist."""

import importlib


def test_apk_static_lief_imports():
    mod = importlib.import_module("apk_static_lief.scanner")
    assert callable(getattr(mod, "analyze_apk"))
    assert callable(getattr(mod, "analyze_source_tree"))
    assert callable(getattr(mod, "build_execution_plan"))
    assert callable(getattr(mod, "load_report"))
    assert callable(getattr(mod, "build_native_hook_plan"))
    assert callable(getattr(mod, "render_native_hook_script"))


def test_trust_e2e_imports():
    importlib.import_module("trust_e2e")


def test_mcp_server_imports():
    importlib.import_module("apk_intercept_mcp")


def test_apk_intercept_imports():
    importlib.import_module("apk_intercept")
    importlib.import_module("apk_intercept.cli")
    workspace = importlib.import_module("apk_intercept.workspace")
    assert callable(getattr(workspace, "create_session"))
    assert callable(getattr(workspace, "migrate_repo_artifacts"))


def test_cli_entry_point():
    from apk_intercept.cli import _build_parser

    parser = _build_parser()
    # Verify all expected subcommands are registered
    expected = {
        "static", "dynamic", "native-session", "plan",
        "hooks", "repack", "trust-server", "trust-bridge",
        "trust-demo", "healthcheck", "mcp-server", "session",
    }
    choices = set(parser._subparsers._actions[-1].choices.keys())
    assert expected == choices


def test_hooks_cmd_bundle_assembly(tmp_path):
    """hooks command assembles JS bundle without requiring Windows."""
    import argparse
    from apk_intercept.cli import cmd_hooks

    out = tmp_path / "bundle.js"
    args = argparse.Namespace(profile="observe", output=str(out))
    rc = cmd_hooks(args)
    assert rc == 0
    content = out.read_text(encoding="utf-8")
    assert "generated bundle profile=observe" in content
    assert "BEGIN hooks/observe_trust_flow.js" in content
