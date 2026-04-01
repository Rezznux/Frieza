import importlib
from pathlib import Path


def test_bootstrap_analysis_session_copies_apk(tmp_path):
    workspace_mod = importlib.import_module("apk_intercept.workspace")
    bootstrap_analysis_session = workspace_mod.bootstrap_analysis_session
    load_manifest = workspace_mod.load_manifest

    workspace = tmp_path / "workspace"
    apk = tmp_path / "demo-target.apk"
    apk.write_bytes(b"apk-content")

    result = bootstrap_analysis_session(apk_path=apk, workspace_root=workspace)

    assert result["seed_mode"] == "copy"
    assert result["seed_apk"] is not None
    seed_path = Path(result["seed_apk"])
    assert seed_path.exists()
    assert seed_path.read_bytes() == b"apk-content"
    assert "demo-target" in result["session_path"]

    manifest = load_manifest(result["session_path"])
    assert manifest["bootstrap_mode"] == "analysis"
    assert manifest["analysis_seed_mode"] == "copy"
    assert manifest["analysis_seed_apk"] == str(seed_path)


def test_bootstrap_analysis_session_reference_mode(tmp_path):
    workspace_mod = importlib.import_module("apk_intercept.workspace")
    bootstrap_analysis_session = workspace_mod.bootstrap_analysis_session

    workspace = tmp_path / "workspace"
    apk = tmp_path / "other.apk"
    apk.write_bytes(b"binary")

    result = bootstrap_analysis_session(apk_path=apk, workspace_root=workspace, copy_apk=False)

    assert result["seed_mode"] == "reference"
    assert result["seed_apk"] == str(apk.resolve())
