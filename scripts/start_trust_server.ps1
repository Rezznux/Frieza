param(
    [string]$Host = "127.0.0.1",
    [int]$Port = 8787,
    [string]$WorkspaceRoot,
    [string]$SessionPath
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_workspace.ps1")
$repoRoot = Split-Path -Parent $PSScriptRoot
$coreSrc = Join-Path $repoRoot "src"
$srcPath = Join-Path $repoRoot "trust-e2e\src"
$env:PYTHONPATH = "$coreSrc;$srcPath"
$env:APKIT_TRUST_LOG = Get-ApkitTrustLogPath -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath

Write-Host "Starting trust-e2e server on $Host`:$Port"
python -c "from trust_e2e.server import run; run(host='$Host', port=$Port)"
