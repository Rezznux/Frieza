param()

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$coreSrc = Join-Path $repoRoot "src"
$staticSrc = Join-Path $repoRoot "static-lief\src"
$mcpSrc = Join-Path $repoRoot "mcp-server\src"
$env:PYTHONPATH = "$coreSrc;$staticSrc;$mcpSrc"

python -m apk_intercept_mcp.server
