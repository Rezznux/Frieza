param(
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
$env:TRUST_E2E_BASE_URL = "http://127.0.0.1:$Port"
$env:FRIEZA_TRUST_LOG = Get-ApkitTrustLogPath -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath

$serverCmd = "from trust_e2e.server import run; run(host='127.0.0.1', port=$Port)"
$server = Start-Process -FilePath python -ArgumentList "-c", $serverCmd -PassThru -WindowStyle Hidden

try {
    $ready = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 300
        try {
            $null = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2
            $ready = $true
            break
        }
        catch {
            if ($server.HasExited) {
                throw "trust-e2e server exited early."
            }
        }
    }
    if (-not $ready) {
        throw "trust-e2e server did not become ready."
    }

    Write-Host "Running trust-e2e simulator against port $Port..."
    python -m trust_e2e.simulator
    Write-Host ""
    Write-Host "Evidence log: $env:FRIEZA_TRUST_LOG"
}
finally {
    if ($server -and !$server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
}
