param(
    [Parameter(Mandatory = $true)]
    [string]$PackageName,
    [Parameter(Mandatory = $true)]
    [string]$IntegrityToken,
    [string]$BearerToken,
    [string]$EndpointTemplate = "https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$srcPath = Join-Path $repoRoot "trust-e2e\src"
$env:PYTHONPATH = $srcPath

$command = @"
from trust_e2e.play_integrity import decode_integrity_token
import json
result = decode_integrity_token(
    package_name=r'''$PackageName''',
    integrity_token=r'''$IntegrityToken''',
    bearer_token=r'''$BearerToken''' if r'''$BearerToken''' else None,
    endpoint_template=r'''$EndpointTemplate'''
)
print(json.dumps(result, indent=2, sort_keys=True))
"@

python -c $command
