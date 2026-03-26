[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("attest", "observe", "network", "native", "hardened")]
    [string]$Profile,
    [string]$ProfilesFile,
    [string]$OutputPath,
    [string]$WorkspaceRoot,
    [string]$SessionPath
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_workspace.ps1")

if (-not $ProfilesFile) {
    $ProfilesFile = Join-Path $PSScriptRoot "..\profiles\hook_profiles.json"
}
if (-not $OutputPath) {
    $hooksDir = Get-ApkitSessionDir -Kind "generated-hooks" -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath
    $OutputPath = Join-Path $hooksDir "apk-intercept-$Profile-bundle.js"
}

if (-not (Test-Path $ProfilesFile)) {
    throw "Profiles file not found: $ProfilesFile"
}

$root = Split-Path -Parent $PSScriptRoot
$profiles = Get-Content -Raw -Path $ProfilesFile | ConvertFrom-Json
$selected = $profiles | Where-Object { $_.name -eq $Profile }
if (-not $selected) {
    throw "Profile not found: $Profile"
}

$parts = @()
$parts += "// generated bundle profile=$Profile"
$parts += "// generated at $(Get-Date -Format o)"

foreach ($hookRel in $selected.hooks) {
    $hookPath = Join-Path $root $hookRel
    if (-not (Test-Path $hookPath)) {
        throw "Hook file not found in profile '$Profile': $hookPath"
    }
    $parts += ""
    $parts += "// BEGIN $hookRel"
    $parts += (Get-Content -Raw -Path $hookPath)
    $parts += "// END $hookRel"
}

$parts -join "`n" | Set-Content -Path $OutputPath
Write-Host $OutputPath
