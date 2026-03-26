[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageName,
    [string]$DeviceId,
    [string]$HookScript,
    [switch]$AttachOnly
)

$ErrorActionPreference = "Stop"

if (-not $HookScript) {
    $HookScript = Join-Path $PSScriptRoot "..\hooks\android_unpinning.js"
}

if (-not (Test-Path $HookScript)) {
    throw "Hook script not found: $HookScript"
}

if ($AttachOnly) {
    if ($DeviceId) {
        & frida -D $DeviceId -n $PackageName -l $HookScript
    } else {
        & frida -U -n $PackageName -l $HookScript
    }
} else {
    if ($DeviceId) {
        & frida -D $DeviceId -f $PackageName -l $HookScript
    } else {
        & frida -U -f $PackageName -l $HookScript
    }
}
