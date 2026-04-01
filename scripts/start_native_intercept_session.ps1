param(
    [Parameter(Mandatory = $true)]
    [string]$PackageName,
    [string]$ReportPath,
    [string]$DeviceId,
    [switch]$LaunchThenAttach,
    [int]$DelaySeconds = 8,
    [string]$WorkspaceRoot,
    [string]$SessionPath
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_workspace.ps1")
$repoRoot = Split-Path -Parent $PSScriptRoot
$hooksDir = Get-ApkitSessionDir -Kind "generated-hooks" -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath
$hookOutput = Join-Path $hooksDir "$($PackageName -replace '[^A-Za-z0-9._-]', '_')-native-hooks.js"

if ($WorkspaceRoot) {
    $env:FRIEZA_HOME = Get-ApkitWorkspaceRoot -WorkspaceRoot $WorkspaceRoot
}
if ($SessionPath) {
    $env:FRIEZA_SESSION = Resolve-ApkitSessionPath -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath
}

function Start-PackageNormally {
    param(
        [string]$ResolvedDeviceId,
        [string]$ResolvedPackageName
    )

    $args = @()
    if ($ResolvedDeviceId) { $args += @("-s", $ResolvedDeviceId) }
    $args += @("shell", "monkey", "-p", $ResolvedPackageName, "-c", "android.intent.category.LAUNCHER", "1")
    & adb @args | Out-Null
}

$generateArgs = @("-ReportPath", $ReportPath, "-OutputScriptPath", $hookOutput)
& (Join-Path $PSScriptRoot "generate_native_hook_plan.ps1") @generateArgs | Out-Host

$fridaArgs = @("-PackageName", $PackageName, "-HookScript", $hookOutput)
if ($DeviceId) { $fridaArgs += @("-DeviceId", $DeviceId) }
if ($LaunchThenAttach) {
    Start-PackageNormally -ResolvedDeviceId $DeviceId -ResolvedPackageName $PackageName
    if ($DelaySeconds -gt 0) {
        Start-Sleep -Seconds $DelaySeconds
    }
    $fridaArgs += "-AttachOnly"
}

& (Join-Path $PSScriptRoot "start_frida_capture.ps1") @fridaArgs
