[CmdletBinding()]
param(
    [string]$PackageName,
    [ValidateSet("attest", "observe", "network", "native", "hardened")]
    [string]$Profile = "hardened",
    [string]$DeviceId,
    [switch]$SelectFromDevice,
    [switch]$IncludeSystemApps,
    [string]$AppFilter,
    [switch]$EnableMitmProxy,
    [string]$ProxyHost = "127.0.0.1",
    [int]$ProxyPort = 8080,
    [switch]$AttachOnly,
    [switch]$LaunchThenAttach,
    [int]$DelaySeconds = 8,
    [string]$WorkspaceRoot,
    [string]$SessionPath
)

$ErrorActionPreference = "Stop"

$scriptsRoot = $PSScriptRoot
$bundleScript = Join-Path $scriptsRoot "build_hook_bundle.ps1"
$fridaScript = Join-Path $scriptsRoot "start_frida_capture.ps1"
$mitmScript = Join-Path $scriptsRoot "start_mitm.ps1"

function Get-OnlineDevices {
    $lines = & adb devices
    $devices = @()
    foreach ($line in $lines) {
        if ($line -match "^(?<id>\S+)\s+device$") {
            $devices += $Matches["id"]
        }
    }
    return @($devices)
}

function Select-Device {
    param([string]$CurrentDeviceId)

    if ($CurrentDeviceId) {
        return $CurrentDeviceId
    }

    $devices = @(Get-OnlineDevices)
    if ($devices.Count -eq 0) {
        throw "No online adb devices found."
    }
    if ($devices.Count -eq 1) {
        Write-Host "[*] Auto-selected device: $($devices[0])"
        return $devices[0]
    }

    Write-Host "[*] Multiple devices found. Select device:"
    for ($i = 0; $i -lt $devices.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), $devices[$i])
    }
    $choice = Read-Host "Enter device number"
    $parsed = 0
    if (-not [int]::TryParse($choice, [ref]$parsed)) {
        throw "Invalid device selection."
    }
    $idx = $parsed - 1
    if ($idx -lt 0 -or $idx -ge $devices.Count) {
        throw "Device selection out of range."
    }
    return $devices[$idx]
}

function Get-InstalledPackages {
    param(
        [string]$ResolvedDeviceId,
        [switch]$ShowSystemApps
    )

    $args = @()
    if ($ResolvedDeviceId) {
        $args += @("-s", $ResolvedDeviceId)
    }
    $args += @("shell", "pm", "list", "packages")
    if (-not $ShowSystemApps) {
        $args += "-3"
    }

    $lines = & adb @args
    $pkgs = @()
    foreach ($line in $lines) {
        if ($line -like "package:*") {
            $pkgs += ($line -replace "^package:", "")
        }
    }
    return @($pkgs | Sort-Object -Unique)
}

function Select-Package {
    param(
        [string]$ResolvedDeviceId,
        [switch]$ShowSystemApps,
        [string]$Filter
    )

    $packages = @(Get-InstalledPackages -ResolvedDeviceId $ResolvedDeviceId -ShowSystemApps:$ShowSystemApps)
    if ($Filter) {
        $packages = $packages | Where-Object { $_ -like "*$Filter*" }
    }

    while ($packages.Count -gt 120) {
        Write-Host "[*] $($packages.Count) packages found. Enter filter text to narrow list."
        $nextFilter = Read-Host "Filter (example: bank, pay, target)"
        if (-not [string]::IsNullOrWhiteSpace($nextFilter)) {
            $packages = $packages | Where-Object { $_ -like "*$nextFilter*" }
        }
    }

    if ($packages.Count -eq 0) {
        throw "No packages found for current selection/filter."
    }

    Write-Host "[*] Select package:"
    for ($i = 0; $i -lt $packages.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), $packages[$i])
    }
    $choice = Read-Host "Enter package number"
    $parsed = 0
    if (-not [int]::TryParse($choice, [ref]$parsed)) {
        throw "Invalid package selection."
    }
    $idx = $parsed - 1
    if ($idx -lt 0 -or $idx -ge $packages.Count) {
        throw "Package selection out of range."
    }
    return $packages[$idx]
}

function Start-PackageNormally {
    param(
        [string]$ResolvedDeviceId,
        [string]$ResolvedPackageName
    )

    $args = @()
    if ($ResolvedDeviceId) {
        $args += @("-s", $ResolvedDeviceId)
    }
    $args += @(
        "shell",
        "monkey",
        "-p",
        $ResolvedPackageName,
        "-c",
        "android.intent.category.LAUNCHER",
        "1"
    )
    & adb @args | Out-Null
}

if ($SelectFromDevice -or -not $PackageName) {
    $DeviceId = Select-Device -CurrentDeviceId $DeviceId
    $PackageName = Select-Package -ResolvedDeviceId $DeviceId -ShowSystemApps:$IncludeSystemApps -Filter $AppFilter
    Write-Host "[*] Selected device: $DeviceId"
    Write-Host "[*] Selected package: $PackageName"
}

if (-not $PackageName) {
    throw "PackageName is required. Use -PackageName or -SelectFromDevice."
}

if ($EnableMitmProxy) {
    # Use hashtable splatting — array splatting with named params is unreliable in PS 5.1
    $mitmSplat = @{ ProxyHost = $ProxyHost; ProxyPort = $ProxyPort }
    if ($DeviceId) { $mitmSplat["DeviceId"] = $DeviceId }
    & $mitmScript @mitmSplat
}

$bundleSplat = @{ Profile = $Profile }
if ($WorkspaceRoot) { $bundleSplat["WorkspaceRoot"] = $WorkspaceRoot }
if ($SessionPath) { $bundleSplat["SessionPath"] = $SessionPath }
$bundlePath = & $bundleScript @bundleSplat

$fridaSplat = @{ PackageName = $PackageName; HookScript = $bundlePath }
if ($DeviceId) { $fridaSplat["DeviceId"] = $DeviceId }
if ($LaunchThenAttach) {
    if ($DelaySeconds -lt 0) {
        throw "DelaySeconds must be >= 0."
    }
    Write-Host "[*] Launching app normally before Frida attach: $PackageName"
    Start-PackageNormally -ResolvedDeviceId $DeviceId -ResolvedPackageName $PackageName
    if ($DelaySeconds -gt 0) {
        Write-Host "[*] Waiting $DelaySeconds second(s) before attach"
        Start-Sleep -Seconds $DelaySeconds
    }
    $fridaSplat["AttachOnly"] = $true
} elseif ($AttachOnly) {
    $fridaSplat["AttachOnly"] = $true
}

& $fridaScript @fridaSplat
