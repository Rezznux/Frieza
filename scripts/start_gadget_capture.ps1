# start_gadget_capture.ps1
# Connect Frida to an embedded Frida Gadget already running inside a repacked APK.
# The Gadget listens on a TCP port on the device; this script forwards it locally
# and attaches the supplied hook script.
#
# Usage:
#   .\start_gadget_capture.ps1 -HookScript hooks\observe_trust_flow.js
#   .\start_gadget_capture.ps1 -HookScript bundle.js -PackageName com.target.app -LaunchPackage
#
param(
    [Parameter(Mandatory = $true)]
    [string]$HookScript,
    [string]$DeviceId,
    [int]$DevicePort = 27042,
    [int]$LocalPort  = 27042,
    [string]$PackageName,
    [switch]$LaunchPackage,
    [int]$DelaySeconds = 0
)

$ErrorActionPreference = "Stop"

function Start-Package {
    param([string]$DevId, [string]$Pkg)
    $adbArgs = @()
    if ($DevId) { $adbArgs += @("-s", $DevId) }
    $adbArgs += @("shell", "monkey", "-p", $Pkg, "-c", "android.intent.category.LAUNCHER", "1")
    & adb @adbArgs | Out-Null
}

# Forward Gadget TCP port from device to localhost.
$fwdArgs = @()
if ($DeviceId) { $fwdArgs += @("-s", $DeviceId) }
$fwdArgs += @("forward", "tcp:$LocalPort", "tcp:$DevicePort")
Write-Host "[*] Forwarding device port $DevicePort → localhost:$LocalPort"
& adb @fwdArgs | Out-Null

if ($LaunchPackage) {
    if (-not $PackageName) { throw "-PackageName is required with -LaunchPackage." }
    Write-Host "[*] Launching $PackageName"
    Start-Package -DevId $DeviceId -Pkg $PackageName
    if ($DelaySeconds -gt 0) {
        Write-Host "[*] Waiting ${DelaySeconds}s for Gadget to initialise"
        Start-Sleep -Seconds $DelaySeconds
    }
}

Write-Host "[*] Attaching Frida to embedded Gadget at 127.0.0.1:$LocalPort"
& frida -H "127.0.0.1:$LocalPort" Gadget -l $HookScript
