[CmdletBinding()]
param(
    [string]$DeviceId
)

$ErrorActionPreference = "Stop"

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host "[*] Checking required tools..."
$required = @("adb", "mitmproxy", "frida")
$missing = @()
foreach ($tool in $required) {
    if (Test-CommandExists -Name $tool) {
        Write-Host "  [+] $tool found"
    } else {
        Write-Host "  [-] $tool missing"
        $missing += $tool
    }
}

if ($missing.Count -gt 0) {
    throw "Missing required tools: $($missing -join ', ')"
}

Write-Host "[*] Checking optional tooling..."
$optional = @("apktool", "zipalign", "apksigner", "keytool")
foreach ($tool in $optional) {
    if (Test-CommandExists -Name $tool) {
        Write-Host "  [+] $tool found"
    } else {
        Write-Host "  [ ] $tool not found (optional)"
    }
}

Write-Host "[*] Listing ADB devices..."
$adbArgs = @("devices", "-l")
if ($DeviceId) {
    $adbArgs = @("-s", $DeviceId) + $adbArgs
}
& adb @adbArgs

Write-Host "[*] Checking Frida device visibility..."
if ($DeviceId) {
    & frida-ps -D $DeviceId
} else {
    & frida-ps -U
}

Write-Host "[+] Environment check complete."
