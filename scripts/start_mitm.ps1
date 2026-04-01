[CmdletBinding()]
param(
    [string]$DeviceId,
    [string]$ProxyHost = "127.0.0.1",
    [int]$ProxyPort = 8080,
    [switch]$ClearProxy
)

$ErrorActionPreference = "Stop"

function Invoke-Adb {
    param([string[]]$Args)
    if ($DeviceId) {
        & adb -s $DeviceId @Args
    } else {
        & adb @Args
    }
}

if ($ClearProxy) {
    Write-Host "[*] Clearing device proxy..."
    Invoke-Adb -Args @("shell", "settings", "put", "global", "http_proxy", ":0")
    Invoke-Adb -Args @("shell", "settings", "delete", "global", "global_http_proxy_host")
    Invoke-Adb -Args @("shell", "settings", "delete", "global", "global_http_proxy_port")
    Write-Host "[+] Proxy cleared."
    exit 0
}

Write-Host "[*] Setting Android global proxy to $ProxyHost`:$ProxyPort"
Invoke-Adb -Args @("shell", "settings", "put", "global", "http_proxy", "$ProxyHost`:$ProxyPort")
Invoke-Adb -Args @("shell", "settings", "put", "global", "global_http_proxy_host", $ProxyHost)
Invoke-Adb -Args @("shell", "settings", "put", "global", "global_http_proxy_port", "$ProxyPort")

Write-Host "[*] Current proxy settings:"
Invoke-Adb -Args @("shell", "settings", "get", "global", "http_proxy")
Invoke-Adb -Args @("shell", "settings", "get", "global", "global_http_proxy_host")
Invoke-Adb -Args @("shell", "settings", "get", "global", "global_http_proxy_port")

Write-Host ""
Write-Host "[*] Start your proxy listener (example):"
Write-Host "    mitmproxy --listen-host 0.0.0.0 --listen-port $ProxyPort"
Write-Host ""
Write-Host "[*] If TLS handshake fails, install CA cert on device and switch to Frida unpinning workflow."
