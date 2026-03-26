[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDir,
    [string]$OutputPath = (Join-Path $PWD "apk_profile.json")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $SourceDir)) {
    throw "Source directory not found: $SourceDir"
}

$patterns = @{
    "play_integrity" = "IntegrityManager|MEETS_DEVICE_INTEGRITY|SafetyNet|attest|attestation"
    "pinning" = "CertificatePinner|TrustManager|HostnameVerifier|X509TrustManager|pinning"
    "crypto_signing" = "HmacSHA|MessageDigest|Signature|Cipher|Mac.getInstance|SecretKeySpec"
    "jni_native" = "System\.loadLibrary|JNI_OnLoad|native "
    "root_emu" = "magisk|/system/xbin/su|ro\.secure|ro\.debuggable|goldfish|qemu|test-keys"
    "anti_instrumentation" = "TracerPid|ptrace|frida|xposed|lsposed|/proc/self/maps|isDebuggerConnected"
}

$results = @{}
foreach ($key in $patterns.Keys) {
    $matches = Get-ChildItem -Path $SourceDir -Recurse -File -ErrorAction SilentlyContinue |
        Select-String -Pattern $patterns[$key] -SimpleMatch:$false -ErrorAction SilentlyContinue
    $results[$key] = @($matches | Select-Object -First 40 | ForEach-Object {
        [PSCustomObject]@{
            file = $_.Path
            line = $_.LineNumber
            text = $_.Line.Trim()
        }
    })
}

$profile = [PSCustomObject]@{
    scanned_at = (Get-Date -Format o)
    source_dir = (Resolve-Path $SourceDir).Path
    categories = $results
}

$profile | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath
Write-Host "[+] Wrote profile to $OutputPath"
