param(
    [string]$LogPath,
    [string]$InputText
)

$ErrorActionPreference = "Stop"
if (-not $LogPath -and -not $InputText) {
    throw "Provide -LogPath or -InputText."
}

if ($LogPath) {
    $InputText = Get-Content -Path $LogPath -Raw
}

$classification = [ordered]@{
    phase = "unknown"
    enforcement = "unknown"
    surfaces = @()
    rationale = @()
}

if ($InputText -match "IntegrityManager|SafetyNet|MEETS_DEVICE_INTEGRITY|attestation") {
    $classification.surfaces += "attestation"
    $classification.rationale += "attestation markers observed"
}
if ($InputText -match "CertificatePinner|TrustManagerImpl|SSLPeerUnverifiedException|pinning") {
    $classification.surfaces += "pinning"
    $classification.rationale += "pinning markers observed"
}
if ($InputText -match "ptrace|TracerPid|/proc/self/maps|frida|27042|gum-js-loop") {
    $classification.surfaces += "anti_instrumentation"
    $classification.rationale += "anti-instrumentation markers observed"
}
if ($InputText -match "403|401|forbidden|integrity verdict invalid|device not trusted") {
    $classification.enforcement = "server"
    $classification.rationale += "server-side denial markers observed"
}
if ($InputText -match "crash|abort|SIGABRT|FATAL EXCEPTION") {
    $classification.enforcement = "local"
    $classification.rationale += "local crash/abort markers observed"
}
if ($InputText -match "startup|Application.onCreate|cold start") {
    $classification.phase = "startup"
} elseif ($InputText -match "login|auth|pre-auth") {
    $classification.phase = "pre-auth"
} elseif ($InputText -match "refresh|re-attest|token refresh|session refresh") {
    $classification.phase = "mid-session"
}

$classification | ConvertTo-Json -Depth 6
