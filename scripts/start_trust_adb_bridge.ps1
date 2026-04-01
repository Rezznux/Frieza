param(
    [string]$DeviceId = "",
    [string]$ServerBaseUrl = "http://127.0.0.1:8787"
)

$ErrorActionPreference = "Stop"

function Invoke-TrustApi {
    param(
        [string]$Path,
        [hashtable]$Body
    )
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$ServerBaseUrl$Path" -Body ($Body | ConvertTo-Json -Depth 8 -Compress) -ContentType "application/json"
        return ($resp | ConvertTo-Json -Depth 8 -Compress)
    }
    catch {
        return "{`"ok`":false,`"error`":`"$($_.Exception.Message)`"}"
    }
}

Write-Host "Starting ADB bridge. Expecting log lines tagged with TRUST_E2E:"
Write-Host "Example log payload:"
Write-Host '{"type":"attest","session_id":"sess-001","expected_nonce":"n1","attestation_token":"..."}'
Write-Host '{"type":"request","method":"POST","path":"/v1/transfer","body":"{}","body_hash":"...","timestamp":123,"counter":1,"session_id":"sess-001","device_id":"device-01","signature":"..."}'
Write-Host '{"type":"tx","action":"transfer","amount":10,"session_id":"sess-001","device_id":"device-01","actor_account_id":"acct-A","resource_account_id":"acct-A"}'

$adbArgs = @()
if ($DeviceId) {
    $adbArgs += @("-s", $DeviceId)
}

& adb @adbArgs logcat -v brief | ForEach-Object {
    $line = $_
    if ($line -notmatch "TRUST_E2E:\s*(\{.*\})") {
        return
    }

    $jsonChunk = $Matches[1]
    try {
        $event = $jsonChunk | ConvertFrom-Json -AsHashtable
    }
    catch {
        Write-Host "Skipping invalid TRUST_E2E event: $jsonChunk"
        return
    }

    $eventType = $event["type"]
    $response = ""
    if ($eventType -eq "attest") {
        $response = Invoke-TrustApi -Path "/v1/attest/verify" -Body $event
    }
    elseif ($eventType -eq "request") {
        $response = Invoke-TrustApi -Path "/v1/request/verify" -Body $event
    }
    elseif ($eventType -eq "tx") {
        $response = Invoke-TrustApi -Path "/v1/transaction/evaluate" -Body $event
    }
    else {
        Write-Host "Ignoring unsupported event type: $eventType"
        return
    }

    Write-Host "[bridge] $eventType -> $response"
}
