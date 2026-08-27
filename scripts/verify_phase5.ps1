Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-StatusProbe([string]$Uri, [string]$RequestId) {
    try {
        return [int](Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Headers @{ "X-Request-ID" = $RequestId } $Uri).StatusCode
    }
    catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        throw
    }
}

$requestId = [guid]::NewGuid().ToString()
$attackStatus = Invoke-StatusProbe "http://127.0.0.1:8080/backend/search?q=%27%20OR%201%3D1--" $requestId
if ($attackStatus -ne 403) { throw "Expected the gateway to block SQL injection, got HTTP $attackStatus." }

$deadline = (Get-Date).AddSeconds(15)
do {
    Start-Sleep -Milliseconds 500
    $events = (Invoke-RestMethod "http://127.0.0.1:8082/v1/security/events?limit=50").events
    $attackEvent = @($events | Where-Object { $_.requestId -eq $requestId } | Select-Object -First 1)
} while ($attackEvent.Count -eq 0 -and (Get-Date) -lt $deadline)

if ($attackEvent.Count -eq 0) { throw "No persisted SQL injection security event was observed." }
if ($attackEvent[0].sourceHash -eq "127.0.0.1" -or $attackEvent[0].detailsJson -match "Authorization|Cookie|password|token") {
    throw "Persisted event did not meet sanitization requirements."
}

[pscustomobject]@{
    attack_status = $attackStatus
    persisted_event_id = $attackEvent[0].eventId
    persisted_category = $attackEvent[0].category
    source_is_hashed = $attackEvent[0].sourceHash -ne "127.0.0.1"
    result = "passed"
} | ConvertTo-Json
