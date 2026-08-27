Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $projectRoot "infra\docker\compose.phase4.yml"

function Clear-WafState {
    docker compose -f $composeFile exec -T redis redis-cli FLUSHDB | Out-Null
}

function Invoke-StatusProbe([string]$Method, [string]$Uri) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method $Method $Uri -TimeoutSec 30
        return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $response.Content }
    }
    catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            $reader = [System.IO.StreamReader]::new($response.GetResponseStream())
            return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $reader.ReadToEnd() }
        }
        throw
    }
}

Clear-WafState
$normal = Invoke-StatusProbe "GET" "http://127.0.0.1:8080/backend/public/hello"
if ($normal.StatusCode -ne 200 -or $normal.Body -notmatch "backend_reached") {
    throw "Expected normal traffic to reach the backend, got HTTP $($normal.StatusCode)."
}

Clear-WafState
$attack = Invoke-StatusProbe "GET" "http://127.0.0.1:8080/backend/search?q=%27%20OR%201%3D1--"
if ($attack.StatusCode -ne 403) {
    throw "Expected the gateway model to block SQL injection, got HTTP $($attack.StatusCode)."
}

Clear-WafState
$failedLogins = 1..5 | ForEach-Object { Invoke-StatusProbe "POST" "http://127.0.0.1:8080/backend/login" }
$bruteForceBlock = Invoke-StatusProbe "POST" "http://127.0.0.1:8080/backend/login"
if (@($failedLogins | Where-Object StatusCode -ne 401).Count -ne 0 -or $bruteForceBlock.StatusCode -ne 403) {
    throw "Expected five failed logins followed by a temporary behavioral block."
}

Clear-WafState
Add-Type -AssemblyName System.Net.Http
$client = [System.Net.Http.HttpClient]::new()
$tasks = [System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]]::new()
1..45 | ForEach-Object { $tasks.Add($client.GetAsync("http://127.0.0.1:8080/backend/public/hello")) }
[Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks.ToArray())
$floodStatuses = $tasks | ForEach-Object { [int]$_.Result.StatusCode }
$mode = Invoke-RestMethod "http://127.0.0.1:8080/actuator/waf/mode"
$temporaryBlock = Invoke-StatusProbe "GET" "http://127.0.0.1:8080/backend/public/hello"
if (($floodStatuses -notcontains 429) -or $mode.mode -notin "DEGRADED", "EMERGENCY" -or $temporaryBlock.StatusCode -ne 403) {
    throw "Expected flood protection to rate-limit, enter a constrained mode, and temporarily block the source."
}

[pscustomobject]@{
    normal_status = $normal.StatusCode
    sql_attack_status = $attack.StatusCode
    brute_force_block_status = $bruteForceBlock.StatusCode
    flood_statuses = ($floodStatuses | Group-Object | Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ","
    operating_mode = $mode.mode
    temporary_block_status = $temporaryBlock.StatusCode
    result = "passed"
} | ConvertTo-Json
