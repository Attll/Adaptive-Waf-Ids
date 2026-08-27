Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$adminUser = if ([string]::IsNullOrWhiteSpace($env:WAF_ADMIN_USERNAME)) { "admin" } else { $env:WAF_ADMIN_USERNAME }
$adminPassword = if ([string]::IsNullOrWhiteSpace($env:WAF_ADMIN_INITIAL_PASSWORD)) { "adaptive_waf_dev" } else { $env:WAF_ADMIN_INITIAL_PASSWORD }
$credentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$adminUser`:$adminPassword"))
$headers = @{ Authorization = "Basic $credentials" }

$unauthenticatedStatus = 0
try { Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8082/v1/control/policy" | Out-Null }
catch { $unauthenticatedStatus = [int]$_.Exception.Response.StatusCode }
if ($unauthenticatedStatus -ne 401) { throw "Expected unauthenticated control-plane request to return 401." }

$before = Invoke-RestMethod -Headers $headers "http://127.0.0.1:8082/v1/control/policy"
$temporaryThreshold = [Math]::Round([Math]::Min(0.99, $before.blockRiskThreshold + 0.01), 2)
$updated = Invoke-RestMethod -Headers $headers -Method Put -ContentType "application/json" -Body (@{ blockRiskThreshold = $temporaryThreshold; rateLimitShortWindow = $before.rateLimitShortWindow } | ConvertTo-Json -Compress) "http://127.0.0.1:8082/v1/control/policy"
Start-Sleep -Seconds 4
$cached = Invoke-RestMethod "http://127.0.0.1:8080/actuator/waf/policy"
if ($cached.blockRiskThreshold -ne $temporaryThreshold) { throw "Gateway policy cache did not refresh." }

$sourceIp = "203.0.113.10"
Invoke-RestMethod -Headers $headers -Method Post -ContentType "application/json" -Body (@{ sourceIp = $sourceIp; reason = "phase6 verification" } | ConvertTo-Json -Compress) "http://127.0.0.1:8082/v1/control/blocks" | Out-Null
$blockValue = docker compose -f (Join-Path (Split-Path -Parent $PSScriptRoot) "infra\docker\compose.phase4.yml") exec -T redis redis-cli GET "waf:block:$sourceIp"
Invoke-RestMethod -Headers $headers -Method Delete "http://127.0.0.1:8082/v1/control/blocks/$sourceIp" | Out-Null
Invoke-RestMethod -Headers $headers -Method Put -ContentType "application/json" -Body (@{ blockRiskThreshold = $before.blockRiskThreshold; rateLimitShortWindow = $before.rateLimitShortWindow } | ConvertTo-Json -Compress) "http://127.0.0.1:8082/v1/control/policy" | Out-Null

if ($blockValue -notmatch "manual:phase6 verification") { throw "Manual block did not reach Redis." }
$audit = Invoke-RestMethod -Headers $headers "http://127.0.0.1:8082/v1/control/audit?limit=50"
if (@($audit.audit).Count -eq 0) { throw "No audit records were returned." }

[pscustomobject]@{
    unauthenticated_status = $unauthenticatedStatus
    policy_version_before = $before.version
    policy_version_updated = $updated.version
    gateway_cached_threshold = $cached.blockRiskThreshold
    manual_block_redis_value = $blockValue.Trim()
    audit_entries = @($audit.audit).Count
    result = "passed"
} | ConvertTo-Json
