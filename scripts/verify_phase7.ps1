param(
    [string]$DashboardUrl = "http://127.0.0.1:5173",
    [string]$DashboardDirectory = "dashboard"
)

$ErrorActionPreference = "Stop"
$adminUsername = if ($env:WAF_ADMIN_USERNAME) { $env:WAF_ADMIN_USERNAME } else { "admin" }
$adminPassword = if ($env:WAF_ADMIN_INITIAL_PASSWORD) { $env:WAF_ADMIN_INITIAL_PASSWORD } else { "adaptive_waf_dev" }
$token = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${adminUsername}:${adminPassword}"))
$headers = @{ Authorization = "Basic $token" }

Push-Location $DashboardDirectory
try {
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw "dashboard production build failed" }
} finally {
    Pop-Location
}

try {
    $dashboard = Invoke-WebRequest -UseBasicParsing -Uri $DashboardUrl -TimeoutSec 2
} catch {
    Start-Process -FilePath "C:\Windows\System32\cmd.exe" -ArgumentList "/c", "npm.cmd run dev -- --host 127.0.0.1" -WorkingDirectory (Resolve-Path $DashboardDirectory) -WindowStyle Hidden
    $deadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 500
        try { $dashboard = Invoke-WebRequest -UseBasicParsing -Uri $DashboardUrl -TimeoutSec 2 } catch { }
    } while (-not $dashboard -and (Get-Date) -lt $deadline)
}

if (-not $dashboard -or $dashboard.StatusCode -ne 200) { throw "dashboard was not reachable" }
if ($dashboard.Content -notmatch "Adaptive WAF Console") { throw "dashboard HTML did not contain the expected title" }

$events = Invoke-RestMethod -Uri "$DashboardUrl/control-api/v1/security/events?limit=2" -Headers $headers
$policy = Invoke-RestMethod -Uri "$DashboardUrl/gateway-api/actuator/waf/policy"
if ($null -eq $events.events) { throw "dashboard control-plane proxy did not return events" }
if ($null -eq $policy.version) { throw "dashboard gateway proxy did not return a policy version" }

[pscustomobject]@{
    dashboard_status = $dashboard.StatusCode
    proxied_event_count = @($events.events).Count
    proxied_policy_version = $policy.version
    result = "passed"
} | ConvertTo-Json
