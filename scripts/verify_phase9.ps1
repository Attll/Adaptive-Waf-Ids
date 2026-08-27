param(
    [string]$ControlUrl = "http://127.0.0.1:8082",
    [string]$AdaptationUrl = "http://127.0.0.1:8084"
)

$ErrorActionPreference = "Stop"
$adminUsername = if ($env:WAF_ADMIN_USERNAME) { $env:WAF_ADMIN_USERNAME } else { "admin" }
$adminPassword = if ($env:WAF_ADMIN_INITIAL_PASSWORD) { $env:WAF_ADMIN_INITIAL_PASSWORD } else { "adaptive_waf_dev" }
$token = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${adminUsername}:${adminPassword}"))
$headers = @{ Authorization = "Basic $token" }

$health = Invoke-RestMethod -Uri "$AdaptationUrl/health" -TimeoutSec 10
if ($health.status -ne "ok") { throw "training-adaptation service is not healthy" }
$runs = Invoke-RestMethod -Uri "$ControlUrl/v1/control/training-runs" -Headers $headers
if (@($runs.runs).Count -lt 1) { throw "no lifecycle training run is available for validation" }
$drift = Invoke-RestMethod -Method Post -Uri "$AdaptationUrl/v1/adaptation/drift" -ContentType "application/json" -Body '{"reference":[0,1,2,3,4,5,6,7,8,9],"observed":[9,9,9,9,9,9,9,9,9,9]}'
if ($drift.automatic_policy_change) { throw "adaptation service reported an automatic policy change" }

[pscustomobject]@{
    adaptation_status = $health.status
    training_run_count = @($runs.runs).Count
    drift_classification = $drift.classification
    automatic_policy_change = $drift.automatic_policy_change
    result = "passed"
} | ConvertTo-Json
