param(
    [string]$GatewayUrl = "http://127.0.0.1:8080",
    [string]$Root = "."
)

$ErrorActionPreference = "Stop"
function ListenerProcess([int]$Port) { (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop | Select-Object -First 1).OwningProcess }
function Wait-Http([string]$Url) { $deadline = (Get-Date).AddSeconds(45); do { try { $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3; if ($response.StatusCode -eq 200) { return } } catch { }; Start-Sleep -Milliseconds 700 } while ((Get-Date) -lt $deadline); throw "$Url did not recover" }
function Gateway-RemainsAvailable([string]$Name) { try { $response = Invoke-WebRequest -UseBasicParsing -Uri "$GatewayUrl/backend/health" -TimeoutSec 12; if ($response.StatusCode -ne 200) { throw "$Name caused gateway status $($response.StatusCode)" } } catch { if ($_.Exception.Response.StatusCode.value__ -ne 200) { throw "$Name caused gateway failure: $($_.Exception.Message)" } } }
function Restart-Python([int]$Port, [string[]]$Arguments, [string]$ReadyUrl) { Start-Process -FilePath (Join-Path $Root '.venv\Scripts\python.exe') -ArgumentList $Arguments -WorkingDirectory $Root -WindowStyle Hidden; Wait-Http $ReadyUrl }

$results = @{}

$detection = ListenerProcess 8000
Stop-Process -Id $detection -ErrorAction Stop
Gateway-RemainsAvailable "detection outage"
Restart-Python 8000 @('-m', 'uvicorn', 'adaptive_waf.service.app:app', '--host', '127.0.0.1', '--port', '8000') 'http://127.0.0.1:8000/ready'
$results.detection = 'fail_open_verified'

$sensor = ListenerProcess 8083
Stop-Process -Id $sensor -ErrorAction Stop
Gateway-RemainsAvailable "network sensor outage"
Restart-Python 8083 @('-m', 'scripts.run_network_sensor') 'http://127.0.0.1:8083/ready'
$results.network_sensor = 'non_blocking_verified'

$adaptation = ListenerProcess 8084
Stop-Process -Id $adaptation -ErrorAction Stop
Gateway-RemainsAvailable "training service outage"
Restart-Python 8084 @('-m', 'scripts.run_training_adaptation_service') 'http://127.0.0.1:8084/health'
$results.training_adaptation = 'non_blocking_verified'

foreach ($dependency in @(@{ name='redis'; container='adaptive-waf-phase4-redis-1' }, @{ name='rabbitmq'; container='adaptive-waf-phase5-rabbitmq-1' }, @{ name='postgresql'; container='adaptive-waf-phase5-postgres-1' })) {
    docker stop $dependency.container | Out-Null
    try { Gateway-RemainsAvailable "$($dependency.name) outage" }
    finally { docker start $dependency.container | Out-Null }
    Start-Sleep -Seconds 3
    $results[$dependency.name] = 'gateway_fail_open_verified'
}

[pscustomobject]@{ results = $results; result = 'passed' } | ConvertTo-Json -Depth 4
