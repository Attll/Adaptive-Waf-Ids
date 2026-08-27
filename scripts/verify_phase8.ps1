param(
    [string]$SensorUrl = "http://127.0.0.1:8083",
    [string]$GatewayUrl = "http://127.0.0.1:8080"
)

$ErrorActionPreference = "Stop"
$sensor = Invoke-RestMethod -Uri "$SensorUrl/ready" -TimeoutSec 10
if ($sensor.status -ne "ready") { throw "network sensor is not ready" }

$line = Get-Content "datasets\processed\cicids2018\cicids2018-flow-subset-v3\test.jsonl" -TotalCount 20 | Where-Object { $_ -match "BRUTE_FORCE" } | Select-Object -First 1
if (-not $line) { throw "expected local BRUTE_FORCE replay fixture was not found" }
$record = $line | ConvertFrom-Json
$body = @{ source_ip = "127.0.0.1"; destination_ip = "127.0.0.1"; features = $record.features } | ConvertTo-Json -Depth 4 -Compress
$evidence = Invoke-RestMethod -Method Post -Uri "$SensorUrl/v1/flows" -ContentType "application/json" -Body $body
if ($evidence.network_context.network_risk -lt 0.81) { throw "replayed brute-force flow did not produce high network risk" }

$requestId = [guid]::NewGuid().ToString()
try { $response = Invoke-WebRequest -UseBasicParsing -Uri "$GatewayUrl/backend/health" -Headers @{ "X-Request-ID" = $requestId } -TimeoutSec 10; $status = $response.StatusCode }
catch { $status = [int]$_.Exception.Response.StatusCode }
if ($status -ne 403) { throw "gateway did not enforce high network context; received $status" }

[pscustomobject]@{
    sensor_model = $sensor.model_version
    network_class = $evidence.network_context.network_class
    network_risk = $evidence.network_context.network_risk
    gateway_status = $status
    result = "passed"
} | ConvertTo-Json
