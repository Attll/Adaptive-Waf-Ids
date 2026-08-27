param(
    [string]$GatewayUrl = "http://127.0.0.1:8080",
    [string]$DetectionUrl = "http://127.0.0.1:8000",
    [string]$SensorUrl = "http://127.0.0.1:8083",
    [string]$AdaptationUrl = "http://127.0.0.1:8084"
)

$ErrorActionPreference = "Stop"
$checks = @(
    @{ name = "detection"; url = "$DetectionUrl/ready" },
    @{ name = "gateway"; url = "$GatewayUrl/actuator/waf/policy" },
    @{ name = "network_sensor"; url = "$SensorUrl/ready" },
    @{ name = "training_adaptation"; url = "$AdaptationUrl/health" }
)
$result = @{}
foreach ($check in $checks) { $response = Invoke-WebRequest -UseBasicParsing -Uri $check.url -TimeoutSec 10; $result[$check.name] = $response.StatusCode }

& .\.venv\Scripts\python.exe -u -m scripts.evaluate_phase10 --requests-per-case 5 --workers 2
if ($LASTEXITCODE -ne 0) { throw "Phase 10 evaluation failed" }
$summary = Get-Content "artifacts\evaluations\phase10-summary.json" -Raw | ConvertFrom-Json
if ($summary.available_requests -ne $summary.total_requests) { throw "evaluation had unavailable requests" }

[pscustomobject]@{
    services = $result
    latency_p95_ms = $summary.latency_p95_ms
    precision = $summary.precision
    recall = $summary.recall
    f1 = $summary.f1
    result = "passed"
} | ConvertTo-Json -Depth 4
