param([Parameter(Mandatory=$true)][string]$RunId, [switch]$Integration)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$runRoot = Join-Path $projectRoot "research/runs/$RunId"
if (Test-Path -LiteralPath $runRoot) { throw 'Select a new run id; existing evidence will not be overwritten.' }
New-Item -ItemType Directory -Path $runRoot | Out-Null
if ($Integration) {
    $env:WAF_TEST_REDIS_PORT = (docker compose -p adaptive-waf-research -f research/compose.integration.yml port redis 6379).Split(':')[-1]
    $env:WAF_TEST_RABBIT_PORT = (docker compose -p adaptive-waf-research -f research/compose.integration.yml port rabbitmq 5672).Split(':')[-1]
    $env:WAF_TEST_POSTGRES_PORT = (docker compose -p adaptive-waf-research -f research/compose.integration.yml port postgres 5432).Split(':')[-1]
    & "$projectRoot/.venv/Scripts/python.exe" -m scripts.wait_research_fixtures --timeout 45 *> "$runRoot/fixture_readiness.json"
    if ($LASTEXITCODE -ne 0) { throw "Isolated fixture protocol readiness failed; see $runRoot/fixture_readiness.json" }
}
$outcomes = @()
foreach ($component in @('gateway-service','security-control-service','demo-backend')) {
    & mvn -o -f "$component/pom.xml" '-DargLine=-XX:+EnableDynamicAgentLoading -Djdk.attach.allowAttachSelf=true' test *> "$runRoot/$component.txt"
    $outcomes += @{ component=$component; exit_code=$LASTEXITCODE }
}
& "$projectRoot/.venv/Scripts/python.exe" -m unittest discover -s tests -v *> "$runRoot/python.txt"
$outcomes += @{ component='python'; exit_code=$LASTEXITCODE }
& npm.cmd --prefix dashboard run build *> "$runRoot/dashboard.txt"
$outcomes += @{ component='dashboard'; exit_code=$LASTEXITCODE }
$outcomes | ConvertTo-Json | Set-Content -LiteralPath "$runRoot/checks.json" -Encoding utf8
$outcomes | Format-Table
if ($outcomes.Where({ $_.exit_code -ne 0 }).Count -gt 0) { exit 1 }
