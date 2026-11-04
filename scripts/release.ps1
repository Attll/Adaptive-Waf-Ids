param([ValidateSet('Validate','Build','Start','Health','Smoke','Logs','Stop','Export','Import')][string]$Action='Health',
      [string]$Project='adaptive-waf-ids-release',[string]$Bundle='releases/adaptive-waf-ids-1.0.0')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $root
$compose=@('compose','--env-file','infra/docker/release/.env','-p',$Project,'-f','infra/docker/release/compose.yml')
switch ($Action) {
 'Validate' { & docker @compose config --quiet }
 'Build' {
   & ./.venv/Scripts/python.exe -m scripts.prepare_release_models
   if ($LASTEXITCODE -ne 0) { throw 'Model integrity failed' }
   & docker @compose build
 }
 'Start' { & docker @compose up -d --no-build --pull never --wait --wait-timeout 300 }
 'Health' { & docker @compose ps }
 'Smoke' { & ./.venv/Scripts/python.exe -m scripts.release_smoke }
 'Logs' { & docker @compose logs --tail=100 }
 'Stop' { & docker @compose down }
 'Export' { & ./.venv/Scripts/python.exe -m scripts.export_release --output $Bundle }
 'Import' { & docker load --input "$Bundle/images.tar" }
}
if ($LASTEXITCODE -ne 0) { throw "Release action $Action failed ($LASTEXITCODE)" }
