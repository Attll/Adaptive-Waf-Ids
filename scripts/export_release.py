"""Export tagged release and infrastructure images with immutable IDs and checksums; no secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

def docker(*args):return subprocess.check_output(['docker',*args],text=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('new release bundle directory required')
    if shutil.disk_usage('.').free < 20*1024**3:parser.error('retain 20 GiB free space before exporting')
    source=Path('infra/docker/release');compose=json.loads((source/'compose.yml').read_text())
    args.output.mkdir(parents=True)
    images=[];tags=[]
    for name,service in compose['services'].items():
        original=service['image'];info=json.loads(docker('image','inspect',original))[0]
        tag=original if original.startswith('adaptive-waf-ids/') else f'adaptive-waf-ids/vendor-{name}:1.0.0'
        if tag!=original:docker('tag',info['Id'],tag)
        service['image']=tag;service.pop('build',None);tags.append(tag)
        images.append({'service':name,'tag':tag,'source':original,'id':info['Id'],'size_bytes':info['Size'],'repo_digests':info.get('RepoDigests',[])})
    (args.output/'compose.yml').write_text(json.dumps(compose,indent=2))
    (args.output/'image-manifest.json').write_text(json.dumps(images,indent=2))
    shutil.copyfile(source/'.env.example',args.output/'.env.example')
    shutil.copyfile(source/'DEPLOYMENT.md',args.output/'DEPLOYMENT.md')
    shutil.copyfile(source/'compose.gpu.yml',args.output/'compose.gpu.yml')
    (args.output/'operate.ps1').write_text('''param([ValidateSet('Start','Health','Logs','Stop','Import')][string]$Action='Health')
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
switch ($Action) {
 'Import' { docker load -i images.tar }
 'Start' { docker compose --env-file .env up -d --no-build --pull never --wait }
 'Health' { docker compose ps }
 'Logs' { docker compose logs --tail=100 }
 'Stop' { docker compose down }
}
if ($LASTEXITCODE -ne 0) { throw 'Release operation failed' }
''')
    shutil.copyfile('release-build/model-manifest.json',args.output/'model-manifest.json')
    (args.output/'README.md').write_text('# Adaptive WAF-IDS 1.0.0\n\nImport `docker load -i images.tar`. Copy `.env.example` to `.env`, replace all credential placeholders with random values, then `docker compose --env-file .env up -d --no-build --pull never --wait`. Dashboard: http://127.0.0.1:3000; gateway: http://127.0.0.1:8080/backend/. Stop with `docker compose down`; never add `-v` for normal cleanup. All models use CPU by default. Experimental routing and microbatching remain disabled. Fixed ML accuracy has known limitations; guarded_fixed is an explicit opt-in rule-assisted strategy. No representative research accuracy is claimed.\n')
    subprocess.run(['docker','save','--output',str(args.output/'images.tar'),*tags],check=True)
    checks={}
    for path in args.output.iterdir():
        if path.is_file():
            with path.open('rb') as stream:checks[path.name]=hashlib.file_digest(stream,'sha256').hexdigest()
    (args.output/'checksums.json').write_text(json.dumps(checks,indent=2))
    print(json.dumps({'bundle':str(args.output),'images':len(images),'archive_bytes':(args.output/'images.tar').stat().st_size}))

if __name__=='__main__':main()
