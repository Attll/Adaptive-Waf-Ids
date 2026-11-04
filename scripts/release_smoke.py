"""Run existing platform checks using the private local release environment."""
from pathlib import Path
import sys
from scripts.smoke_platform import main

def run():
    settings=dict(line.split('=',1) for line in Path('infra/docker/release/.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
    sys.argv=['smoke_platform','--username',settings.get('ADMIN_USERNAME','admin'),'--password',settings['ADMIN_PASSWORD']]
    for service,default in [('gateway',8080),('control',8082),('detection',8000),('sensor',8083),('adaptation',8084)]:
        sys.argv += ['--'+service,'http://127.0.0.1:'+settings.get(service.upper()+'_PORT',str(default))]
    return main()

if __name__=='__main__':raise SystemExit(run())
