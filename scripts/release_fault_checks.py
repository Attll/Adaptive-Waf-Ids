"""Bounded fault/restart checks on the explicitly owned release acceptance project."""
import json,subprocess,time
from pathlib import Path
from scripts.smoke_platform import try_request

def main():
    root=Path('research/runs/docker-faults-v38');root.mkdir(exist_ok=False)
    env=dict(x.split('=',1) for x in Path('infra/docker/release/.env').read_text().splitlines() if '=' in x)
    compose=['docker','compose','--env-file','infra/docker/release/.env','-p','adaptive-waf-release-acceptance','-f','infra/docker/release/compose.yml']
    def command(*args):
        result=subprocess.run([*compose,*args],capture_output=True,text=True)
        if result.returncode:raise RuntimeError(result.stderr)
        return result.stdout
    def get(service,path):return try_request('http://127.0.0.1:'+env[service.upper()+'_PORT']+path)
    results={}
    before=get('detection','/v1/deep/jobs')[1]['jobs']
    for service in ['detection','redis','rabbitmq']:
        command('stop',service)
        try:
            status,body=get('gateway','/backend/health')
            results[service]={'gateway_status_during_outage':status,'response':body}
        finally:
            command('up','-d','--no-build','--pull','never','--wait','--wait-timeout','180',service)
        results[service]['recovered_status']=get('gateway','/backend/health')[0]
    command('down')
    command('up','-d','--no-build','--pull','never','--wait','--wait-timeout','240')
    after=get('detection','/v1/deep/jobs')[1]['jobs']
    results['restart']={'before_job_ids':[x['job_id'] for x in before],'after_job_ids':[x['job_id'] for x in after],
                        'preserved':{x['job_id'] for x in before}.issubset({x['job_id'] for x in after})}
    results['limits']='Real service outages/recovery and persistent deep-job metadata. Gateway publication has no disk spool; not an exactly-once or partition durability guarantee.'
    (root/'results.json').write_text(json.dumps(results,indent=2))
    print(json.dumps({k:v for k,v in results.items() if k!='limits'},indent=2))
    if not results['restart']['preserved'] or results['detection']['gateway_status_during_outage']!=503:raise SystemExit(1)

if __name__=='__main__':main()
