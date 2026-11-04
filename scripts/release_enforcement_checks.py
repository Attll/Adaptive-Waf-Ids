"""Isolated release policy propagation, Redis burst enforcement and temporary block expiry."""
import base64,json,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor

def main():
    env=dict(x.split('=',1) for x in Path('infra/docker/release/.env').read_text().splitlines() if '=' in x)
    auth='Basic '+base64.b64encode((env['ADMIN_USERNAME']+':'+env['ADMIN_PASSWORD']).encode()).decode()
    def call(service,path,method='GET',data=None):
        headers={'Authorization':auth,'Content-Type':'application/json'}
        request=Request('http://127.0.0.1:'+env[service.upper()+'_PORT']+path,json.dumps(data).encode() if data is not None else None,headers=headers,method=method)
        try:r=urlopen(request,timeout=10)
        except HTTPError as error:r=error
        with r:
            raw=r.read()
            return r.status,json.loads(raw) if raw else {}
    baseline=call('control','/v1/control/policy')[1]
    def wait(rate):
        for _ in range(80):
            if call('gateway','/actuator/waf/policy')[1].get('rateLimitShortWindow')==rate:return True
            time.sleep(.5)
        return False
    results={}
    try:
        call('control','/v1/control/policy','PUT',{'blockRiskThreshold':baseline['blockRiskThreshold'],'rateLimitShortWindow':3})
        results['policy_propagated']=wait(3)
        with ThreadPoolExecutor(4) as pool:codes=list(pool.map(lambda _:call('gateway','/backend/health')[0],range(12)))
        results['burst_codes']=codes;results['rate_limit_observed']=429 in codes
    finally:
        call('control','/v1/control/policy','PUT',{'blockRiskThreshold':baseline['blockRiskThreshold'],'rateLimitShortWindow':baseline['rateLimitShortWindow']})
        results['policy_restored']=wait(baseline['rateLimitShortWindow'])
    events=call('control','/v1/security/events?limit=20')[1]['events']
    source=next(event['sourceIp'] for event in events if event.get('sourceIp'))
    status,_=call('control','/v1/control/blocks','POST',{'sourceIp':source,'reason':'Owned release expiry acceptance','duration':'PT2S'})
    results['block_created']=status in (200,201)
    results['temporary_block_status']=call('gateway','/backend/health')[0]
    time.sleep(3)
    results['after_expiry_status']=call('gateway','/backend/health')[0]
    Path('research/runs/docker-enforcement-v51.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
    if not (results['policy_propagated'] and results['policy_restored'] and results['rate_limit_observed'] and results['temporary_block_status']==403 and results['after_expiry_status']==200):raise SystemExit(1)

if __name__=='__main__':main()
