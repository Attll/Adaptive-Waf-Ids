"""Owned Docker release acceptance: real HTTP, journal correlation, sensor and deferred completion."""
import argparse,base64,json,time,uuid
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor
from scripts.evaluate_phase10 import CASES

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--env-file',type=Path,default=Path('infra/docker/release/.env'));args=parser.parse_args()
    if args.output.exists():parser.error('new report required')
    env=dict(x.split('=',1) for x in args.env_file.read_text().splitlines() if '=' in x)
    auth='Basic '+base64.b64encode((env.get('ADMIN_USERNAME','admin')+':'+env['ADMIN_PASSWORD']).encode()).decode()
    def call(service,path,data=None,headers=None):
        port=env[service.upper()+'_PORT'];h=headers or {}
        if service=='control':h={**h,'Authorization':auth}
        if data is not None:h={**h,'Content-Type':'application/json'}
        req=Request('http://127.0.0.1:'+port+path,json.dumps(data).encode() if data is not None else None,headers=h)
        try:r=urlopen(req,timeout=15)
        except HTTPError as error:r=error
        with r:
            raw=r.read()
            try:body=json.loads(raw)
            except ValueError:body=raw.decode(errors='replace')[:300]
            return r.status,body
    rows=[]
    for name,case in CASES.items():
        identifier=str(uuid.uuid4());start=time.perf_counter()
        # Cookies are deliberately serialized as an HTTP header at the actual gateway boundary.
        from urllib.parse import quote
        query=case.get('query','')
        path='/backend'+case['path']+('?' + quote(query,safe='=&%') if query else '')
        status,body=call('gateway',path,headers={'X-Request-ID':identifier,'Cookie':'; '.join(k+'='+v for k,v in case.get('cookies',{}).items())})
        rows.append({'case':name,'request_id':identifier,'http_status':status,'round_trip_ms':(time.perf_counter()-start)*1000})
    events={}
    for _ in range(40):
        status,body=call('control','/v1/security/events?limit=200')
        events={item['requestId']:item for item in body.get('events',[])}
        if all(row['request_id'] in events for row in rows):break
        time.sleep(.25)
    for row in rows:
        event=events.get(row['request_id'],{})
        row.update(persisted=bool(event),inspection_status=event.get('inspectionStatus'),action=event.get('action'),prediction=event.get('predictedAttack'))
    # Use a complete existing sampled flow, not the old smoke's intentionally partial vector.
    record=json.loads(Path('datasets/samples/network-corpus.jsonl').read_text().splitlines()[0])
    features=record.get('features',{})
    sensor_status,sensor=call('sensor','/v1/flows',{'source_ip':'192.0.2.71','features':features})
    jobs_status,jobs=call('detection','/v1/deep/jobs')
    for _ in range(40):
        if any(job['state']=='COMPLETED' for job in jobs.get('jobs',[])):break
        time.sleep(.25)
        jobs_status,jobs=call('detection','/v1/deep/jobs')
    dashboard_status,dashboard=call('dashboard','/')
    proxy_status,_=call('dashboard','/control-api/v1/control/policy',headers={'Authorization':auth})
    blocked_internal,_=call('dashboard','/detection-api/internal/v1/research/state')
    checks={'all_requests_persisted':all(row['persisted'] for row in rows),'benign_forwarded':rows[0]['http_status']==200,
            'five_attacks_blocked':sum(row['http_status']==403 for row in rows[1:])==5,
            'network_full_vector':sensor_status==200,'durable_completed_jobs':any(job['state']=='COMPLETED' for job in jobs.get('jobs',[])),
            'dashboard_html':dashboard_status==200,'dashboard_authenticated_proxy':proxy_status==200,'browser_internal_route_blocked':blocked_internal==404}
    report={'checks':checks,'requests':rows,'network':{'status':sensor_status,'result':sensor},'deep_jobs':jobs,
            'scope':'six development diagnostics; no representative model-only accuracy or browser automation claim'}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2))
    print(json.dumps(checks,indent=2))
    if not all(checks.values()):raise SystemExit(1)

if __name__=='__main__':main()
