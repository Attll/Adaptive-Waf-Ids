"""Exercise the deployed, authenticated operator workflows without changing active policies."""
import argparse,base64,json,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('new evidence directory required')
    args.output.mkdir(parents=True)
    env=dict(line.split('=',1) for line in Path('infra/docker/release/.env').read_text().splitlines() if '=' in line)
    base='http://127.0.0.1:'+env['DASHBOARD_PORT']
    auth='Basic '+base64.b64encode((env['ADMIN_USERNAME']+':'+env['ADMIN_PASSWORD']).encode()).decode()
    def call(path,body=None,authenticated=True):
        headers={'Content-Type':'application/json'}
        if authenticated:headers['Authorization']=auth
        request=Request(base+'/control-api/v1/control/tools'+path,json.dumps(body).encode() if body is not None else None,headers=headers)
        try:response=urlopen(request,timeout=35)
        except HTTPError as error:response=error
        with response:
            raw=response.read()
            try:data=json.loads(raw)
            except ValueError:data=raw.decode(errors='replace')[:1000]
            return response.status,data
    results={}
    results['unauthenticated_cache_status']=call('/redis',authenticated=False)[0]
    replay=[]
    for request in [{'method':'GET','path':'/health'},
                    {'method':'GET','path':'/search','query':'q=<script>alert(1)</script>'},
                    {'method':'GET','path':'/search','cookies':{'session':"x' OR '1'='1"}},
                    {'method':'POST','path':'/api/echo','headers':{'Content-Type':'application/json'},'body':'{"note":"operator fixture"}'}]:
        status,data=call('/replay',request);replay.append({'status':status,'result':data})
    results['replay']=replay
    status,cache=call('/redis');results['redis']={'status':status,'data':cache}
    templates=[{'method':'GET','path':'/health','query':''},{'method':'GET','path':'/search','query':"q=1' OR '1'='1"}]
    network=json.loads(Path('datasets/samples/network-corpus.jsonl').read_text().splitlines()[0])
    models=[]
    for stage in ('triage','router','injection','execution','deep','network'):
        requests=[network] if stage=='network' else templates
        for algorithm in (['deployed'] if stage=='deep' else ['deployed','random_forest','extra_trees','logistic_regression']):
            status,data=call('/models/query',{'stage':stage,'algorithm':algorithm,'requests':requests})
            models.append({'stage':stage,'algorithm':algorithm,'status':status,'response':data})
    results['models']=models
    status,report=call('/rl/validate',{})
    results['rl']={'status':status,'report':report}
    history_status,history=call('/rl/runs')
    saved_status,saved=call('/rl/runs/'+report['run_id']) if status==200 else (0,{})
    results['routing_history']={'status':history_status,'saved_status':saved_status,'runs':history}
    time.sleep(1)
    request=Request(base+'/control-api/v1/security/events?limit=100',headers={'Authorization':auth})
    with urlopen(request,timeout=5) as response:events=json.load(response)['events']
    seen={event['requestId'] for event in events}
    checks={'cache_auth':results['unauthenticated_cache_status']==401,'replay_gateway_results':all(row['status']==200 and row['result'].get('requestId') for row in replay),
            'cookie_evidence_blocked':replay[2]['result'].get('status')==403,
            'journal_correlation':all(row['result'].get('requestId') in seen for row in replay),
            'live_redis_values':results['redis']['status']==200 and all('value' in row for row in cache.get('entries',[])),
            'all_models_queryable':all(row['status']==200 and row['response'].get('model_only') for row in models),
            'rl_shadow_validation':status==200 and report.get('shadow_only') and not report.get('automatic_promotion') and len(report.get('results',[]))==6,
            'routing_artifacts_retrievable':history_status==200 and saved_status==200 and any(row['run_id']==report.get('run_id') for row in history.get('runs',[])) and saved.get('input_sha256')==report.get('input_sha256')}
    results['checks']=checks
    (args.output/'results.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(checks,indent=2))
    if not all(checks.values()):raise SystemExit(1)

if __name__=='__main__':main()
