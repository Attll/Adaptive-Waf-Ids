"""Small labeled Docker gateway diagnostic; inspection coverage is joined from real journal entries."""
import argparse,base64,json,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request,urlopen
from scripts.research_probe import invoke,summarize
from scripts.evaluate_phase10 import CASES

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('new report required')
    env=dict(x.split('=',1) for x in Path('infra/docker/release/.env').read_text().splitlines() if '=' in x)
    auth='Basic '+base64.b64encode((env['ADMIN_USERNAME']+':'+env['ADMIN_PASSWORD']).encode()).decode()
    results=[]
    for concurrency in (1,4):
        started=time.perf_counter()
        with ThreadPoolExecutor(concurrency) as pool:rows=list(pool.map(lambda job:invoke('gateway','http://127.0.0.1:'+env['GATEWAY_PORT'],job),CASES.items()))
        elapsed=time.perf_counter()-started
        for _ in range(40):
            request=Request('http://127.0.0.1:'+env['CONTROL_PORT']+'/v1/security/events?limit=200',headers={'Authorization':auth})
            with urlopen(request,timeout=5) as response:events={r['requestId']:r for r in json.load(response)['events']}
            if all(row['request_id'] in events for row in rows):break
            time.sleep(.1)
        for row in rows:
            event=events.get(row['request_id'],{})
            row.update(predicted_attack=event.get('predictedAttack'),inspection_status=event.get('inspectionStatus','UNKNOWN'),action=event.get('action','UNKNOWN'),detection_latency_ms=event.get('detectionLatencyMs'))
        metrics=summarize(rows,elapsed)
        metrics['rule_only_count']=sum(row['inspection_status']=='RULES_ONLY' for row in rows)
        results.append({'concurrency':concurrency,'metrics':metrics,'raw':rows})
    args.output.write_text(json.dumps({'scope':'one six-development-probe pass per concurrency; not independent accuracy or sustained capacity; asynchronous jobs never retroactively counted as fully inspected inline',
                                     'experiments':results},indent=2))
    print(json.dumps([{k:v for k,v in row.items() if k!='raw'} for row in results],indent=2))

if __name__=='__main__':main()
