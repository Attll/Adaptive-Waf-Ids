"""Bounded read-only warmed development inference; no training or accuracy claims."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from time import perf_counter
import tomllib

from scripts.evaluate_phase10 import CASES
from scripts.research_probe import percentile
from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.runtime.artifacts import DistilBertPredictor
from adaptive_waf.runtime.microbatch import MicrobatchPredictor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--repeats',type=int,default=2)
    args = parser.parse_args()
    if args.output.exists() or not 1 <= args.repeats <= 3:
        parser.error('new output path and 1..3 repeats required')
    import torch
    torch.set_num_threads(1)
    deep = tomllib.loads(Path('configs/models/deep_deployment.toml').read_text())
    calibration = tomllib.loads(Path('configs/models/calibration_deployment.toml').read_text())['deep']
    requests = [HttpRequestRecord('GET',case['path'],case.get('query',''),cookies=case.get('cookies',{})) for case in CASES.values()]
    report = {'scope':'six repeated development requests; warmed in-process inference, not generalization or gateway throughput',
              'torch':str(torch.__version__),'threads':1,'model_run_id':deep['run_id'],'records':[]}
    for device in (['cpu','cuda'] if torch.cuda.is_available() else ['cpu']):
        model = DistilBertPredictor(Path(deep['artifact']),Path(calibration['artifact']),device)
        model.warm()
        reference = [model(request) for request in requests]
        model.predict_many(requests)
        for batch_size in (1,2,4,6):
            times, count, delta, equal = [], 0, 0., True
            begun = perf_counter()
            for _ in range(args.repeats):
                for start in range(0,len(requests),batch_size):
                    before = perf_counter()
                    predictions = model.predict_many(requests[start:start+batch_size])
                    times.append((perf_counter()-before)*1000)
                    count += len(predictions)
                    for expected,actual in zip(reference[start:start+batch_size],predictions,strict=True):
                        delta = max(delta,max(abs(expected[key]-actual[key]) for key in expected))
                        equal = equal and max(expected,key=expected.get) == max(actual,key=actual.get)
            elapsed = perf_counter()-begun
            report['records'].append({'device':device,'mode':'offline_batch','batch_size':batch_size,'requests':count,
                 'requests_per_second':count/elapsed,'batch_p95_ms':percentile(times,.95),
                 'predictions_equal_to_single':equal,'maximum_probability_delta':delta})
        for concurrency in (1,4,8):
            for enabled in (False,True):
                adapter = MicrobatchPredictor(model,max_batch=4,wait_ms=2,timeout_seconds=10) if enabled else None
                def invoke(index):
                    request = requests[index % len(requests)]
                    before = perf_counter()
                    result = (adapter or model)(request)
                    return {'index':index,'elapsed_ms':(perf_counter()-before)*1000,'prediction':str(max(result,key=result.get)),
                            'maximum_delta':max(abs(result[key]-reference[index % len(requests)][key]) for key in result)}
                try:
                    begun = perf_counter()
                    with ThreadPoolExecutor(concurrency) as pool:
                        rows = list(pool.map(invoke,range(len(requests)*args.repeats)))
                    elapsed = perf_counter()-begun
                    report['records'].append({'device':device,'mode':'microbatch' if enabled else 'serialized_lock',
                        'concurrency':concurrency,'requests':len(rows),'requests_per_second':len(rows)/elapsed,
                        'request_p50_ms':percentile([row['elapsed_ms'] for row in rows],.5),
                        'request_p95_ms':percentile([row['elapsed_ms'] for row in rows],.95),
                        'maximum_probability_delta':max(row['maximum_delta'] for row in rows),
                        'predictions_equal_to_single':all(row['prediction'] == str(max(reference[row['index'] % len(requests)],key=reference[row['index'] % len(requests)].get)) for row in rows),
                        'batch_statistics':adapter.statistics() if adapter else None,'raw':rows})
                finally:
                    if adapter:adapter.close()
        del model
        if device == 'cuda':torch.cuda.empty_cache()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as destination:json.dump(report,destination,indent=2,allow_nan=False)
    print(json.dumps([{key:value for key,value in row.items() if key not in {'raw','batch_statistics'}} for row in report['records']],indent=2))


if __name__ == '__main__':main()
