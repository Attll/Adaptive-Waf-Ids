"""Allowlisted model-only operator queries, independent of enforcement rules."""
from functools import lru_cache
from pathlib import Path
from time import perf_counter
import tomllib
import joblib
from adaptive_waf.features.classical import ClassicalFeatureExtractor
from adaptive_waf.training.http_data import _request_from_record

STAGES={'triage':'triage_deployment','router':'router_deployment','injection':'injection_expert_deployment',
        'execution':'execution_expert_deployment','network':'network_deployment','deep':'deep_deployment'}

@lru_cache(maxsize=12)
def artifact(path):
    model=joblib.load(path)
    from adaptive_waf.runtime.optimization import configure_inference_threads
    configure_inference_threads(model,1)
    return model

def query_models(body,pipeline,root=Path('.')):
    stage=body['stage']; algorithm=body.get('algorithm','deployed')
    if stage not in STAGES:raise ValueError('unknown model stage')
    options=tomllib.loads((root/'configs/models'/f'{STAGES[stage]}.toml').read_text(encoding='utf-8'))
    selected=options.get('algorithm',options.get('candidate'))
    if algorithm!='deployed' and algorithm not in {'random_forest','extra_trees','logistic_regression','distilbert'}:raise ValueError('unknown candidate algorithm')
    path=root/options['artifact']
    if algorithm!='deployed' and algorithm!=selected:
        if stage=='deep':raise ValueError('requested deep candidate is not available')
        path=path.parent.parent/algorithm/'model.joblib'
    if not path.is_file() and stage!='deep':raise ValueError('candidate artifact unavailable')
    requests=body.get('requests',[])
    if not 1<=len(requests)<=32:raise ValueError('provide 1..32 requests')
    base=pipeline
    while hasattr(base,'baseline') or hasattr(base,'pipeline'):
        base=getattr(base,'baseline',None) or base.pipeline
    rows=[]
    for record in requests:
        started=perf_counter()
        if stage=='deep':
            output,_=pipeline.adjudicate(_request_from_record(record))
            scores={str(key):value for key,value in output.class_scores.items()}
        else:
            if algorithm=='deployed' and stage in {'triage','router','injection','execution'}:
                from adaptive_waf.contracts import ExpertFamily
                model=base._triage_model if stage=='triage' else base._router_model if stage=='router' else base._expert_models[ExpertFamily.INJECTION if stage=='injection' else ExpertFamily.EXECUTION]
            else:model=artifact(str(path.resolve()))
            if stage=='network':
                import json
                manifest=__import__('json').loads((path.parent.parent/'feature_manifest.json').read_text())
                features=record['features'];values=[features[key] for key in manifest['feature_names']]
            else:values=list(ClassicalFeatureExtractor().extract(_request_from_record(record)).values)
            scores={str(label):float(probability) for label,probability in zip(model.classes_,model.predict_proba([values])[0],strict=True)}
        supplied=record.get('expected',record.get('label'))
        expected=supplied
        if stage=='triage' and supplied:expected='BENIGN_LIKE' if supplied=='BENIGN' else 'SUSPICIOUS'
        if stage=='router':
            expected='INJECTION' if supplied in {'SQL_INJECTION','XSS','COOKIE_INJECTION'} else 'EXECUTION' if supplied in {'REMOTE_CODE_EXECUTION','DIRECTORY_TRAVERSAL'} else None
        if expected not in scores:expected=None
        predicted=max(scores,key=scores.get)
        rows.append({'probabilities':scores,'prediction':predicted,'latency_ms':(perf_counter()-started)*1000,
                     'expected_label_supplied':supplied,'expected_model_label':expected,
                     'matches_supplied_label':predicted==expected if expected else None})
    return {'stage':stage,'algorithm':selected if algorithm=='deployed' else algorithm,'model_only':True,
            'rules_used':False,'calibration':'runtime deployed calibration' if algorithm=='deployed' else 'raw candidate artifact',
            'model_version':str(options.get('run_id','fixture'))+':'+str(selected if algorithm=='deployed' else algorithm),
            'results':rows,'scope':'direct model query; no gateway request or security event is implied'}
