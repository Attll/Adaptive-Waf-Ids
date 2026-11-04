"""Bounded offline routing fits with genuinely separate input populations."""
from pathlib import Path
import hashlib,json,time
from uuid import uuid4
from adaptive_waf.runtime.routing import LinUCB,labeled_reward
from adaptive_waf.runtime.replay import validate_population,replay

def controlled_fixture():
    """Deterministic test environment; route costs are prescribed, not hardware measurements."""
    def row(index,role):
        attack=index%2==1
        return {'request_id':f'{role}-{index}','group_id':f'{role}/controlled-{index}','population':role,'label_source':'VERIFIED',
                'expected':'XSS' if attack else 'BENIGN','pre_action_context':{'fast_risk':.8 if attack else .05,'entropy':.8 if attack else .05,'margin':.1 if attack else .9},
                'outcomes':{'FAST_ONLY':{'predicted':'BENIGN','latency_ms':1,'compute_cost':.01},
                            'BOTH':{'predicted':'XSS' if attack else 'BENIGN','latency_ms':2,'compute_cost':.02}}}
    return {'review_reference':'CONTROLLED_SIMULATION_BY_CONSTRUCTION','data_origin':'CONTROLLED_SIMULATION',
            'model_versions':{'simulated-detectors':'fixture-v1'},'development':[row(i,'development') for i in range(100)],
            'evaluation':[row(i,'evaluation') for i in range(40)]}

def train(request,root):
    if Path(root).exists() and sum(1 for path in Path(root).iterdir() if path.is_dir())>=200:
        raise ValueError('Routing artifact capacity reached; archive reviewed runs before creating more')
    development,evaluation=request['development'],request['evaluation']
    if not request.get('review_reference') or not 1<=len(development)<=1000 or not 1<=len(evaluation)<=1000:
        raise ValueError('review reference and 1..1000 rows per population required')
    validate_population(development,'development')
    validate_population(evaluation,'evaluation',{r['request_id'] for r in development},{r['group_id'] for r in development})
    versions=request.get('model_versions')
    if not isinstance(versions,dict) or not versions:raise ValueError('executed model versions required')
    from adaptive_waf.runtime.routing import ROUTES
    for row in [*development,*evaluation]:
        if set(row['outcomes'])-set(ROUTES):raise ValueError('unknown routing action')
        if any(not 0<=value<=1 for value in row['pre_action_context'].values()):raise ValueError('pre-action features must be normalized to 0..1')
    start=time.monotonic();results=[];policies=[]
    for seed in (641,642,643):
        for constrained in (False,True):
            if time.monotonic()-start>20:raise ValueError('offline training time budget reached')
            policy=LinUCB(seed=seed)
            learning=replay(development,policy,learn=True,constrained=constrained,deadline=start+20)
            observations=replay(evaluation,policy,constrained=constrained,deadline=start+20)
            results.append({'seed':seed,'constrained':constrained,'training_rows':len(learning),'evaluation_rows':len(observations),
                            'mean_reward':sum(r['reward'] for r in observations)/len(observations),'decisions':observations})
            policies.append({'seed':seed,'constrained':constrained,'policy':policy.state(),'model_versions':versions})
    common=set.intersection(*(set(row['outcomes']) for row in evaluation))
    baselines={route:sum(labeled_reward(row['expected'],row['outcomes'][route]['predicted'],row['outcomes'][route]['latency_ms'],row['outcomes'][route]['compute_cost']) for row in evaluation)/len(evaluation) for route in sorted(common)}
    report={'run_id':str(uuid4()),'shadow_only':True,'automatic_promotion':False,'elapsed_seconds':time.monotonic()-start,
            'data_origin':request.get('data_origin','USER_REVIEWED_OUTCOMES'),
            'results':results,'static_baselines':baselines,'review_reference':request['review_reference'],
            'input_sha256':hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest(),
            'limitations':'Full-information offline replay. Controlled simulation costs are prescribed, not hardware measurements or real-world accuracy. User-provided VERIFIED provenance must be reviewed; no live security or shift guarantee.'}
    directory=Path(root)/report['run_id'];directory.mkdir(parents=True,exist_ok=False)
    report['policy_artifacts']=[]
    for policy in policies:
        name=f"policy-{policy['seed']}-{'constrained' if policy['constrained'] else 'unconstrained'}.json"
        (directory/name).write_text(json.dumps({**policy,'shadow_only':True},indent=2))
        report['policy_artifacts'].append(name)
    (directory/'report.json').write_text(json.dumps(report,indent=2))
    (directory/'policies.json').write_text(json.dumps(policies))
    return report
