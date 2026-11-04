"""Preflight, bounded sequential training, and quarantined model-only evaluation.

Default is read-only preflight. --execute is reserved for approved experiments.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
from time import monotonic, perf_counter, sleep
import tomllib

from adaptive_waf.contracts import AttackClass
from adaptive_waf.training.candidate_data import TOKEN_VERSION, load_role, protocol_manifest, sha256

CLASSES = [label.value for label in AttackClass]
SOURCE_FILES = ['src/adaptive_waf/features/inspection.py', 'src/adaptive_waf/features/classical.py',
                'src/adaptive_waf/features/canonical.py', 'src/adaptive_waf/training/candidate_data.py',
                'src/adaptive_waf/training/candidates.py', 'src/adaptive_waf/training/deep_training.py',
                'src/adaptive_waf/randomness.py', 'src/adaptive_waf/data/preparation.py',
                'src/adaptive_waf/contracts.py', 'scripts/candidate_experiments.py']


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, allow_nan=False)+'\n', encoding='utf-8')


def identity(config, candidate, seed, manifest):
    options = config['candidates'][candidate]
    base = Path(options['pretrained_model']) if 'pretrained_model' in options else None
    return {'candidate':candidate, 'seed':seed, 'classes':CLASSES, 'options':options,
            'populations_sha256':manifest['sha256'], 'representation':manifest['representation'],
            'token_representation':TOKEN_VERSION, 'source_sha256':{name:sha256(name) for name in SOURCE_FILES},
            'initialization_sha256':{name:sha256(base/name) for name in ('config.json','tokenizer.json','model.safetensors')} if base else {}}


def signature(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def preflight(config):
    if not 0 < config['limits']['wall_minutes'] <= 90 or not 0 < config['limits']['rss_gib'] <= 8:
        raise ValueError('experiment resource bounds exceeded')
    if not 1 <= len(config['seeds']) <= 3 or len(set(config['seeds'])) != len(config['seeds']):
        raise ValueError('experiment trial bounds exceeded')
    manifest = protocol_manifest(config['protocol'])
    for role in ('train', 'tune'):
        _, labels, _, _ = load_role(config['protocol'], role)
        if set(labels) != set(CLASSES):
            raise ValueError('each fitting role must contain all classes')
    for name, options in config['candidates'].items():
        if name not in {'structural','lexical','byte_cnn','compact_transformer','full_transformer'}:
            raise ValueError('unsupported candidate')
        if name.endswith('transformer'):
            source = Path(options['pretrained_model'])
            for required in ('config.json','model.safetensors','tokenizer.json'):
                if not (source/required).is_file():
                    raise ValueError('required pristine cached weights/tokenizer missing')
            base = json.loads((source/'config.json').read_text(encoding='utf-8'))
            if any('SequenceClassification' in value for value in base.get('architectures', [])):
                raise ValueError('old task-fitted model is not a pristine initialization')
        if name not in {'structural','lexical'}:
            if not 1 <= options['epochs'] <= 10 or not 1 <= options['batch_size'] <= 64:
                raise ValueError('unbounded epoch or batch configuration')
            if not 64 <= options['max_length'] <= 4096 or not 0 < options.get('gpu_memory_fraction', .5) <= .5:
                raise ValueError('invalid token/GPU allocation budget')
    return manifest


def fit(config, name, seed, directory, resume=None):
    from adaptive_waf.training.candidates import classical_candidate, fit_torch
    import joblib
    train_requests, train_labels, manifest, _ = load_role(config['protocol'], 'train')
    tune_requests, tune_labels, _, _ = load_role(config['protocol'], 'tune')
    provenance = identity(config, name, seed, manifest)
    directory.mkdir(parents=True, exist_ok=False)
    write_json(directory/'frozen_identity.json', provenance)
    started = perf_counter()
    if name in {'structural','lexical'}:
        if resume:
            raise ValueError('classical candidates restart as new runs')
        model = classical_candidate(name, seed)
        model.fit(train_requests, train_labels)
        joblib.dump(model, directory/'model.joblib')
        details = {'device':'cpu', 'fit_seconds':perf_counter()-started}
    else:
        details = fit_torch(name, (train_requests,train_labels), (tune_requests,tune_labels), CLASSES,
                            config['candidates'][name], seed, directory, signature(provenance),
                            config.get('device','auto'), resume)
    # Checkpoints remain resumable but are not required to perform inference.
    artifacts = {str(path.relative_to(directory)).replace('\\','/'):sha256(path)
                 for path in directory.rglob('*') if path.is_file() and path.suffix not in {'.tmp'}
                 and path.name not in {'last_checkpoint.pt','candidate.json'}}
    import sklearn
    write_json(directory/'candidate.json', {**provenance, 'signature':signature(provenance), 'artifacts':artifacts,
               'training':details, 'selection':'tune log loss only; no evaluation predictions during fitting',
               'environment':{'python':platform.python_version(),'sklearn':sklearn.__version__,'platform':platform.platform()},
               'rules_used':False, 'active_model_replaced':False})


def wilson(successes, count):
    if not count:
        return None
    z = 1.959963984540054
    p = successes/count
    center = (p+z*z/(2*count))/(1+z*z/count)
    radius = z*((p*(1-p)/count+z*z/(4*count*count))**.5)/(1+z*z/count)
    return [max(0,center-radius), min(1,center+radius)]


def evaluate(config, directory, role='evaluation'):
    from adaptive_waf.training.candidates import CandidatePredictor
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, log_loss
    import numpy as np
    requests, labels, manifest, identifiers = load_role(config['protocol'], role)
    predictor = CandidatePredictor(directory, config.get('device','auto'))
    expected = predictor.manifest['populations_sha256'][role]
    if expected != manifest['sha256'][role]:
        raise ValueError('candidate scored against a different population')
    started = perf_counter()
    rows = predictor.predict_many(requests)
    batch_seconds = perf_counter()-started
    predictions = [CLASSES[int(np.argmax(row))] for row in rows]
    durations = []
    # Warm batched model-only predictions above; these are serial request timings.
    for request in requests:
        begun = perf_counter()
        predictor.predict_many([request])
        durations.append((perf_counter()-begun)*1000)
    report = classification_report(labels, predictions, labels=CLASSES, output_dict=True, zero_division=0)
    benign = [i for i,label in enumerate(labels) if label == 'BENIGN']
    attacks = [i for i,label in enumerate(labels) if label != 'BENIGN']
    fp = sum(predictions[i] != 'BENIGN' for i in benign)
    fn = sum(predictions[i] == 'BENIGN' for i in attacks)
    per_class_intervals = {}
    for label in CLASSES:
        support = labels.count(label)
        correct = sum(a == b == label for a,b in zip(labels,predictions,strict=True))
        per_class_intervals[label] = {'correct':correct, 'support':support, 'recall_wilson95':wilson(correct,support)}
    # ECE is descriptive only; the tune set was used for model selection, not conformal calibration.
    confidence = np.max(rows, axis=1)
    correctness = np.array([a == b for a,b in zip(labels,predictions,strict=True)])
    ece = 0
    for lower in np.linspace(0,.9,10):
        selected = (confidence >= lower) & (confidence < lower+.1 if lower < .9 else confidence <= 1)
        if selected.any():
            ece += float(selected.mean()*abs(correctness[selected].mean()-confidence[selected].mean()))
    return {'population':role,'population_sha256':expected, 'classes':CLASSES,
            'accuracy':float(accuracy_score(labels,predictions)), 'classification':report,
            'confusion_matrix':confusion_matrix(labels,predictions,labels=CLASSES).tolist(),
            'recall_intervals':per_class_intervals, 'false_positive_rate':fp/len(benign),
            'fpr_wilson95':wilson(fp,len(benign)), 'false_negative_rate':fn/len(attacks),
            'log_loss':float(log_loss(labels,np.array(rows)[:,[CLASSES.index(label) for label in sorted(CLASSES)]],labels=sorted(CLASSES))), 'ece_10_bins':ece,
            'entropy_mean':float(np.mean(-np.sum(np.array(rows)*np.log(np.maximum(rows,1e-12)),axis=1))),
            'model_only_batch_requests_per_second':len(requests)/batch_seconds,
            'serial_model_only_ms':dict(zip(('p50','p95','p99'),np.percentile(durations,[50,95,99]).tolist())),
            'rules_used':False,'fully_inspected_model_decisions':len(requests),
            'measurement_boundary':'in-process candidate encoding+model; not gateway throughput',
            'limitations':manifest['limitations'], 'samples':[{'group_id':group,'label':label,'prediction':prediction,'probabilities':row}
                for group,label,prediction,row in zip(identifiers,labels,predictions,rows,strict=True)]}


def monitored(command, log, deadline, rss_limit):
    import psutil
    env = {**os.environ, 'OMP_NUM_THREADS':'2', 'MKL_NUM_THREADS':'2', 'OPENBLAS_NUM_THREADS':'2', 'TOKENIZERS_PARALLELISM':'false',
           'HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1'}
    peak, reason, cpu_seconds, next_gpu = 0, None, 0, 0
    resource_path = log.with_suffix('.resources.jsonl')
    with log.open('x',encoding='utf-8') as output, resource_path.open('x',encoding='utf-8') as resources:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, env=env)
        parent = psutil.Process(process.pid)
        try:
            while process.poll() is None:
                try:
                    children = parent.children(recursive=True)
                except psutil.NoSuchProcess:
                    break
                rss, cpu = 0, 0
                for item in [parent,*children]:
                    try:
                        rss += item.memory_info().rss
                        times = item.cpu_times()
                        cpu += times.user+times.system
                    except psutil.NoSuchProcess:
                        pass
                cpu_seconds = max(cpu_seconds,cpu)
                peak = max(peak,rss)
                sample = {'monotonic_seconds':monotonic(),'process_tree_rss_bytes':rss,'sampled_cpu_seconds':cpu}
                if monotonic() >= next_gpu:
                    next_gpu = monotonic()+2
                    try:
                        gpu = subprocess.run(['nvidia-smi','--query-gpu=utilization.gpu,memory.used,memory.total,power.draw',
                                              '--format=csv,noheader,nounits'],capture_output=True,text=True,timeout=2)
                        sample['whole_device_gpu_sample'] = gpu.stdout.strip() if gpu.returncode == 0 else None
                    except (OSError,subprocess.TimeoutExpired):
                        sample['whole_device_gpu_sample'] = None
                resources.write(json.dumps(sample)+'\n')
                resources.flush()
                if monotonic() >= deadline or rss > rss_limit:
                    reason = 'wall-clock budget exceeded' if monotonic() >= deadline else 'RSS budget exceeded'
                    for child in children:
                        child.kill()
                    process.kill()
                    break
                sleep(.25)
        except BaseException:
            if parent.is_running():
                for child in parent.children(recursive=True):
                    if child.is_running():
                        child.kill()
            if process.poll() is None:
                process.kill()
            raise
        finally:
            process.wait()
    return {'exit_code':process.returncode,'peak_process_tree_rss_bytes':peak,'budget_stop':reason,
            'sampled_cpu_seconds_lower_bound':cpu_seconds,'resource_samples':str(resource_path),
            'gpu_sample_boundary':'whole shared device; not process-attributed GPU time or energy'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--fit',choices=['structural','lexical','byte_cnn','compact_transformer','full_transformer'],help=argparse.SUPPRESS)
    parser.add_argument('--score',type=Path,help=argparse.SUPPRESS)
    parser.add_argument('--seed',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--resume',type=Path,help='Resume a --fit worker into a new output directory')
    args = parser.parse_args()
    config = tomllib.loads(args.config.read_text(encoding='utf-8'))
    manifest = preflight(config)
    if args.fit:
        if not args.output or args.seed is None:
            parser.error('fit requires output and seed')
        fit(config,args.fit,args.seed,args.output,args.resume)
        return
    if args.score:
        if not args.output or args.output.exists():
            parser.error('score requires a new result file')
        write_json(args.output,evaluate(config,args.score))
        return
    runs = [(name,seed) for name in config['candidates'] for seed in config['seeds']]
    plan = {'config_sha256':sha256(args.config),'protocol_sha256':sha256(Path(config['protocol'])/'manifest.json'),
            'counts':manifest['counts'],'runs':[identity(config,name,seed,manifest) for name,seed in runs],
            'limits':config['limits'],'evaluation_only_after_all_fits':True,'downloads':False,'deployment':False}
    if not args.execute:
        print(json.dumps(plan,indent=2))
        return
    if not args.output or args.output.exists():
        parser.error('execute requires a new output directory')
    args.output.mkdir(parents=True)
    write_json(args.output/'plan.json',plan)
    deadline = monotonic()+config['limits']['wall_minutes']*60
    outcomes = []
    for name,seed in runs:
        directory = args.output/f'{name}-{seed}'
        command = [sys.executable,'-m','scripts.candidate_experiments','--config',str(args.config),
                   '--fit',name,'--seed',str(seed),'--output',str(directory)]
        outcome = {'candidate':name,'seed':seed,'phase':'fit',**monitored(command,args.output/f'{name}-{seed}-fit.log',deadline,
                    config['limits']['rss_gib']*1024**3)}
        outcomes.append(outcome)
        write_json(args.output/'outcomes.json',outcomes)
        if outcome['exit_code'] != 0:
            raise RuntimeError('fit failed/budget exhausted; evidence retained, evaluation unopened')
    # Final evaluation is only reached after all candidate definitions/weights are fixed.
    for name,seed in runs:
        command = [sys.executable,'-m','scripts.candidate_experiments','--config',str(args.config),
                   '--score',str(args.output/f'{name}-{seed}'),'--output',str(args.output/f'{name}-{seed}-evaluation.json')]
        outcome = {'candidate':name,'seed':seed,'phase':'evaluation',**monitored(command,args.output/f'{name}-{seed}-score.log',deadline,
                    config['limits']['rss_gib']*1024**3)}
        outcomes.append(outcome)
        write_json(args.output/'outcomes.json',outcomes)
        if outcome['exit_code'] != 0:
            raise RuntimeError('evaluation failed/budget exhausted; evidence retained')


if __name__ == '__main__':
    main()
